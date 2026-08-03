"""Normalize heterogeneous scanner outputs into unified threat report."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from apk_plug.report import (
    RiskLevel,
    SchemaValidationError,
    ThreatReport,
    ToolStatus,
    validate_report,
)

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1.0.0"


def _safe_load_json(path: Path) -> dict[str, Any] | None:
    """Safely load JSON file, returning None on error."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to load %s: %s", path, e)
        return None


def _safe_read_text(path: Path) -> str | None:
    """Safely read text file, returning None on error."""
    if not path.exists():
        return None
    try:
        return path.read_text()
    except OSError as e:
        logger.warning("Failed to read %s: %s", path, e)
        return None


def parse_mobsf(data: dict[str, Any]) -> dict[str, Any]:
    """Parse MobSF JSON report."""
    result: dict[str, Any] = {
        "status": ToolStatus.RAN.value,
        "permissions": [],
        "components": [],
        "findings": [],
        "urls": [],
    }

    # Extract permissions
    if "permissions" in data:
        perms = data["permissions"]
        if isinstance(perms, dict):
            result["permissions"] = list(perms.keys())
        elif isinstance(perms, list):
            result["permissions"] = perms

    # Extract components from manifest analysis
    if "manifest_analysis" in data:
        manifest = data["manifest_analysis"]
        if isinstance(manifest, list):
            for item in manifest:
                if isinstance(item, dict) and "title" in item:
                    result["findings"].append({
                        "rule": item.get("title", ""),
                        "severity": item.get("severity", "info"),
                        "description": item.get("description", ""),
                    })

    # Extract malicious code findings
    if "malicious_code" in data:
        for item in data["malicious_code"]:
            if isinstance(item, dict):
                result["findings"].append({
                    "rule": item.get("title", "malicious_code"),
                    "severity": "high",
                    "description": item.get("description", ""),
                })

    # Extract secrets
    if "secrets" in data:
        for secret in data["secrets"]:
            if isinstance(secret, dict):
                result["findings"].append({
                    "rule": "hardcoded_secret",
                    "severity": "high",
                    "description": secret.get("description", str(secret)),
                })

    # Extract URLs. MobSF's v1 API emits `urls` as a list of objects shaped
    # {"urls": ["https://...", ...], "path": "src/File.java"} — NOT a flat list
    # of strings. Flatten to strings so downstream set()-dedup never sees an
    # unhashable dict. Tolerate the string-list and {"url": "..."} shapes too.
    if "urls" in data and isinstance(data["urls"], list):
        flat: list[str] = []
        for entry in data["urls"]:
            if isinstance(entry, str):
                flat.append(entry)
            elif isinstance(entry, dict):
                inner = entry.get("urls")
                if isinstance(inner, list):
                    flat.extend(u for u in inner if isinstance(u, str))
                elif isinstance(entry.get("url"), str):
                    flat.append(entry["url"])
        result["urls"] = flat

    # Extract exported components
    for comp_type in ["exported_activities", "exported_services", "exported_receivers", "exported_providers"]:
        if comp_type in data:
            comp_list = data[comp_type]
            if isinstance(comp_list, list):
                type_name = comp_type.replace("exported_", "").rstrip("s")
                for comp in comp_list:
                    name = comp if isinstance(comp, str) else comp.get("name", str(comp))
                    result["components"].append({
                        "type": type_name,
                        "name": name,
                        "source_tool": "mobsf",
                        "exported": True,
                    })

    return result


def parse_quark(data: dict[str, Any]) -> dict[str, Any]:
    """Parse Quark engine JSON report."""
    result: dict[str, Any] = {
        "status": ToolStatus.RAN.value,
        "findings": [],
        "threat_level": data.get("threat_level", "unknown"),
        "total_score": data.get("total_score", 0),
    }

    # Extract crimes (behavioral findings)
    if "crimes" in data:
        for crime in data["crimes"]:
            if isinstance(crime, dict):
                confidence = _quark_confidence_to_int(crime.get("confidence", 0))
                result["findings"].append({
                    "rule": crime.get("crime", "unknown_behavior"),
                    "severity": _quark_confidence_to_severity(confidence),
                    "description": crime.get("crime", ""),
                    "confidence": confidence,
                })

    return result


def _quark_confidence_to_int(confidence: object) -> int:
    """Coerce a quark confidence into an integer 0-100.

    Real quark-engine emits confidence as a percentage STRING (e.g. "100%",
    "60%"), while older fixtures / tests may use a bare int/float. Both must
    map to an int so downstream severity comparison and the schema (which types
    `confidence` as integer) never break. Anything unparseable becomes 0.
    """
    if isinstance(confidence, bool):
        return 0
    if isinstance(confidence, (int, float)):
        return int(confidence)
    if isinstance(confidence, str):
        match = re.search(r"-?\d+", confidence)
        if match:
            return int(match.group())
    return 0


def _quark_confidence_to_severity(confidence: int | float) -> str:
    """Convert Quark confidence score to severity level."""
    if confidence >= 80:
        return "critical"
    if confidence >= 60:
        return "high"
    if confidence >= 40:
        return "medium"
    return "low"


def parse_semgrep_sarif(data: dict[str, Any]) -> dict[str, Any]:
    """Parse Semgrep SARIF report."""
    result: dict[str, Any] = {
        "status": ToolStatus.RAN.value,
        "findings": [],
    }

    if "runs" not in data:
        return result

    for run_data in data["runs"]:
        if "results" not in run_data:
            continue

        for finding in run_data["results"]:
            severity = _sarif_level_to_severity(finding.get("level", "note"))
            result["findings"].append({
                "rule": finding.get("ruleId", "unknown"),
                "severity": severity,
                "description": finding.get("message", {}).get("text", ""),
                "location": _extract_sarif_location(finding),
            })

    return result


def _sarif_level_to_severity(level: str) -> str:
    """Convert SARIF level to our severity."""
    mapping = {
        "error": "high",
        "warning": "medium",
        "note": "low",
        "none": "info",
    }
    return mapping.get(level, "info")


def _extract_sarif_location(finding: dict[str, Any]) -> str | None:
    """Extract location from SARIF finding."""
    locations = finding.get("locations", [])
    if not locations:
        return None
    loc = locations[0].get("physicalLocation", {})
    artifact = loc.get("artifactLocation", {}).get("uri", "")
    region = loc.get("region", {})
    line = region.get("startLine", "")
    return f"{artifact}:{line}" if artifact else None


def parse_apkleaks(data: dict[str, Any]) -> dict[str, Any]:
    """Parse APKLeaks JSON report."""
    result: dict[str, Any] = {
        "status": ToolStatus.RAN.value,
        "findings": [],
        "urls": [],
    }

    if "results" not in data:
        return result

    results = data["results"]

    # Real apkleaks emits `results` as a LIST of {"name": <rule>, "matches": [...]}
    # objects. (An older/dict shape — {category: [items]} — is also tolerated for
    # back-compat with the golden fixture.) Normalize both into (category, items).
    if isinstance(results, list):
        pairs = [
            (entry.get("name", "unknown"), entry.get("matches", []))
            for entry in results
            if isinstance(entry, dict)
        ]
    elif isinstance(results, dict):
        pairs = list(results.items())
    else:
        return result

    url_categories = ("URL", "URI", "ENDPOINT", "LINKFINDER", "LINK")
    for category, items in pairs:
        if not isinstance(items, list):
            continue

        if str(category).upper() in url_categories:
            result["urls"].extend(str(i).strip() for i in items if isinstance(i, str))
        else:
            for item in items:
                result["findings"].append({
                    "rule": f"apkleaks_{str(category).lower()}",
                    "severity": "medium",
                    "description": str(item).strip(),
                    "category": str(category),
                })

    return result


def parse_apkid(text: str) -> dict[str, Any]:
    """Parse APKiD text output."""
    result: dict[str, Any] = {
        "status": ToolStatus.RAN.value,
        "findings": [],
        "packers": [],
        "compilers": [],
        "obfuscators": [],
    }

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("["):
            continue

        # APKiD output format: "category : value"
        if ":" in line:
            parts = line.split(":", 1)
            if len(parts) == 2:
                category = parts[0].strip().lower()
                value = parts[1].strip()

                if "packer" in category:
                    result["packers"].append(value)
                    result["findings"].append({
                        "rule": "packer_detected",
                        "severity": "high",
                        "description": f"Packer detected: {value}",
                    })
                elif "compiler" in category:
                    result["compilers"].append(value)
                elif "obfuscator" in category:
                    result["obfuscators"].append(value)
                    result["findings"].append({
                        "rule": "obfuscator_detected",
                        "severity": "medium",
                        "description": f"Obfuscator detected: {value}",
                    })

    return result


def parse_apktriage(data: dict[str, Any]) -> dict[str, Any]:
    """Parse apktriage JSON report."""
    result: dict[str, Any] = {
        "status": ToolStatus.RAN.value,
        "findings": [],
        "mitre_techniques": [],
        "yara_matches": [],
    }

    # Extract YARA matches
    if "yara" in data:
        for match in data["yara"]:
            if isinstance(match, dict):
                result["yara_matches"].append(match.get("rule", str(match)))
                result["findings"].append({
                    "rule": f"yara_{match.get('rule', 'unknown')}",
                    "severity": "high",
                    "description": match.get("description", f"YARA rule match: {match.get('rule', '')}"),
                })
            elif isinstance(match, str):
                result["yara_matches"].append(match)
                result["findings"].append({
                    "rule": f"yara_{match}",
                    "severity": "high",
                    "description": f"YARA rule match: {match}",
                })

    # Extract MITRE techniques
    if "mitre" in data:
        for tech in data["mitre"]:
            if isinstance(tech, dict):
                result["mitre_techniques"].append({
                    "id": tech.get("id", ""),
                    "name": tech.get("name", ""),
                })

    return result


def calculate_aggregate_risk(
    tools_data: dict[str, dict[str, Any]],
    all_findings: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    """Calculate aggregate risk score from all findings."""
    score = 0
    drivers: list[str] = []

    # Count findings by severity.
    severity_weights = {"critical": 25, "high": 15, "medium": 5, "low": 1, "info": 0}

    # quark's per-crime findings are behavioral observations, not per-item
    # threats — its risk contribution is the single weighted total_score /
    # threat_level handled below (matching the stage-2 decision tree, which
    # keys off quark's 0-100 score). Summing every crime's confidence-derived
    # severity here would double-count and let quark's known over-reporting
    # alone max the aggregate on clean SDK-heavy apps, so exclude it.
    for tool_name, findings in all_findings.items():
        if tool_name == "quark":
            continue
        for finding in findings:
            severity = finding.get("severity", "info")
            weight = severity_weights.get(severity, 0)
            score += weight

    # quark emits a human label ("Low/Moderate/High Risk"), not the bare
    # "high"/"dangerous" tokens — match case-insensitively. The label
    # over-reports ("High Risk" at near-zero total_score on SDK-heavy apps),
    # so credit it only when quark's numeric score is also non-trivial.
    quark_data = tools_data.get("quark", {})
    if quark_data.get("status") == ToolStatus.RAN.value:
        threat_level = str(quark_data.get("threat_level", "")).lower()
        total_score = quark_data.get("total_score", 0)
        if not isinstance(total_score, (int, float)):
            total_score = 0
        if ("high" in threat_level or "dangerous" in threat_level) and total_score >= 10:
            score += 30
            drivers.append("quark_high_threat")
        if total_score >= 80:
            score += 20
            drivers.append("quark_score_80plus")

    # Check for packers (high risk indicator)
    apkid_data = tools_data.get("apkid", {})
    if apkid_data.get("packers"):
        score += 20
        drivers.append("packer_detected")

    # Companion-data blind spots (payloads outside the universal/target APK)
    companion_findings = all_findings.get("companion", [])
    if any(f.get("severity") in ("critical", "high") for f in companion_findings):
        score += 20
        drivers.append("companion_data_payload")

    # Normalize to 0-100
    score = min(score, 100)

    # Determine level
    if score >= 80:
        level = RiskLevel.CRITICAL
    elif score >= 50:
        level = RiskLevel.HIGH
    elif score >= 25:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW

    return {
        "score": score,
        "level": level.value,
        "drivers": drivers,
    }


def compute_sha256(path: Path) -> str:
    """Compute SHA256 hash of a file."""
    if not path.exists():
        return ""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def _decoded_manifest_path(apk_path: Path) -> Path:
    return apk_path.parent.parent / "decompile" / "smali" / "AndroidManifest.xml"


def parse_manifest_permissions(manifest_path: Path) -> list[str]:
    """Read requested permissions from an apktool-decoded AndroidManifest.xml.

    Fallback for when MobSF (the only other permission source) did not run.
    Returns [] on any parse error so report generation never breaks.
    """
    if not manifest_path.exists():
        return []
    try:
        root = ET.parse(manifest_path).getroot()
    except (ET.ParseError, OSError) as e:
        logger.warning("Could not parse manifest %s: %s", manifest_path, e)
        return []
    perms: list[str] = []
    for el in root.iter("uses-permission"):
        name = el.get(f"{_ANDROID_NS}name")
        if name:
            perms.append(name)
    return perms


def parse_manifest_components(manifest_path: Path) -> list[dict[str, Any]]:
    """Read exported components from an apktool-decoded AndroidManifest.xml.

    Fallback for when MobSF did not run. Only emits components explicitly
    marked android:exported="true" (the attack surface). Returns [] on error.
    """
    if not manifest_path.exists():
        return []
    try:
        root = ET.parse(manifest_path).getroot()
    except (ET.ParseError, OSError) as e:
        logger.warning("Could not parse manifest %s: %s", manifest_path, e)
        return []
    app = root.find("application")
    if app is None:
        return []
    components: list[dict[str, Any]] = []
    for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
        for el in app.findall(tag):
            if el.get(f"{_ANDROID_NS}exported") != "true":
                continue
            name = el.get(f"{_ANDROID_NS}name")
            if not name:
                continue
            comp: dict[str, Any] = {
                "type": tag.replace("activity-alias", "activity"),
                "name": name,
                "source_tool": "manifest",
                "exported": True,
            }
            perm = el.get(f"{_ANDROID_NS}permission")
            if perm:
                comp["permission"] = perm
            components.append(comp)
    return components


_URL_RE = re.compile(r"https?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
_URL_HOST_RE = re.compile(r"https?://([a-zA-Z0-9._-]+)")
_URL_SCAN_MAX_FILES = 20000


def extract_urls_from_sources(java_dir: Path, *, limit: int = 4000) -> list[str]:
    """Extract http(s) URLs from decompiled Java as an apkleaks fallback.

    apkleaks can abort its JSON writer on very large multi-DEX APKs, leaving no
    URL evidence. This is a best-effort sweep bounded by file/URL caps so it
    stays cheap. Schema-namespace hosts (schemas.android.com, w3.org, etc.) are
    dropped because they are XML boilerplate, not network endpoints.
    """
    if not java_dir.exists():
        return []
    schema_hosts = {
        "schemas.android.com", "www.w3.org", "www.apache.org", "xmlpull.org",
        "ns.adobe.com", "xml.org", "www.ietf.org", "tizen.org", "semver.org",
        "java.sun.com", "www.slf4j.org",
    }
    found: set[str] = set()
    scanned = 0
    for path in java_dir.rglob("*.java"):
        if scanned >= _URL_SCAN_MAX_FILES or len(found) >= limit:
            break
        scanned += 1
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        for m in _URL_RE.finditer(text):
            url = m.group()
            host_m = _URL_HOST_RE.match(url)
            if host_m and host_m.group(1) in schema_hosts:
                continue
            found.add(url)
            if len(found) >= limit:
                break
    return sorted(found)


def _safe_parse(
    name: str,
    fn: Callable[[Any], dict[str, Any]],
    data: Any,
) -> dict[str, Any]:
    """
    Run a scanner-output parser defensively.

    A parser that chokes on an unexpected real-world output shape must mark that
    tool `error` and let the unified report still be produced — the same
    never-hard-crash contract Stage 2 applies to the scanners themselves.
    Regression: real MobSF `urls` (a list of dicts) and real apkleaks `results`
    (a list, not a dict) each crashed a parser and aborted the whole report so
    no threat-report.json was written.
    """
    try:
        return fn(data)
    except Exception as exc:  # noqa: BLE001 - heterogeneous external tool output
        logger.warning("Parser %s failed on its output (marked error): %s", name, exc)
        return {"status": ToolStatus.ERROR.value}


def normalize_scanner_outputs(
    scan_dir: Path,
    apk_path: Path,
    now: str | None = None,
    schema_path: Path | None = None,
) -> ThreatReport:
    """
    Normalize all scanner outputs into a unified ThreatReport.

    Args:
        scan_dir: Directory containing scanner output subdirectories.
        apk_path: Path to the analyzed APK (for metadata).
        now: Override timestamp for testing (ISO format).
        schema_path: Override path to JSON schema.

    Returns:
        Unified ThreatReport.

    Raises:
        SchemaValidationError: If the generated report fails validation.
    """
    if now is None:
        now = datetime.now(timezone.utc).isoformat()

    tools_data: dict[str, dict[str, Any]] = {}
    all_findings: dict[str, list[dict[str, Any]]] = {}
    all_urls: list[str] = []
    all_permissions: list[str] = []
    all_components: list[dict[str, Any]] = []
    all_mitre: list[dict[str, str]] = []

    # Parse MobSF
    mobsf_path = scan_dir / "mobsf" / "report.json"
    mobsf_data = _safe_load_json(mobsf_path)
    if mobsf_data:
        parsed = _safe_parse("mobsf", parse_mobsf, mobsf_data)
        tools_data["mobsf"] = {"status": parsed["status"]}
        all_findings["mobsf"] = parsed.get("findings", [])
        all_permissions.extend(parsed.get("permissions", []))
        all_components.extend(parsed.get("components", []))
        all_urls.extend(parsed.get("urls", []))
    else:
        tools_data["mobsf"] = {"status": ToolStatus.NOT_RUN.value}

    # Parse Quark
    quark_path = scan_dir / "quark" / "report.json"
    quark_data = _safe_load_json(quark_path)
    if quark_data:
        parsed = _safe_parse("quark", parse_quark, quark_data)
        # Omit threat_level/total_score when absent (e.g. the _safe_parse error
        # default) so a null never reaches the schema (which types them
        # string/integer).
        quark_entry: dict[str, Any] = {"status": parsed["status"]}
        if parsed.get("threat_level") is not None:
            quark_entry["threat_level"] = parsed["threat_level"]
        if parsed.get("total_score") is not None:
            quark_entry["total_score"] = parsed["total_score"]
        tools_data["quark"] = quark_entry
        all_findings["quark"] = parsed.get("findings", [])
    else:
        tools_data["quark"] = {"status": ToolStatus.NOT_RUN.value}

    # Parse Semgrep SARIF
    semgrep_path = scan_dir / "semgrep" / "report.sarif"
    semgrep_data = _safe_load_json(semgrep_path)
    if semgrep_data:
        parsed = _safe_parse("semgrep", parse_semgrep_sarif, semgrep_data)
        tools_data["semgrep"] = {"status": parsed["status"]}
        all_findings["semgrep"] = parsed.get("findings", [])
    else:
        tools_data["semgrep"] = {"status": ToolStatus.NOT_RUN.value}

    # Parse APKLeaks
    apkleaks_path = scan_dir / "apkleaks" / "report.json"
    apkleaks_data = _safe_load_json(apkleaks_path)
    if apkleaks_data:
        parsed = _safe_parse("apkleaks", parse_apkleaks, apkleaks_data)
        tools_data["apkleaks"] = {"status": parsed["status"]}
        all_findings["apkleaks"] = parsed.get("findings", [])
        all_urls.extend(parsed.get("urls", []))
    else:
        tools_data["apkleaks"] = {"status": ToolStatus.NOT_RUN.value}

    # Parse APKiD
    apkid_path = scan_dir / "apkid" / "report.txt"
    apkid_text = _safe_read_text(apkid_path)
    if apkid_text:
        parsed = _safe_parse("apkid", parse_apkid, apkid_text)
        tools_data["apkid"] = {
            "status": parsed["status"],
            "packers": parsed.get("packers", []),
            "obfuscators": parsed.get("obfuscators", []),
        }
        all_findings["apkid"] = parsed.get("findings", [])
    else:
        tools_data["apkid"] = {"status": ToolStatus.NOT_RUN.value}

    # Parse apktriage
    apktriage_path = scan_dir / "apktriage" / "report.json"
    apktriage_data = _safe_load_json(apktriage_path)
    if apktriage_data:
        parsed = _safe_parse("apktriage", parse_apktriage, apktriage_data)
        tools_data["apktriage"] = {
            "status": parsed["status"],
            "yara_matches": parsed.get("yara_matches", []),
        }
        all_findings["apktriage"] = parsed.get("findings", [])
        all_mitre.extend(parsed.get("mitre_techniques", []))
    else:
        tools_data["apktriage"] = {"status": ToolStatus.NOT_RUN.value}

    # Parse companion-data scan (OBB / dropped feature modules / asset packs /
    # DEX-in-assets). Already emitted in the unified-findings shape by Stage 2.
    companion_path = scan_dir / "companion" / "report.json"
    companion_data = _safe_load_json(companion_path)
    if companion_data:
        tools_data["companion"] = {"status": ToolStatus.RAN.value}
        all_findings["companion"] = companion_data.get("findings", [])
    else:
        tools_data["companion"] = {"status": ToolStatus.NOT_RUN.value}

    # Deduplicate. Guard against a scanner emitting a non-string (e.g. a dict):
    # keep only hashable strings so report generation can never hard-crash here.
    all_urls = sorted({u for u in all_urls if isinstance(u, str)})
    all_permissions = sorted({p for p in all_permissions if isinstance(p, str)})

    # Fallbacks from the apktool-decoded manifest / jadx sources when the only
    # scanner that supplies these (MobSF) did not run, or apkleaks produced no
    # URLs. Best-effort: failures return [] and leave the report unchanged.
    manifest_path = _decoded_manifest_path(apk_path)
    if not all_permissions:
        all_permissions = sorted(set(parse_manifest_permissions(manifest_path)))
    if not all_components:
        all_components = parse_manifest_components(manifest_path)
    if not all_urls:
        java_dir = apk_path.parent.parent / "decompile" / "java"
        all_urls = extract_urls_from_sources(java_dir)

    # Calculate aggregate risk
    aggregate_risk = calculate_aggregate_risk(tools_data, all_findings)

    # Build report
    report = ThreatReport(
        schema_version=SCHEMA_VERSION,
        apk={
            "name": apk_path.name,
            "sha256": compute_sha256(apk_path),
        },
        generated_at=now,
        tools=tools_data,
        components=all_components,
        urls=all_urls,
        permissions=all_permissions,
        mitre_techniques=all_mitre,
        findings=all_findings,
        aggregate_risk=aggregate_risk,
    )

    # Validate against schema
    report_dict = report.to_dict()
    validate_report(report_dict, schema_path)

    return report
