"""Stage 2: Run security scanners and normalize outputs."""

from __future__ import annotations

import json
import logging
import shutil
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apk_plug.workspace import Workspace

from apk_plug.normalize import normalize_scanner_outputs
from apk_plug.runner import ToolFailedError, ToolNotFoundError, run

logger = logging.getLogger(__name__)

# File signatures used to detect payloads hidden under non-code extensions.
_DEX_MAGIC = b"dex\n"
_ELF_MAGIC = b"\x7fELF"


def _file_magic(path: Path, n: int = 8) -> bytes:
    """Read the first n bytes of a file, returning b'' on error."""
    try:
        with path.open("rb") as f:
            return f.read(n)
    except OSError:
        return b""


def find_embedded_payloads(root: Path) -> list[dict[str, str]]:
    """
    Recursively find DEX/ELF payloads under a directory.

    Detects by BOTH extension and file magic, so a `.dex` renamed to `.png`
    (a common evasion) is still caught.

    Args:
        root: Directory to scan.

    Returns:
        List of {"path": relative_path, "type": "dex"|"elf"} findings.
    """
    findings: list[dict[str, str]] = []
    if not root.exists():
        return findings

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        magic = _file_magic(path)
        rel = str(path.relative_to(root))
        if path.suffix == ".dex" or magic.startswith(_DEX_MAGIC):
            findings.append({"path": rel, "type": "dex"})
        elif path.suffix == ".so" or magic.startswith(_ELF_MAGIC):
            findings.append({"path": rel, "type": "elf"})

    return findings


def scan_apk_assets_for_dex(apk_path: Path) -> list[str]:
    """
    Detect DEX payloads smuggled inside an APK's assets/ directory.

    jadx/apktool do not decompile DEX nested in assets/, so reflection /
    DexClassLoader payloads there are a scan blind spot in every input format.

    Args:
        apk_path: Path to the APK (or universal target.apk).

    Returns:
        List of asset entry names that are DEX (by extension or magic).
    """
    dex_entries: list[str] = []
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                if not name.startswith("assets/") or name.endswith("/"):
                    continue
                if name.endswith(".dex"):
                    dex_entries.append(name)
                    continue
                try:
                    with zf.open(name) as f:
                        if f.read(4).startswith(_DEX_MAGIC):
                            dex_entries.append(name)
                except (OSError, zipfile.BadZipFile):
                    continue
    except zipfile.BadZipFile:
        logger.debug("%s is not a zip archive", apk_path.name)

    return dex_entries


def scan_companion_artifacts(workspace: Workspace) -> list[dict[str, str]]:
    """
    Scan ALL companion data surfaces for hidden payloads and write a report.

    Covers the blind spots that never reach the main jadx/apktool/scanner pass
    because they live outside the universal/target APK:
      - OBB expansion files (XAPK/APKM) — hidden DEX
      - AAB dynamic feature modules dropped from the universal APK (fusing=false)
      - Play Asset Delivery asset packs (fast-follow / on-demand) — DEX/ELF
      - DEX smuggled inside the target APK's own assets/ directory

    Writes scan/companion/report.json in the unified-findings shape so the
    normalizer can fold it into threat-report.json.

    Args:
        workspace: The workspace to scan.

    Returns:
        List of finding dicts (rule, severity, description, category).
    """
    findings: list[dict[str, str]] = []

    # 1. OBB expansion files (existing behavior, now routed into findings).
    for obb_name, dex_files in scan_obb_files(workspace).items():
        for dex in dex_files:
            findings.append({
                "rule": "dex_in_obb",
                "severity": "high",
                "description": f"Hidden DEX '{dex}' inside OBB '{obb_name}'",
                "category": "companion_data",
            })

    # 2. AAB feature modules + asset packs preserved under input/aab-raw/.
    raw_dir = workspace.aab_raw_dir
    companion_modules = [
        (m, "feature") for m in workspace.state.feature_modules
    ] + [
        (m, "asset_pack") for m in workspace.state.asset_packs
    ]
    for module, kind in companion_modules:
        name = module.get("name", "")
        module_root = raw_dir / name
        payloads = find_embedded_payloads(module_root)
        in_universal = module.get("in_universal")
        dropped = in_universal is False

        # A dropped module carrying code is itself a blind spot worth flagging,
        # even before payload detection.
        if dropped and (module.get("has_dex") or module.get("has_lib")):
            findings.append({
                "rule": "dropped_feature_module_with_code",
                "severity": "high",
                "description": (
                    f"{kind} '{name}' is NOT in the universal APK "
                    f"(in_universal=false) yet ships DEX/native code — invisible "
                    f"to the main scan; analyzed from raw bundle"
                ),
                "category": "companion_data",
            })

        for payload in payloads:
            # DEX/ELF in an asset pack, or in a non-fused module, is high risk.
            severity = "high" if (kind == "asset_pack" or dropped) else "medium"
            findings.append({
                "rule": f"{payload['type']}_in_{kind}",
                "severity": severity,
                "description": (
                    f"{payload['type'].upper()} payload '{payload['path']}' "
                    f"in {kind} '{name}' (in_universal={in_universal})"
                ),
                "category": "companion_data",
            })

    # 3. DEX hidden inside the target APK's own assets/.
    for entry in scan_apk_assets_for_dex(workspace.target_apk):
        findings.append({
            "rule": "dex_in_apk_assets",
            "severity": "high",
            "description": (
                f"DEX payload '{entry}' inside APK assets/ — reflection / "
                f"DexClassLoader vector, not decompiled by jadx/apktool"
            ),
            "category": "companion_data",
        })

    # Persist in the unified-findings shape for the normalizer.
    report = {
        "status": "ran",
        "findings": findings,
    }
    report_path = workspace.scan_dir / "companion" / "report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n")

    if findings:
        logger.warning("Companion-data scan found %d payload/blind-spot finding(s)", len(findings))

    return findings


def check_obb_for_dex(obb_path: Path) -> list[str]:
    """
    Check an OBB file for hidden DEX payloads.

    Args:
        obb_path: Path to the OBB file.

    Returns:
        List of DEX files found within the OBB.
    """
    dex_files: list[str] = []

    try:
        with zipfile.ZipFile(obb_path, "r") as zf:
            for name in zf.namelist():
                if name.endswith(".dex") or "classes" in name.lower() and name.endswith(".dex"):
                    dex_files.append(name)
                    logger.warning("Hidden DEX found in OBB %s: %s", obb_path.name, name)
    except zipfile.BadZipFile:
        # OBB might not be a zip file
        logger.debug("OBB %s is not a zip archive", obb_path.name)

    return dex_files


def scan_obb_files(workspace: Workspace) -> dict[str, list[str]]:
    """
    Scan all OBB files in workspace for hidden DEX payloads.

    Args:
        workspace: The workspace containing OBB files.

    Returns:
        Dict mapping OBB filename to list of DEX files found.
    """
    results: dict[str, list[str]] = {}

    if not workspace.obb_dir.exists():
        return results

    for obb_file in workspace.obb_dir.glob("*.obb"):
        dex_files = check_obb_for_dex(obb_file)
        if dex_files:
            results[obb_file.name] = dex_files

    return results


def run_mobsf_scan(workspace: Workspace, api_url: str | None = None, api_key: str | None = None) -> bool:
    """
    Run MobSF scan via API.

    Args:
        workspace: The workspace to scan.
        api_url: MobSF API URL (default: http://localhost:8000).
        api_key: MobSF API key.

    Returns:
        True if scan succeeded, False otherwise.
    """
    if api_url is None:
        api_url = "http://localhost:8000"

    if api_key is None:
        logger.warning("MobSF API key not provided - skipping MobSF scan")
        return False

    apk_path = workspace.target_apk
    output_dir = workspace.scan_dir / "mobsf"

    try:
        # Upload APK
        upload_result = run(
            [
                "curl", "-s",
                "-F", f"file=@{apk_path}",
                "-H", f"Authorization: {api_key}",
                f"{api_url}/api/v1/upload",
            ],
            timeout=120.0,
            check=False,
        )

        if upload_result.returncode != 0:
            logger.warning("MobSF upload failed: %s", upload_result.stderr)
            return False

        upload_data = json.loads(upload_result.stdout)
        file_hash = upload_data.get("hash")

        if not file_hash:
            logger.warning("MobSF upload did not return hash")
            return False

        # Trigger scan
        scan_result = run(
            [
                "curl", "-s", "-X", "POST",
                "-H", f"Authorization: {api_key}",
                "-d", f"hash={file_hash}&scan_type=apk",
                f"{api_url}/api/v1/scan",
            ],
            timeout=600.0,
            check=False,
        )

        if scan_result.returncode != 0:
            logger.warning("MobSF scan failed: %s", scan_result.stderr)
            return False

        # Save report
        report_path = output_dir / "report.json"
        report_path.write_text(scan_result.stdout)
        logger.info("MobSF scan complete: %s", report_path)
        return True

    except (ToolNotFoundError, json.JSONDecodeError) as e:
        logger.warning("MobSF scan error: %s", e)
        return False


def run_mobsfscan(workspace: Workspace) -> bool:
    """
    Run mobsfscan on decompiled source.

    Args:
        workspace: The workspace to scan.

    Returns:
        True if scan succeeded, False otherwise.
    """
    output_dir = workspace.scan_dir / "mobsfscan"
    output_file = output_dir / "report.json"

    try:
        run(
            [
                "mobsfscan",
                str(workspace.decompile_java_dir),
                "--json",
                "-o", str(output_file),
            ],
            timeout=300.0,
        )
        logger.info("mobsfscan complete: %s", output_file)
        return True
    except ToolNotFoundError:
        logger.warning("mobsfscan not found - skipping")
        return False
    except ToolFailedError as e:
        logger.warning("mobsfscan failed: %s", e)
        return False


def run_semgrep(workspace: Workspace, rules_path: str | None = None) -> bool:
    """
    Run semgrep with Android security rules.

    Args:
        workspace: The workspace to scan.
        rules_path: Path to semgrep rules (default: auto-detect).

    Returns:
        True if scan succeeded, False otherwise.
    """
    output_dir = workspace.scan_dir / "semgrep"
    output_file = output_dir / "report.sarif"

    # Default rules location
    if rules_path is None:
        # Try common locations
        candidates = [
            Path.home() / ".local/share/semgrep-rules-android-security/rules",
            Path("/usr/local/share/semgrep-rules-android-security/rules"),
        ]
        for candidate in candidates:
            if candidate.exists():
                rules_path = str(candidate)
                break

    if rules_path is None:
        logger.warning("Semgrep Android rules not found - skipping")
        return False

    try:
        run(
            [
                "semgrep",
                "-c", rules_path,
                str(workspace.decompile_java_dir),
                "--sarif",
                "-o", str(output_file),
            ],
            timeout=600.0,
            check=False,  # semgrep returns non-zero if findings exist
        )
        logger.info("semgrep complete: %s", output_file)
        return output_file.exists()
    except ToolNotFoundError:
        logger.warning("semgrep not found - skipping")
        return False


def run_apktriage(workspace: Workspace) -> bool:
    """
    Run apktriage scanner.

    Args:
        workspace: The workspace to scan.

    Returns:
        True if scan succeeded, False otherwise.
    """
    output_dir = workspace.scan_dir / "apktriage"

    try:
        run(
            [
                "apktriage",
                str(workspace.target_apk),
                "--out", str(output_dir),
            ],
            timeout=300.0,
        )

        # apktriage outputs multiple files; consolidate to report.json
        report_file = output_dir / "report.json"
        if not report_file.exists():
            # Try to find and rename the output
            for f in output_dir.glob("*.json"):
                shutil.copy(f, report_file)
                break

        logger.info("apktriage complete: %s", output_dir)
        return True
    except ToolNotFoundError:
        logger.warning("apktriage not found - skipping")
        return False
    except ToolFailedError as e:
        logger.warning("apktriage failed: %s", e)
        return False


def run_quark(workspace: Workspace) -> bool:
    """
    Run quark-engine behavioral analysis.

    Args:
        workspace: The workspace to scan.

    Returns:
        True if scan succeeded, False otherwise.
    """
    output_dir = workspace.scan_dir / "quark"
    output_file = output_dir / "report.json"

    try:
        run(
            [
                "quark",
                "-a", str(workspace.target_apk),
                "-o", str(output_file),
                "--json",
            ],
            timeout=600.0,
        )
        logger.info("quark complete: %s", output_file)
        return True
    except ToolNotFoundError:
        logger.warning("quark not found - skipping")
        return False
    except ToolFailedError as e:
        logger.warning("quark failed: %s", e)
        return False


def run_apkleaks(workspace: Workspace) -> bool:
    """
    Run APKLeaks endpoint/secret scanner.

    Args:
        workspace: The workspace to scan.

    Returns:
        True if scan succeeded, False otherwise.
    """
    output_dir = workspace.scan_dir / "apkleaks"
    output_file = output_dir / "report.json"

    try:
        run(
            [
                "apkleaks",
                "-f", str(workspace.target_apk),
                "-o", str(output_file),
                "--json",
            ],
            timeout=300.0,
        )
        logger.info("apkleaks complete: %s", output_file)
        return True
    except ToolNotFoundError:
        logger.warning("apkleaks not found - skipping")
        return False
    except ToolFailedError as e:
        logger.warning("apkleaks failed: %s", e)
        return False


def run_apkid(workspace: Workspace) -> bool:
    """
    Run APKiD packer/obfuscator fingerprinting.

    Args:
        workspace: The workspace to scan.

    Returns:
        True if scan succeeded, False otherwise.
    """
    output_dir = workspace.scan_dir / "apkid"
    output_file = output_dir / "report.txt"

    try:
        result = run(
            ["apkid", str(workspace.target_apk)],
            timeout=120.0,
            check=False,
        )
        output_file.write_text(result.stdout)
        logger.info("apkid complete: %s", output_file)
        return True
    except ToolNotFoundError:
        logger.warning("apkid not found - skipping")
        return False


def run_stage2(
    workspace: Workspace,
    mobsf_api_key: str | None = None,
    semgrep_rules: str | None = None,
) -> Path:
    """
    Run Stage 2: Scan and normalize.

    Runs all available scanners and produces unified threat-report.json.

    Args:
        workspace: The workspace to scan.
        mobsf_api_key: Optional MobSF API key.
        semgrep_rules: Optional path to semgrep rules.

    Returns:
        Path to the generated threat-report.json.
    """
    workspace.require_stage("scan")

    # Scan every companion-data surface (OBB, dropped AAB feature modules,
    # asset packs, and DEX-in-assets) for payloads the main scan cannot see.
    scan_companion_artifacts(workspace)

    # Run scanners (graceful degradation - skip unavailable)
    run_mobsf_scan(workspace, api_key=mobsf_api_key)
    run_mobsfscan(workspace)
    run_semgrep(workspace, rules_path=semgrep_rules)
    run_apktriage(workspace)
    run_quark(workspace)
    run_apkleaks(workspace)
    run_apkid(workspace)

    # Normalize all outputs into unified report
    report = normalize_scanner_outputs(
        scan_dir=workspace.scan_dir,
        apk_path=workspace.target_apk,
    )

    # Write report
    report_path = workspace.reports_dir / "threat-report.json"
    report_path.write_text(report.to_json())

    workspace.state.mark_complete("scan")
    workspace.save_state()

    logger.info("Stage 2 (scan) complete: %s", report_path)
    return report_path
