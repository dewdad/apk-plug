"""Stage 5: Post-fix validation - re-scan, permission diff, OBB commands."""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, TypedDict

if TYPE_CHECKING:
    from apk_plug.workspace import Workspace

from apk_plug.runner import ToolFailedError, ToolNotFoundError, run

logger = logging.getLogger(__name__)


class Stage5Result(TypedDict):
    """Structured result of Stage 5 post-fix validation."""

    passed: bool
    scan_results: dict[str, bool]
    permission_diff: dict[str, list[str]]
    residual_c2: list[dict[str, str]]
    obb_commands: list[str]
    companion_warnings: list[str]


class ValidationError(Exception):
    """Raised when validation fails."""


def diff_permissions(original: list[str], fixed: list[str]) -> dict[str, list[str]]:
    """
    Compute permission difference between original and fixed APK.

    Args:
        original: Permissions from original APK.
        fixed: Permissions from fixed APK.

    Returns:
        Dict with 'added', 'removed', and 'unchanged' permission lists.
    """
    orig_set = set(original)
    fixed_set = set(fixed)

    return {
        "added": sorted(fixed_set - orig_set),
        "removed": sorted(orig_set - fixed_set),
        "unchanged": sorted(orig_set & fixed_set),
    }


def extract_permissions_from_manifest(manifest_path: Path) -> list[str]:
    """
    Extract uses-permission from AndroidManifest.xml.

    Args:
        manifest_path: Path to AndroidManifest.xml.

    Returns:
        List of permission names.
    """
    import xml.etree.ElementTree as ET

    permissions: list[str] = []

    if not manifest_path.exists():
        return permissions

    try:
        tree = ET.parse(manifest_path)  # noqa: S314
        root = tree.getroot()

        # Handle namespace
        ns = {"android": "http://schemas.android.com/apk/res/android"}

        for perm in root.findall(".//uses-permission", ns):
            name = perm.get("{http://schemas.android.com/apk/res/android}name")
            if name:
                permissions.append(name)

        # Also check without namespace (some tools output without it)
        for perm in root.findall(".//uses-permission"):
            name = perm.get("android:name") or perm.get("name")
            if name and name not in permissions:
                permissions.append(name)

    except ET.ParseError as e:
        logger.warning("Failed to parse manifest: %s", e)

    return sorted(permissions)


def grep_residual_c2(directory: Path, exclude_patterns: list[str] | None = None) -> list[dict[str, str]]:
    """
    Grep for residual C2/URL strings in decompiled code.

    Args:
        directory: Directory to search.
        exclude_patterns: Patterns to exclude (e.g., schemas.android.com).

    Returns:
        List of findings with file and matched string.
    """
    if exclude_patterns is None:
        exclude_patterns = [
            "schemas.android.com",
            "www.w3.org",
            "xmlns",
            "android.com/apk",
        ]

    findings: list[dict[str, str]] = []

    # Search for URL-like patterns
    import re

    url_pattern = re.compile(r'(https?|tcp|mqtt)://[^\s"\'<>]+', re.IGNORECASE)

    for ext in ("*.smali", "*.xml", "*.java"):
        for file_path in directory.rglob(ext):
            try:
                content = file_path.read_text(errors="ignore")
                for match in url_pattern.finditer(content):
                    url = match.group(0)
                    # Check exclusions
                    if any(excl in url for excl in exclude_patterns):
                        continue
                    findings.append({
                        "file": str(file_path.relative_to(directory)),
                        "url": url,
                    })
            except OSError:
                continue

    return findings


def generate_obb_push_commands(workspace: Workspace, package_name: str | None = None) -> list[str]:
    """
    Generate adb push commands for OBB files.

    Args:
        workspace: The workspace containing OBB files.
        package_name: Package name for destination path.

    Returns:
        List of adb push command strings.
    """
    commands: list[str] = []

    if not workspace.obb_dir.exists():
        return commands

    # Use package name from state or provided
    pkg = package_name or workspace.state.package_name

    if not pkg:
        logger.warning("Package name unknown - OBB push commands will use placeholder")
        pkg = "<package_name>"

    for obb_file in workspace.obb_dir.glob("*.obb"):
        dest = f"/sdcard/Android/obb/{pkg}/{obb_file.name}"
        cmd = f"adb push {obb_file} {dest}"
        commands.append(cmd)

    return commands


def generate_companion_warnings(workspace: Workspace) -> list[str]:
    """
    Warn about companion data the rebuilt universal APK cannot represent.

    The rebuild derives from the universal APK, so on-demand/conditional feature
    modules (fusing=false) and non-install-time asset packs are NOT present in
    the rebuilt artifact and cannot be exercised by a sideloaded smoke test
    (there is no Play SplitInstallManager / AssetPackManager to fetch them).
    Surfacing this prevents a false "app works" verdict.

    Args:
        workspace: The workspace to inspect.

    Returns:
        List of human-readable warning strings.
    """
    warnings: list[str] = []

    for module in workspace.state.feature_modules:
        if module.get("in_universal") is False:
            name = module.get("name", "?")
            warnings.append(
                f"Feature module '{name}' (fusing=false) is absent from the "
                f"rebuilt universal APK; its code cannot be remediated in-place "
                f"and on-demand features depending on it will be unavailable when "
                f"sideloaded."
            )

    for pack in workspace.state.asset_packs:
        if pack.get("in_universal") is False:
            name = pack.get("name", "?")
            delivery = pack.get("delivery_type", "on-demand/fast-follow")
            warnings.append(
                f"Asset pack '{name}' ({delivery}) is not bundled into the "
                f"rebuilt APK; the app will try to fetch it from Play at runtime "
                f"and may fail or misbehave when sideloaded."
            )

    return warnings


def run_post_scan(workspace: Workspace, signed_apk: Path) -> dict[str, bool]:
    """
    Run scanners on the rebuilt APK.

    Args:
        workspace: The workspace.
        signed_apk: Path to the signed APK.

    Returns:
        Dict mapping scanner name to success status.
    """
    results: dict[str, bool] = {}
    output_dir = workspace.reports_postfix_dir

    # Run mobsfscan on decompiled source (if it was re-decompiled)
    try:
        run(
            ["mobsfscan", str(workspace.decompile_smali_dir), "--json", "-o", str(output_dir / "mobsfscan.json")],
            timeout=300.0,
        )
        results["mobsfscan"] = True
    except (ToolNotFoundError, ToolFailedError):
        results["mobsfscan"] = False

    # Run apktriage
    # Upstream CLI: `apktriage scan <apk> --out <dir> [-f json]`.
    # It writes report.json / report.md / a YARA rule into --out.
    # Postfix consumers (see test_verify.py) look for a flat `apktriage.json`
    # in output_dir, so we surface the produced report.json under that name.
    try:
        apktriage_dir = output_dir / "apktriage"
        apktriage_dir.mkdir(parents=True, exist_ok=True)
        run(
            [
                "apktriage", "scan", str(signed_apk),
                "--out", str(apktriage_dir),
                "-f", "json",
            ],
            timeout=300.0,
        )
        produced = apktriage_dir / "report.json"
        if produced.exists():
            shutil.copy(produced, output_dir / "apktriage.json")
        results["apktriage"] = True
    except (ToolNotFoundError, ToolFailedError):
        results["apktriage"] = False

    # Run quark
    try:
        run(
            ["quark", "-a", str(signed_apk), "-o", str(output_dir / "quark.json"), "--json"],
            timeout=600.0,
        )
        results["quark"] = True
    except (ToolNotFoundError, ToolFailedError):
        results["quark"] = False

    return results


def run_stage5(workspace: Workspace) -> Stage5Result:
    """
    Run Stage 5: Post-fix validation.

    Performs:
    - Re-scans rebuilt APK
    - Permission diff (original vs fixed)
    - Residual C2 string grep
    - OBB push command generation

    Args:
        workspace: The workspace to validate.

    Returns:
        Validation results dict.

    Raises:
        ValidationError: If fixed permissions are broader than original.
    """
    workspace.require_stage("validate")

    results: Stage5Result = {
        "passed": True,
        "scan_results": {},
        "permission_diff": {},
        "residual_c2": [],
        "obb_commands": [],
        "companion_warnings": [],
    }

    # Find signed APK
    signed_apks = list(workspace.build_signed_dir.glob("*.apk"))
    if not signed_apks:
        logger.error("No signed APK found")
        results["passed"] = False
        return results

    signed_apk = signed_apks[0]

    # Run post-fix scans
    results["scan_results"] = run_post_scan(workspace, signed_apk)

    # Permission diff
    original_manifest = workspace.decompile_smali_dir / "AndroidManifest.xml"
    original_perms = extract_permissions_from_manifest(original_manifest)

    # Load original report if exists
    original_report = workspace.reports_dir / "threat-report.json"
    if original_report.exists():
        try:
            report_data = json.loads(original_report.read_text())
            original_perms = report_data.get("permissions", original_perms)
        except json.JSONDecodeError:
            pass

    # Get current permissions from manifest (after remediation)
    current_perms = extract_permissions_from_manifest(original_manifest)

    perm_diff = diff_permissions(original_perms, current_perms)
    results["permission_diff"] = perm_diff

    # Check if permissions got broader (added permissions = potential problem)
    if perm_diff["added"]:
        logger.warning("Fixed APK has MORE permissions than original: %s", perm_diff["added"])
        results["passed"] = False

    # Grep for residual C2 strings
    residual = grep_residual_c2(workspace.decompile_smali_dir)
    results["residual_c2"] = residual
    if residual:
        logger.warning("Found %d potential residual C2/URL strings", len(residual))

    # Generate OBB push commands if needed
    if workspace.state.obb_files:
        obb_commands = generate_obb_push_commands(workspace)
        results["obb_commands"] = obb_commands
        if obb_commands:
            logger.info("OBB files present - use these commands to push:")
            for cmd in obb_commands:
                logger.info("  %s", cmd)

    # Warn about companion data the rebuilt universal APK cannot represent.
    companion_warnings = generate_companion_warnings(workspace)
    results["companion_warnings"] = companion_warnings
    for warning in companion_warnings:
        logger.warning("%s", warning)

    # Write validation report
    validation_report = workspace.reports_postfix_dir / "validation-summary.json"
    validation_report.write_text(json.dumps(results, indent=2) + "\n")

    workspace.state.mark_complete("validate")
    workspace.save_state()

    logger.info("Stage 5 (validate) complete: passed=%s", results["passed"])

    if not results["passed"]:
        raise ValidationError("Validation failed - see validation-summary.json for details")

    return results
