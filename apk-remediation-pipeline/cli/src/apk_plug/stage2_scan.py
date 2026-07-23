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

    # Scan OBB files for hidden DEX
    obb_dex = scan_obb_files(workspace)
    if obb_dex:
        logger.warning("Hidden DEX files found in OBB: %s", obb_dex)
        # Record in apktriage output directory
        obb_report = workspace.scan_dir / "apktriage" / "obb_dex.json"
        obb_report.parent.mkdir(parents=True, exist_ok=True)
        obb_report.write_text(json.dumps(obb_dex, indent=2))

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
