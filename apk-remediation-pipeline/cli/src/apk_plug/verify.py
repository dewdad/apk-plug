"""Verification gates for each pipeline stage."""

from __future__ import annotations

import json
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apk_plug.workspace import Workspace

from apk_plug.runner import ToolNotFoundError, run

logger = logging.getLogger(__name__)


class GateResult(Enum):
    """Result of a verification gate check."""

    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"


@dataclass(frozen=True, slots=True)
class GateCheck:
    """Result of a single gate check."""

    name: str
    result: GateResult
    message: str


@dataclass
class VerificationResult:
    """Result of stage verification."""

    stage: int
    passed: bool
    checks: list[GateCheck]

    @property
    def failed_gates(self) -> list[GateCheck]:
        """Return list of failed gate checks."""
        return [c for c in self.checks if c.result == GateResult.FAIL]


class VerificationError(Exception):
    """Raised when verification fails."""

    def __init__(self, result: VerificationResult) -> None:
        self.result = result
        failed = result.failed_gates
        if failed:
            msg = f"Stage {result.stage} verification failed: {failed[0].name} - {failed[0].message}"
        else:
            msg = f"Stage {result.stage} verification failed"
        super().__init__(msg)


def check_manifest_validity(manifest_path: Path) -> GateCheck:
    """
    Check that AndroidManifest.xml is valid XML.

    Args:
        manifest_path: Path to AndroidManifest.xml.

    Returns:
        GateCheck result.
    """
    if not manifest_path.exists():
        return GateCheck(
            name="manifest_exists",
            result=GateResult.FAIL,
            message=f"AndroidManifest.xml not found at {manifest_path}",
        )

    try:
        ET.parse(manifest_path)  # noqa: S314
        return GateCheck(
            name="manifest_valid_xml",
            result=GateResult.PASS,
            message="AndroidManifest.xml is valid XML",
        )
    except ET.ParseError as e:
        return GateCheck(
            name="manifest_valid_xml",
            result=GateResult.FAIL,
            message=f"AndroidManifest.xml is malformed XML: {e}",
        )


def check_java_files_exist(java_dir: Path) -> GateCheck:
    """
    Check that at least one .java file exists in decompiled output.

    Args:
        java_dir: Path to jadx output directory.

    Returns:
        GateCheck result.
    """
    if not java_dir.exists():
        return GateCheck(
            name="java_files_exist",
            result=GateResult.FAIL,
            message=f"Java output directory not found: {java_dir}",
        )

    java_files = list(java_dir.rglob("*.java"))
    if java_files:
        return GateCheck(
            name="java_files_exist",
            result=GateResult.PASS,
            message=f"Found {len(java_files)} .java files",
        )

    return GateCheck(
        name="java_files_exist",
        result=GateResult.FAIL,
        message="No .java files found in decompiled output",
    )


def check_smali_files_exist(smali_dir: Path) -> GateCheck:
    """
    Check that at least one .smali file exists.

    Args:
        smali_dir: Path to apktool output directory.

    Returns:
        GateCheck result.
    """
    if not smali_dir.exists():
        return GateCheck(
            name="smali_files_exist",
            result=GateResult.FAIL,
            message=f"Smali output directory not found: {smali_dir}",
        )

    # Look for smali files in smali*/ directories
    smali_files: list[Path] = []
    for smali_subdir in smali_dir.glob("smali*"):
        if smali_subdir.is_dir():
            smali_files.extend(smali_subdir.rglob("*.smali"))

    # Also check root
    smali_files.extend(smali_dir.rglob("*.smali"))

    if smali_files:
        return GateCheck(
            name="smali_files_exist",
            result=GateResult.PASS,
            message=f"Found {len(smali_files)} .smali files",
        )

    return GateCheck(
        name="smali_files_exist",
        result=GateResult.FAIL,
        message="No .smali files found in decompiled output",
    )


def check_dangling_references(smali_dir: Path, deleted_classes: list[str]) -> GateCheck:
    """
    Check for dangling references to deleted classes.

    Args:
        smali_dir: Path to smali directory.
        deleted_classes: List of class names that were deleted.

    Returns:
        GateCheck result.
    """
    if not deleted_classes:
        return GateCheck(
            name="no_dangling_refs",
            result=GateResult.PASS,
            message="No deleted classes to check",
        )

    dangling: list[str] = []

    for smali_file in smali_dir.rglob("*.smali"):
        content = smali_file.read_text(errors="ignore")
        for class_name in deleted_classes:
            # Convert class name to smali format (L<path>;)
            smali_ref = f"L{class_name.replace('.', '/')};"
            if smali_ref in content:
                dangling.append(f"{smali_file.name} -> {class_name}")

    if dangling:
        return GateCheck(
            name="no_dangling_refs",
            result=GateResult.FAIL,
            message=f"Dangling references found: {', '.join(dangling[:5])}",
        )

    return GateCheck(
        name="no_dangling_refs",
        result=GateResult.PASS,
        message="No dangling references to deleted classes",
    )


def check_apksigner_verify(apk_path: Path) -> GateCheck:
    """
    Verify APK signature using apksigner.

    Args:
        apk_path: Path to the signed APK.

    Returns:
        GateCheck result.
    """
    if not apk_path.exists():
        return GateCheck(
            name="apksigner_verify",
            result=GateResult.FAIL,
            message=f"APK not found: {apk_path}",
        )

    try:
        result = run(
            ["apksigner", "verify", "--verbose", str(apk_path)],
            timeout=60.0,
            check=False,
        )

        if result.returncode == 0:
            return GateCheck(
                name="apksigner_verify",
                result=GateResult.PASS,
                message="APK signature verified",
            )

        return GateCheck(
            name="apksigner_verify",
            result=GateResult.FAIL,
            message=f"APK signature invalid: {result.stderr[:200]}",
        )

    except ToolNotFoundError:
        return GateCheck(
            name="apksigner_verify",
            result=GateResult.SKIP,
            message="apksigner not available - skipping signature verification",
        )


def verify_stage1(workspace: Workspace) -> VerificationResult:
    """
    Verify Stage 1 (decompile) completed successfully.

    Checks:
    - AndroidManifest.xml is valid XML
    - At least 1 .java file exists
    - At least 1 .smali file exists

    Args:
        workspace: The workspace to verify.

    Returns:
        VerificationResult with all gate checks.
    """
    checks: list[GateCheck] = []

    # Check manifest
    manifest_path = workspace.decompile_smali_dir / "AndroidManifest.xml"
    checks.append(check_manifest_validity(manifest_path))

    # Check java files
    checks.append(check_java_files_exist(workspace.decompile_java_dir))

    # Check smali files
    checks.append(check_smali_files_exist(workspace.decompile_smali_dir))

    passed = all(c.result != GateResult.FAIL for c in checks)

    return VerificationResult(stage=1, passed=passed, checks=checks)


def verify_stage2(workspace: Workspace) -> VerificationResult:
    """
    Verify Stage 2 (scan) produced a schema-valid threat report.

    Checks:
    - reports/threat-report.json exists
    - it validates against assets/threat-report.schema.json

    Args:
        workspace: The workspace to verify.

    Returns:
        VerificationResult with all gate checks.
    """
    checks: list[GateCheck] = []

    report_path = workspace.reports_dir / "threat-report.json"
    if not report_path.exists():
        checks.append(GateCheck(
            name="threat_report_exists",
            result=GateResult.FAIL,
            message=f"threat-report.json not found at {report_path}",
        ))
        return VerificationResult(stage=2, passed=False, checks=checks)

    checks.append(GateCheck(
        name="threat_report_exists",
        result=GateResult.PASS,
        message="threat-report.json present",
    ))

    try:
        data = json.loads(report_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        checks.append(GateCheck(
            name="threat_report_schema",
            result=GateResult.FAIL,
            message=f"threat-report.json is unreadable: {e}",
        ))
        return VerificationResult(stage=2, passed=False, checks=checks)

    from apk_plug.report import SchemaValidationError, validate_report

    try:
        validate_report(data)
        checks.append(GateCheck(
            name="threat_report_schema",
            result=GateResult.PASS,
            message="threat-report.json is schema-valid",
        ))
    except SchemaValidationError as e:
        checks.append(GateCheck(
            name="threat_report_schema",
            result=GateResult.FAIL,
            message=f"threat-report.json failed schema validation: {e}",
        ))
    except FileNotFoundError as e:
        checks.append(GateCheck(
            name="threat_report_schema",
            result=GateResult.SKIP,
            message=f"schema file unavailable - skipping: {e}",
        ))

    passed = all(c.result != GateResult.FAIL for c in checks)
    return VerificationResult(stage=2, passed=passed, checks=checks)


def verify_stage3(workspace: Workspace, deleted_classes: list[str] | None = None) -> VerificationResult:
    """
    Verify Stage 3 (remediation) requirements.

    Checks:
    - No dangling references to deleted classes
    - AndroidManifest.xml still valid

    Args:
        workspace: The workspace to verify.
        deleted_classes: List of classes that were deleted during remediation.

    Returns:
        VerificationResult with all gate checks.
    """
    checks: list[GateCheck] = []

    # Check manifest still valid
    manifest_path = workspace.decompile_smali_dir / "AndroidManifest.xml"
    checks.append(check_manifest_validity(manifest_path))

    # Check for dangling references
    if deleted_classes:
        checks.append(check_dangling_references(workspace.decompile_smali_dir, deleted_classes))

    passed = all(c.result != GateResult.FAIL for c in checks)

    return VerificationResult(stage=3, passed=passed, checks=checks)


def verify_stage4(workspace: Workspace) -> VerificationResult:
    """
    Verify Stage 4 (rebuild) completed successfully.

    Checks:
    - Signed APK exists
    - apksigner verify succeeds

    Args:
        workspace: The workspace to verify.

    Returns:
        VerificationResult with all gate checks.
    """
    checks: list[GateCheck] = []

    # Find signed APK
    signed_apks = list(workspace.build_signed_dir.glob("*.apk"))
    if not signed_apks:
        checks.append(GateCheck(
            name="signed_apk_exists",
            result=GateResult.FAIL,
            message="No signed APK found in build/signed/",
        ))
    else:
        checks.append(GateCheck(
            name="signed_apk_exists",
            result=GateResult.PASS,
            message=f"Found signed APK: {signed_apks[0].name}",
        ))

        # Verify signature
        checks.append(check_apksigner_verify(signed_apks[0]))

    passed = all(c.result != GateResult.FAIL for c in checks)

    return VerificationResult(stage=4, passed=passed, checks=checks)


def verify_stage5(workspace: Workspace) -> VerificationResult:
    """
    Verify Stage 5 (validate) produced post-fix validation artifacts.

    Checks:
    - reports/post-fix/ contains at least one artifact (re-scan output)

    Args:
        workspace: The workspace to verify.

    Returns:
        VerificationResult with all gate checks.
    """
    checks: list[GateCheck] = []

    postfix_dir = workspace.reports_postfix_dir
    artifacts = (
        [p for p in postfix_dir.rglob("*") if p.is_file()]
        if postfix_dir.exists()
        else []
    )

    if artifacts:
        checks.append(GateCheck(
            name="postfix_report_exists",
            result=GateResult.PASS,
            message=f"Found {len(artifacts)} post-fix validation artifact(s)",
        ))
    else:
        checks.append(GateCheck(
            name="postfix_report_exists",
            result=GateResult.FAIL,
            message=f"No post-fix validation artifacts in {postfix_dir}",
        ))

    passed = all(c.result != GateResult.FAIL for c in checks)
    return VerificationResult(stage=5, passed=passed, checks=checks)


def verify_stage(
    workspace: Workspace,
    stage: int,
    deleted_classes: list[str] | None = None,
) -> VerificationResult:
    """
    Run verification for a specific stage.

    Args:
        workspace: The workspace to verify.
        stage: Stage number (1, 2, 3, 4, or 5).
        deleted_classes: For stage 3, list of deleted classes.

    Returns:
        VerificationResult.

    Raises:
        ValueError: If stage number is invalid.
    """
    if stage == 1:
        return verify_stage1(workspace)
    if stage == 2:
        return verify_stage2(workspace)
    if stage == 3:
        return verify_stage3(workspace, deleted_classes)
    if stage == 4:
        return verify_stage4(workspace)
    if stage == 5:
        return verify_stage5(workspace)

    msg = f"Invalid stage number: {stage}. Valid stages: 1, 2, 3, 4, 5"
    raise ValueError(msg)
