"""Stage 0: Input normalization - format routing and OBB extraction."""

from __future__ import annotations

import json
import logging
import shutil
import zipfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apk_plug.workspace import Workspace

from apk_plug.runner import run

logger = logging.getLogger(__name__)


class InputFormat(Enum):
    """Supported input formats."""

    APK = "apk"
    AAB = "aab"
    XAPK = "xapk"
    APKM = "apkm"
    APKS = "apks"
    ZIP = "zip"


class InputTool(Enum):
    """Tools used for input normalization."""

    PASSTHROUGH = "passthrough"
    BUNDLETOOL = "bundletool"
    APKEDITOR = "apkeditor"


@dataclass(frozen=True, slots=True)
class InputPlan:
    """Plan for normalizing an input file to target.apk."""

    format: InputFormat
    tool: InputTool
    tool_args: tuple[str, ...]
    has_obb: bool = False
    obb_files: tuple[str, ...] = ()
    package_name: str | None = None


def detect_format(path: Path) -> InputFormat:
    """
    Detect input format from extension and content signature.

    Args:
        path: Path to the input file.

    Returns:
        Detected InputFormat.
    """
    ext = path.suffix.lower()

    format_map = {
        ".apk": InputFormat.APK,
        ".aab": InputFormat.AAB,
        ".xapk": InputFormat.XAPK,
        ".apkm": InputFormat.APKM,
        ".apks": InputFormat.APKS,
        ".zip": InputFormat.ZIP,
    }

    return format_map.get(ext, InputFormat.APK)


def route_input(path: Path, output_dir: Path) -> InputPlan:
    """
    Determine the normalization plan for an input file.

    This is a PURE function - it only inspects the file and returns a plan,
    without executing any tools.

    Args:
        path: Path to the input file.
        output_dir: Directory where target.apk will be placed.

    Returns:
        InputPlan describing how to normalize the input.
    """
    fmt = detect_format(path)
    target_apk = output_dir / "target.apk"

    if fmt == InputFormat.APK:
        # Plain APK - just copy
        return InputPlan(
            format=fmt,
            tool=InputTool.PASSTHROUGH,
            tool_args=(str(path), str(target_apk)),
        )

    if fmt == InputFormat.AAB:
        # Android App Bundle -> bundletool
        apks_output = output_dir / "bundle.apks"
        return InputPlan(
            format=fmt,
            tool=InputTool.BUNDLETOOL,
            tool_args=(
                "build-apks",
                "--bundle", str(path),
                "--output", str(apks_output),
                "--mode=universal",
            ),
        )

    # XAPK/APKM/APKS/ZIP -> APKEditor merge
    # Also check for OBB files and manifest
    obb_files: list[str] = []
    package_name: str | None = None

    if fmt in (InputFormat.XAPK, InputFormat.APKM, InputFormat.APKS, InputFormat.ZIP):
        try:
            with zipfile.ZipFile(path, "r") as zf:
                names = zf.namelist()
                # Check for OBB files
                for name in names:
                    if name.endswith(".obb"):
                        obb_files.append(name)

                # Try to read manifest.json for package name (XAPK format)
                if "manifest.json" in names:
                    try:
                        manifest_data = json.loads(zf.read("manifest.json"))
                        package_name = manifest_data.get("package_name")
                    except (json.JSONDecodeError, KeyError):
                        pass
        except zipfile.BadZipFile:
            logger.warning("Could not read %s as zip file", path)

    return InputPlan(
        format=fmt,
        tool=InputTool.APKEDITOR,
        tool_args=(
            "m",
            "-i", str(path),
            "-o", str(target_apk),
        ),
        has_obb=len(obb_files) > 0,
        obb_files=tuple(obb_files),
        package_name=package_name,
    )


def extract_obb_files(archive_path: Path, obb_dir: Path, obb_files: tuple[str, ...]) -> list[Path]:
    """
    Extract OBB files from an archive to the OBB directory.

    Args:
        archive_path: Path to the archive (XAPK/APKM/etc).
        obb_dir: Directory to extract OBB files into.
        obb_files: List of OBB file paths within the archive.

    Returns:
        List of paths to extracted OBB files.
    """
    extracted: list[Path] = []

    with zipfile.ZipFile(archive_path, "r") as zf:
        for obb_name in obb_files:
            # Extract to obb_dir with just the filename (strip any directory)
            dest_name = Path(obb_name).name
            dest_path = obb_dir / dest_name

            with zf.open(obb_name) as src, dest_path.open("wb") as dst:
                shutil.copyfileobj(src, dst)

            extracted.append(dest_path)
            logger.info("Extracted OBB: %s -> %s", obb_name, dest_path)

    return extracted


def execute_plan(plan: InputPlan, workspace: Workspace) -> Path:
    """
    Execute an input normalization plan.

    Args:
        plan: The InputPlan to execute.
        workspace: The workspace to operate in.

    Returns:
        Path to the normalized target.apk.
    """
    target_apk = workspace.target_apk
    input_path = Path(workspace.state.apk_path)

    if plan.tool == InputTool.PASSTHROUGH:
        # Just copy the APK
        shutil.copy2(input_path, target_apk)
        logger.info("Copied APK to %s", target_apk)

    elif plan.tool == InputTool.BUNDLETOOL:
        # Run bundletool to create universal APK
        apks_output = workspace.input_dir / "bundle.apks"
        run(["bundletool", *plan.tool_args[1:]], timeout=600.0)

        # Extract universal.apk from the .apks file
        with zipfile.ZipFile(apks_output, "r") as zf:
            with zf.open("universal.apk") as src, target_apk.open("wb") as dst:
                shutil.copyfileobj(src, dst)
        logger.info("Extracted universal APK from bundle to %s", target_apk)

    elif plan.tool == InputTool.APKEDITOR:
        # Run APKEditor to merge splits
        run(["APKEditor", *plan.tool_args], timeout=600.0)
        logger.info("Merged splits to %s", target_apk)

    # Extract OBB files if present
    if plan.has_obb and plan.obb_files:
        extracted = extract_obb_files(input_path, workspace.obb_dir, plan.obb_files)
        workspace.state.obb_files = [str(p.name) for p in extracted]

    # Update workspace state
    if plan.package_name:
        workspace.state.package_name = plan.package_name

    workspace.state.original_format = plan.format.value
    workspace.state.mark_complete("init")
    workspace.save_state()

    return target_apk


def run_stage0(workspace: Workspace) -> Path:
    """
    Run Stage 0: Input normalization.

    Args:
        workspace: The workspace to operate in.

    Returns:
        Path to the normalized target.apk.
    """
    input_path = Path(workspace.state.apk_path)
    plan = route_input(input_path, workspace.input_dir)
    return execute_plan(plan, workspace)
