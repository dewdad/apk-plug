"""Stage 1: Decompile APK using jadx and apktool."""

from __future__ import annotations

import logging
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apk_plug.workspace import Workspace

from apk_plug.runner import ToolNotFoundError, run

logger = logging.getLogger(__name__)


class DecompileError(Exception):
    """Raised when decompilation produced no usable output at all."""


def build_jadx_args(apk_path: Path, output_dir: Path) -> list[str]:
    """Build command arguments for jadx decompilation."""
    return [
        "jadx",
        "--deobf",
        "--show-bad-code",
        "-d", str(output_dir),
        str(apk_path),
    ]


def build_apktool_args(apk_path: Path, output_dir: Path) -> list[str]:
    """Build command arguments for apktool decompilation."""
    return [
        "apktool",
        "d",
        "-f",
        "-o", str(output_dir),
        str(apk_path),
    ]


def extract_native_libs(apk_path: Path, output_dir: Path) -> list[Path]:
    """
    Extract native libraries from APK.

    Args:
        apk_path: Path to the APK file.
        output_dir: Directory to extract native libs into.

    Returns:
        List of paths to extracted .so files.
    """
    extracted: list[Path] = []

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                if name.startswith("lib/") and name.endswith(".so"):
                    # Preserve directory structure
                    dest = output_dir / name.removeprefix("lib/")
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(name) as src, dest.open("wb") as dst:
                        dst.write(src.read())
                    extracted.append(dest)
                    logger.debug("Extracted native lib: %s", dest)
    except zipfile.BadZipFile:
        logger.warning("Could not read %s as zip for native lib extraction", apk_path)

    return extracted


def run_jadx(workspace: Workspace) -> bool:
    """
    Run jadx decompilation.

    jadx routinely exits non-zero on real-world APKs (bad-code / classes it
    cannot fully decompile) while STILL producing usable Java. Treat a non-zero
    exit as success when `.java` output was produced; only report failure when
    no output appeared.

    Args:
        workspace: The workspace to operate in.

    Returns:
        True if jadx produced Java output, False if unavailable or empty.
    """
    apk_path = workspace.target_apk
    output_dir = workspace.decompile_java_dir

    try:
        args = build_jadx_args(apk_path, output_dir)
        result = run(args, timeout=600.0, check=False)
    except ToolNotFoundError:
        logger.warning("jadx not found - skipping Java decompilation")
        return False

    produced = output_dir.exists() and any(output_dir.rglob("*.java"))
    if result.returncode != 0:
        if produced:
            logger.warning(
                "jadx exited %d but produced Java output - continuing "
                "(bad-code is expected on obfuscated/real APKs)",
                result.returncode,
            )
            return True
        logger.error(
            "jadx failed (exit %d) with no output: %s",
            result.returncode,
            result.stderr[:200],
        )
        return False

    logger.info("jadx decompilation complete: %s", output_dir)
    return True


def run_apktool(workspace: Workspace) -> bool:
    """
    Run apktool decompilation.

    As with jadx, tolerate a non-zero exit when smali/manifest output was
    produced; only report failure when nothing usable appeared.

    Args:
        workspace: The workspace to operate in.

    Returns:
        True if apktool produced smali output, False if unavailable or empty.
    """
    apk_path = workspace.target_apk
    output_dir = workspace.decompile_smali_dir

    try:
        args = build_apktool_args(apk_path, output_dir)
        result = run(args, timeout=600.0, check=False)
    except ToolNotFoundError:
        logger.warning("apktool not found - skipping smali decompilation")
        return False

    manifest = output_dir / "AndroidManifest.xml"
    produced = manifest.exists() or (output_dir.exists() and any(output_dir.rglob("*.smali")))
    if result.returncode != 0:
        if produced:
            logger.warning(
                "apktool exited %d but produced output - continuing",
                result.returncode,
            )
            return True
        logger.error(
            "apktool failed (exit %d) with no output: %s",
            result.returncode,
            result.stderr[:200],
        )
        return False

    logger.info("apktool decompilation complete: %s", output_dir)
    return True


def run_stage1(workspace: Workspace) -> None:
    """
    Run Stage 1: Decompile.

    Runs jadx (for Java view) + apktool (for smali) + native lib extraction.

    Args:
        workspace: The workspace to operate in.
    """
    workspace.require_stage("decompile")

    apk_path = workspace.target_apk

    # jadx and apktool are independent; run BOTH regardless of the other's
    # exit status (jadx exiting non-zero must never skip apktool).
    jadx_ok = run_jadx(workspace)
    apktool_ok = run_apktool(workspace)

    # Extract native libraries
    native_libs = extract_native_libs(apk_path, workspace.decompile_native_dir)
    if native_libs:
        logger.info("Extracted %d native libraries", len(native_libs))

    if not (jadx_ok or apktool_ok):
        msg = (
            "Decompilation produced no output - jadx and apktool are both "
            "unavailable or failed. Install them via scripts/install-toolchain.sh"
        )
        raise DecompileError(msg)

    workspace.state.mark_complete("decompile")
    workspace.save_state()

    logger.info("Stage 1 (decompile) complete")
