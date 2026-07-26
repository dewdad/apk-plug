"""Stage 4: Rebuild, align, and sign APK."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apk_plug.workspace import Workspace

from apk_plug.runner import ToolNotFoundError, run

logger = logging.getLogger(__name__)


class KeystoreError(Exception):
    """Raised when keystore is missing or invalid."""

    def __init__(self, message: str) -> None:
        super().__init__(f"Keystore error: {message} — provide --keystore path or set APK_PLUG_KEYSTORE env var")


class RebuildError(Exception):
    """Raised when rebuild process fails."""


@dataclass(frozen=True, slots=True)
class SigningConfig:
    """Configuration for APK signing."""

    keystore_path: Path
    key_alias: str
    keystore_pass: str | None = None
    key_pass: str | None = None


def build_apktool_build_args(smali_dir: Path, output_apk: Path) -> list[str]:
    """Build apktool b command arguments."""
    return [
        "apktool",
        "b",
        str(smali_dir),
        "-o", str(output_apk),
    ]


def build_zipalign_args(input_apk: Path, output_apk: Path) -> list[str]:
    """Build zipalign command arguments."""
    return [
        "zipalign",
        "-f",
        "-p", "4",
        str(input_apk),
        str(output_apk),
    ]


def build_apksigner_args(
    input_apk: Path,
    output_apk: Path,
    config: SigningConfig,
) -> list[str]:
    """Build apksigner sign command arguments."""
    args = [
        "apksigner",
        "sign",
        "--ks", str(config.keystore_path),
        "--ks-key-alias", config.key_alias,
        "--v1-signing-enabled", "true",
        "--v2-signing-enabled", "true",
        "--v3-signing-enabled", "true",
        "--out", str(output_apk),
    ]

    if config.keystore_pass:
        args.extend(["--ks-pass", f"pass:{config.keystore_pass}"])

    if config.key_pass:
        args.extend(["--key-pass", f"pass:{config.key_pass}"])

    args.append(str(input_apk))

    return args


def _run_apktool_build(smali_dir: Path, output_apk: Path) -> Path:
    """
    Run apktool build to create unsigned APK.

    Args:
        smali_dir: Path to smali directory.
        output_apk: Path for output APK.

    Returns:
        Path to the unsigned APK.
    """
    args = build_apktool_build_args(smali_dir, output_apk)
    run(args, timeout=600.0)
    logger.info("apktool build complete: %s", output_apk)
    return output_apk


def _run_zipalign(unsigned_apk: Path, aligned_apk: Path) -> Path:
    """
    Run zipalign on APK.

    This MUST be called BEFORE signing - the order is enforced by this module's API.

    Args:
        unsigned_apk: Path to unsigned APK.
        aligned_apk: Path for aligned output.

    Returns:
        Path to the aligned APK.
    """
    args = build_zipalign_args(unsigned_apk, aligned_apk)
    run(args, timeout=120.0)
    logger.info("zipalign complete: %s", aligned_apk)
    return aligned_apk


def _run_apksigner(aligned_apk: Path, signed_apk: Path, config: SigningConfig) -> Path:
    """
    Sign APK with apksigner.

    This MUST be called AFTER zipalign - signing an unaligned APK is invalid.
    The order is enforced by requiring the aligned_apk path from _run_zipalign.

    Args:
        aligned_apk: Path to aligned APK (must be output of zipalign).
        signed_apk: Path for signed output.
        config: Signing configuration.

    Returns:
        Path to the signed APK.
    """
    args = build_apksigner_args(aligned_apk, signed_apk, config)
    run(args, timeout=120.0)
    logger.info("apksigner complete: %s", signed_apk)
    return signed_apk


def resolve_signing_config(
    keystore: Path | str | None = None,
    key_alias: str | None = None,
    keystore_pass: str | None = None,
    key_pass: str | None = None,
) -> SigningConfig:
    """
    Resolve signing configuration from arguments or environment.

    Args:
        keystore: Path to keystore file.
        key_alias: Key alias within keystore.
        keystore_pass: Keystore password.
        key_pass: Key password.

    Returns:
        SigningConfig with resolved values.

    Raises:
        KeystoreError: If keystore cannot be resolved.
    """
    # Resolve keystore path
    if keystore is None:
        keystore = os.environ.get("APK_PLUG_KEYSTORE")

    if keystore is None:
        raise KeystoreError("no keystore specified")

    keystore_path = Path(keystore)
    if not keystore_path.exists():
        raise KeystoreError(f"keystore not found: {keystore_path}")

    # Resolve alias
    if key_alias is None:
        key_alias = os.environ.get("APK_PLUG_KEY_ALIAS", "key0")

    # Resolve passwords from env if not provided
    if keystore_pass is None:
        keystore_pass = os.environ.get("APK_PLUG_KEYSTORE_PASS")

    if key_pass is None:
        key_pass = os.environ.get("APK_PLUG_KEY_PASS")

    return SigningConfig(
        keystore_path=keystore_path,
        key_alias=key_alias,
        keystore_pass=keystore_pass,
        key_pass=key_pass,
    )


def rebuild_and_sign(
    workspace: Workspace,
    keystore: Path | str | None = None,
    key_alias: str | None = None,
    keystore_pass: str | None = None,
    key_pass: str | None = None,
) -> Path:
    """
    Rebuild, align, and sign APK.

    The order of operations is ENFORCED by the implementation:
    1. apktool b (build unsigned APK)
    2. zipalign (align the APK)
    3. apksigner sign (sign the aligned APK)

    It is structurally impossible to call this function and have signing
    happen before alignment.

    Args:
        workspace: The workspace to rebuild.
        keystore: Path to keystore file.
        key_alias: Key alias.
        keystore_pass: Keystore password.
        key_pass: Key password.

    Returns:
        Path to the signed APK.

    Raises:
        KeystoreError: If keystore is not found.
    """
    # Resolve signing configuration FIRST - fail fast if no keystore
    config = resolve_signing_config(keystore, key_alias, keystore_pass, key_pass)

    # Define output paths
    apk_name = Path(workspace.state.apk_path).stem
    unsigned_apk = workspace.build_unsigned_dir / f"{apk_name}-unsigned.apk"
    aligned_apk = workspace.build_aligned_dir / f"{apk_name}-aligned.apk"
    signed_apk = workspace.build_signed_dir / f"{apk_name}-signed.apk"

    # Step 1: Build unsigned APK
    _run_apktool_build(workspace.decompile_smali_dir, unsigned_apk)

    # Step 2: Align (MUST happen before signing)
    aligned_path = _run_zipalign(unsigned_apk, aligned_apk)

    # Step 3: Sign (takes aligned APK as input - order enforced)
    signed_path = _run_apksigner(aligned_path, signed_apk, config)

    return signed_path


def run_stage4(
    workspace: Workspace,
    keystore: Path | str | None = None,
    key_alias: str | None = None,
    keystore_pass: str | None = None,
    key_pass: str | None = None,
) -> Path:
    """
    Run Stage 4: Rebuild and sign.

    Args:
        workspace: The workspace to rebuild.
        keystore: Path to keystore.
        key_alias: Key alias.
        keystore_pass: Keystore password.
        key_pass: Key password.

    Returns:
        Path to the signed APK.
    """
    workspace.require_stage("rebuild")

    signed_apk = rebuild_and_sign(
        workspace,
        keystore=keystore,
        key_alias=key_alias,
        keystore_pass=keystore_pass,
        key_pass=key_pass,
    )

    workspace.state.mark_complete("rebuild")
    workspace.save_state()

    logger.info("Stage 4 (rebuild) complete: %s", signed_apk)
    return signed_apk
