"""Tests for stage4_rebuild - rebuild, align, and sign."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from apk_plug.stage4_rebuild import (
    KeystoreError,
    build_apksigner_args,
    build_apktool_build_args,
    build_zipalign_args,
    rebuild_and_sign,
    resolve_signing_config,
)
from apk_plug.workspace import create_workspace


class TestBuildOrder:
    """Test that zipalign happens before apksigner."""

    @patch("apk_plug.stage4_rebuild.run")
    def test_zipalign_invoked_before_apksigner(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """The rebuild process MUST call zipalign before apksigner."""
        # Create workspace
        fake_apk = tmp_path / "test.apk"
        fake_apk.touch()

        ws = create_workspace(
            apk_path=fake_apk,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_120000",
        )

        # Create fake keystore
        keystore = tmp_path / "test.jks"
        keystore.touch()

        # Create smali dir with manifest (apktool needs this)
        manifest = ws.decompile_smali_dir / "AndroidManifest.xml"
        manifest.write_text('<?xml version="1.0"?><manifest/>')

        # Mock run to succeed and create expected output files
        def side_effect(args, **kwargs):
            # Create output files that subsequent steps expect
            if args[0] == "apktool":
                ws.build_unsigned_dir.mkdir(parents=True, exist_ok=True)
                (ws.build_unsigned_dir / "test-unsigned.apk").touch()
            elif args[0] == "zipalign":
                ws.build_aligned_dir.mkdir(parents=True, exist_ok=True)
                (ws.build_aligned_dir / "test-aligned.apk").touch()
            elif args[0] == "apksigner":
                ws.build_signed_dir.mkdir(parents=True, exist_ok=True)
                (ws.build_signed_dir / "test-signed.apk").touch()
            return MagicMock(returncode=0)

        mock_run.side_effect = side_effect

        # Run rebuild
        rebuild_and_sign(ws, keystore=keystore, key_alias="testkey")

        # Verify call order
        assert mock_run.call_count == 3

        calls = mock_run.call_args_list
        call_tools = [c[0][0][0] for c in calls]

        # Assert order: apktool -> zipalign -> apksigner
        assert call_tools == ["apktool", "zipalign", "apksigner"]

        # More specifically, verify zipalign appears before apksigner
        zipalign_idx = call_tools.index("zipalign")
        apksigner_idx = call_tools.index("apksigner")
        assert zipalign_idx < apksigner_idx, "zipalign must be called before apksigner"


class TestKeystoreError:
    """Test keystore error handling."""

    def test_missing_keystore_raises_actionable_error(self, tmp_path: Path) -> None:
        """Missing keystore should raise KeystoreError with actionable message."""
        fake_apk = tmp_path / "test.apk"
        fake_apk.touch()

        ws = create_workspace(
            apk_path=fake_apk,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_120000",
        )

        with pytest.raises(KeystoreError) as exc_info:
            rebuild_and_sign(ws)  # No keystore provided

        error_str = str(exc_info.value)
        assert "keystore" in error_str.lower()

    def test_nonexistent_keystore_raises_error(self, tmp_path: Path) -> None:
        """Specifying a non-existent keystore should raise KeystoreError."""
        fake_apk = tmp_path / "test.apk"
        fake_apk.touch()

        ws = create_workspace(
            apk_path=fake_apk,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_120000",
        )

        with pytest.raises(KeystoreError) as exc_info:
            rebuild_and_sign(ws, keystore="/nonexistent/path.jks")

        assert "not found" in str(exc_info.value).lower()

    def test_keystore_env_var_used_when_no_arg(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """APK_PLUG_KEYSTORE env var should be used when no arg provided."""
        keystore = tmp_path / "env.jks"
        keystore.touch()

        monkeypatch.setenv("APK_PLUG_KEYSTORE", str(keystore))

        config = resolve_signing_config()

        assert config.keystore_path == keystore


class TestCommandArgs:
    """Test command argument building."""

    def test_apktool_build_args(self, tmp_path: Path) -> None:
        """apktool b args should be correct."""
        smali_dir = tmp_path / "smali"
        output = tmp_path / "output.apk"

        args = build_apktool_build_args(smali_dir, output)

        assert args[0] == "apktool"
        assert args[1] == "b"
        assert str(smali_dir) in args
        assert "-o" in args

    def test_zipalign_args(self, tmp_path: Path) -> None:
        """zipalign args should include -p 4."""
        input_apk = tmp_path / "unsigned.apk"
        output_apk = tmp_path / "aligned.apk"

        args = build_zipalign_args(input_apk, output_apk)

        assert args[0] == "zipalign"
        assert "-p" in args
        assert "4" in args
        assert "-f" in args

    def test_apksigner_args_include_all_signing_versions(self, tmp_path: Path) -> None:
        """apksigner args should enable v1, v2, and v3 signing."""
        from apk_plug.stage4_rebuild import SigningConfig

        keystore = tmp_path / "test.jks"
        keystore.touch()

        config = SigningConfig(
            keystore_path=keystore,
            key_alias="mykey",
        )

        input_apk = tmp_path / "aligned.apk"
        output_apk = tmp_path / "signed.apk"

        args = build_apksigner_args(input_apk, output_apk, config)

        assert args[0] == "apksigner"
        assert "sign" in args
        assert "--v1-signing-enabled" in args
        assert "--v2-signing-enabled" in args
        assert "--v3-signing-enabled" in args
        assert "true" in args


class TestRecordedCallOrder:
    """Test that we can verify call order through recording."""

    @patch("apk_plug.stage4_rebuild.run")
    def test_recorded_calls_show_correct_order(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Record all tool invocations and verify zipalign before apksigner."""
        recorded_calls: list[str] = []

        def record_call(args, **kwargs):
            recorded_calls.append(args[0])
            # Create expected outputs
            if args[0] == "apktool":
                output_path = Path(args[args.index("-o") + 1])
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.touch()
            elif args[0] == "zipalign":
                output_path = Path(args[-1])
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.touch()
            elif args[0] == "apksigner":
                output_idx = args.index("--out") + 1
                output_path = Path(args[output_idx])
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.touch()
            return MagicMock(returncode=0)

        mock_run.side_effect = record_call

        fake_apk = tmp_path / "test.apk"
        fake_apk.touch()

        ws = create_workspace(
            apk_path=fake_apk,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_120000",
        )

        keystore = tmp_path / "test.jks"
        keystore.touch()

        ws.decompile_smali_dir.mkdir(parents=True, exist_ok=True)
        (ws.decompile_smali_dir / "AndroidManifest.xml").write_text("<manifest/>")

        rebuild_and_sign(ws, keystore=keystore, key_alias="key")

        # Verify recorded order
        assert "zipalign" in recorded_calls
        assert "apksigner" in recorded_calls
        assert recorded_calls.index("zipalign") < recorded_calls.index("apksigner")
