"""Tests for stage0_input - format routing and OBB extraction."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from apk_plug.stage0_input import (
    InputFormat,
    InputPlan,
    InputTool,
    extract_obb_files,
    route_input,
)
from apk_plug.workspace import create_workspace


class TestRouteInputFormatDetection:
    """Test that route_input correctly identifies input formats."""

    def test_aab_routes_to_bundletool(self, tmp_path: Path) -> None:
        """A .aab file should route to bundletool."""
        aab_file = tmp_path / "app.aab"
        aab_file.touch()

        plan = route_input(aab_file, tmp_path / "output")

        assert plan.format == InputFormat.AAB
        assert plan.tool == InputTool.BUNDLETOOL
        assert "build-apks" in plan.tool_args
        assert "--mode=universal" in plan.tool_args

    def test_xapk_routes_to_apkeditor(self, tmp_path: Path) -> None:
        """A .xapk file should route to APKEditor."""
        xapk_file = tmp_path / "app.xapk"
        # Create a minimal valid zip
        with zipfile.ZipFile(xapk_file, "w") as zf:
            zf.writestr("base.apk", b"fake apk content")

        plan = route_input(xapk_file, tmp_path / "output")

        assert plan.format == InputFormat.XAPK
        assert plan.tool == InputTool.APKEDITOR
        assert "m" in plan.tool_args  # merge command

    def test_apkm_routes_to_apkeditor(self, tmp_path: Path) -> None:
        """A .apkm file should route to APKEditor."""
        apkm_file = tmp_path / "app.apkm"
        with zipfile.ZipFile(apkm_file, "w") as zf:
            zf.writestr("base.apk", b"fake apk content")

        plan = route_input(apkm_file, tmp_path / "output")

        assert plan.format == InputFormat.APKM
        assert plan.tool == InputTool.APKEDITOR

    def test_apks_routes_to_apkeditor(self, tmp_path: Path) -> None:
        """A .apks file should route to APKEditor."""
        apks_file = tmp_path / "app.apks"
        with zipfile.ZipFile(apks_file, "w") as zf:
            zf.writestr("base.apk", b"fake apk content")

        plan = route_input(apks_file, tmp_path / "output")

        assert plan.format == InputFormat.APKS
        assert plan.tool == InputTool.APKEDITOR

    def test_apk_routes_to_passthrough(self, tmp_path: Path) -> None:
        """A .apk file should route to passthrough (just copy)."""
        apk_file = tmp_path / "app.apk"
        apk_file.touch()

        plan = route_input(apk_file, tmp_path / "output")

        assert plan.format == InputFormat.APK
        assert plan.tool == InputTool.PASSTHROUGH


class TestObbDetection:
    """Test OBB file detection in archives."""

    def test_xapk_with_obb_detected(self, tmp_path: Path) -> None:
        """An XAPK containing .obb files should be detected."""
        xapk_file = tmp_path / "game.xapk"
        with zipfile.ZipFile(xapk_file, "w") as zf:
            zf.writestr("base.apk", b"fake apk")
            zf.writestr("main.123.com.example.game.obb", b"fake obb data")
            zf.writestr("patch.123.com.example.game.obb", b"fake patch obb")

        plan = route_input(xapk_file, tmp_path / "output")

        assert plan.has_obb
        assert len(plan.obb_files) == 2
        assert any("main" in f for f in plan.obb_files)
        assert any("patch" in f for f in plan.obb_files)

    def test_xapk_without_obb(self, tmp_path: Path) -> None:
        """An XAPK without .obb files should report has_obb=False."""
        xapk_file = tmp_path / "app.xapk"
        with zipfile.ZipFile(xapk_file, "w") as zf:
            zf.writestr("base.apk", b"fake apk")
            zf.writestr("split_config.apk", b"fake split")

        plan = route_input(xapk_file, tmp_path / "output")

        assert not plan.has_obb
        assert len(plan.obb_files) == 0


class TestObbExtraction:
    """Test OBB file extraction."""

    def test_obb_extracted_to_workspace(self, tmp_path: Path) -> None:
        """OBB files should be extracted to workspace/input/obb/."""
        # Create synthetic XAPK with OBB
        xapk_file = tmp_path / "game.xapk"
        obb_content = b"This is fake OBB content for testing"
        with zipfile.ZipFile(xapk_file, "w") as zf:
            zf.writestr("base.apk", b"fake apk")
            zf.writestr("main.123.com.example.game.obb", obb_content)

        # Create workspace
        fake_apk = tmp_path / "game.apk"
        fake_apk.touch()
        ws = create_workspace(
            apk_path=fake_apk,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_120000",
        )

        # Extract OBB
        extracted = extract_obb_files(
            xapk_file,
            ws.obb_dir,
            ("main.123.com.example.game.obb",),
        )

        # Verify extraction
        assert len(extracted) == 1
        assert extracted[0].exists()
        assert extracted[0].name == "main.123.com.example.game.obb"
        assert extracted[0].read_bytes() == obb_content

    def test_multiple_obb_extraction(self, tmp_path: Path) -> None:
        """Multiple OBB files should all be extracted."""
        xapk_file = tmp_path / "game.xapk"
        with zipfile.ZipFile(xapk_file, "w") as zf:
            zf.writestr("base.apk", b"fake apk")
            zf.writestr("main.100.obb", b"main content")
            zf.writestr("patch.100.obb", b"patch content")

        obb_dir = tmp_path / "obb"
        obb_dir.mkdir()

        extracted = extract_obb_files(
            xapk_file,
            obb_dir,
            ("main.100.obb", "patch.100.obb"),
        )

        assert len(extracted) == 2
        assert (obb_dir / "main.100.obb").exists()
        assert (obb_dir / "patch.100.obb").exists()


class TestManifestParsing:
    """Test XAPK manifest.json parsing for package name."""

    def test_package_name_extracted_from_manifest(self, tmp_path: Path) -> None:
        """Package name should be extracted from XAPK manifest.json."""
        xapk_file = tmp_path / "app.xapk"
        manifest = {"package_name": "com.example.testapp", "version_code": 123}

        with zipfile.ZipFile(xapk_file, "w") as zf:
            zf.writestr("base.apk", b"fake apk")
            zf.writestr("manifest.json", json.dumps(manifest))

        plan = route_input(xapk_file, tmp_path / "output")

        assert plan.package_name == "com.example.testapp"

    def test_missing_manifest_handled_gracefully(self, tmp_path: Path) -> None:
        """Missing manifest.json should not cause errors."""
        xapk_file = tmp_path / "app.xapk"
        with zipfile.ZipFile(xapk_file, "w") as zf:
            zf.writestr("base.apk", b"fake apk")

        plan = route_input(xapk_file, tmp_path / "output")

        assert plan.package_name is None


class TestExecutePlanMocked:
    """Test plan execution with mocked tools."""

    def test_passthrough_copies_apk(self, tmp_path: Path) -> None:
        """Passthrough plan should copy APK to target location."""
        # Create fake APK
        fake_apk = tmp_path / "source.apk"
        fake_apk.write_bytes(b"PK fake apk content")

        ws = create_workspace(
            apk_path=fake_apk,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_120000",
        )

        plan = InputPlan(
            format=InputFormat.APK,
            tool=InputTool.PASSTHROUGH,
            tool_args=(str(fake_apk), str(ws.target_apk)),
        )

        # Import here to avoid circular import issues
        from apk_plug.stage0_input import execute_plan

        result = execute_plan(plan, ws)

        assert result.exists()
        assert result.read_bytes() == b"PK fake apk content"
        assert ws.state.is_complete("init")

    @patch("apk_plug.stage0_input.run")
    def test_bundletool_invoked_for_aab(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """AAB plan should invoke bundletool."""
        fake_aab = tmp_path / "app.aab"
        fake_aab.touch()

        ws = create_workspace(
            apk_path=fake_aab,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_120000",
        )

        plan = route_input(fake_aab, ws.input_dir)

        # Create fake apks output that bundletool would produce
        apks_output = ws.input_dir / "bundle.apks"
        with zipfile.ZipFile(apks_output, "w") as zf:
            zf.writestr("universal.apk", b"fake universal apk")

        from apk_plug.stage0_input import execute_plan

        execute_plan(plan, ws)

        # Verify bundletool was called
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert call_args[0] == "bundletool"

    @patch("apk_plug.stage0_input.run")
    def test_apkeditor_invoked_for_xapk(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """XAPK plan should invoke APKEditor."""
        xapk_file = tmp_path / "app.xapk"
        with zipfile.ZipFile(xapk_file, "w") as zf:
            zf.writestr("base.apk", b"fake apk")

        ws = create_workspace(
            apk_path=xapk_file,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_120000",
        )

        plan = route_input(xapk_file, ws.input_dir)

        # Simulate APKEditor creating the output
        ws.target_apk.write_bytes(b"merged apk")

        from apk_plug.stage0_input import execute_plan

        execute_plan(plan, ws)

        # Verify APKEditor was called
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert call_args[0] == "APKEditor"
        assert "m" in call_args  # merge command
