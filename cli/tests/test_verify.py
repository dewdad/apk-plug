"""Tests for verify module - verification gates."""

from __future__ import annotations

from pathlib import Path

import pytest

from apk_plug.verify import (
    GateResult,
    VerificationError,
    check_java_files_exist,
    check_manifest_validity,
    check_smali_files_exist,
    verify_stage,
    verify_stage1,
)
from apk_plug.workspace import create_workspace


class TestManifestValidity:
    """Test AndroidManifest.xml validation gate."""

    def test_valid_manifest_passes(self, tmp_path: Path) -> None:
        """Valid XML manifest should pass."""
        manifest = tmp_path / "AndroidManifest.xml"
        manifest.write_text("""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">
    <application android:label="Test" />
</manifest>
""")

        result = check_manifest_validity(manifest)

        assert result.result == GateResult.PASS
        assert "valid XML" in result.message

    def test_malformed_manifest_fails(self, tmp_path: Path) -> None:
        """Malformed XML manifest should fail."""
        manifest = tmp_path / "AndroidManifest.xml"
        manifest.write_text("""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">
    <application android:label="Test"
    <!-- missing closing tag -->
""")

        result = check_manifest_validity(manifest)

        assert result.result == GateResult.FAIL
        assert "malformed" in result.message.lower()

    def test_missing_manifest_fails(self, tmp_path: Path) -> None:
        """Missing manifest should fail."""
        manifest = tmp_path / "NonExistent.xml"

        result = check_manifest_validity(manifest)

        assert result.result == GateResult.FAIL
        assert "not found" in result.message.lower()


class TestJavaFilesExist:
    """Test Java files existence gate."""

    def test_java_files_present_passes(self, tmp_path: Path) -> None:
        """Directory with .java files should pass."""
        java_dir = tmp_path / "sources"
        java_dir.mkdir()
        (java_dir / "com" / "example").mkdir(parents=True)
        (java_dir / "com" / "example" / "MainActivity.java").touch()

        result = check_java_files_exist(java_dir)

        assert result.result == GateResult.PASS

    def test_no_java_files_fails(self, tmp_path: Path) -> None:
        """Directory without .java files should fail."""
        java_dir = tmp_path / "sources"
        java_dir.mkdir()
        (java_dir / "empty.txt").touch()

        result = check_java_files_exist(java_dir)

        assert result.result == GateResult.FAIL
        assert "No .java files" in result.message


class TestSmaliFilesExist:
    """Test smali files existence gate."""

    def test_smali_files_present_passes(self, tmp_path: Path) -> None:
        """Directory with .smali files should pass."""
        smali_dir = tmp_path / "smali"
        smali_dir.mkdir()
        (smali_dir / "smali" / "com" / "example").mkdir(parents=True)
        (smali_dir / "smali" / "com" / "example" / "MainActivity.smali").touch()

        result = check_smali_files_exist(smali_dir)

        assert result.result == GateResult.PASS

    def test_no_smali_files_fails(self, tmp_path: Path) -> None:
        """Directory without .smali files should fail."""
        smali_dir = tmp_path / "smali"
        smali_dir.mkdir()

        result = check_smali_files_exist(smali_dir)

        assert result.result == GateResult.FAIL
        assert "No .smali files" in result.message


class TestVerifyStage1:
    """Test Stage 1 verification."""

    def test_broken_workspace_returns_nonzero(self, tmp_path: Path) -> None:
        """Workspace missing smali should fail verification."""
        fake_apk = tmp_path / "test.apk"
        fake_apk.touch()

        ws = create_workspace(
            apk_path=fake_apk,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_120000",
        )

        # Create valid manifest but no smali files
        manifest = ws.decompile_smali_dir / "AndroidManifest.xml"
        manifest.write_text('<?xml version="1.0"?><manifest/>')

        # Create java files
        java_file = ws.decompile_java_dir / "Test.java"
        java_file.write_text("public class Test {}")

        # Verify - should fail because no smali
        result = verify_stage1(ws)

        assert not result.passed
        assert any(c.result == GateResult.FAIL for c in result.checks)

        # Check that failed gate is named
        failed = result.failed_gates
        assert len(failed) > 0
        assert "smali" in failed[0].name.lower()

    def test_valid_workspace_passes(self, tmp_path: Path) -> None:
        """Properly decompiled workspace should pass."""
        fake_apk = tmp_path / "test.apk"
        fake_apk.touch()

        ws = create_workspace(
            apk_path=fake_apk,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_120000",
        )

        # Create valid manifest
        manifest = ws.decompile_smali_dir / "AndroidManifest.xml"
        manifest.write_text('<?xml version="1.0"?><manifest/>')

        # Create java files
        java_file = ws.decompile_java_dir / "Test.java"
        java_file.write_text("public class Test {}")

        # Create smali files
        smali_subdir = ws.decompile_smali_dir / "smali" / "com" / "example"
        smali_subdir.mkdir(parents=True)
        (smali_subdir / "Test.smali").write_text(".class public Lcom/example/Test;")

        result = verify_stage1(ws)

        assert result.passed

    def test_malformed_manifest_fails_with_gate_name(self, tmp_path: Path) -> None:
        """Malformed manifest should fail and name the manifest gate."""
        fake_apk = tmp_path / "test.apk"
        fake_apk.touch()

        ws = create_workspace(
            apk_path=fake_apk,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_120000",
        )

        # Create malformed manifest
        manifest = ws.decompile_smali_dir / "AndroidManifest.xml"
        manifest.write_text("<manifest><broken")

        # Create files (to isolate manifest failure)
        java_file = ws.decompile_java_dir / "Test.java"
        java_file.write_text("public class Test {}")
        smali_subdir = ws.decompile_smali_dir / "smali"
        smali_subdir.mkdir()
        (smali_subdir / "Test.smali").touch()

        result = verify_stage1(ws)

        assert not result.passed
        failed = result.failed_gates
        assert any("manifest" in g.name.lower() for g in failed)


FIXTURES = Path(__file__).parent / "fixtures"


class TestVerifyStage2:
    """Test Stage 2 (scan) verification gate."""

    def _ws(self, tmp_path: Path):
        fake_apk = tmp_path / "test.apk"
        fake_apk.touch()
        return create_workspace(
            apk_path=fake_apk,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_120000",
        )

    def test_missing_report_fails(self, tmp_path: Path) -> None:
        """No threat-report.json should fail and name the report gate."""
        ws = self._ws(tmp_path)
        result = verify_stage(ws, 2)
        assert not result.passed
        assert any("report" in g.name.lower() for g in result.failed_gates)

    def test_valid_report_passes(self, tmp_path: Path) -> None:
        """A schema-valid threat-report.json should pass."""
        ws = self._ws(tmp_path)
        golden = (FIXTURES / "expected-threat-report.json").read_text()
        (ws.reports_dir / "threat-report.json").write_text(golden)
        result = verify_stage(ws, 2)
        assert result.passed

    def test_malformed_report_fails_schema(self, tmp_path: Path) -> None:
        """A present-but-invalid report should fail the schema gate."""
        ws = self._ws(tmp_path)
        (ws.reports_dir / "threat-report.json").write_text('{"not": "valid"}')
        result = verify_stage(ws, 2)
        assert not result.passed
        assert any("schema" in g.name.lower() for g in result.failed_gates)


class TestVerifyStage5:
    """Test Stage 5 (validate) verification gate."""

    def _ws(self, tmp_path: Path):
        fake_apk = tmp_path / "test.apk"
        fake_apk.touch()
        return create_workspace(
            apk_path=fake_apk,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_120000",
        )

    def test_missing_postfix_fails(self, tmp_path: Path) -> None:
        """Empty reports/post-fix should fail."""
        ws = self._ws(tmp_path)
        result = verify_stage(ws, 5)
        assert not result.passed
        assert any("post" in g.name.lower() for g in result.failed_gates)

    def test_postfix_present_passes(self, tmp_path: Path) -> None:
        """A post-fix artifact should pass."""
        ws = self._ws(tmp_path)
        (ws.reports_postfix_dir / "apktriage.json").write_text("{}")
        result = verify_stage(ws, 5)
        assert result.passed


class TestVerifyStageDispatch:
    """verify_stage accepts all five stage numbers 1-5."""

    def test_invalid_stage_raises(self, tmp_path: Path) -> None:
        fake_apk = tmp_path / "test.apk"
        fake_apk.touch()
        ws = create_workspace(
            apk_path=fake_apk,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_120000",
        )
        with pytest.raises(ValueError):
            verify_stage(ws, 99)
