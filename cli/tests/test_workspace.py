"""Tests for workspace module - scaffold creation and stage ordering."""

from __future__ import annotations

from pathlib import Path

import pytest

from apk_plug.workspace import (
    StageOrderError,
    Workspace,
    WorkspaceState,
    create_workspace,
    load_workspace,
)


class TestCreateWorkspace:
    """Test workspace scaffold creation."""

    def test_init_creates_all_required_directories(self, tmp_path: Path) -> None:
        """apk-plug init must create the full directory scaffold."""
        fake_apk = tmp_path / "test.apk"
        fake_apk.touch()

        ws = create_workspace(
            apk_path=fake_apk,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_120000",
        )

        # Check all required directories exist
        assert ws.input_dir.exists()
        assert ws.obb_dir.exists()
        assert ws.decompile_java_dir.exists()
        assert ws.decompile_smali_dir.exists()
        assert ws.decompile_native_dir.exists()
        assert ws.scan_dir.exists()
        assert (ws.scan_dir / "mobsf").exists()
        assert (ws.scan_dir / "mobsfscan").exists()
        assert (ws.scan_dir / "semgrep").exists()
        assert (ws.scan_dir / "apktriage").exists()
        assert (ws.scan_dir / "quark").exists()
        assert (ws.scan_dir / "apkleaks").exists()
        assert ws.build_unsigned_dir.exists()
        assert ws.build_aligned_dir.exists()
        assert ws.build_signed_dir.exists()
        assert ws.reports_dir.exists()
        assert ws.reports_postfix_dir.exists()
        assert ws.keystores_dir.exists()
        assert (ws.root / "patches").exists()

    def test_state_file_created(self, tmp_path: Path) -> None:
        """State file .apk-plug-state.json must be created."""
        fake_apk = tmp_path / "sample.apk"
        fake_apk.touch()

        ws = create_workspace(
            apk_path=fake_apk,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_120000",
        )

        assert ws.state_file.exists()
        assert ws.state_file.name == ".apk-plug-state.json"

    def test_workspace_name_includes_apk_stem_and_timestamp(self, tmp_path: Path) -> None:
        """Workspace directory name follows pattern: <apkstem>_<timestamp>."""
        fake_apk = tmp_path / "myapp.apk"
        fake_apk.touch()

        ws = create_workspace(
            apk_path=fake_apk,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_143022",
        )

        assert ws.root.name == "myapp_20260723_143022"


class TestStageOrdering:
    """Test that stages enforce ordering requirements."""

    def test_scan_before_decompile_raises_error(self, tmp_path: Path) -> None:
        """Running scan before decompile must raise StageOrderError with 'decompile' in message."""
        fake_apk = tmp_path / "test.apk"
        fake_apk.touch()

        ws = create_workspace(
            apk_path=fake_apk,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_120000",
        )

        # Mark init as complete but NOT decompile
        ws.state.mark_complete("init")
        ws.save_state()

        # Attempt to require scan stage - should fail
        with pytest.raises(StageOrderError) as exc_info:
            ws.require_stage("scan")

        # Error message must mention 'decompile'
        assert "decompile" in str(exc_info.value).lower()
        assert exc_info.value.required_stage == "decompile"

    def test_decompile_after_init_allowed(self, tmp_path: Path) -> None:
        """Running decompile after init is allowed."""
        fake_apk = tmp_path / "test.apk"
        fake_apk.touch()

        ws = create_workspace(
            apk_path=fake_apk,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_120000",
        )

        ws.state.mark_complete("init")
        ws.save_state()

        # This should NOT raise
        ws.require_stage("decompile")

    def test_rebuild_requires_scan_complete(self, tmp_path: Path) -> None:
        """Rebuild requires scan to be complete."""
        fake_apk = tmp_path / "test.apk"
        fake_apk.touch()

        ws = create_workspace(
            apk_path=fake_apk,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_120000",
        )

        ws.state.mark_complete("init")
        ws.state.mark_complete("decompile")
        # Note: scan NOT marked complete
        ws.save_state()

        with pytest.raises(StageOrderError) as exc_info:
            ws.require_stage("rebuild")

        assert "scan" in str(exc_info.value).lower()

    def test_rebuild_reachable_after_scan(self, tmp_path: Path) -> None:
        """After init+decompile+scan, rebuild must be reachable.

        Regression: 'verify' is a cross-cutting gate, not a linear pipeline
        stage that gets marked complete. If it sits in STAGE_ORDER between scan
        and rebuild, rebuild becomes permanently unreachable (nothing marks
        'verify'). Stage 3 remediation is manual, with no CLI command to mark.
        """
        fake_apk = tmp_path / "test.apk"
        fake_apk.touch()

        ws = create_workspace(
            apk_path=fake_apk,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_120000",
        )

        ws.state.mark_complete("init")
        ws.state.mark_complete("decompile")
        ws.state.mark_complete("scan")
        ws.save_state()

        # Must NOT raise - remediation (Stage 3) is manual, then rebuild resumes.
        ws.require_stage("rebuild")

    def test_validate_reachable_after_rebuild(self, tmp_path: Path) -> None:
        """After init+decompile+scan+rebuild, validate must be reachable."""
        fake_apk = tmp_path / "test.apk"
        fake_apk.touch()

        ws = create_workspace(
            apk_path=fake_apk,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_120000",
        )

        for stage in ("init", "decompile", "scan", "rebuild"):
            ws.state.mark_complete(stage)
        ws.save_state()

        ws.require_stage("validate")


class TestLoadWorkspace:
    """Test loading existing workspaces."""

    def test_load_preserves_state(self, tmp_path: Path) -> None:
        """Loading a workspace preserves its state."""
        fake_apk = tmp_path / "test.apk"
        fake_apk.touch()

        ws = create_workspace(
            apk_path=fake_apk,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_120000",
        )

        ws.state.mark_complete("init")
        ws.state.mark_complete("decompile")
        ws.state.package_name = "com.example.app"
        ws.state.obb_files = ["main.123.obb"]
        ws.save_state()

        # Load the workspace
        loaded = load_workspace(ws.root)

        assert loaded.state.is_complete("init")
        assert loaded.state.is_complete("decompile")
        assert not loaded.state.is_complete("scan")
        assert loaded.state.package_name == "com.example.app"
        assert loaded.state.obb_files == ["main.123.obb"]


class TestWorkspaceState:
    """Test WorkspaceState dataclass behavior."""

    def test_mark_complete_idempotent(self) -> None:
        """Marking a stage complete multiple times doesn't duplicate."""
        state = WorkspaceState(apk_path="/fake/path.apk")
        state.mark_complete("init")
        state.mark_complete("init")
        state.mark_complete("init")

        assert state.completed_stages.count("init") == 1

    def test_is_complete_returns_correct_value(self) -> None:
        """is_complete returns True only for completed stages."""
        state = WorkspaceState(apk_path="/fake/path.apk")
        state.mark_complete("init")

        assert state.is_complete("init")
        assert not state.is_complete("decompile")
