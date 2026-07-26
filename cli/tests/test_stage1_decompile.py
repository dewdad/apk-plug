"""Tests for stage1_decompile - resilience to real-world tool exit codes.

Regression: jadx frequently exits non-zero on real APKs while still producing
usable Java output. The decompile stage must NOT abort on that (and must still
run apktool), but must fail cleanly when NO output is produced at all.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

from apk_plug.runner import RunResult, ToolFailedError, ToolNotFoundError
from apk_plug.stage1_decompile import DecompileError, run_stage1
from apk_plug.workspace import create_workspace


def _arg_after(cmd: Sequence[str], flag: str) -> str:
    idx = list(cmd).index(flag)
    return cmd[idx + 1]


def _make_workspace(tmp_path: Path):
    fake_apk = tmp_path / "target.apk"
    # a minimal real zip so extract_native_libs does not warn
    import zipfile

    with zipfile.ZipFile(fake_apk, "w") as zf:
        zf.writestr("classes.dex", "dex")
    ws = create_workspace(
        apk_path=fake_apk,
        workspace_base=tmp_path / "ws",
        timestamp="20260723_120000",
    )
    # workspace copies the apk to input/target.apk; ensure target exists
    if not ws.target_apk.exists():
        ws.target_apk.write_bytes(fake_apk.read_bytes())
    # `apk-plug init` marks the init stage complete; replicate so the
    # decompile order-gate (which requires init) is satisfied.
    ws.state.mark_complete("init")
    ws.save_state()
    return ws


def _fake_run_factory(
    plan: dict[str, tuple[int, Callable[[Sequence[str]], None]]],
) -> Callable[..., RunResult]:
    """Emulate runner.run: honor `check`, invoke the per-tool side effect."""

    def _fake(cmd: Sequence[str], *, timeout: float = 300.0, cwd=None, check: bool = True) -> RunResult:  # noqa: ANN001, ARG001
        tool = cmd[0]
        if tool not in plan:
            raise ToolNotFoundError(tool)
        rc, side_effect = plan[tool]
        side_effect(cmd)
        if check and rc != 0:
            raise ToolFailedError(tool, rc, "bad code errors")
        return RunResult(returncode=rc, stdout="", stderr="bad code errors" if rc else "")

    return _fake


class TestDecompileResilience:
    def test_jadx_nonzero_with_output_still_runs_apktool(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """jadx exit 1 WITH output must not abort; apktool must still run."""
        ws = _make_workspace(tmp_path)

        def jadx_effect(cmd: Sequence[str]) -> None:
            out = Path(_arg_after(cmd, "-d"))
            (out / "sources").mkdir(parents=True, exist_ok=True)
            (out / "sources" / "Main.java").write_text("class Main {}")

        def apktool_effect(cmd: Sequence[str]) -> None:
            out = Path(_arg_after(cmd, "-o"))
            (out / "smali").mkdir(parents=True, exist_ok=True)
            (out / "smali" / "Main.smali").write_text(".class LMain;")
            (out / "AndroidManifest.xml").write_text("<manifest/>")

        fake = _fake_run_factory({"jadx": (1, jadx_effect), "apktool": (0, apktool_effect)})
        monkeypatch.setattr("apk_plug.stage1_decompile.run", fake)

        run_stage1(ws)  # must NOT raise

        assert list(ws.decompile_java_dir.rglob("*.java"))
        assert list(ws.decompile_smali_dir.rglob("*.smali"))
        assert (ws.decompile_smali_dir / "AndroidManifest.xml").exists()
        assert ws.state.is_complete("decompile")

    def test_jadx_fails_no_output_but_apktool_ok(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """jadx exit 1 with NO output: apktool still runs and stage completes."""
        ws = _make_workspace(tmp_path)

        def jadx_effect(cmd: Sequence[str]) -> None:
            return  # produce nothing

        def apktool_effect(cmd: Sequence[str]) -> None:
            out = Path(_arg_after(cmd, "-o"))
            (out / "smali").mkdir(parents=True, exist_ok=True)
            (out / "smali" / "Main.smali").write_text(".class LMain;")
            (out / "AndroidManifest.xml").write_text("<manifest/>")

        fake = _fake_run_factory({"jadx": (1, jadx_effect), "apktool": (0, apktool_effect)})
        monkeypatch.setattr("apk_plug.stage1_decompile.run", fake)

        run_stage1(ws)

        assert list(ws.decompile_smali_dir.rglob("*.smali"))
        assert ws.state.is_complete("decompile")

    def test_no_tools_available_raises_actionable(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Both tools missing and no output: raise a clear, actionable error."""
        ws = _make_workspace(tmp_path)
        fake = _fake_run_factory({})  # every tool -> ToolNotFoundError
        monkeypatch.setattr("apk_plug.stage1_decompile.run", fake)

        with pytest.raises(DecompileError) as exc:
            run_stage1(ws)
        assert "install" in str(exc.value).lower()
        assert not ws.state.is_complete("decompile")
