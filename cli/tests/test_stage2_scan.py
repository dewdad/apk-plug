"""Tests for Stage 2 scan-orchestration resilience.

The skill contract (SKILL.md: "apk-plug scan never hard-crashes on a partial
toolchain"; stage2-scan.md: "Any scanner absent at run time is logged and
marked not_run") requires that a single scanner failing — missing, timing out,
or erroring unexpectedly — must NOT abort Stage 2. The unified
threat-report.json must still be produced.

This locks that behaviour. Before the _safe_scan backstop, a scanner raising
subprocess.TimeoutExpired (semgrep on a very large decompiled tree) propagated
out of run_stage2 and no report was written, which in turn failed
`verify --stage 2`. These tests are the RED->GREEN proof of the fix.
"""

from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path
from unittest.mock import patch

from apk_plug.stage2_scan import run_stage2
from apk_plug.workspace import create_workspace

_DEX = b"dex\n035\x00code"

# Every scanner entry point run_stage2 dispatches, so a test can neutralize the
# ones it is not exercising.
_SCANNERS = (
    "run_mobsf_scan",
    "run_mobsfscan",
    "run_semgrep",
    "run_apktriage",
    "run_quark",
    "run_apkleaks",
    "run_apkid",
)


def _ready_workspace(tmp_path: Path):
    """A workspace with init+decompile complete and a minimal target.apk."""
    src = tmp_path / "app.apk"
    with zipfile.ZipFile(src, "w") as zf:
        zf.writestr("classes.dex", _DEX)

    ws = create_workspace(
        apk_path=src,
        workspace_base=tmp_path / "ws",
        timestamp="20260726_000000",
    )
    with zipfile.ZipFile(ws.target_apk, "w") as zf:
        zf.writestr("classes.dex", _DEX)

    ws.state.mark_complete("init")
    ws.state.mark_complete("decompile")
    ws.save_state()
    return ws


def _patchers(failing: dict[str, BaseException]):
    """Patch every scanner: those in `failing` raise, the rest return False."""
    ctxs = []
    for name in _SCANNERS:
        if name in failing:
            ctxs.append(patch(f"apk_plug.stage2_scan.{name}", side_effect=failing[name]))
        else:
            ctxs.append(patch(f"apk_plug.stage2_scan.{name}", return_value=False))
    return ctxs


class TestStage2Resilience:
    """A failing scanner must never abort the unified report."""

    def test_scanner_timeout_does_not_abort_report(self, tmp_path: Path) -> None:
        ws = _ready_workspace(tmp_path)
        failing = {"run_semgrep": subprocess.TimeoutExpired(cmd="semgrep", timeout=600.0)}

        ctxs = _patchers(failing)
        for c in ctxs:
            c.start()
        try:
            report_path = run_stage2(ws)
        finally:
            for c in ctxs:
                c.stop()

        assert report_path.exists(), "threat-report.json must be written despite a scanner timeout"
        assert report_path.name == "threat-report.json"
        assert ws.state.is_complete("scan")

    def test_unexpected_scanner_error_does_not_abort_report(self, tmp_path: Path) -> None:
        ws = _ready_workspace(tmp_path)
        failing = {"run_mobsf_scan": RuntimeError("boom")}

        ctxs = _patchers(failing)
        for c in ctxs:
            c.start()
        try:
            report_path = run_stage2(ws)
        finally:
            for c in ctxs:
                c.stop()

        assert report_path.exists()
        assert ws.state.is_complete("scan")

    def test_all_scanners_failing_still_writes_report(self, tmp_path: Path) -> None:
        ws = _ready_workspace(tmp_path)
        failing = {name: RuntimeError(f"{name} exploded") for name in _SCANNERS}

        ctxs = _patchers(failing)
        for c in ctxs:
            c.start()
        try:
            report_path = run_stage2(ws)
        finally:
            for c in ctxs:
                c.stop()

        assert report_path.exists()
        assert ws.state.is_complete("scan")
