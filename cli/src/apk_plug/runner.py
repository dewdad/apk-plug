"""Guarded subprocess runner with actionable error messages."""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)


class ToolNotFoundError(Exception):
    """Raised when a required tool is not found on PATH."""

    def __init__(self, tool: str, hint: str | None = None) -> None:
        self.tool = tool
        self.hint = hint or f"install it via scripts/install-toolchain.sh"
        super().__init__(f"{tool} not found on PATH — {self.hint}")


class ToolFailedError(Exception):
    """Raised when a tool exits with non-zero status."""

    def __init__(self, tool: str, returncode: int, stderr: str) -> None:
        self.tool = tool
        self.returncode = returncode
        self.stderr = stderr
        # Truncate stderr for readability
        summary = stderr[:500] + "..." if len(stderr) > 500 else stderr
        super().__init__(f"{tool} failed (exit {returncode}): {summary}")


@dataclass(frozen=True, slots=True)
class RunResult:
    """Result of a successful tool invocation."""

    returncode: int
    stdout: str
    stderr: str


def run(
    cmd: Sequence[str],
    *,
    timeout: float = 300.0,
    cwd: Path | str | None = None,
    check: bool = True,
) -> RunResult:
    """
    Run an external tool with guarded error handling.

    Args:
        cmd: Command and arguments to run.
        timeout: Timeout in seconds (default 5 minutes).
        cwd: Working directory for the command.
        check: If True (default), raise ToolFailedError on non-zero exit.

    Returns:
        RunResult with stdout, stderr, and returncode.

    Raises:
        ToolNotFoundError: If the tool binary is not found.
        ToolFailedError: If check=True and tool exits non-zero.
        subprocess.TimeoutExpired: If timeout is exceeded.
    """
    if not cmd:
        msg = "cmd must be a non-empty sequence"
        raise ValueError(msg)

    tool_name = cmd[0]

    # Check if tool exists on PATH
    if shutil.which(tool_name) is None:
        logger.error("Tool not found: %s", tool_name)
        raise ToolNotFoundError(tool_name)

    logger.debug("Running: %s", " ".join(str(c) for c in cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            check=False,
        )
    except FileNotFoundError as e:
        # This can happen if the tool disappears between which() and run()
        logger.error("Tool not found during execution: %s", tool_name)
        raise ToolNotFoundError(tool_name) from e

    run_result = RunResult(
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )

    if check and result.returncode != 0:
        logger.error(
            "Tool %s failed with exit code %d: %s",
            tool_name,
            result.returncode,
            result.stderr[:200],
        )
        raise ToolFailedError(tool_name, result.returncode, result.stderr)

    return run_result
