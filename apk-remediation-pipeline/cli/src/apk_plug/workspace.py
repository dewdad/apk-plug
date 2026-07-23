"""Workspace scaffold creation and stage state management."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)

STATE_FILENAME: Final[str] = ".apk-plug-state.json"

# Required subdirectories for a workspace
WORKSPACE_DIRS: Final[tuple[str, ...]] = (
    "input",
    "input/obb",
    "decompile/java",
    "decompile/smali",
    "decompile/native",
    "scan/mobsf",
    "scan/mobsfscan",
    "scan/semgrep",
    "scan/apktriage",
    "scan/quark",
    "scan/apkleaks",
    "patches",
    "build/unsigned",
    "build/aligned",
    "build/signed",
    "reports",
    "reports/post-fix",
    "keystores",
)

# Linear pipeline stages - each requires the previous ones complete.
# NOTE: 'verify' is intentionally NOT here. It is a cross-cutting gate invoked
# ad-hoc as `apk-plug verify --stage N`, not a stage that gets marked complete.
# Stage 3 (remediation) is also absent: it is manual (agent/human) with no CLI
# command, so rebuild resumes directly after scan.
STAGE_ORDER: Final[tuple[str, ...]] = (
    "init",
    "decompile",
    "scan",
    "rebuild",
    "validate",
)


class WorkspaceError(Exception):
    """Base error for workspace operations."""


class StageOrderError(WorkspaceError):
    """Raised when stages are run out of order."""

    def __init__(self, current_stage: str, required_stage: str) -> None:
        self.current_stage = current_stage
        self.required_stage = required_stage
        super().__init__(
            f"Cannot run '{current_stage}' — run 'apk-plug {required_stage}' first"
        )


class WorkspaceNotFoundError(WorkspaceError):
    """Raised when workspace directory doesn't exist."""

    def __init__(self, path: Path) -> None:
        self.path = path
        super().__init__(f"Workspace not found: {path}")


@dataclass
class WorkspaceState:
    """Persistent state for a workspace."""

    apk_path: str
    package_name: str | None = None
    obb_files: list[str] = field(default_factory=list)
    completed_stages: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    original_format: str = "apk"  # apk, aab, xapk, apkm, apks

    def mark_complete(self, stage: str) -> None:
        """Mark a stage as completed."""
        if stage not in self.completed_stages:
            self.completed_stages.append(stage)

    def is_complete(self, stage: str) -> bool:
        """Check if a stage has been completed."""
        return stage in self.completed_stages


@dataclass(frozen=True, slots=True)
class Workspace:
    """Handle for an APK analysis workspace."""

    root: Path
    state: WorkspaceState

    @property
    def input_dir(self) -> Path:
        return self.root / "input"

    @property
    def obb_dir(self) -> Path:
        return self.root / "input" / "obb"

    @property
    def decompile_java_dir(self) -> Path:
        return self.root / "decompile" / "java"

    @property
    def decompile_smali_dir(self) -> Path:
        return self.root / "decompile" / "smali"

    @property
    def decompile_native_dir(self) -> Path:
        return self.root / "decompile" / "native"

    @property
    def scan_dir(self) -> Path:
        return self.root / "scan"

    @property
    def build_unsigned_dir(self) -> Path:
        return self.root / "build" / "unsigned"

    @property
    def build_aligned_dir(self) -> Path:
        return self.root / "build" / "aligned"

    @property
    def build_signed_dir(self) -> Path:
        return self.root / "build" / "signed"

    @property
    def reports_dir(self) -> Path:
        return self.root / "reports"

    @property
    def reports_postfix_dir(self) -> Path:
        return self.root / "reports" / "post-fix"

    @property
    def keystores_dir(self) -> Path:
        return self.root / "keystores"

    @property
    def target_apk(self) -> Path:
        """Path to the normalized target.apk."""
        return self.input_dir / "target.apk"

    @property
    def state_file(self) -> Path:
        return self.root / STATE_FILENAME

    def save_state(self) -> None:
        """Persist workspace state to disk."""
        data = {
            "apk_path": self.state.apk_path,
            "package_name": self.state.package_name,
            "obb_files": self.state.obb_files,
            "completed_stages": self.state.completed_stages,
            "created_at": self.state.created_at,
            "original_format": self.state.original_format,
        }
        self.state_file.write_text(json.dumps(data, indent=2) + "\n")
        logger.debug("Saved workspace state to %s", self.state_file)

    def require_stage(self, stage: str) -> None:
        """
        Check that a stage's prerequisites are complete.

        Raises:
            StageOrderError: If a required stage hasn't been run.
        """
        stage_idx = STAGE_ORDER.index(stage) if stage in STAGE_ORDER else -1
        if stage_idx <= 0:
            return  # init has no prerequisites

        for prev_stage in STAGE_ORDER[:stage_idx]:
            if not self.state.is_complete(prev_stage):
                raise StageOrderError(stage, prev_stage)


def create_workspace(
    apk_path: Path,
    workspace_base: Path | None = None,
    timestamp: str | None = None,
) -> Workspace:
    """
    Create a new workspace scaffold for APK analysis.

    Args:
        apk_path: Path to the input APK/AAB/XAPK file.
        workspace_base: Base directory for workspaces (default: ./workspace).
        timestamp: Override timestamp for directory name (for testing).

    Returns:
        Workspace handle with state initialized.
    """
    if workspace_base is None:
        workspace_base = Path("workspace")

    if timestamp is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    apk_stem = apk_path.stem
    workspace_name = f"{apk_stem}_{timestamp}"
    workspace_root = workspace_base / workspace_name

    # Create all required directories
    for subdir in WORKSPACE_DIRS:
        (workspace_root / subdir).mkdir(parents=True, exist_ok=True)
        logger.debug("Created directory: %s", workspace_root / subdir)

    # Determine original format from extension
    ext = apk_path.suffix.lower()
    format_map = {
        ".apk": "apk",
        ".aab": "aab",
        ".xapk": "xapk",
        ".apkm": "apkm",
        ".apks": "apks",
        ".zip": "zip",
    }
    original_format = format_map.get(ext, "apk")

    state = WorkspaceState(
        apk_path=str(apk_path.resolve()),
        original_format=original_format,
    )

    workspace = Workspace(root=workspace_root, state=state)
    workspace.save_state()

    logger.info("Created workspace: %s", workspace_root)
    return workspace


def load_workspace(workspace_path: Path) -> Workspace:
    """
    Load an existing workspace from disk.

    Args:
        workspace_path: Path to the workspace directory.

    Returns:
        Workspace handle with state loaded.

    Raises:
        WorkspaceNotFoundError: If the workspace doesn't exist.
    """
    if not workspace_path.exists():
        raise WorkspaceNotFoundError(workspace_path)

    state_file = workspace_path / STATE_FILENAME
    if not state_file.exists():
        raise WorkspaceNotFoundError(workspace_path)

    data = json.loads(state_file.read_text())
    state = WorkspaceState(
        apk_path=data["apk_path"],
        package_name=data.get("package_name"),
        obb_files=data.get("obb_files", []),
        completed_stages=data.get("completed_stages", []),
        created_at=data.get("created_at", ""),
        original_format=data.get("original_format", "apk"),
    )

    return Workspace(root=workspace_path, state=state)


def find_workspace(start_path: Path | None = None) -> Workspace | None:
    """
    Find a workspace by looking for state file in current or parent directories.

    Args:
        start_path: Starting path for search (default: cwd).

    Returns:
        Workspace if found, None otherwise.
    """
    if start_path is None:
        start_path = Path.cwd()

    current = start_path.resolve()
    while current != current.parent:
        state_file = current / STATE_FILENAME
        if state_file.exists():
            return load_workspace(current)
        current = current.parent

    return None
