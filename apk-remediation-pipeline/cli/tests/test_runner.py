"""Tests for runner module - guarded subprocess execution."""

from __future__ import annotations

import pytest

from apk_plug.runner import ToolNotFoundError, run


class TestRunMissingBinary:
    """Test that missing binaries produce actionable errors."""

    def test_missing_binary_raises_tool_not_found_error(self) -> None:
        """Calling run() for a guaranteed-missing binary raises ToolNotFoundError."""
        with pytest.raises(ToolNotFoundError) as exc_info:
            run(["this-binary-definitely-does-not-exist-xyz123"])

        assert exc_info.value.tool == "this-binary-definitely-does-not-exist-xyz123"

    def test_error_message_contains_install_hint(self) -> None:
        """The error message must contain 'install' and the tool name."""
        with pytest.raises(ToolNotFoundError) as exc_info:
            run(["jadx-nonexistent-tool"])

        error_str = str(exc_info.value)
        assert "install" in error_str.lower()
        assert "jadx-nonexistent-tool" in error_str

    def test_error_is_not_bare_file_not_found(self) -> None:
        """Ensure we don't leak a bare FileNotFoundError to the user."""
        with pytest.raises(ToolNotFoundError):
            # This should NOT raise FileNotFoundError
            run(["nonexistent-apktool-binary"])

    def test_error_mentions_install_script(self) -> None:
        """Error should mention install-toolchain.sh for actionable guidance."""
        with pytest.raises(ToolNotFoundError) as exc_info:
            run(["missing-zipalign"])

        error_str = str(exc_info.value)
        assert "install-toolchain.sh" in error_str


class TestRunValidBinary:
    """Test running valid binaries (platform-agnostic)."""

    def test_run_echo_succeeds(self) -> None:
        """Running a simple echo command should succeed."""
        # Use Python as a cross-platform binary that exists
        result = run(["python", "--version"], check=False)
        assert result.returncode == 0

    def test_empty_cmd_raises_value_error(self) -> None:
        """Empty command sequence should raise ValueError."""
        with pytest.raises(ValueError, match="non-empty"):
            run([])
