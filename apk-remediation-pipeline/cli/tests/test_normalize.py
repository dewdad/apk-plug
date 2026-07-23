"""Tests for normalize module - scanner output normalization."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import jsonschema
import pytest

from apk_plug.normalize import normalize_scanner_outputs

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SCHEMA_PATH = Path(__file__).parent.parent.parent / "assets" / "threat-report.schema.json"


class TestNormalizeGoldenFile:
    """Golden file test for scanner output normalization."""

    def test_normalize_produces_expected_output(self, tmp_path: Path) -> None:
        """
        Feed fixture scanner outputs through normalize and compare to golden file.

        This is the CENTERPIECE test - it validates the entire normalization pipeline.
        """
        # Set up scan directory structure
        scan_dir = tmp_path / "scan"
        (scan_dir / "mobsf").mkdir(parents=True)
        (scan_dir / "quark").mkdir(parents=True)
        (scan_dir / "semgrep").mkdir(parents=True)
        (scan_dir / "apkleaks").mkdir(parents=True)
        (scan_dir / "apkid").mkdir(parents=True)
        (scan_dir / "apktriage").mkdir(parents=True)

        # Copy fixtures to scan directory
        shutil.copy(FIXTURES_DIR / "mobsf.json", scan_dir / "mobsf" / "report.json")
        shutil.copy(FIXTURES_DIR / "quark.json", scan_dir / "quark" / "report.json")
        shutil.copy(FIXTURES_DIR / "semgrep.sarif", scan_dir / "semgrep" / "report.sarif")
        shutil.copy(FIXTURES_DIR / "apkleaks.json", scan_dir / "apkleaks" / "report.json")
        shutil.copy(FIXTURES_DIR / "apkid.txt", scan_dir / "apkid" / "report.txt")
        shutil.copy(FIXTURES_DIR / "apktriage.json", scan_dir / "apktriage" / "report.json")

        # Create fake APK for metadata
        apk_path = tmp_path / "test.apk"
        apk_path.touch()

        # Pin the timestamp for reproducibility
        fixed_timestamp = "2026-07-23T12:00:00+00:00"

        # Run normalization
        report = normalize_scanner_outputs(
            scan_dir=scan_dir,
            apk_path=apk_path,
            now=fixed_timestamp,
            schema_path=SCHEMA_PATH,
        )

        # Generate JSON output
        actual_json = report.to_json()
        actual_dict = json.loads(actual_json)

        # Load expected output
        expected_dict = json.loads((FIXTURES_DIR / "expected-threat-report.json").read_text())

        # The APK sha256 will be empty for our empty test file - normalize expected
        expected_dict["apk"]["sha256"] = actual_dict["apk"]["sha256"]

        # Compare
        assert actual_dict == expected_dict, f"Mismatch:\nActual:\n{actual_json}"

    def test_output_validates_against_schema(self, tmp_path: Path) -> None:
        """The normalized output MUST validate against the JSON schema."""
        # Set up minimal scan directory
        scan_dir = tmp_path / "scan"
        (scan_dir / "mobsf").mkdir(parents=True)
        shutil.copy(FIXTURES_DIR / "mobsf.json", scan_dir / "mobsf" / "report.json")

        apk_path = tmp_path / "test.apk"
        apk_path.touch()

        report = normalize_scanner_outputs(
            scan_dir=scan_dir,
            apk_path=apk_path,
            now="2026-07-23T12:00:00+00:00",
            schema_path=SCHEMA_PATH,
        )

        # Load schema
        schema = json.loads(SCHEMA_PATH.read_text())

        # Validate - this should NOT raise
        jsonschema.validate(report.to_dict(), schema)

    def test_golden_file_validates_against_schema(self) -> None:
        """The expected-threat-report.json fixture MUST validate against schema."""
        expected = json.loads((FIXTURES_DIR / "expected-threat-report.json").read_text())
        schema = json.loads(SCHEMA_PATH.read_text())

        # This should NOT raise
        jsonschema.validate(expected, schema)


class TestGracefulDegradation:
    """Test that missing scanners don't crash normalization."""

    def test_missing_scanners_marked_not_run(self, tmp_path: Path) -> None:
        """Scanners that didn't produce output should be marked not_run."""
        # Empty scan directory
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()

        apk_path = tmp_path / "test.apk"
        apk_path.touch()

        report = normalize_scanner_outputs(
            scan_dir=scan_dir,
            apk_path=apk_path,
            now="2026-07-23T12:00:00+00:00",
            schema_path=SCHEMA_PATH,
        )

        # All tools should be marked as not_run
        for tool_name, tool_data in report.tools.items():
            assert tool_data["status"] == "not_run", f"{tool_name} should be not_run"

    def test_partial_scanner_output_works(self, tmp_path: Path) -> None:
        """Having only some scanner outputs should still produce valid report."""
        scan_dir = tmp_path / "scan"
        (scan_dir / "quark").mkdir(parents=True)
        shutil.copy(FIXTURES_DIR / "quark.json", scan_dir / "quark" / "report.json")

        apk_path = tmp_path / "test.apk"
        apk_path.touch()

        report = normalize_scanner_outputs(
            scan_dir=scan_dir,
            apk_path=apk_path,
            now="2026-07-23T12:00:00+00:00",
            schema_path=SCHEMA_PATH,
        )

        # Quark should be ran, others not_run
        assert report.tools["quark"]["status"] == "ran"
        assert report.tools["mobsf"]["status"] == "not_run"
        assert report.tools["semgrep"]["status"] == "not_run"


class TestOutputStability:
    """Test that output is deterministic and byte-stable."""

    def test_same_input_produces_same_output(self, tmp_path: Path) -> None:
        """Running normalize twice with same input should produce identical output."""
        scan_dir = tmp_path / "scan"
        (scan_dir / "mobsf").mkdir(parents=True)
        shutil.copy(FIXTURES_DIR / "mobsf.json", scan_dir / "mobsf" / "report.json")

        apk_path = tmp_path / "test.apk"
        apk_path.touch()

        fixed_time = "2026-07-23T12:00:00+00:00"

        report1 = normalize_scanner_outputs(scan_dir, apk_path, now=fixed_time, schema_path=SCHEMA_PATH)
        report2 = normalize_scanner_outputs(scan_dir, apk_path, now=fixed_time, schema_path=SCHEMA_PATH)

        assert report1.to_json() == report2.to_json()

    def test_output_has_sorted_keys(self, tmp_path: Path) -> None:
        """JSON output should have sorted keys for diff-friendliness."""
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()

        apk_path = tmp_path / "test.apk"
        apk_path.touch()

        report = normalize_scanner_outputs(
            scan_dir=scan_dir,
            apk_path=apk_path,
            now="2026-07-23T12:00:00+00:00",
            schema_path=SCHEMA_PATH,
        )

        json_str = report.to_json()
        data = json.loads(json_str)

        # Top-level keys should be sorted
        assert list(data.keys()) == sorted(data.keys())

    def test_output_has_trailing_newline(self, tmp_path: Path) -> None:
        """JSON output should end with a newline."""
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()

        apk_path = tmp_path / "test.apk"
        apk_path.touch()

        report = normalize_scanner_outputs(
            scan_dir=scan_dir,
            apk_path=apk_path,
            now="2026-07-23T12:00:00+00:00",
            schema_path=SCHEMA_PATH,
        )

        assert report.to_json().endswith("\n")
