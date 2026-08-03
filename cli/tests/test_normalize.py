"""Tests for normalize module - scanner output normalization."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import jsonschema
import pytest

from apk_plug.normalize import normalize_scanner_outputs
from apk_plug.report import _BUNDLED_SCHEMA, _default_schema_path, load_schema

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SCHEMA_PATH = Path(__file__).parent.parent.parent / "assets" / "threat-report.schema.json"


class TestSchemaResolution:
    """The schema must resolve WITHOUT an explicit path.

    Regression: report.SCHEMA_PATH was computed relative to the source tree
    (parent x4 -> repo/assets/), which does not exist once the CLI is
    pip/pipx-installed. `validate_report` then raised FileNotFoundError and no
    threat-report.json was written (verify --stage 2 failed). The schema is now
    bundled as package data (src/apk_plug/data/) and resolved from there.
    """

    def test_schema_bundled_as_package_data(self) -> None:
        assert _BUNDLED_SCHEMA.exists(), "schema must be bundled in the package for standalone installs"

    def test_load_schema_without_explicit_path(self) -> None:
        schema = load_schema()  # the exact production call
        assert schema.get("title") == "APK Threat Report"

    def test_default_schema_path_exists(self) -> None:
        assert _default_schema_path().exists()

    def test_normalize_without_schema_path_writes_report(self, tmp_path: Path) -> None:
        # Production path: normalize with NO schema_path override.
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        apk_path = tmp_path / "test.apk"
        apk_path.touch()
        report = normalize_scanner_outputs(
            scan_dir=scan_dir, apk_path=apk_path, now="2026-07-23T12:00:00+00:00"
        )
        assert report.to_json().endswith("\n")


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


class TestMobsfUrlShapes:
    """MobSF v1 emits `urls` as a list of objects, not strings.

    Regression: on a real MobSF report, `urls` is
    [{"urls": ["https://..."], "path": "src/File.java"}, ...]. The old parser
    passed those dicts straight through and `sorted(set(all_urls))` crashed
    with `TypeError: unhashable type: 'dict'`, so no threat-report.json was
    written and `verify --stage 2` failed. URLs must be flattened to strings.
    """

    def _run_with_mobsf(self, tmp_path: Path, mobsf_obj: dict):
        scan_dir = tmp_path / "scan"
        (scan_dir / "mobsf").mkdir(parents=True)
        (scan_dir / "mobsf" / "report.json").write_text(json.dumps(mobsf_obj))
        apk_path = tmp_path / "test.apk"
        apk_path.touch()
        return normalize_scanner_outputs(
            scan_dir=scan_dir,
            apk_path=apk_path,
            now="2026-07-23T12:00:00+00:00",
            schema_path=SCHEMA_PATH,
        )

    def test_mobsf_object_urls_are_flattened(self, tmp_path: Path) -> None:
        report = self._run_with_mobsf(
            tmp_path,
            {
                "urls": [
                    {"urls": ["https://a.example/x", "https://b.example/y"], "path": "A.java"},
                    {"urls": ["https://a.example/x"], "path": "B.java"},  # dup url
                ],
            },
        )
        assert report.urls == ["https://a.example/x", "https://b.example/y"]
        assert all(isinstance(u, str) for u in report.urls)

    def test_mobsf_string_urls_still_supported(self, tmp_path: Path) -> None:
        report = self._run_with_mobsf(
            tmp_path, {"urls": ["https://c.example/z", "https://c.example/z"]}
        )
        assert report.urls == ["https://c.example/z"]

    def test_mobsf_url_key_object_shape(self, tmp_path: Path) -> None:
        report = self._run_with_mobsf(
            tmp_path, {"urls": [{"url": "https://d.example/w", "path": "C.java"}]}
        )
        assert report.urls == ["https://d.example/w"]


class TestApkleaksShapes:
    """apkleaks emits `results` as a LIST of {name, matches}, not a dict.

    Regression: `parse_apkleaks` did `results.items()`, so a real apkleaks
    report crashed normalization with `'list' object has no attribute 'items'`
    and no threat-report.json was written. APK1/APK2 dodged it only because
    apkleaks timed out there; a smaller app (where apkleaks completes) hit it.
    """

    def _run_with_apkleaks(self, tmp_path: Path, apkleaks_obj: dict):
        scan_dir = tmp_path / "scan"
        (scan_dir / "apkleaks").mkdir(parents=True)
        (scan_dir / "apkleaks" / "report.json").write_text(json.dumps(apkleaks_obj))
        apk_path = tmp_path / "test.apk"
        apk_path.touch()
        return normalize_scanner_outputs(
            scan_dir=scan_dir, apk_path=apk_path, now="2026-07-23T12:00:00+00:00"
        )

    def test_list_results_shape_does_not_crash(self, tmp_path: Path) -> None:
        report = self._run_with_apkleaks(
            tmp_path,
            {
                "package": "com.example",
                "results": [
                    {"name": "Artifactory_API_Token", "matches": [" AKCjgBHJzy7fAUWLtZ"]},
                    {"name": "LinkFinder", "matches": ["https://api.example/v1"]},
                ],
            },
        )
        assert report.tools["apkleaks"]["status"] == "ran"
        # LinkFinder matches are catalogued as URLs; the token is a finding.
        assert "https://api.example/v1" in report.urls
        assert any(f["rule"] == "apkleaks_artifactory_api_token" for f in report.findings["apkleaks"])

    def test_dict_results_shape_still_supported(self, tmp_path: Path) -> None:
        report = self._run_with_apkleaks(
            tmp_path, {"results": {"URL": ["https://legacy.example/x"], "AWS": ["AKIA..."]}}
        )
        assert "https://legacy.example/x" in report.urls
        assert any(f["category"] == "AWS" for f in report.findings["apkleaks"])


class TestParserNeverAborts:
    """A parser that chokes on a malformed output marks the tool error, never
    aborting the whole report (the normalize-layer never-hard-crash contract)."""

    def test_parser_exception_marks_error_and_writes_report(self, tmp_path: Path) -> None:
        scan_dir = tmp_path / "scan"
        (scan_dir / "quark").mkdir(parents=True)
        # `crimes` as a bare int makes `for crime in data["crimes"]` raise
        # TypeError inside parse_quark -> _safe_parse must catch it and mark the
        # tool error, WITHOUT aborting the whole report.
        (scan_dir / "quark" / "report.json").write_text(json.dumps({"crimes": 123}))
        apk_path = tmp_path / "test.apk"
        apk_path.touch()

        report = normalize_scanner_outputs(
            scan_dir=scan_dir, apk_path=apk_path, now="2026-07-23T12:00:00+00:00"
        )
        # Report still produced and schema-valid; quark marked error.
        assert report.to_json().endswith("\n")
        assert report.tools["quark"]["status"] == "error"
        # The error path must not inject schema-invalid nulls.
        assert "threat_level" not in report.tools["quark"]
        assert "total_score" not in report.tools["quark"]


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
