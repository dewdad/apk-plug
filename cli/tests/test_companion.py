"""Tests for AAB companion-data handling (feature modules + asset packs).

Covers the gap where `bundletool build-apks --mode=universal` drops on-demand /
conditional feature modules (fusing=false) and non-install-time asset packs,
which are scan blind spots that must be analyzed from the raw bundle.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from apk_plug.stage0_input import (
    AabModule,
    InputPlan,
    InputFormat,
    InputTool,
    compute_in_universal,
    enumerate_aab_modules,
    _enrich_aab_state,
    _parse_dist_flags,
    read_module_flags,
    route_input,
)
from apk_plug.stage2_scan import (
    find_embedded_payloads,
    scan_apk_assets_for_dex,
    scan_companion_artifacts,
)
from apk_plug.workspace import create_workspace

# 8-byte DEX file magic ("dex\n035\0") and ELF magic.
DEX_MAGIC = b"dex\n035\x00"
ELF_MAGIC = b"\x7fELF\x02\x01\x01\x00"

# Decoded manifests as `bundletool dump manifest` would emit them.
_FEATURE_ONDEMAND_NOFUSE = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          xmlns:dist="http://schemas.android.com/apk/distribution"
          split="featureB">
  <dist:module dist:onDemand="true" dist:title="@string/title">
    <dist:fusing dist:include="false"/>
    <dist:delivery>
      <dist:on-demand/>
    </dist:delivery>
  </dist:module>
</manifest>
"""

_ASSET_PACK_ONDEMAND = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          xmlns:dist="http://schemas.android.com/apk/distribution"
          split="asset_pack_2">
  <dist:module dist:type="asset-pack">
    <dist:delivery>
      <dist:on-demand/>
    </dist:delivery>
  </dist:module>
</manifest>
"""

_BASE_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.game">
  <application/>
</manifest>
"""


def _make_synthetic_aab(path: Path) -> None:
    """Write a synthetic .aab: base + fusing=false feature + on-demand asset pack."""
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("BundleConfig.pb", b"\x00\x01")
        # base module
        zf.writestr("base/manifest/AndroidManifest.xml", _BASE_MANIFEST)
        zf.writestr("base/dex/classes.dex", DEX_MAGIC + b"base code")
        zf.writestr("base/resources.pb", b"\x00")
        # on-demand feature module with fusing=false (DROPPED from universal)
        zf.writestr("featureB/manifest/AndroidManifest.xml", _FEATURE_ONDEMAND_NOFUSE)
        zf.writestr("featureB/dex/classes.dex", DEX_MAGIC + b"hidden feature code")
        zf.writestr("featureB/lib/arm64-v8a/libhidden.so", ELF_MAGIC + b"native")
        # on-demand asset pack carrying a smuggled DEX
        zf.writestr("asset_pack_2/manifest/AndroidManifest.xml", _ASSET_PACK_ONDEMAND)
        zf.writestr("asset_pack_2/assets/level_data/payload.dex", DEX_MAGIC + b"payload")


class TestEnumerateAabModules:
    """Structural (pure) enumeration and classification of .aab modules."""

    def test_classifies_base_feature_and_asset_pack(self, tmp_path: Path) -> None:
        aab = tmp_path / "game.aab"
        _make_synthetic_aab(aab)

        modules = {m.name: m for m in enumerate_aab_modules(aab)}

        assert set(modules) == {"base", "featureB", "asset_pack_2"}
        assert modules["base"].kind == "base"
        assert modules["featureB"].kind == "feature"
        assert modules["featureB"].has_dex is True
        assert modules["featureB"].has_lib is True
        assert modules["asset_pack_2"].kind == "asset_pack"
        assert modules["asset_pack_2"].has_assets is True
        assert modules["asset_pack_2"].has_dex is False

    def test_invalid_zip_returns_empty(self, tmp_path: Path) -> None:
        bad = tmp_path / "empty.aab"
        bad.touch()  # not a valid zip
        assert enumerate_aab_modules(bad) == ()

    def test_route_input_populates_modules(self, tmp_path: Path) -> None:
        aab = tmp_path / "game.aab"
        _make_synthetic_aab(aab)

        plan = route_input(aab, tmp_path / "out")

        assert plan.format == InputFormat.AAB
        assert plan.tool == InputTool.BUNDLETOOL
        assert {m.name for m in plan.aab_modules} == {"base", "featureB", "asset_pack_2"}


class TestComputeInUniversal:
    """Universal-APK inclusion logic."""

    def test_base_always_included(self) -> None:
        assert compute_in_universal("base", None, None, None) is True

    def test_feature_fusing_true_included(self) -> None:
        assert compute_in_universal("feature", True, True, None) is True

    def test_feature_fusing_false_dropped(self) -> None:
        assert compute_in_universal("feature", True, False, None) is False

    def test_feature_unknown_fusing_is_none(self) -> None:
        assert compute_in_universal("feature", None, None, None) is None

    def test_asset_pack_install_time_included(self) -> None:
        assert compute_in_universal("asset_pack", None, None, "install-time") is True

    def test_asset_pack_on_demand_dropped(self) -> None:
        assert compute_in_universal("asset_pack", None, None, "on-demand") is False
        assert compute_in_universal("asset_pack", None, None, "fast-follow") is False

    def test_asset_pack_unknown_delivery_is_none(self) -> None:
        assert compute_in_universal("asset_pack", None, None, None) is None


class TestParseDistFlags:
    """Delivery-flag parsing from decoded manifests."""

    def test_feature_ondemand_nofuse(self) -> None:
        flags = _parse_dist_flags(_FEATURE_ONDEMAND_NOFUSE)
        assert flags["on_demand"] is True
        assert flags["fusing"] is False
        assert flags["delivery_type"] == "on-demand"

    def test_asset_pack_ondemand(self) -> None:
        flags = _parse_dist_flags(_ASSET_PACK_ONDEMAND)
        assert flags["delivery_type"] == "on-demand"

    def test_malformed_xml_returns_empty(self) -> None:
        assert _parse_dist_flags("<not-valid") == {}


class TestReadModuleFlags:
    """Best-effort flag refinement, with graceful degradation."""

    def test_base_short_circuits_without_tool(self, tmp_path: Path) -> None:
        aab = tmp_path / "g.aab"
        _make_synthetic_aab(aab)
        base = AabModule(name="base", kind="base")
        # Must not call bundletool for the base module.
        with patch("apk_plug.stage0_input.run") as mock_run:
            refined = read_module_flags(aab, base)
        mock_run.assert_not_called()
        assert refined.in_universal is True

    def test_bundletool_missing_leaves_flags_unknown(self, tmp_path: Path) -> None:
        from apk_plug.runner import ToolNotFoundError

        aab = tmp_path / "g.aab"
        _make_synthetic_aab(aab)
        mod = AabModule(name="featureB", kind="feature", has_dex=True)

        with patch("apk_plug.stage0_input.run", side_effect=ToolNotFoundError("bundletool")):
            refined = read_module_flags(aab, mod)

        assert refined.fusing is None
        assert refined.in_universal is None  # conservative: scan anyway


class TestEnrichAabState:
    """End-to-end Stage 0 enrichment with bundletool mocked."""

    def test_populates_state_and_flags(self, tmp_path: Path) -> None:
        aab = tmp_path / "game.aab"
        _make_synthetic_aab(aab)

        ws = create_workspace(
            apk_path=aab,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_120000",
        )
        plan = route_input(aab, ws.input_dir)

        manifests = {
            "featureB": _FEATURE_ONDEMAND_NOFUSE,
            "asset_pack_2": _ASSET_PACK_ONDEMAND,
            "base": _BASE_MANIFEST,
        }

        def fake_run(cmd, **_kwargs):
            module = cmd[cmd.index("--module") + 1] if "--module" in cmd else "base"
            return MagicMock(returncode=0, stdout=manifests[module], stderr="")

        with patch("apk_plug.stage0_input.run", side_effect=fake_run):
            _enrich_aab_state(plan, ws, aab)

        # Raw bundle preserved for scanning.
        assert (ws.aab_raw_dir / "featureB" / "dex" / "classes.dex").exists()
        assert (ws.aab_raw_dir / "asset_pack_2" / "assets" / "level_data" / "payload.dex").exists()

        # State captured with correct drop classification.
        assert len(ws.state.feature_modules) == 1
        fm = ws.state.feature_modules[0]
        assert fm["name"] == "featureB"
        assert fm["fusing"] is False
        assert fm["in_universal"] is False

        assert len(ws.state.asset_packs) == 1
        ap = ws.state.asset_packs[0]
        assert ap["name"] == "asset_pack_2"
        assert ap["in_universal"] is False

        assert ws.state.package_name == "com.example.game"


class TestFindEmbeddedPayloads:
    """DEX/ELF detection by extension AND magic."""

    def test_detects_dex_and_elf(self, tmp_path: Path) -> None:
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "a.dex").write_bytes(DEX_MAGIC + b"x")
        (tmp_path / "sub" / "b.so").write_bytes(ELF_MAGIC + b"y")
        (tmp_path / "clean.txt").write_bytes(b"nothing here")

        payloads = {p["path"].replace("\\", "/"): p["type"] for p in find_embedded_payloads(tmp_path)}

        assert payloads["sub/a.dex"] == "dex"
        assert payloads["sub/b.so"] == "elf"
        assert "clean.txt" not in payloads

    def test_detects_dex_renamed_to_png(self, tmp_path: Path) -> None:
        (tmp_path / "icon.png").write_bytes(DEX_MAGIC + b"disguised")
        payloads = find_embedded_payloads(tmp_path)
        assert any(p["type"] == "dex" for p in payloads)

    def test_missing_dir_returns_empty(self, tmp_path: Path) -> None:
        assert find_embedded_payloads(tmp_path / "nope") == []


class TestScanApkAssetsForDex:
    """DEX smuggled inside an APK's assets/ directory."""

    def test_finds_dex_in_assets(self, tmp_path: Path) -> None:
        apk = tmp_path / "target.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("classes.dex", DEX_MAGIC + b"legit")
            zf.writestr("assets/payload.dex", DEX_MAGIC + b"evil")
            zf.writestr("assets/config.json", b"{}")
            zf.writestr("assets/hidden.bin", DEX_MAGIC + b"magic-only")

        found = scan_apk_assets_for_dex(apk)

        assert "assets/payload.dex" in found  # by extension
        assert "assets/hidden.bin" in found  # by magic
        assert "assets/config.json" not in found
        assert "classes.dex" not in found  # not under assets/


class TestScanCompanionArtifacts:
    """Full companion-data scan producing routed findings."""

    def _prepare_workspace(self, tmp_path: Path):
        aab = tmp_path / "game.aab"
        _make_synthetic_aab(aab)
        ws = create_workspace(
            apk_path=aab,
            workspace_base=tmp_path / "workspace",
            timestamp="20260723_120000",
        )
        # Simulate Stage 0 having extracted the raw bundle + recorded state.
        with zipfile.ZipFile(aab, "r") as zf:
            zf.extractall(ws.aab_raw_dir)
        ws.state.feature_modules = [
            {
                "name": "featureB", "kind": "feature", "has_dex": True,
                "has_lib": True, "has_assets": False, "on_demand": True,
                "fusing": False, "delivery_type": "on-demand", "in_universal": False,
            }
        ]
        ws.state.asset_packs = [
            {
                "name": "asset_pack_2", "kind": "asset_pack", "has_dex": False,
                "has_lib": False, "has_assets": True, "on_demand": None,
                "fusing": None, "delivery_type": "on-demand", "in_universal": False,
            }
        ]
        return ws

    def test_flags_dropped_module_and_payloads(self, tmp_path: Path) -> None:
        ws = self._prepare_workspace(tmp_path)
        # A clean target.apk (no assets dex) so those findings come only from raw.
        with zipfile.ZipFile(ws.target_apk, "w") as zf:
            zf.writestr("classes.dex", DEX_MAGIC + b"base")

        findings = scan_companion_artifacts(ws)
        rules = {f["rule"] for f in findings}

        assert "dropped_feature_module_with_code" in rules
        assert "dex_in_asset_pack" in rules  # payload.dex under the asset pack
        # ELF in the dropped (non-fused) feature module is high severity.
        assert any(
            f["rule"] == "elf_in_feature" and f["severity"] == "high" for f in findings
        )
        # Report written for the normalizer.
        assert (ws.scan_dir / "companion" / "report.json").exists()

    def test_flags_dex_in_target_apk_assets(self, tmp_path: Path) -> None:
        ws = self._prepare_workspace(tmp_path)
        with zipfile.ZipFile(ws.target_apk, "w") as zf:
            zf.writestr("classes.dex", DEX_MAGIC + b"base")
            zf.writestr("assets/sneaky.dex", DEX_MAGIC + b"evil")

        findings = scan_companion_artifacts(ws)

        assert any(f["rule"] == "dex_in_apk_assets" for f in findings)
