"""Stage 0: Input normalization - format routing and OBB extraction."""

from __future__ import annotations

import json
import logging
import shutil
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from apk_plug.workspace import Workspace

from apk_plug.runner import ToolFailedError, ToolNotFoundError, run

logger = logging.getLogger(__name__)

# Android distribution namespace used in feature/asset-pack manifests.
_DIST_NS = "http://schemas.android.com/apk/distribution"
# Top-level .aab entries that are NOT modules.
_AAB_NON_MODULE_PREFIXES = ("BUNDLE-METADATA/", "META-INF/")


class InputFormat(Enum):
    """Supported input formats."""

    APK = "apk"
    AAB = "aab"
    XAPK = "xapk"
    APKM = "apkm"
    APKS = "apks"
    ZIP = "zip"


class InputTool(Enum):
    """Tools used for input normalization."""

    PASSTHROUGH = "passthrough"
    BUNDLETOOL = "bundletool"
    APKEDITOR = "apkeditor"


@dataclass(frozen=True, slots=True)
class AabModule:
    """A module inside an Android App Bundle (.aab).

    Covers the base module, dynamic feature modules (DFMs), and Play Asset
    Delivery asset packs. `in_universal` records whether the module's code and
    resources survive `bundletool build-apks --mode=universal` — anything that
    does NOT (on-demand/conditional DFMs with fusing=false, and fast-follow /
    on-demand asset packs) is a scan blind spot that must be analyzed directly
    from the raw bundle.
    """

    name: str  # top-level directory name in the .aab (e.g. "base", "featureX")
    kind: str  # "base" | "feature" | "asset_pack"
    has_dex: bool = False
    has_lib: bool = False
    has_assets: bool = False
    on_demand: bool | None = None  # DFM: dist:onDemand; None if unknown
    fusing: bool | None = None  # DFM: dist:fusing dist:include; None if unknown
    delivery_type: str | None = None  # asset pack: install-time/fast-follow/on-demand
    in_universal: bool | None = None  # True/False if determinable, else None

    def to_state_dict(self) -> dict:
        """Serialize to the plain-dict shape persisted in WorkspaceState."""
        return {
            "name": self.name,
            "kind": self.kind,
            "has_dex": self.has_dex,
            "has_lib": self.has_lib,
            "has_assets": self.has_assets,
            "on_demand": self.on_demand,
            "fusing": self.fusing,
            "delivery_type": self.delivery_type,
            "in_universal": self.in_universal,
        }


@dataclass(frozen=True, slots=True)
class InputPlan:
    """Plan for normalizing an input file to target.apk."""

    format: InputFormat
    tool: InputTool
    tool_args: tuple[str, ...]
    has_obb: bool = False
    obb_files: tuple[str, ...] = ()
    package_name: str | None = None
    # Preliminary module inventory for .aab inputs (structure-only; delivery
    # flags are refined by tool-backed read_module_flags during execution).
    aab_modules: tuple[AabModule, ...] = ()


def detect_format(path: Path) -> InputFormat:
    """
    Detect input format from extension and content signature.

    Args:
        path: Path to the input file.

    Returns:
        Detected InputFormat.
    """
    ext = path.suffix.lower()

    format_map = {
        ".apk": InputFormat.APK,
        ".aab": InputFormat.AAB,
        ".xapk": InputFormat.XAPK,
        ".apkm": InputFormat.APKM,
        ".apks": InputFormat.APKS,
        ".zip": InputFormat.ZIP,
    }

    return format_map.get(ext, InputFormat.APK)


def route_input(path: Path, output_dir: Path) -> InputPlan:
    """
    Determine the normalization plan for an input file.

    This is a PURE function - it only inspects the file and returns a plan,
    without executing any tools.

    Args:
        path: Path to the input file.
        output_dir: Directory where target.apk will be placed.

    Returns:
        InputPlan describing how to normalize the input.
    """
    fmt = detect_format(path)
    target_apk = output_dir / "target.apk"

    if fmt == InputFormat.APK:
        # Plain APK - just copy
        return InputPlan(
            format=fmt,
            tool=InputTool.PASSTHROUGH,
            tool_args=(str(path), str(target_apk)),
        )

    if fmt == InputFormat.AAB:
        # Android App Bundle -> bundletool. Enumerate modules purely from the
        # zip structure now; delivery flags are refined during execution.
        apks_output = output_dir / "bundle.apks"
        return InputPlan(
            format=fmt,
            tool=InputTool.BUNDLETOOL,
            tool_args=(
                "build-apks",
                "--bundle", str(path),
                "--output", str(apks_output),
                "--mode=universal",
            ),
            aab_modules=enumerate_aab_modules(path),
        )

    # XAPK/APKM/APKS/ZIP -> APKEditor merge
    # Also check for OBB files and manifest
    obb_files: list[str] = []
    package_name: str | None = None

    if fmt in (InputFormat.XAPK, InputFormat.APKM, InputFormat.APKS, InputFormat.ZIP):
        try:
            with zipfile.ZipFile(path, "r") as zf:
                names = zf.namelist()
                # Check for OBB files
                for name in names:
                    if name.endswith(".obb"):
                        obb_files.append(name)

                # Try to read manifest.json for package name (XAPK format)
                if "manifest.json" in names:
                    try:
                        manifest_data = json.loads(zf.read("manifest.json"))
                        package_name = manifest_data.get("package_name")
                    except (json.JSONDecodeError, KeyError):
                        pass
        except zipfile.BadZipFile:
            logger.warning("Could not read %s as zip file", path)

    return InputPlan(
        format=fmt,
        tool=InputTool.APKEDITOR,
        tool_args=(
            "m",
            "-i", str(path),
            "-o", str(target_apk),
        ),
        has_obb=len(obb_files) > 0,
        obb_files=tuple(obb_files),
        package_name=package_name,
    )


def extract_obb_files(archive_path: Path, obb_dir: Path, obb_files: tuple[str, ...]) -> list[Path]:
    """
    Extract OBB files from an archive to the OBB directory.

    Args:
        archive_path: Path to the archive (XAPK/APKM/etc).
        obb_dir: Directory to extract OBB files into.
        obb_files: List of OBB file paths within the archive.

    Returns:
        List of paths to extracted OBB files.
    """
    extracted: list[Path] = []

    with zipfile.ZipFile(archive_path, "r") as zf:
        for obb_name in obb_files:
            # Extract to obb_dir with just the filename (strip any directory)
            dest_name = Path(obb_name).name
            dest_path = obb_dir / dest_name

            with zf.open(obb_name) as src, dest_path.open("wb") as dst:
                shutil.copyfileobj(src, dst)

            extracted.append(dest_path)
            logger.info("Extracted OBB: %s -> %s", obb_name, dest_path)

    return extracted


def _classify_module(name: str, *, has_dex: bool, has_assets: bool) -> str:
    """Classify an .aab top-level module directory by its structure."""
    if name == "base":
        return "base"
    if has_dex:
        return "feature"
    if has_assets:
        return "asset_pack"
    # No dex, no assets — treat as a feature module so it is still scanned.
    return "feature"


def enumerate_aab_modules(aab_path: Path) -> tuple[AabModule, ...]:
    """
    Enumerate modules inside an .aab from its ZIP structure alone (PURE).

    Classification is purely structural (no manifest decoding), so this never
    needs external tools. Delivery flags (on_demand / fusing / delivery_type)
    are left as None here and refined later by read_module_flags.

    Args:
        aab_path: Path to the .aab file.

    Returns:
        Tuple of AabModule entries (empty if the file is not a valid zip).
    """
    try:
        with zipfile.ZipFile(aab_path, "r") as zf:
            names = zf.namelist()
    except zipfile.BadZipFile:
        logger.warning("Could not read %s as a zip (.aab) file", aab_path)
        return ()

    modules: dict[str, dict[str, bool]] = {}
    for name in names:
        if "/" not in name:
            continue  # top-level file such as BundleConfig.pb
        if name.startswith(_AAB_NON_MODULE_PREFIXES):
            continue
        top, rest = name.split("/", 1)
        info = modules.setdefault(
            top,
            {"manifest": False, "dex": False, "lib": False, "assets": False},
        )
        if rest.startswith("manifest/"):
            info["manifest"] = True
        elif rest.startswith("dex/"):
            info["dex"] = True
        elif rest.startswith("lib/"):
            info["lib"] = True
        elif rest.startswith("assets/"):
            info["assets"] = True

    result: list[AabModule] = []
    for top in sorted(modules):
        info = modules[top]
        # Keep base always; keep others only if they carry a manifest or payload.
        carries_payload = info["dex"] or info["lib"] or info["assets"]
        if top != "base" and not info["manifest"] and not carries_payload:
            continue
        result.append(
            AabModule(
                name=top,
                kind=_classify_module(top, has_dex=info["dex"], has_assets=info["assets"]),
                has_dex=info["dex"],
                has_lib=info["lib"],
                has_assets=info["assets"],
            )
        )
    return tuple(result)


def compute_in_universal(
    kind: str,
    on_demand: bool | None,  # noqa: ARG001 - kept for symmetry / future use
    fusing: bool | None,
    delivery_type: str | None,
) -> bool | None:
    """
    Decide whether a module survives `bundletool build-apks --mode=universal`.

    Returns None when it cannot be determined (flags unknown) — callers must
    treat None conservatively and scan the module anyway.
    """
    if kind == "base":
        return True
    if kind == "asset_pack":
        if delivery_type == "install-time":
            return True
        if delivery_type in ("on-demand", "fast-follow"):
            return False
        return None
    # Feature module: the fusing gate alone decides inclusion in the universal APK.
    if fusing is True:
        return True
    if fusing is False:
        return False
    return None


def _dump_manifest(aab_path: Path, module_name: str) -> str | None:
    """Return the decoded XML manifest for an .aab module via bundletool, or None."""
    try:
        result = run(
            [
                "bundletool", "dump", "manifest",
                "--bundle", str(aab_path),
                "--module", module_name,
            ],
            timeout=120.0,
            check=False,
        )
    except (ToolNotFoundError, ToolFailedError):
        logger.info(
            "bundletool unavailable — delivery flags for module '%s' left unknown",
            module_name,
        )
        return None
    if result.returncode != 0:
        logger.debug(
            "bundletool dump manifest failed for '%s': %s",
            module_name,
            result.stderr[:200],
        )
        return None
    return result.stdout


def _local_name(tag: str) -> str:
    """Strip an XML namespace from a tag, returning the local name."""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _dist_attr(elem: ET.Element, attr: str) -> str | None:
    """Read a distribution-namespaced attribute, tolerating prefix/plain forms."""
    return (
        elem.get(f"{{{_DIST_NS}}}{attr}")
        or elem.get(f"dist:{attr}")
        or elem.get(attr)
    )


def _parse_dist_flags(xml_text: str) -> dict[str, Any]:
    """Parse onDemand / fusing / delivery-type flags from a decoded manifest."""
    out: dict[str, Any] = {}
    try:
        root = ET.fromstring(xml_text)  # noqa: S314 - analyst-provided sample, best-effort parse
    except ET.ParseError:
        return out

    for elem in root.iter():
        lname = _local_name(elem.tag)
        if lname == "module":
            on_demand = _dist_attr(elem, "onDemand")
            if on_demand is not None:
                out["on_demand"] = on_demand == "true"
        elif lname == "fusing":
            include = _dist_attr(elem, "include")
            if include is not None:
                out["fusing"] = include == "true"
        elif lname in ("install-time", "on-demand", "fast-follow"):
            # Child of <dist:delivery>; marks the module/asset-pack delivery mode.
            out.setdefault("delivery_type", lname)
    return out


def read_module_flags(aab_path: Path, module: AabModule) -> AabModule:
    """
    Refine a module's delivery flags using bundletool (best-effort).

    Degrades gracefully: if bundletool is unavailable or errors, flags stay
    None and in_universal is computed conservatively (unknown -> None).

    Args:
        aab_path: Path to the .aab file.
        module: The structurally-enumerated module to refine.

    Returns:
        A new AabModule with delivery flags and in_universal filled in.
    """
    if module.kind == "base":
        return replace(module, in_universal=True)

    on_demand, fusing, delivery_type = module.on_demand, module.fusing, module.delivery_type

    xml_text = _dump_manifest(aab_path, module.name)
    if xml_text is not None:
        parsed = _parse_dist_flags(xml_text)
        on_demand = parsed.get("on_demand", on_demand)
        fusing = parsed.get("fusing", fusing)
        delivery_type = parsed.get("delivery_type", delivery_type)

    return replace(
        module,
        on_demand=on_demand,
        fusing=fusing,
        delivery_type=delivery_type,
        in_universal=compute_in_universal(module.kind, on_demand, fusing, delivery_type),
    )


def _read_aab_package_name(aab_path: Path) -> str | None:
    """Extract the applicationId/package from the base module manifest."""
    xml_text = _dump_manifest(aab_path, "base")
    if xml_text is None:
        return None
    try:
        root = ET.fromstring(xml_text)  # noqa: S314 - best-effort parse of sample
    except ET.ParseError:
        return None
    return root.get("package")


def _safe_extractall(zf: zipfile.ZipFile, dest: Path) -> None:
    """Extract a zip guarding against path traversal (zip-slip) from samples."""
    dest = dest.resolve()
    for member in zf.namelist():
        target = (dest / member).resolve()
        if dest != target and dest not in target.parents:
            logger.warning("Skipping zip-slip entry in bundle: %s", member)
            continue
        if member.endswith("/"):
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(member) as src, target.open("wb") as dst:
            shutil.copyfileobj(src, dst)


def _enrich_aab_state(plan: InputPlan, workspace: Workspace, aab_path: Path) -> None:
    """
    Preserve and inventory the raw .aab so dropped modules stay analyzable.

    Unzips the bundle into workspace.aab_raw_dir, refines each module's delivery
    flags, records feature modules and asset packs in workspace state, and
    backfills the package name. All best-effort: a bad zip or missing bundletool
    degrades to "record what we can, scan everything".
    """
    try:
        with zipfile.ZipFile(aab_path, "r") as zf:
            _safe_extractall(zf, workspace.aab_raw_dir)
    except zipfile.BadZipFile:
        logger.warning("Could not unzip %s as .aab — skipping companion inventory", aab_path)
        return

    modules = tuple(read_module_flags(aab_path, m) for m in plan.aab_modules)

    workspace.state.feature_modules = [
        m.to_state_dict() for m in modules if m.kind == "feature"
    ]
    workspace.state.asset_packs = [
        m.to_state_dict() for m in modules if m.kind == "asset_pack"
    ]

    dropped = [m.name for m in modules if m.in_universal is False]
    if dropped:
        logger.warning(
            "AAB modules NOT in universal APK (scanned from raw bundle): %s",
            ", ".join(dropped),
        )

    pkg = _read_aab_package_name(aab_path)
    if pkg:
        workspace.state.package_name = pkg


def execute_plan(plan: InputPlan, workspace: Workspace) -> Path:
    """
    Execute an input normalization plan.

    Args:
        plan: The InputPlan to execute.
        workspace: The workspace to operate in.

    Returns:
        Path to the normalized target.apk.
    """
    target_apk = workspace.target_apk
    input_path = Path(workspace.state.apk_path)

    if plan.tool == InputTool.PASSTHROUGH:
        # Just copy the APK
        shutil.copy2(input_path, target_apk)
        logger.info("Copied APK to %s", target_apk)

    elif plan.tool == InputTool.BUNDLETOOL:
        # Run bundletool to create universal APK
        apks_output = workspace.input_dir / "bundle.apks"
        run(["bundletool", *plan.tool_args[1:]], timeout=600.0)

        # Extract universal.apk from the .apks file
        with zipfile.ZipFile(apks_output, "r") as zf:
            with zf.open("universal.apk") as src, target_apk.open("wb") as dst:
                shutil.copyfileobj(src, dst)
        logger.info("Extracted universal APK from bundle to %s", target_apk)

        # The universal APK DROPS on-demand/conditional feature modules with
        # fusing=false and all non-install-time asset packs. Preserve the raw
        # bundle contents so Stage 2 can scan those blind spots directly.
        _enrich_aab_state(plan, workspace, input_path)

    elif plan.tool == InputTool.APKEDITOR:
        # Run APKEditor to merge splits
        run(["APKEditor", *plan.tool_args], timeout=600.0)
        logger.info("Merged splits to %s", target_apk)

    # Extract OBB files if present
    if plan.has_obb and plan.obb_files:
        extracted = extract_obb_files(input_path, workspace.obb_dir, plan.obb_files)
        workspace.state.obb_files = [str(p.name) for p in extracted]

    # Update workspace state
    if plan.package_name:
        workspace.state.package_name = plan.package_name

    workspace.state.original_format = plan.format.value
    workspace.state.mark_complete("init")
    workspace.save_state()

    return target_apk


def run_stage0(workspace: Workspace) -> Path:
    """
    Run Stage 0: Input normalization.

    Args:
        workspace: The workspace to operate in.

    Returns:
        Path to the normalized target.apk.
    """
    input_path = Path(workspace.state.apk_path)
    plan = route_input(input_path, workspace.input_dir)
    return execute_plan(plan, workspace)
