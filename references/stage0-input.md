# Stage 0 — Input Normalization

Driven by `apk-plug init <input>`. Modern apps rarely ship as a bare `.apk`:
Play Store distributes `.aab` App Bundles, and third-party stores ship split
sets as `.xapk` (APKPure), `.apkm` (APKMirror), `.apks`, or loose split zips.
Without normalization the pipeline silently fails on the majority of real apps.

## Format → tool routing (D14)

| Input | Tool | Command | Result |
| --- | --- | --- | --- |
| `.aab` | **bundletool** | `bundletool build-apks --bundle=input/app.aab --output=build/app.apks --mode=universal` then extract `universal.apk` | one universal `target.apk` |
| `.xapk` | **APKEditor** | `apkeditor m -i input/app.xapk -o input/target.apk` | one standalone `target.apk` |
| `.apkm` | **APKEditor** | `apkeditor m -i input/app.apkm -o input/target.apk` | one standalone `target.apk` |
| `.apks` / `.zip` / loose splits | **APKEditor** | `apkeditor m -i <in> -o input/target.apk` | one standalone `target.apk` |
| `.apk` | — | pass through | `target.apk` unchanged |

### Why not "bundletool does everything"

`bundletool` only understands Google's own `.aab` and `.apks` formats. It
**cannot read** `.xapk` or `.apkm` — those are third-party ZIP-of-splits
containers with their own `manifest.json`. Route them to **APKEditor**
(REAndroid, ~2K★, active, aapt-independent), the best-in-breed OSS merger for all
split formats. Reserve bundletool strictly for `.aab`.

```bash
# .aab path (bundletool)
bundletool build-apks --bundle=input/app.aab --output=build/app.apks --mode=universal
unzip -p build/app.apks universal.apk > input/target.apk

# .xapk / .apkm / .apks / split path (APKEditor)
apkeditor m -i input/app.xapk -o input/target.apk
```

## AAB companion data — feature modules & asset packs (D15)

`bundletool build-apks --mode=universal` produces the scannable/rebuildable
`target.apk`, but the universal APK **silently drops** data the `.aab` carries:

| Companion data in the `.aab` | In `universal.apk`? | Blind spot? |
| --- | --- | --- |
| base module, install-time DFMs (`dist:fusing dist:include="true"`), install-time asset packs, all ABI/density/language config splits | ✅ yes | no — scanned normally |
| on-demand / conditional DFM with `dist:fusing dist:include="false"` → DEX + `.so` | ❌ **dropped** | 🔴 code invisible to the universal-APK scan |
| fast-follow / on-demand PAD asset packs | ❌ **dropped** | 🔴 can smuggle DEX/ELF/scripts fetched post-install |

Everything dropped is still physically present in the `.aab` (a plain ZIP), so
`apk-plug init` **unzips the raw bundle into `input/aab-raw/`** and inventories
every module:

1. **Enumerate** each top-level module directory purely from ZIP structure
   (`base` / feature / asset pack, and whether it ships `dex/`, `lib/`, `assets/`).
2. **Refine delivery flags** (`dist:onDemand`, `dist:fusing`, asset-pack
   `deliveryType`) via `bundletool dump manifest --module=<name>`. If bundletool
   is unavailable the flags stay unknown and the module is scanned **anyway**
   (conservative default — never a silent skip).
3. **Record** feature modules and asset packs in workspace state with a computed
   `in_universal` flag, and backfill the base module's `package_name` (used by the
   Stage 5 OBB/asset push targets).

Stage 2 (`apk-plug scan`) then scans each dropped module's `dex/`+`lib/` and each
asset pack's `assets/` directly from `input/aab-raw/`. Stage 4's rebuild derives
from the universal APK, so edits to a `fusing=false` module cannot be carried
back — `apk-plug verify --stage 4` surfaces this as an advisory, and Stage 5 warns
that such modules/packs are unavailable in the sideloaded rebuilt APK.

> Classic OBB is **not** used by AABs (Play replaced it with Play Asset Delivery),
> so the AAB path does no OBB extraction — that stays exclusive to XAPK/APKM.

## OBB expansion files (`.obb`)

XAPK/APKM containers frequently bundle `.obb` expansion files. `apk-plug init`
extracts every `.obb` into `input/obb/` and records it in workspace state.
OBBs matter twice:

1. **Malware-hiding surface** — an `.obb` can smuggle a hidden `classes.dex` or
   payload. Stage 2 (`apk-plug scan`) unzips and scans each one.
2. **Runtime dependency** — the app reads its OBBs from
   `Android/obb/<pkg>/` at launch. Stage 5's smoke test must `adb push` them
   back or the app crashes on start (a functional false-negative). See
   [stage5-validate.md](stage5-validate.md).

If the XAPK carries a `manifest.json`, it is parsed for the package name and the
OBB list so the Stage 5 push targets the correct `<pkg>`.

## Gate

`apk-plug verify --stage 0` confirms a single normalized `input/target.apk`
exists, any expansion files landed in `input/obb/`, and (for `.aab` inputs) the
raw bundle was preserved in `input/aab-raw/` with feature modules and asset packs
recorded in workspace state.
