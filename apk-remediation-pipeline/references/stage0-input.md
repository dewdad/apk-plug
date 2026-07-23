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
exists and any expansion files landed in `input/obb/`.
