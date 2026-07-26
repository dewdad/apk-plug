# Stage 5 — Post-Remediation Validation

Driven by `apk-plug validate`. A static fix might break the app or miss a
runtime-loaded payload, so prove the fix held both statically and dynamically.

## Static re-scan

```bash
FIXED="build/signed/fixed-signed.apk"

# Re-run the fast scanners on the REBUILT APK
mobsfscan decompile/smali/ --json -o reports/post-fix/mobsfscan.json
apktriage "$FIXED" --out reports/post-fix/apktriage/
quark -a "$FIXED" -s -o reports/post-fix/quark/

# Permission diff: original vs fixed (fail if the fixed set is BROADER)
diff <(aapt dump permissions input/target.apk | sort) \
     <(aapt dump permissions "$FIXED" | sort)

# Confirm no C2 strings remain
grep -rE "(http|https|tcp|mqtt)://" decompile/smali/assets/ decompile/smali/res/ 2>/dev/null \
  | grep -v "schemas.android.com" | grep -v "www.w3.org"
```

`apk-plug validate` exits non-zero if the fixed permission set is unexpectedly
broader than the original, or if residual C2 strings survive.

## Dynamic checks (Frida / Objection)

```bash
adb install -r build/signed/fixed-signed.apk
objection -g com.target.app explore
#   → android sslpinning disable       (verify no pinning remains)
#   → android filesystem ls            (check for dropped payloads)
#   → android hooking list activities  (verify no hidden activities)
#   → android hooking watch class com.evil.Payload   (confirm it is dead)

# Or raw Frida for custom checks:
frida -U -f com.target.app -l validate_fix.js
```

Dynamic validation confirms the smali edit neutralized behavior at runtime,
catches DEX loaded from `assets/` at runtime that static analysis missed, and
verifies the app still functions (no crash-on-launch).

## OBB carry-through (critical false-negative guard)

If `input/obb/` is non-empty, the app expects its expansion files at
`Android/obb/<pkg>/`. **Push them before the smoke test** or the app crashes on
launch and you record a false negative:

```bash
adb push input/obb/main.<ver>.<pkg>.obb /sdcard/Android/obb/<pkg>/
```

`apk-plug validate` emits the exact `adb push <obb> /sdcard/Android/obb/<pkg>/`
commands (and runs them when a device is attached) for every file in
`input/obb/`, using the package name recorded in Stage 0.

## Companion-data warnings (AAB — false "app works" guard)

The rebuilt APK is a **universal** APK, so any AAB companion data that is not in
the universal APK is also not in the rebuild:

- **on-demand / conditional feature modules** (`fusing=false`) — their code is
  absent from the rebuilt artifact; a remediation edit to such a module cannot be
  carried through, and any feature depending on it will be unavailable when
  sideloaded (no Play `SplitInstallManager` to fetch it).
- **fast-follow / on-demand asset packs** — the sideloaded app tries to fetch
  them from Play at runtime and may fail or misbehave.

`apk-plug validate` emits a `companion_warnings` entry for each such module/pack
(from workspace state) so a passing smoke test is not mistaken for full coverage.
`apk-plug verify --stage 4` also surfaces the same limitation as a non-failing
`companion_rebuild_coverage` advisory.

## Gate

`apk-plug verify --stage 5` — but the true acceptance is: re-scan shows the
threat gone, permission set not broader, and the app launches (with OBBs pushed).
