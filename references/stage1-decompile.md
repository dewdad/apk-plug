# Stage 1 — Decompile

Driven by `apk-plug decompile`. Produces two parallel views of `input/target.apk`:

- **Java (jadx)** — human-readable, for *understanding* logic, tracing data
  flows, identifying C2 URLs and permission usage. Read-only reference.
- **Smali + resources (apktool)** — the *editable* representation you modify in
  Stage 3 and recompile in Stage 4.

## Commands

```bash
APK="input/target.apk"

# Java view (read-only reference)
jadx --deobf --show-bad-code -d decompile/java "$APK"

# Smali + resources (editable, round-trippable)
apktool d -f -o decompile/smali "$APK"

# Native libraries (feeds Stage 1.5 when present)
unzip -o "$APK" "lib/*" -d decompile/native/ 2>/dev/null || true
```

`apk-plug decompile` composes exactly these calls through the guarded runner.

## Verification gate

`apk-plug verify --stage 1`:

| Check | Pass criteria |
| --- | --- |
| `decompile/java/sources/` contains `.java` files | ≥ 1 file |
| `decompile/smali/AndroidManifest.xml` is valid XML | `xmllint --noout` returns 0 |
| `decompile/smali/smali*/` contains `.smali` files | ≥ 1 file |
| No apktool error about unsupported API level | exit code 0 |

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `jadx` **OOM** on large APK | `jadx -Xmx4g --threads-count 4 ...` |
| `apktool d` fails on **resources.arsc** | update apktool; if persistent, `apktool d --no-res` (loses resource editing) |
| **Obfuscated** single-letter classes | `--deobf` in jadx; in smali rely on cross-references (`grep -r "invoke"`) |
| **Split** APKs / App Bundle reached Stage 1 unmerged | go back to Stage 0 — merge with APKEditor (or `bundletool ... --mode=universal` for `.aab`) first |
| DEX jadx cannot parse | legacy `dex2jar` fallback, then re-open in jadx |

## Next

If `decompile/native/` contains any `.so`, proceed to
[stage1.5-native.md](stage1.5-native.md) before scanning. Otherwise go straight
to [stage2-scan.md](stage2-scan.md).
