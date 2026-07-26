# Stage 4 — Rebuild, Align & Sign

Driven by `apk-plug rebuild`. The CLI enforces the order `apktool b` →
`zipalign` → `apksigner` **in code**, so signing an unaligned APK is structurally
unreachable.

## Commands (what the CLI runs)

```bash
# 1. Rebuild from edited smali
apktool b decompile/smali -o build/unsigned/fixed.apk

# 2. Zipalign — REQUIRED BEFORE sign (signing after aligning is fine; aligning
#    after signing invalidates the signature)
zipalign -f -p 4 build/unsigned/fixed.apk build/aligned/fixed-aligned.apk

# 3. Sign with apksigner (primary; v1 + v2 + v3 schemes)
apksigner sign \
  --ks keystores/my-release.jks \
  --ks-key-alias mykey \
  --v1-signing-enabled true \
  --v2-signing-enabled true \
  --v3-signing-enabled true \
  --out build/signed/fixed-signed.apk \
  build/aligned/fixed-aligned.apk

# 4. Verify
apksigner verify --verbose --print-certs build/signed/fixed-signed.apk
```

`apksigner` is the **primary** signer. `uber-apk-signer` is **optional**
convenience only (one-shot debug-keystore testing) and is stale (2023) — never
depend on it for a release artifact.

## Keystore management

```bash
keytool -genkeypair -v \
  -keystore keystores/my-release.jks \
  -keyalg RSA -keysize 4096 -validity 10000 -alias mykey
# keystores/ is gitignored — NEVER commit a keystore.
```

## Critical constraints

| Constraint | Explanation |
| --- | --- |
| **Cannot reuse the original signature** | you do not have the original dev's private key; the rebuilt APK has a **different signer** |
| No update-install over the store version | different signer → Android treats it as a different app; uninstall the original first or install fresh |
| v2/v3 required for Android 7+ | `jarsigner` (v1 only) is insufficient; always use `apksigner` |
| **zipalign BEFORE sign** | aligning after signing invalidates the signature — order matters |
| `--v1-signing-enabled true` | still needed for Android < 7 compatibility |

## Verification gate

`apk-plug verify --stage 4`:

- [ ] `apktool b` exits 0, no smali syntax errors
- [ ] `zipalign -c 4` confirms alignment
- [ ] `apksigner verify` shows a valid v2/v3 signature
- [ ] APK installs without `INSTALL_PARSE_FAILED`
- [ ] app launches, core functionality works (smoke test — see Stage 5)
