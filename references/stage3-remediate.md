# Stage 3 — Remediate (Manual, Guided)

## ⚠️ Legal gate (restated)

**Only operate on APKs you own, have explicit written authorization to modify, or
are analyzing in an isolated research lab.** Remediation modifies and re-signs a
third-party binary — the point of no return. Redistribution may violate
copyright, the CFAA, or DMCA §1201. Confirm lawful authorization for THIS APK
before editing. If unsure whether the work is legal, stop and ask.

## This stage is NOT wrapped by the CLI

`apk-plug` halts after `scan`. **There is no `fix`/`patch`/`remediate`
subcommand.** Remediation is **inherently manual** — no tool auto-patches
malicious logic. You read `threat-report.json`, reason about intent, and edit the
apktool smali/resource output yourself. LLMs assist as *reasoning aids* (explain
smali, propose patches) via [../assets/llm-analysis-prompt.md](../assets/llm-analysis-prompt.md),
never as auto-fixers. When done, resume with `apk-plug rebuild`.

## Common remediation patterns

| Threat | Location | Fix |
| --- | --- | --- |
| Malicious `<service>` / `<receiver>` | `AndroidManifest.xml` | delete the XML element |
| Over-broad `<uses-permission>` (e.g. `READ_SMS` on a calculator) | `AndroidManifest.xml` | delete the line |
| Hardcoded C2 / exfil URL | `smali/**/*.smali` or `assets/` | replace the string with `""` or `http://127.0.0.1` via `const-string` |
| Injected class (`com.evil.Payload`) | `smali/com/evil/Payload.smali` | delete file; remove references in callers |
| SMS/Call interception method | smali method body | gut it: replace body with `return-void` |
| Native `.so` exfil library | `lib/arm64-v8a/libevil.so` | delete file; remove the `System.loadLibrary("evil")` call in smali |
| Obfuscated dex payload | `assets/payload.dex` | delete; remove dynamic-loading code |

**Prefer `return-void` / `const-string ""` over deletion** to avoid smali
verification errors on rebuild.

Copy-paste smali snippets per culprit class (void/object/boolean neutralization,
permission removal, exported-component guarding, C2 repointing, tracker stripping,
dex-loader blocking) are in [remediation-recipes.md](remediation-recipes.md).

## Workflow

```bash
# Side-by-side: jadx-gui decompile/java (understand) | editor on decompile/smali (edit)

# Example: neutralize a malicious BroadcastReceiver
grep -n "receiver" decompile/smali/AndroidManifest.xml   # 1. find it
# 2. remove the <receiver> block from AndroidManifest.xml
# 3. gut the smali class: replace method bodies with return-void
# 4. remove any <uses-permission> only that receiver used
grep -r "Lcom/evil/Payload;" decompile/smali/            # 5. find dangling refs → nop/remove each invoke
```

## Certificate-pinning removal (specialized)

The single most common modification. Choose the tool by need:

| Criteria | **apk-mitm** | **android-unpinner** |
| --- | --- | --- |
| Permanent modification (rebuilt APK) | ✅ yes | ❌ runtime only |
| Works without a device | ✅ yes | ❌ needs ADB |
| Handles native/Flutter pinning | ❌ no | ✅ yes (Frida hooks) |
| Handles XAPK/splits | ⚠️ partial | ✅ yes |
| Invasiveness | high (rewrites smali) | low (manifest only) |
| Use when | you need a permanently patched APK | you need to inspect traffic from a complex app |

```bash
npx apk-mitm input/target.apk        # decode → patch NSC + pinning → rebuild → debug-sign
# or, runtime bypass via Frida Gadget (needs a connected device):
android-unpinner all input/target.apk
```

## Verification gate

`apk-plug verify --stage 3`:

- [ ] every identified Stage-2 threat has a corresponding edit
- [ ] `grep -r` confirms no dangling references to deleted classes
- [ ] `AndroidManifest.xml` passes `xmllint --noout`
- [ ] no `.smali` syntax errors (apktool build catches these)
- [ ] patch log written: `patches/CHANGELOG.md` lists every edit with rationale
