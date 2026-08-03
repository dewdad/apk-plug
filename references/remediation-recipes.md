# Remediation Recipes — Healing the Culprit Code

Deep-dive companion to [stage3-remediate.md](stage3-remediate.md): exact, copy-paste
edits per culprit class. Stage 3 is **manual** — `apk-plug` has no
`fix`/`patch`/`remediate` subcommand. Edit only inside `decompile/smali/`. Prefer
minimal, surgical neutralization over deletion — deleting a referenced component
crashes the app.

## Table of contents

- [Golden rules](#golden-rules)
- [Remove a dangerous permission](#remove-a-dangerous-permission)
- [Remove or guard an exported component](#remove-or-guard-an-exported-component)
- [Neutralize a malicious method](#neutralize-a-malicious-method)
- [Remove a hardcoded C2 endpoint](#remove-a-hardcoded-c2-endpoint)
- [Strip an injected tracker/adware SDK](#strip-an-injected-trackeradware-sdk)
- [Block dynamic dex loading](#block-dynamic-dex-loading)
- [After every edit](#after-every-edit)

## Golden rules

- One change at a time, then rebuild-test. Batching edits makes `apktool b`
  failures impossible to localize.
- Neutralize > delete. Replace a method body with a safe return rather than
  removing call sites.
- Keep a diff. `cp -r decompile/smali decompile/smali.bak` before the first edit
  so you can compare and revert. Log every edit with rationale in
  `patches/CHANGELOG.md` (required by the Stage 3 gate).
- Never edit jadx Java output (`decompile/java/`) — it is not recompilable. Edit
  smali; read Java only to understand.

## Remove a dangerous permission

In `decompile/smali/AndroidManifest.xml`, delete the line:

```xml
<uses-permission android:name="android.permission.READ_SMS"/>
```

If code still calls the guarded API after removal, that call throws
`SecurityException` at runtime — either neutralize the calling method too, or wrap
the intent. Confirm the app's core features do not legitimately need the
permission first.

## Remove or guard an exported component

Malicious persistence receiver in the manifest:

```xml
<receiver android:name=".BootReceiver" android:exported="true">
  <intent-filter><action android:name="android.intent.action.BOOT_COMPLETED"/></intent-filter>
</receiver>
```

Options, least invasive first:
1. Set `android:exported="false"` if it must exist but should not be externally
   triggerable.
2. Remove the `<intent-filter>` to stop auto-trigger while keeping the class.
3. Delete the whole `<receiver>` only if no code references it (grep smali for the
   class name first).

## Neutralize a malicious method

Find the method in its `.smali` file. Replace the body with a safe return matching
its return type. Keep `.locals 0` (or adjust) so the verifier passes.

Void method:
```smali
.method public exfiltrateContacts()V
    .locals 0
    return-void
.end method
```

Object-returning method:
```smali
.method public stealSms()Ljava/lang/String;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method
```

Boolean:
```smali
.method public isPayloadReady()Z
    .locals 1
    const/4 v0, 0x0
    return v0
.end method
```

This preserves the method signature (callers still link) while removing behavior.
Adjust `.locals` to the number of registers the new body uses.

## Remove a hardcoded C2 endpoint

If in a resource/asset: edit `decompile/smali/res/values/strings.xml` or the file
under `decompile/smali/assets/` and blank or repoint the URL. If in smali as a
`const-string`:

```smali
const-string v0, "http://malicious-c2.example/collect"
```

Repoint to a sink that does nothing, e.g. `const-string v0, "http://127.0.0.1/"`,
or neutralize the sending method (above). Do not just delete the `const-string` —
the following `invoke` expects the register populated.

## Strip an injected tracker/adware SDK

1. Delete the SDK's smali package dir:
   `rm -rf decompile/smali/smali/com/airpush`.
2. Remove its manifest registrations (`<service>`, `<receiver>`, `<activity>`,
   `<meta-data>`).
3. Grep for residual references (`grep -r "Lcom/airpush" decompile/smali/`) and
   neutralize any calling methods, else rebuild fails on unresolved refs.

## Block dynamic dex loading

If a `DexClassLoader` loads a decrypted payload from `assets/`, neutralize the
loader method (return null) AND delete the payload file from
`decompile/smali/assets/`. Verify no legitimate feature depends on it (many
packers use this legitimately — confirm it is the malicious path via the
C2/permission correlation in
[detection-heuristics.md](detection-heuristics.md#dynamic-code-loading-and-reflection)).

## After every edit

Resume the CLI to rebuild and gate the change:

```bash
apk-plug rebuild --keystore <path>     # apktool b → zipalign → apksigner (enforced order)
apk-plug verify --stage 3              # every threat edited, no dangling refs, manifest valid
apk-plug verify --stage 4              # build exit 0, aligned, apksigner verify valid
```

If `apktool b` fails, the edit broke smali/resource syntax — the error names the
file + line; fix it and rebuild. Once it builds, sign, then re-scan with
`apk-plug validate` (Stage 5) to confirm the specific finding is gone. Repeat per
finding. Sanitization is not done until the re-scan is clean AND the app still
launches.
