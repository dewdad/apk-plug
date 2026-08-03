# Remediation Recipes — Healing the Culprit Code

Deep-dive companion to [stage3-remediate.md](stage3-remediate.md): exact, copy-paste
edits per culprit class. Stage 3 is **manual** — `apk-plug` has no
`fix`/`patch`/`remediate` subcommand. Edit only inside `decompile/smali/`.

**Two remediation postures — pick by culprit class:**

- **Surgical (functional / malware code the app links against):** prefer minimal
  neutralization over deletion — gutting a referenced method or blanking a
  `const-string` keeps callers linking; deleting a referenced component crashes the
  app. Use for C2 senders, interception methods, native loaders, exported
  components the app actually uses.
- **Aggressive (ad SDKs, trackers/analytics, over-broad permissions):** strip by
  **default**, not only when "confirmed malicious". Ad and tracking code is
  non-essential to the app's stated function, so the bar for removal is low: rip
  the SDK package, delete its manifest registrations, cut the permissions it needs,
  and neutralize the thin glue left behind. The only constraint is rebuildability —
  leave no dangling `invoke` to a class you deleted (see the recipes below for how
  to keep it building).

## Table of contents

- [Golden rules](#golden-rules)
- [Remove a dangerous or ad/tracking permission](#remove-a-dangerous-or-adtracking-permission)
- [Remove or guard an exported component](#remove-or-guard-an-exported-component)
- [Neutralize a malicious method](#neutralize-a-malicious-method)
- [Remove a hardcoded C2 endpoint](#remove-a-hardcoded-c2-endpoint)
- [Strip ad SDKs and trackers (aggressive)](#strip-ad-sdks-and-trackers-aggressive)
- [Block dynamic dex loading](#block-dynamic-dex-loading)
- [After every edit](#after-every-edit)

## Golden rules

- One change at a time, then rebuild-test. Batching edits makes `apktool b`
  failures impossible to localize.
- Neutralize > delete **for functional/malware code**. Replace a method body with a
  safe return rather than removing call sites.
- **Strip ad SDKs, trackers, and over-broad permissions aggressively.** They are
  never load-bearing for the app's real feature, so remove them by default rather
  than neutralizing in place. Rip the whole SDK package + manifest entries + the
  permissions it pulled in, then neutralize only the residual glue that would
  otherwise leave a dangling reference.
- Keep a diff. `cp -r decompile/smali decompile/smali.bak` before the first edit
  so you can compare and revert. Log every edit with rationale in
  `patches/CHANGELOG.md` (required by the Stage 3 gate).
- Never edit jadx Java output (`decompile/java/`) — it is not recompilable. Edit
  smali; read Java only to understand.

## Remove a dangerous or ad/tracking permission

In `decompile/smali/AndroidManifest.xml`, delete the line:

```xml
<uses-permission android:name="android.permission.READ_SMS"/>
```

If code still calls the guarded API after removal, that call throws
`SecurityException` at runtime — either neutralize the calling method too, or wrap
the intent.

**Default to removal for over-broad and ad/tracking permissions.** Do not wait for
"confirmed malicious" — if a permission is not required by the app's stated core
feature, strip it. Reinstate one only if the smoke test in Stage 5 proves a
legitimate feature broke.

Strip these aggressively unless the app's declared purpose obviously needs them:

```xml
<!-- Advertising / attribution identifiers (Android 12L+/13+ ad ID + Privacy Sandbox) -->
<uses-permission android:name="com.google.android.gms.permission.AD_ID"/>
<uses-permission android:name="android.permission.ACCESS_ADSERVICES_AD_ID"/>
<uses-permission android:name="android.permission.ACCESS_ADSERVICES_ATTRIBUTION"/>
<uses-permission android:name="android.permission.ACCESS_ADSERVICES_TOPICS"/>
<!-- Install-referrer harvesting (attribution SDKs) -->
<uses-permission android:name="com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE"/>
<!-- Overlay ads -->
<uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
<!-- Ad-targeting location / device fingerprinting when not a core feature -->
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
<uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<uses-permission android:name="android.permission.GET_ACCOUNTS"/>
<!-- Background ad/tracker persistence -->
<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
```

Removing `AD_ID` / `ACCESS_ADSERVICES_*` and the install-referrer service binding is
safe: they only feed ad attribution and are not linked against by app feature code,
so they will not throw `SecurityException`. For `SYSTEM_ALERT_WINDOW`,
location, `READ_PHONE_STATE`, and `GET_ACCOUNTS`, pair the removal with stripping
the ad SDK that requested them (below) and gut any residual caller, so the guarded
API is never reached.

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

## Strip ad SDKs and trackers (aggressive)

Ad and tracking SDKs are non-essential to the app's real function — remove them by
**default**, not only when injected/undisclosed. Work one SDK at a time so a
rebuild failure is localizable.

Known ad / tracker / attribution package roots to strip (grep smali for each,
`Lcom/…`):

| Class | Package roots (smali path `com/…`) |
| --- | --- |
| Ad networks / mediation | `com.google.android.gms.ads`, `com.google.ads`, `com.facebook.ads`, `com.applovin`, `com.unity3d.ads`, `com.unity3d.services`, `com.ironsource`, `com.mbridge`, `com.mintegral`, `com.vungle`, `com.chartboost`, `com.adcolony`, `com.inmobi`, `com.tapjoy`, `com.fyber`, `com.smaato`, `com.appodeal`, `com.mopub`, `com.startapp`, `com.airpush`, `com.pangle`, `com.bytedance.sdk`, `com.yandex.mobile.ads`, `com.my.target` |
| Analytics / attribution / trackers | `com.appsflyer`, `com.adjust.sdk`, `io.branch`, `com.flurry`, `com.amplitude`, `com.mixpanel`, `com.segment.analytics`, `com.kochava`, `com.singular`, `com.onesignal`, `com.comscore` |

Cross-reference MobSF's Exodus tracker list in `threat-report.json` — anything it
flags that is not the app's own analytics gets the same treatment.

Per SDK:

1. Delete the SDK's smali package dir(s):
   `rm -rf decompile/smali/smali*/com/applovin`.
2. Remove its manifest registrations — `<service>`, `<receiver>`, `<activity>`
   (ad/interstitial/offerwall activities), `<provider>` (many ad SDKs ship an
   init `ContentProvider`), and `<meta-data>` (app IDs / API keys such as
   `com.google.android.gms.ads.APPLICATION_ID`, `applovin.sdk.key`).
3. Remove the permissions that SDK pulled in (see the ad/tracking permission list
   above) if no other component needs them.
4. Grep for residual references (`grep -rE "Lcom/applovin|Lcom/appsflyer" decompile/smali/`)
   and neutralize every calling method — gut ad-load/show calls to `return-void`,
   ad-getter methods to `const/4 v0, 0x0` + `return-object v0` — else rebuild fails
   on unresolved refs. A leftover `invoke-static {...}, Lcom/applovin/...` in the
   app's own code must be removed or nopped, not left dangling.
5. Delete ad/tracker init calls wired into `Application.onCreate` / the launcher
   `Activity` so the stripped SDK is never initialized.

Prefer full package deletion over in-place neutralization here: an ad SDK is a
self-contained subtree, so removing it wholesale is cleaner than gutting hundreds
of its methods. Only the app's *own* glue code that referenced it needs the
`return-void` treatment.

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
