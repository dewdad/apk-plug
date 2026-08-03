# Detection Heuristics — Reading `threat-report.json`

Deep-dive companion to [stage2-scan.md](stage2-scan.md). Stage 2 produces one
schema-validated `threat-report.json`; this file is the catalog for turning that
report into a triage decision. Classify each finding as **malicious /
suspicious / benign** before touching code in Stage 3
([remediation-recipes.md](remediation-recipes.md)).

## Table of contents

- [Dangerous permissions](#dangerous-permissions)
- [Exported components](#exported-components)
- [Command-and-control (C2) indicators](#command-and-control-c2-indicators)
- [Source-level SAST findings (mobsfscan / semgrep)](#source-level-sast-findings-mobsfscan--semgrep)
- [Dynamic code loading and reflection](#dynamic-code-loading-and-reflection)
- [Trackers and adware SDKs](#trackers-and-adware-sdks)
- [Packers and obfuscation](#packers-and-obfuscation)
- [Native libraries](#native-libraries)
- [MITRE ATT&CK Mobile mapping](#mitre-attck-mobile-mapping)
- [From report to triage](#from-report-to-triage)

## Dangerous permissions

`threat-report.json.permissions` lists every requested permission. Flag those
that do not match the app's stated function. High-risk (MobSF marks these):
`READ_SMS`, `RECEIVE_SMS`, `SEND_SMS`, `READ_CONTACTS`, `READ_CALL_LOG`,
`PROCESS_OUTGOING_CALLS`, `ACCESS_FINE_LOCATION`, `RECORD_AUDIO`, `CAMERA`,
`READ_PHONE_STATE`, `SYSTEM_ALERT_WINDOW` (overlay),
`BIND_ACCESSIBILITY_SERVICE` (input capture), `REQUEST_INSTALL_PACKAGES`,
`RECEIVE_BOOT_COMPLETED` (persistence).

A flashlight app requesting `READ_SMS` + `SEND_SMS` = malicious. A messaging app
requesting them = benign. Judge against declared purpose.

## Exported components

`android:exported="true"` on `Activity`/`Service`/`Receiver`/`Provider` without a
permission guard = attack surface (surfaced in `threat-report.json.components`).
Malware often adds an exported receiver on `BOOT_COMPLETED` or `SMS_RECEIVED` for
persistence and interception. Cross-check each exported component's smali in
`decompile/smali/` for the actual behavior.

## Command-and-control (C2) indicators

`threat-report.json.urls` holds every endpoint the scanners extracted (APKLeaks
and MobSF populate it). Cross-check against the decoded output as a fast manual
pass:

```bash
grep -rEi 'https?://|[0-9]{1,3}(\.[0-9]{1,3}){3}' \
  decompile/smali/assets decompile/smali/res decompile/smali/smali* \
  | grep -vE 'schemas.android.com|w3.org|apache.org|google.com/android'
```

Flag: raw IPs, dynamic-DNS domains, base64 blobs decoding to URLs, Telegram bot
tokens, pastebin/raw gist URLs, non-TLS `http://` exfil. APKLeaks and MobSF
surface these automatically; the grep is a fast manual cross-check. Each hit is a
location to cross-reference in smali/assets and classify — APKLeaks over-reports
(SDK/analytics/CDN hosts are benign), so triage against the app's declared
function, same as permissions.

## Source-level SAST findings (mobsfscan / semgrep)

MobSF/apktriage/quark reason about the APK binary. **mobsfscan** and **semgrep**
(with the MASTG-derived Android ruleset) reason about the decompiled Java from
Stage 1 (`decompile/java/`), catching code-level defects the binary scanners miss
and emitting SARIF that `apk-plug scan` folds into `threat-report.json`.

Reading the output:

- Each SARIF result has a `ruleId`, a `level` (error/warning/note), and a
  `region` pinning `file:line` in the jadx tree — map that back to the
  corresponding smali in `decompile/smali/` for the heal.
- High-signal mobsfscan rules: hardcoded secrets/keys, insecure `WebView`
  (`setJavaScriptEnabled` + `addJavascriptInterface`), cleartext/`http://`
  traffic, weak crypto (ECB, static IV), exported components without permission,
  insecure `BroadcastReceiver`/`PendingIntent`.
- semgrep's value is **taint tracking**: it flags when untrusted input reaches a
  sink (`Runtime.exec`, `loadUrl`, file writes), i.e. an actual data-flow, not
  just a pattern hit.
- Both over-report on bundled libraries. Use the ruleset's `.semgrepignore` /
  exclude known-SDK paths to cut false positives before triage.

These are **vulnerability/quality** findings, not malware-presence proof. A
hardcoded key in the app's own code is a fix candidate; the same pattern inside a
benign vendored SDK is usually noise.

## Dynamic code loading and reflection

High-signal for malware hiding payloads. Grep `decompile/smali/` for:

- `DexClassLoader`, `PathClassLoader`, `InMemoryDexClassLoader` — loads code at
  runtime (often decrypted from assets).
- `Ldalvik/system/` dex loading APIs.
- `java/lang/reflect/Method;->invoke` combined with string decryption — hides real
  call targets.
- `Landroid/content/pm/PackageManager;->setComponentEnabledSetting` —
  hides/reveals icons.

A benign app rarely loads dex from `assets/`. Trace where the loaded file comes
from. Note: DEX smuggled in the APK's own `assets/` is also caught by the Stage 2
**companion-data scan** (see [stage2-scan.md](stage2-scan.md#companion-data-scan-blind-spots-outside-the-target-apk)).

## Trackers and adware SDKs

MobSF lists known trackers (Exodus dataset). Adware signatures: aggressive ad SDKs
(`com.airpush`, `com.startapp`, `com.adcolony` when undisclosed), out-of-app
overlay ads via `SYSTEM_ALERT_WINDOW`, ads shown from background services. Remove
the SDK package + its manifest registrations if it is injected/undisclosed
(recipe: [remediation-recipes.md](remediation-recipes.md#strip-an-injected-trackeradware-sdk)).

## Packers and obfuscation

APKiD output (in `threat-report.json`) identifies packers (e.g. `Jiagu`,
`Bangcle`, `SecShell`, `ApkProtect`) and anti-analysis (`anti_vm`, `anti_debug`,
`anti_frida`). A packer defeats static analysis: the real `classes.dex` is
decrypted at runtime. If packed:

1. Note it in the report.
2. Unpack (FRIDA-DEXDump / BlackDex) then re-run `apk-plug decompile` +
   `apk-plug scan`, or pivot to dynamic analysis (MobSF dynamic / Frida).
3. Heavy obfuscation alone is not proof of malware, but packed +
   dangerous-permission + C2 = strong signal.

## Native libraries

`.so` files in `lib/` (extracted to `decompile/native/`). Flag imports of
`ptrace` (anti-debug), `dlopen`/`system`/`exec` (command execution), `JNI_OnLoad`
doing decryption. LIEF (via apktriage) parses the headers/imports for a fast
triage pass.

Native payloads survive smali edits — a blind spot for the rest of the pipeline.
When LIEF flags suspicious imports, or smali contains `System.loadLibrary("x")`
whose behavior you cannot account for, analyze the library in Ghidra +
JNIAnalyzer — full workflow in [stage1.5-native.md](stage1.5-native.md).

Look for: network calls (socket/HTTP), file I/O into app-private dirs, crypto
routines decrypting a bundled blob, and `dlopen`/`dexload` of a second-stage
payload. Correlate exported native functions with the `native` method
declarations JNIAnalyzer recovered in the Java view. Removing a malicious `.so`
usually breaks the app (the loader call and JNI bindings remain) — prefer
neutralizing the smali call site over deleting the library, and re-test on a
device.

## MITRE ATT&CK Mobile mapping

apktriage maps findings to techniques (`threat-report.json.mitre_techniques`).
Common malicious ones:

- T1636 Protected User Data (contacts/SMS/calendar/location access)
- T1430 Location Tracking
- T1512 Video/Camera Capture, T1429 Audio Capture
- T1409 Stored Application Data access
- T1407 Download New Code at Runtime (dynamic loading)
- T1541 Foreground Persistence, T1624 Event Triggered Execution (BOOT_COMPLETED)
- T1521 Encrypted Channel (C2)

Use the mapping to prioritize: data-theft + persistence + C2 together =
trojan/spyware.

## From report to triage

`apk-plug scan` does the mechanical collection for you: it merges every scanner
output (MobSF JSON, quark score, semgrep/mobsfscan SARIF, APKLeaks JSON, APKiD
text, apktriage YARA/MITRE, Ghidra native, companion-data scan) plus the decoded
manifest (dangerous permissions + unguarded exported components) into one
normalized, deduped, severity-ranked `threat-report.json` — with `components`,
`urls`, `permissions`, `mitre_techniques`, per-tool `findings[]` (each with
`source`, `severity`, `location`, `message`), and an `aggregate_risk` block.

Your job is the judgment the tooling cannot do: classify each finding
(**malicious / suspicious / benign**) using the catalog above, then map every
malicious item to a recipe in [remediation-recipes.md](remediation-recipes.md).
Re-run `apk-plug scan` after each re-scan so the report reflects current findings.
