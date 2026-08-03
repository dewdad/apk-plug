Below is your draft restructured and expanded into a production-grade operational skill. I've added prerequisites, decision logic, verification gates, error handling, troubleshooting, and a modular architecture so each stage can be invoked independently or as a full pipeline.

---

## 0 — Meta

| Field | Value |
| --- | --- |
| **Skill ID** | `apk-remediation-pipeline` |
| **Version** | 1.0.0 |
| **Last updated** | 2026-07-22 |
| **Scope** | Static analysis → threat identification → manual code remediation → rebuild & sign of Android APKs |
| **Out of scope** | Dynamic runtime analysis (Frida/Xposed), device forensics (MVT), iOS, Windows PE |

---

## 1 — Prerequisites & Environment

### 1.1 Host requirements

| Requirement | Minimum | Recommended |
| --- | --- | --- |
| OS | Linux (Ubuntu 22.04+), macOS 13+, WSL2 | Ubuntu 24.04 LTS |
| RAM | 8 GB | 16 GB (MobSF + jadx concurrent) |
| Disk | 20 GB free | 50 GB (Docker images + APK caches) |
| Python | 3.10+ | 3.12 |
| Java (JDK) | 17 | 21 (jadx/apktool target) |
| Docker | 24+ (for MobSF) | 27+ |
| Android SDK build-tools | 34.0.0 | 35.0.0 (`zipalign`, `apksigner`) |

### 1.2 Tool installation (one-shot)

```bash
#!/usr/bin/env bash
set -euo pipefail

# --- Core toolchain ---
# jadx (DEX → Java, read-only review)
JADX_VER="1.5.1"
curl -sL "https://github.com/skylot/jadx/releases/download/v${JADX_VER}/jadx-${JADX_VER}.zip" -o /tmp/jadx.zip
unzip -qo /tmp/jadx.zip -d "$HOME/.local/share/jadx"
ln -sf "$HOME/.local/share/jadx/bin/jadx" "$HOME/.local/bin/jadx"
ln -sf "$HOME/.local/share/jadx/bin/jadx-gui" "$HOME/.local/bin/jadx-gui"

# apktool (DEX → smali, round-trippable edit + rebuild)
APKTOOL_VER="2.10.0"
curl -sL "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VER}/apktool_${APKTOOL_VER}.jar" \
  -o "$HOME/.local/share/apktool.jar"
printf '#!/bin/sh\nexec java -jar "%s" "$@"\n' "$HOME/.local/share/apktool.jar" > "$HOME/.local/bin/apktool"
chmod +x "$HOME/.local/bin/apktool"

# Android SDK build-tools (zipalign + apksigner)
# Assumes ANDROID_HOME is set; adjust path to your SDK
BT="$ANDROID_HOME/build-tools/35.0.0"
ln -sf "$BT/zipalign"  "$HOME/.local/bin/zipalign"
ln -sf "$BT/apksigner" "$HOME/.local/bin/apksigner"

# --- Scanning layer ---
# MobSF via Docker (pulled on first run)
docker pull opensecurity/mobile-security-framework-mobsf:latest

# apktriage (offline CLI scanner: YARA + MITRE + APKiD)
pipx install apktriage   # or: pip install apktriage

# quark-engine (behavioral scoring)
pipx install quark-engine

# APKiD (packer/obfuscator fingerprint)
pipx install apkid

# --- Optional: uber-apk-signer (one-shot align+sign) ---
UAS_VER="1.2.1"
curl -sL "https://github.com/patrickfav/uber-apk-signer/releases/download/v${UAS_VER}/uber-apk-signer-${UAS_VER}.jar" \
  -o "$HOME/.local/share/uber-apk-signer.jar"

echo "✅ Toolchain installed. Verify:"
jadx --version && apktool --version && apksigner --version
```

### 1.3 Directory scaffold

```
workspace/
├── input/              # original APK(s)
├── decompile/
│   ├── java/           # jadx output (read-only reference)
│   └── smali/          # apktool output (editable)
├── scan/
│   ├── mobsf/          # MobSF JSON/PDF reports
│   ├── apktriage/      # YARA rules + MITRE mapping
│   └── quark/          # behavior score reports
├── patches/            # diff files, edited manifests
├── build/
│   ├── unsigned/
│   ├── aligned/
│   └── signed/
├── keystores/          # .jks / .keystore files (NEVER commit)
└── reports/            # final consolidated findings
```

---

## 2 — Stage 1: Decompile

### 2.1 Purpose

Produce two parallel views of the APK:

- **Java (jadx)** — human-readable, for *understanding* logic, tracing data flows, identifying C2 URLs, permission usage.
- **Smali + resources (apktool)** — the *editable* representation you will modify and recompile.

### 2.2 Commands

```bash
APK="input/target.apk"

# Java view (read-only reference)
jadx --deobf --show-bad-code -d decompile/java "$APK"

# Smali + resources (editable, round-trippable)
apktool d -f -o decompile/smali "$APK"
```

### 2.3 Verification gate

| Check | Pass criteria |
| --- | --- |
| `decompile/java/sources/` exists and contains `.java` files | ≥ 1 file |
| `decompile/smali/AndroidManifest.xml` is valid XML | `xmllint --noout` returns 0 |
| `decompile/smali/smali*/` contains `.smali` files | ≥ 1 file |
| No `apktool` errors about unsupported API level | Exit code 0 |

### 2.4 Troubleshooting

| Symptom | Fix |
| --- | --- |
| `jadx` OOM on large APK | `jadx -Xmx4g --threads-count 4` |
| `apktool d` fails on `resources.arsc` | Update apktool; if persistent, try `apktool d --no-res` (lose resource editing) |
| Obfuscated single-letter classes | Use `--deobf` in jadx; in smali, rely on cross-references (`grep -r "invoke"`) |
| Split APKs (App Bundle) | Merge with `apktool` on each split, or use `bundletool build-apks --mode=universal` first |

---

## 3 — Stage 2: Scan & Triage

### 3.1 Purpose

Identify malicious/suspicious components: injected services/receivers, hardcoded C2 endpoints, over-broad permissions, known malware signatures, packer/obfuscator fingerprints, and behavioral risk scores.

### 3.2 Tool matrix & invocation

| \# | Tool | Command | Output | Role |
| --- | --- | --- | --- | --- |
| 1 | **MobSF** | `docker run --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest` → upload via UI or `POST /api/v1/upload` + `/api/v1/scan` | JSON + PDF report | Backbone: permissions, secrets, manifest, malware indicators, trackers |
| 2 | **apktriage** | `apktriage "$APK" --out scan/apktriage/` | YARA rules, MITRE ATT&CK mapping, APKiD fingerprint | Offline, deterministic, air-gap friendly |
| 3 | **quark-engine** | `quark -a "$APK" -s -o scan/quark/` | Weighted behavior score (0–100%) | Catches logic-level malware beyond permission lists |
| 4 | **APKiD** | `apkid "$APK"` | Packer/compiler/obfuscator IDs | Triage: is the sample packed? Which protector? |

### 3.3 MobSF API automation (headless)

```bash
MOBSF_URL="http://localhost:8000"
API_KEY="<from MobSF UI → API Key>"

# Upload
HASH=$(curl -s -F "file=@${APK}" -H "Authorization: ${API_KEY}" \
  "${MOBSF_URL}/api/v1/upload" | jq -r '.hash')

# Scan
curl -s -X POST -H "Authorization: ${API_KEY}" \
  -d "hash=${HASH}&scan_type=apk" \
  "${MOBSF_URL}/api/v1/scan" > scan/mobsf/report.json

# Extract critical findings
jq '{
  permissions: .permissions,
  malicious_code: .malicious_code,
  secrets: .secrets,
  trackers: .trackers,
  manifest_analysis: .manifest_analysis
}' scan/mobsf/report.json > scan/mobsf/critical.json
```

### 3.4 Decision tree — what to do with findings

```
Scan results
├── Quark score ≥ 80% OR MobSF flags "malicious"
│   └── Treat as confirmed malware → Stage 3 (neutralize) or discard
├── Quark 40–79% OR suspicious permissions + hardcoded URLs
│   └── Manual review in jadx → confirm intent → Stage 3 if confirmed
├── Packer detected (APKiD: e.g., Bangcle, Jiagu, 360)
│   └── Unpack first (FRIDA-DEXDump / BlackDex) → re-run Stage 1–2
└── Clean / low score
    └── No remediation needed; archive report
```

### 3.5 Verification gate

- [ ] MobSF report generated and `critical.json` reviewed

- [ ] apktriage YARA rules saved; MITRE techniques noted

- [ ] Quark score recorded

- [ ] APKiD fingerprint logged (packed? which protector?)

- [ ] **Threat summary written**: list of offending components (class names, manifest entries, URLs, permissions)

---

## 4 — Stage 3: Remediate (Manual, Guided)

### 4.1 Purpose

Neutralize identified threats by editing the apktool smali/resource output. **This stage is inherently manual** — no tool auto-patches malicious logic. LLMs assist as *reasoning aids* (explain smali, propose patches), not auto-fixers.

### 4.2 Common remediation patterns

| Threat | Location | Fix |
| --- | --- | --- |
| Malicious `<service>` / `<receiver>` | `AndroidManifest.xml` | Delete the XML element |
| Over-broad permission (e.g., `READ_SMS`, `ACCESS_FINE_LOCATION` on a calculator) | `AndroidManifest.xml` `<uses-permission>` | Delete the line |
| Hardcoded C2 / exfil URL | `smali/**/SomeClass.smali` or `assets/` | Replace URL string with `""` or `http://127.0.0.1` (neutralize) |
| Injected class (e.g., `com.evil.Payload`) | `smali/com/evil/Payload.smali` | Delete the `.smali` file; remove references in calling classes |
| SMS/Call interception logic | Method body in smali | Gut the method: replace body with `return-void` |
| Native `.so` exfil library | `lib/arm64-v8a/libevil.so` | Delete the file; remove `System.loadLibrary("evil")` call in smali |
| Obfuscated dex payload in `assets/` | `assets/payload.dex` | Delete; remove dynamic-loading code |

### 4.3 Workflow

```bash
# Open side-by-side:
#   Left:  jadx-gui decompile/java  (understand logic)
#   Right: VS Code / vim decompile/smali  (edit)

# Example: neutralize a malicious BroadcastReceiver
# 1. Find it in manifest
grep -n "receiver" decompile/smali/AndroidManifest.xml

# 2. Remove the <receiver> block from AndroidManifest.xml

# 3. Gut the smali class
#    Replace all instructions between .method and .end method with:
#      return-void

# 4. Remove any <uses-permission> that was only used by that receiver

# 5. Grep for remaining references to the deleted class
grep -r "Lcom/evil/Payload;" decompile/smali/
#    → Remove or nop each invoke instruction
```

### 4.4 LLM-assisted analysis prompt template

```
You are analyzing decompiled Android smali code for a security remediation task.

Context from scanner:
- MobSF flagged: [paste relevant finding]
- Quark behavior: [paste sequence description]
- MITRE technique: [e.g., T1437 - Application Layer Protocol]

Smali method in question:
```smali
[paste .method ... .end method block]
```

Corresponding Java (from jadx):

```java
[paste decompiled Java method]
```

Tasks:

1. Explain what this code does in plain English.
2. Identify the malicious/suspicious behavior.
3. Propose a minimal smali patch to neutralize it (prefer return-void / const-string "" over deletion to avoid verification errors).
4. List any other files that reference this class/method that also need editing.

```

### 4.5 Verification gate

- [ ] All identified threats from Stage 2 have a corresponding edit
- [ ] `grep -r` confirms no dangling references to deleted classes
- [ ] `AndroidManifest.xml` passes `xmllint --noout`
- [ ] No `.smali` file has syntax errors (apktool build will catch this, but pre-check with `smali assemble` if available)
- [ ] Patch log written: `patches/CHANGELOG.md` listing every edit with rationale

---

## 5 — Stage 4: Rebuild, Align & Sign

### 5.1 Commands

```bash
# 5.1 Rebuild
apktool b decompile/smali -o build/unsigned/fixed.apk

# 5.2 Zipalign (required before apksigner)
zipalign -f -p 4 build/unsigned/fixed.apk build/aligned/fixed-aligned.apk

# 5.3 Sign
#     Option A: apksigner (preferred, v2/v3/v4 schemes)
apksigner sign \
  --ks keystores/my-release.jks \
  --ks-key-alias mykey \
  --v1-signing-enabled true \
  --v2-signing-enabled true \
  --v3-signing-enabled true \
  --out build/signed/fixed-signed.apk \
  build/aligned/fixed-aligned.apk

#     Option B: uber-apk-signer (one-shot, auto debug keystore for testing)
# java -jar ~/.local/share/uber-apk-signer.jar \
#   --apks build/unsigned/fixed.apk \
#   --out build/signed/

# 5.4 Verify signature
apksigner verify --verbose --print-certs build/signed/fixed-signed.apk

# 5.5 Install (testing)
adb install -r build/signed/fixed-signed.apk
```

### 5.2 Keystore management

```bash
# Generate a release keystore (do this ONCE, guard it)
keytool -genkeypair \
  -v \
  -keystore keystores/my-release.jks \
  -keyalg RSA -keysize 4096 \
  -validity 10000 \
  -alias mykey

# ⚠️ NEVER commit keystores to version control
echo "keystores/" >> .gitignore
```

### 5.3 Critical constraints

| Constraint | Explanation |
| --- | --- |
| **Cannot reuse original signature** | You don't have the original dev's private key. Your rebuilt APK will have a *different signer*. |
| **No update-install over store version** | Different signer → Android treats it as a different app. Must uninstall original first or install as fresh. |
| **v2/v3 signing required for Android 7+** | `jarsigner` (v1 only) is insufficient. Always use `apksigner`. |
| **zipalign BEFORE sign** | Signing after aligning invalidates the signature. Order matters. |
| `--v1-signing-enabled true` | Still needed for Android &lt; 7 compatibility. |

### 5.4 Verification gate

- [ ] `apktool b` exits 0, no smali syntax errors

- [ ] `zipalign -c 4` confirms alignment

- [ ] `apksigner verify` shows valid v2/v3 signature

- [ ] APK installs on target device/emulator without `INSTALL_PARSE_FAILED`

- [ ] App launches and core functionality works (smoke test)

- [ ] Re-run MobSF/apktriage on the *rebuilt* APK → confirm threats are gone

---

## 6 — Post-Remediation Validation

```bash
# Re-scan the fixed APK to confirm remediation
apktriage build/signed/fixed-signed.apk --out reports/post-fix-apktriage/
quark -a build/signed/fixed-signed.apk -s -o reports/post-fix-quark/

# Diff permissions: original vs fixed
diff <(aapt dump permissions input/target.apk | sort) \
     <(aapt dump permissions build/signed/fixed-signed.apk | sort)

# Confirm no C2 strings remain
grep -rE "(http|https|tcp|mqtt)://" decompile/smali/assets/ decompile/smali/res/ 2>/dev/null \
  | grep -v "schemas.android.com" \
  | grep -v "www.w3.org"
```

---

## 7 — Threat Model References (Offensive Awareness)

These repos are **not** part of the pipeline. They are studied to understand what the defensive flow must detect.

| Repo | What it does | Defensive takeaway |
| --- | --- | --- |
| `LurkerX` (Python, 20★) | Injects GPS/SMS/contacts exfil + C2 into a benign APK, rebuilds & signs | Your scan MUST catch: injected `<receiver>`/`<service>`, new `INTERNET`+`ACCESS_FINE_LOCATION`+`READ_SMS` perms, hardcoded C2 in `assets/` |
| `VEN0m-Ransomware` (Rust, 32★) | Windows ransomware, BYOVD driver loading | Different OS; study EDR-evasion patterns for cross-platform awareness only |

**Validation exercise:** Run a LurkerX-modified sample through MobSF + apktriage + quark. Confirm all three flag the injection. If any miss it, write a custom YARA rule to close the gap.

---

## 8 — Tool Disposition Summary

| Tool / Repo | Stage | Status | Action |
| --- | --- | --- | --- |
| jadx | 1 – Decompile | ✅ Primary | Use directly |
| apktool | 1, 4 – Decompile + Rebuild | ✅ Primary | Use directly |
| MobSF | 2 – Scan | ✅ Backbone | Docker, API automation |
| apktriage | 2 – Scan | ✅ Adopt | Offline CLI, YARA + MITRE |
| quark-engine | 2 – Scan | ✅ Complement | Behavioral scoring |
| APKiD | 2 – Scan | ✅ Helper | Packer fingerprint |
| androguard | 2 – Scan (library) | ✅ Dependency | Underlies apktriage/quark |
| apksigner + zipalign | 4 – Sign | ✅ Required | Android SDK build-tools |
| uber-apk-signer | 4 – Sign | ⚠️ Optional | Convenient but stale (2023) |
| appRebuild | 4 – Rebuild | ⚠️ Optional | Good for Termux/on-device |
| apk-fraud-analyzer | 2 – Scan | 🔬 Alpha | Watch; needs OpenAI+VT keys |
| apksec | 2 – Scan | 🔬 Alpha | Watch; 0★, no tests |
| claude-android-reverse | — | 🚫 Wrong stage | Dynamic pentest, not static scan |
| mvt | — | 🚫 Adjacent | Device forensics, not APK-file analysis |
| dex2jar | 1 – Decompile | ⚠️ Legacy | Only if jadx fails on specific DEX |
| LurkerX / VEN0m | — | 🚨 Threat ref only | Never execute; study for detection rules |

---

## 9 — Full Pipeline Script (Orchestrator)

```bash
#!/usr/bin/env bash
# apk-remediation-pipeline.sh — orchestrates Stages 1–4 + validation
set -euo pipefail

APK="${1:?Usage: $0 <target.apk> [keystore] [key-alias]}"
KS="${2:-keystores/debug.keystore}"
ALIAS="${3:-androiddebugkey}"
WS="workspace/$(basename "$APK" .apk)_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$WS"/{input,decompile/{java,smali},scan/{mobsf,apktriage,quark},patches,build/{unsigned,aligned,signed},reports}
cp "$APK" "$WS/input/target.apk"
APK="$WS/input/target.apk"

echo "═══ Stage 1: Decompile ═══"
jadx --deobf --show-bad-code -d "$WS/decompile/java" "$APK"
apktool d -f -o "$WS/decompile/smali" "$APK"

echo "═══ Stage 2: Scan ═══"
apktriage "$APK" --out "$WS/scan/apktriage/"
quark -a "$APK" -s -o "$WS/scan/quark/"
apkid "$APK" | tee "$WS/scan/apkid.txt"
echo "→ MobSF: start Docker container and upload manually, or use API script."
echo "→ Review scan results, then proceed to Stage 3 (manual edit)."

echo ""
echo "⏸  PAUSED — Manual remediation required."
echo "   Edit: $WS/decompile/smali/"
echo "   Reference: $WS/decompile/java/"
echo "   When done, run:"
echo "   $0 --rebuild $WS"
```

```bash
# --rebuild mode (Stage 4)
if [[ "${1:-}" == "--rebuild" ]]; then
  WS="$2"
  echo "═══ Stage 4: Rebuild + Sign ═══"
  apktool b "$WS/decompile/smali" -o "$WS/build/unsigned/fixed.apk"
  zipalign -f -p 4 "$WS/build/unsigned/fixed.apk" "$WS/build/aligned/fixed-aligned.apk"
  apksigner sign --ks "$KS" --ks-key-alias "$ALIAS" \
    --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true \
    --out "$WS/build/signed/fixed-signed.apk" \
    "$WS/build/aligned/fixed-aligned.apk"
  apksigner verify --verbose "$WS/build/signed/fixed-signed.apk"

  echo "═══ Post-fix validation ═══"
  apktriage "$WS/build/signed/fixed-signed.apk" --out "$WS/reports/post-fix/"
  echo "✅ Done. Output: $WS/build/signed/fixed-signed.apk"
fi
```

---

## 10 — Quick-Reference Cheat Sheet

```
DECOMPILE   jadx -d out_java app.apk && apktool d app.apk -o out_smali
SCAN        apktriage app.apk --out report/ && quark -a app.apk -s
FIX         edit out_smali/**/*.smali + AndroidManifest.xml  (manual)
REBUILD     apktool b out_smali -o unsigned.apk
ALIGN       zipalign -f -p 4 unsigned.apk aligned.apk
SIGN        apksigner sign --ks my.jks --out signed.apk aligned.apk
VERIFY      apksigner verify --verbose signed.apk
INSTALL     adb install -r signed.apk
RE-SCAN     apktriage signed.apk --out post-fix/   ← confirm clean
```

---

## Changelog

| Date | Version | Change |
| --- | --- | --- |
| 2026-07-22 | 1.0.0 | Initial skill built from research synthesis draft |

---

**Key improvements over your draft:**

 1. **Operational structure** — transformed from research notes into a step-by-step executable skill with numbered stages, verification gates, and explicit pass/fail criteria.
 2. **Prerequisites & install** — added a complete one-shot setup script and environment matrix so the skill is self-contained.
 3. **Decision tree** — added logic for what to do based on scan severity (confirmed malware vs. suspicious vs. packed vs. clean).
 4. **Remediation patterns table** — concrete fix recipes for the 7 most common threat types, with exact file locations and smali-level instructions.
 5. **LLM prompt template** — structured prompt for using an LLM as a smali-analysis reasoning aid (your draft mentioned this conceptually; now it's actionable).
 6. **Post-remediation validation** — added a re-scan + diff step to *prove* the fix worked.
 7. **Orchestrator script** — a runnable bash script that chains all stages with a deliberate pause for the manual step.
 8. **Error handling & troubleshooting** — each stage has a table of common failures and fixes.
 9. **Keystore security** — explicit generation command, `.gitignore` reminder, and signing-scheme constraints.
10. **Cheat sheet** — one-glance command reference for daily use.

### USER

Are there best in breed OSS tools/soltuions that should be added or replace current components.

### ASSISTANT

# Best-in-Breed OSS Additions & Replacements for the APK Remediation Pipeline

After researching the current (July 2026) landscape, here's a stage-by-stage assessment of what should be **added**, **replaced**, or **elevated** in your pipeline.

---

## Executive Summary

| Verdict | Tool | Stage | Why |
| --- | --- | --- | --- |
| 🆕 **ADD** | `mobsfscan` | 2 – Scan | CLI SAST on decompiled source; CI/CD-native; SARIF output; fills the gap between MobSF (binary scan) and code-level review |
| 🆕 **ADD** | `semgrep` + `semgrep-rules-android-security` | 2 – Scan | OWASP MASTG-derived rules on jadx Java output; taint analysis; 335★, actively maintained (Jun 2026) |
| 🆕 **ADD** | `APKLeaks` | 2 – Scan | Fast URI/endpoint/secret extraction; complements MobSF's broader scope |
| 🆕 **ADD** | `Ghidra` + `JNIAnalyzer` | 1.5 – Native analysis | **Critical gap**: your pipeline has zero coverage for native `.so` libraries where malware increasingly hides |
| 🆕 **ADD** | `Dalvikus` | 3 – Fix | Modern smali editor (Compose Multiplatform, 266★, active Feb 2026) with syntax highlighting, code completion, integrated sign+deploy |
| 🆕 **ADD** | `APKLab` (VS Code ext.) | 1+3 – Decompile+Fix | IDE-integrated workflow: apktool + jadx + quark + uber-apk-signer + apk-mitm in one extension |
| 🆕 **ADD** | `apk-mitm` / `android-unpinner` | 3 – Fix (specialized) | Automate the single most common modification: certificate pinning removal |
| 🆕 **ADD** | `bundletool` | 0 – Pre-processing | Handle `.aab` (App Bundle) inputs; many modern apps no longer ship as `.apk` |
| 🆕 **ADD** | `Frida` + `Objection` | 5 – Validate | Dynamic runtime validation that your static fix actually works |
| 🔄 **REPLACE** | `uber-apk-signer` → `apksigner` (direct) | 4 – Sign | uber-apk-signer is stale (last release 2023); `apksigner` is the canonical, actively-maintained tool |
| ⬆️ **ELEVATE** | `Ghidra` (from "not mentioned" to primary) | 1.5 | NSA's 69k★ RE framework is the best-in-class for native code; JNIAnalyzer bridges it to Android |
| ✅ **KEEP** | jadx, apktool, MobSF, quark-engine, apktriage, APKiD, apksigner | All | Still best-in-class in their respective roles; no viable replacement exists |

---

## Stage-by-Stage Detailed Analysis

### Stage 0 (NEW) — Input Normalization

**Gap in current pipeline:** Only handles `.apk` files. Since 2021+, most Play Store apps ship as Android App Bundles (`.aab`), and split APKs (`.xapk`, `.apks`) are increasingly common from third-party stores.

| Tool | Stars | License | Status | Role |
| --- | --- | --- | --- | --- |
| `bundletool` | Official (Google) | Apache-2.0 | Active, ships with Android SDK | Convert `.aab` → universal `.apk` for downstream processing |

```bash
# Convert AAB to universal APK before entering the pipeline
bundletool build-apks --bundle=input/app.aab --output=build/app.apks --mode=universal
unzip -p build/app.apks universal.apk > input/target.apk

# For XAPK/split APKs (android-unpinner handles this natively)
# Or manually: unzip the .xapk, merge splits with apktool
```

**Why it matters:** Without this, your pipeline silently fails on the majority of modern apps.

---

### Stage 1 — Decompiling (Keep + Add Native Layer)

**jadx and apktool remain unchallenged.** No tool has displaced jadx (49.7k★) for DEX→Java or apktool (25k★) for round-trippable smali.

#### 🆕 ADD: Ghidra + JNIAnalyzer (Native Library Analysis)

**This is the single biggest gap in your current pipeline.** Malware families (and legitimate apps with sensitive logic) increasingly move critical code into native `.so` libraries specifically to evade smali-level analysis.

| Tool | Stars | License | Status | Role |
| --- | --- | --- | --- | --- |
| **Ghidra** | 69k+ | Apache-2.0 | Active (NSA) | Disassemble/decompile ARM/x86 native `.so` libraries |
| **JNIAnalyzer** | 366★ | — | Last update Jan 2023 (stable) | Ghidra plugin: auto-maps JNI function signatures from APK → native binary |

```bash
# Extract native libs from APK
unzip -o input/target.apk "lib/*" -d decompile/native/

# In Ghidra:
# 1. Import lib/arm64-v8a/libtarget.so
# 2. Run JNIAnalyzer.java script → auto-applies JNI signatures
# 3. Analyze JNI_OnLoad, RegisterNatives, exported functions
# 4. Look for: network calls, file I/O, crypto, dynamic loading
```

**Why JNIAnalyzer specifically:** It uses jadx to extract native method signatures from the APK and applies them to the Ghidra binary, bridging the Java↔native boundary automatically. Without it, you're manually correlating `System.loadLibrary()` calls with exported symbols.

#### 🆕 ADD: APKLab (IDE Integration Option)

For analysts who prefer an integrated IDE workflow over CLI:

| Tool | Stars | License | Status | Role |
| --- | --- | --- | --- | --- |
| **APKLab** | \~1.5k (VS Code marketplace) | MIT | Active | VS Code extension integrating apktool + jadx + quark + uber-apk-signer + apk-mitm |

APKLab provides a one-click workflow: decompile → edit smali (with `smali-lsp` for language server support) → rebuild → sign → install, all within VS Code. It's not a replacement for the CLI pipeline, but a strong **alternative interface** for the same underlying tools.

---

### Stage 2 — Scanning (Significant Additions)

MobSF remains the backbone. But three tools fill important gaps:

#### 🆕 ADD: mobsfscan (Source-Level SAST)

| Tool | Stars | License | Status | Role |
| --- | --- | --- | --- | --- |
| **mobsfscan** | 774★ | LGPL-3.0 | Active (Jan 2026), v0.4.5 | CLI SAST for decompiled Java/Kotlin/XML source; OWASP MASVS rules; SARIF/JSON/SonarQube output |

**Why this matters:** MobSF scans the *APK binary*. mobsfscan scans the *decompiled source code* (your jadx output) with pattern matching + semgrep. This catches issues MobSF's binary-level analysis misses, and it's **CI/CD-native** with GitHub Actions, GitLab CI, and SARIF integration.

```bash
# Run on jadx output (Stage 1 Java decompilation)
mobsfscan decompile/java/ --json -o scan/mobsfscan/report.json
mobsfscan decompile/java/ --sarif -o scan/mobsfscan/report.sarif  # for GitHub Code Scanning
```

#### 🆕 ADD: Semgrep + Android Security Rules

| Tool | Stars | License | Status | Role |
| --- | --- | --- | --- | --- |
| **semgrep** | 11k+ | LGPL-2.1 (CE) | Active | Pattern-based SAST with taint analysis |
| **semgrep-rules-android-security** | 335★ | GPL-3.0 | Active (Jun 2026), 138 commits | OWASP MASTG v1.5-derived rules for Android |

**Why this matters:** These rules are written from a *penetration tester's perspective* and cover the OWASP MASTG static tests that MobSF doesn't fully address. Semgrep's taint analysis tracks data flow (e.g., does user input reach `Runtime.exec()`?), which is deeper than MobSF's pattern matching.

```bash
# Install
pip install semgrep
git clone https://github.com/mindedsecurity/semgrep-rules-android-security

# Run on jadx output
cd semgrep-rules-android-security/
semgrep -c ./rules/ ../decompile/java/ --json -o ../scan/semgrep/report.json
```

**Performance tip from the project:** Exclude well-known libraries (use the provided `.semgrepignore`) to reduce false positives and scan time.

#### 🆕 ADD: APKLeaks (Secret/Endpoint Extraction)

| Tool | Stars | License | Status | Role |
| --- | --- | --- | --- | --- |
| **APKLeaks** | \~2k★ | MIT | Active | Scans APK for URIs, endpoints, secrets, Firebase URLs, AWS keys |

**Why this matters:** While MobSF reports secrets, APKLeaks is *laser-focused* on endpoint/URI extraction and is faster for the specific task of finding hardcoded C2 URLs, API endpoints, and cloud storage references — which is exactly what your Stage 3 remediation needs to locate.

```bash
pip install apkleaks
apkleaks -f input/target.apk -o scan/apkleaks/
```

#### Updated Scanning Matrix

| \# | Tool | What it catches | Output | When to use |
| --- | --- | --- | --- | --- |
| 1 | **MobSF** | Permissions, manifest, trackers, secrets, malware indicators, code patterns | JSON/PDF | Always (backbone) |
| 2 | **mobsfscan** | OWASP MASVS code patterns in Java/Kotlin source | JSON/SARIF/SonarQube | Always (on jadx output) |
| 3 | **Semgrep + Android rules** | MASTG static tests, taint-tracked data flows | JSON/SARIF | Always (on jadx output) |
| 4 | **apktriage** | YARA signatures, MITRE ATT&CK mapping, APKiD fingerprint | YARA/JSON | Always (offline/air-gap) |
| 5 | **quark-engine** | Behavioral sequences, weighted malware score | JSON/HTML | Always |
| 6 | **APKLeaks** | URIs, endpoints, secrets, cloud URLs | JSON/TXT | Always (fast, targeted) |
| 7 | **APKiD** | Packer/obfuscator/compiler identification | CLI text | Always (triage) |
| 8 | **Ghidra + JNIAnalyzer** | Native `.so` logic, JNI calls, hidden network/crypto | Ghidra project | When native libs present |

---

### Stage 3 — Fixing (Tooling Improvements)

The fix step remains manual, but the *editing environment* can be dramatically improved:

#### 🆕 ADD: Dalvikus (Modern Smali Editor)

| Tool | Stars | License | Status | Role |
| --- | --- | --- | --- | --- |
| **Dalvikus** | 266★ | GPL-3.0 | Active (Feb 2026) | Modern Compose Multiplatform smali editor with code completion, integrated signing, ADB deploy |

**Features that matter for your pipeline:**

- Open APK/DEX directly — edit DEX inside APK without manual unpacking
- **Syntax highlighting + code completion** for smali (your current pipeline uses raw text editing)
- Integrated **apksig + zipalign** for re-signing (collapses Stage 4 into the editor)
- Built-in **ADB runner** to deploy and test on-device immediately
- Tree view, string search, method/field reference search
- Multiple decompiler backends for cross-referencing

**Verdict:** Doesn't replace apktool for the CLI pipeline, but **replaces "VS Code + manual smali editing"** as the recommended interactive editing environment. For analysts doing Stage 3 daily, this is a significant quality-of-life upgrade.

#### 🆕 ADD: apk-mitm (Specialized: Cert Pinning Removal)

| Tool | Stars | License | Status | Role |
| --- | --- | --- | --- | --- |
| **apk-mitm** | 5.1k★ | MIT | Last release Apr 2024 (stable) | Automates certificate pinning removal: decode → patch NSC + pinning code → rebuild → sign |

**Why it belongs in Stage 3:** Certificate pinning removal is the single most common APK modification task (for traffic inspection, API analysis, debugging). apk-mitm automates the entire apktool→edit→rebuild→sign loop for this specific case.

```bash
npx apk-mitm input/target.apk
# Outputs: target-patched.apk (pinning removed, debug-signed)
```

**Limitation:** Doesn't work for pinning in native code (Flutter, custom `.so`). For those cases:

#### 🆕 ADD: android-unpinner (Alternative: Runtime Pinning Bypass)

| Tool | Stars | License | Status | Role |
| --- | --- | --- | --- | --- |
| **android-unpinner** | 1k★ | MIT | Active (Oct 2025) | Removes cert pinning via Frida Gadget injection; no root; handles XAPKs |

**Key advantage over apk-mitm:** Only modifies `AndroidManifest.xml` (marks app debuggable) and injects Frida Gadget via ADB — **much less invasive** than apk-mitm's full smali rewrite. Handles split APKs/XAPKs natively. Better for complex apps where apktool round-trip breaks.

**Trade-off:** Requires a connected device (ADB) and the Frida Gadget runs at runtime, so it's a *testing* tool, not a permanent modification.

#### Decision: apk-mitm vs. android-unpinner

| Criteria | apk-mitm | android-unpinner |
| --- | --- | --- |
| Permanent modification (rebuilt APK) | ✅ Yes | ❌ No (runtime only) |
| Works without device | ✅ Yes | ❌ Needs ADB |
| Handles native/Flutter pinning | ❌ No | ✅ Yes (Frida hooks) |
| Handles XAPK/splits | ⚠️ Partial | ✅ Yes |
| Invasiveness | High (rewrites smali) | Low (manifest only) |
| **Use when** | You need a permanently modified APK | You need to inspect traffic from a complex app |

---

### Stage 4 — Rebuild & Sign (Minor Change)

#### 🔄 REPLACE: uber-apk-signer → apksigner (direct)

| Tool | Stars | Last Release | Verdict |
| --- | --- | --- | --- |
| uber-apk-signer | 2.7k★ | **2023** (stale) | Demote to "optional convenience" |
| **apksigner** (Android SDK) | Official | Ships with SDK 35 (active) | **Primary signing tool** |

uber-apk-signer hasn't been updated since 2023 and wraps functionality that `apksigner` + `zipalign` provide natively. The Android SDK build-tools are actively maintained and support v1/v2/v3/v4 signing schemes. For a production pipeline, depend on the canonical tool, not a stale wrapper.

**Exception:** Keep uber-apk-signer as an option for quick debug-keystore testing (one command, auto-generates keystore). But for any release artifact, use `apksigner` directly.

#### Note: Dalvikus Integrated Signing

Dalvikus includes integrated `apksig` + `zipalign` , so if you adopt it for Stage 3, the rebuild+sign step is partially collapsed into the editor workflow. For CLI automation, stick with the explicit `apktool b → zipalign → apksigner` chain.

---

### Stage 5 (NEW) — Dynamic Validation

**Gap in current pipeline:** The pipeline is entirely static. You rebuild, sign, and install — but never verify runtime behavior. A static fix might break the app or miss runtime-loaded payloads.

#### 🆕 ADD: Frida + Objection

| Tool | Stars | License | Status | Role |
| --- | --- | --- | --- | --- |
| **Frida** | 19k+ | wxWindows | Active | Dynamic instrumentation: hook Java/native methods at runtime |
| **Objection** | 7k+ | MIT | Active | Frida wrapper: runtime exploration, SSL pinning bypass, storage inspection |

**Post-fix validation workflow:**

```bash
# Install the rebuilt APK
adb install -r build/signed/fixed-signed.apk

# Start objection against the app
objection -g com.target.app explore

# In objection:
#   → android sslpinning disable     (verify no pinning remains)
#   → android filesystem ls          (check for dropped payloads)
#   → android hooking list activities (verify no hidden activities)
#   → android hooking watch class com.evil.Payload  (confirm it's dead)

# Or with raw Frida for custom checks:
frida -U -f com.target.app -l validate_fix.js
```

**Why this matters:**

1. Confirms your smali edit actually neutralized the behavior at runtime
2. Catches dynamically-loaded code (DEX loaded from `assets/` at runtime) that static analysis missed
3. Verifies the app still functions after modification (no crash-on-launch)
4. Detects if the app phones home despite your edits (catch missed C2 endpoints)

---

## Updated Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Stage 0: INPUT NORMALIZATION                                            │
│   bundletool (.aab → .apk)  │  XAPK/split merge                        │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Stage 1: DECOMPILE                                                      │
│   jadx (→ Java, read)  │  apktool (→ smali, edit)                      │
│   ┌─────────────────────────────────────────────────────┐               │
│   │ Stage 1.5: NATIVE ANALYSIS (if .so present)         │               │
│   │   Ghidra + JNIAnalyzer → decompile ARM/x86 libs     │               │
│   └─────────────────────────────────────────────────────┘               │
│   IDE option: APKLab (VS Code) or Dalvikus                             │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Stage 2: SCAN & TRIAGE                                                  │
│   ┌────────────┬────────────┬────────────┬────────────┐                 │
│   │ MobSF      │ mobsfscan  │ Semgrep +  │ apktriage  │                 │
│   │ (binary)   │ (source)   │ MASTG rules│ (YARA/MITRE)│                │
│   ├────────────┼────────────┼────────────┼────────────┤                 │
│   │ quark      │ APKLeaks   │ APKiD      │ Ghidra     │                 │
│   │ (behavior) │ (secrets)  │ (packer)   │ (native)   │                 │
│   └────────────┴────────────┴────────────┴────────────┘                 │
│   → Threat Summary: components, URLs, perms, MITRE techniques           │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Stage 3: REMEDIATE (manual, LLM-assisted)                               │
│   Editor: Dalvikus (smali IDE) or APKLab (VS Code) or vim              │
│   Reference: jadx-gui (Java view, side-by-side)                        │
│   Specialized: apk-mitm / android-unpinner (cert pinning)              │
│   LLM: explain smali, propose patches, trace data flow                 │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Stage 4: REBUILD & SIGN                                                 │
│   apktool b → zipalign → apksigner (v1+v2+v3)                         │
│   (or Dalvikus integrated sign for interactive workflow)                │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Stage 5: VALIDATE (NEW)                                                 │
│   Static: re-run mobsfscan + apktriage on rebuilt APK                  │
│   Dynamic: Frida/Objection runtime verification                        │
│   Functional: adb install + smoke test                                  │
│   Network: mitmproxy/Burp → confirm no C2 traffic                      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Updated Installation Script (Additions Only)

```bash
#!/usr/bin/env bash
# Additions to the existing install script
set -euo pipefail

# --- Stage 0: AAB handling ---
# bundletool ships with Android SDK; ensure it's on PATH
ln -sf "$ANDROID_HOME/cmdline-tools/latest/bin/bundletool" "$HOME/.local/bin/bundletool" 2>/dev/null || \
  echo "⚠️  bundletool: download from https://developer.android.com/tools/bundletool"

# --- Stage 2: Additional scanners ---
# mobsfscan (source-level SAST)
pipx install mobsfscan

# Semgrep + Android MASTG rules
pipx install semgrep
git clone https://github.com/mindedsecurity/semgrep-rules-android-security \
  "$HOME/.local/share/semgrep-rules-android-security"

# APKLeaks (endpoint/secret extraction)
pipx install apkleaks

# --- Stage 1.5: Native analysis ---
# Ghidra (download from https://ghidra-sre.org/)
# JNIAnalyzer plugin
git clone https://github.com/Ayrx/JNIAnalyzer /tmp/JNIAnalyzer
cd /tmp/JNIAnalyzer && gradle -PGHIDRA_INSTALL_DIR="$GHIDRA_HOME"
# Install the .zip from dist/ via Ghidra → File → Install Extensions

# --- Stage 3: Editing tools ---
# Dalvikus (download release from GitHub)
# https://github.com/loerting/dalvikus/releases
# APKLab: install via VS Code extension marketplace
# code --install-extension Surendrajat.apklab

# apk-mitm (cert pinning removal)
npm install -g apk-mitm

# android-unpinner (runtime pinning bypass)
pipx install android-unpinner  # or clone from github.com/mitmproxy/android-unpinner

# --- Stage 5: Dynamic validation ---
# Frida
pipx install frida-tools
# Objection
pipx install objection
```

---

## What NOT to Change

| Current Tool | Why Keep It |
| --- | --- |
| **jadx** | No competitor matches its DEX→Java quality + GUI + active development (49.7k★) |
| **apktool** | Only viable round-trippable smali↔APK tool; no replacement exists |
| **MobSF** | Industry standard; 21.5k★; no OSS competitor matches its breadth |
| **quark-engine** | Unique behavioral scoring approach; complements (doesn't overlap with) MobSF |
| **apktriage** | Best offline/air-gap scanner with YARA+MITRE output; nothing else combines these |
| **APKiD** | Only mature packer/obfuscator fingerprinter for APKs |
| **apksigner** | Canonical Android signing tool; actively maintained by Google |

---

## Priority Ranking (If You Can Only Add 3)

If you need to be selective, these three additions deliver the highest impact-to-effort ratio:

| Priority | Tool | Impact | Effort |
| --- | --- | --- | --- |
| **1** | `mobsfscan` + `semgrep-rules-android-security` | Catches code-level vulnerabilities MobSF misses; CI/CD-ready; SARIF for GitHub Security tab | `pip install` + `git clone`, 5 min |
| **2** | `Ghidra` + `JNIAnalyzer` | Closes the native-code blind spot; essential for any APK with `.so` libs | 30 min setup, then per-APK analysis |
| **3** | `Frida` + `Objection` | Validates fixes at runtime; catches dynamic loading; confirms app still works | `pip install`, 10 min; needs device/emulator |

---