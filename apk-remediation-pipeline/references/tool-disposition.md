# Tool Disposition

Every tool tagged: **KEEP** (already best-in-class), **ADD** (new capability),
**REPLACE** (demote a stale tool for the canonical one), **ELEVATE** (promote
from unmentioned to primary).

## Executive summary

| Verdict | Tool | Stage | Why |
| --- | --- | --- | --- |
| **ADD** | `mobsfscan` | 2 | CLI SAST on decompiled source; CI/CD-native; SARIF; fills gap between MobSF binary scan and code review |
| **ADD** | `semgrep` + `semgrep-rules-android-security` | 2 | OWASP MASTG rules + taint analysis on jadx Java |
| **ADD** | `APKLeaks` | 2 | fast URI/endpoint/secret extraction |
| **ADD** | `Ghidra` + `JNIAnalyzer` | 1.5 | closes the native `.so` blind spot |
| **ADD** | `apk-mitm` / `android-unpinner` | 3 | automate the most common mod: cert-pinning removal |
| **ADD** | `bundletool` | 0 | handle `.aab` inputs |
| **ADD** | `APKEditor` | 0 | merge `.xapk`/`.apkm`/`.apks`/splits (bundletool cannot) |
| **ADD** | `Frida` + `Objection` | 5 | dynamic runtime validation of the static fix |
| **REPLACE** | `uber-apk-signer` → `apksigner` (direct) | 4 | uber-apk-signer stale since 2023; apksigner is canonical + maintained |
| **ELEVATE** | `Ghidra` | 1.5 | NSA 69k★ RE framework, best-in-class for native code |
| **KEEP** | jadx, apktool, MobSF, quark-engine, apktriage, APKiD, apksigner | all | still best-in-class; no viable replacement |

## Full matrix

| Tool / Repo | Stage | Status | Action |
| --- | --- | --- | --- |
| jadx | 1 | **KEEP** ✅ Primary | use directly |
| apktool | 1, 4 | **KEEP** ✅ Primary | use directly |
| MobSF | 2 | **KEEP** ✅ Backbone | Docker + API |
| apktriage | 2 | **KEEP** ✅ Adopt | offline YARA + MITRE |
| quark-engine | 2 | **KEEP** ✅ Complement | behavioral scoring |
| APKiD | 2 | **KEEP** ✅ Helper | packer fingerprint |
| androguard | 2 | **KEEP** ✅ Dependency | underlies apktriage/quark |
| apksigner + zipalign | 4 | **KEEP** ✅ Required | SDK build-tools |
| mobsfscan | 2 | **ADD** 🆕 | source-level SAST |
| semgrep + MASTG rules | 2 | **ADD** 🆕 | taint analysis |
| APKLeaks | 2 | **ADD** 🆕 | endpoint/secret extraction |
| Ghidra + JNIAnalyzer | 1.5 | **ADD / ELEVATE** ⬆️ | native analysis |
| bundletool | 0 | **ADD** 🆕 | `.aab` → universal APK |
| APKEditor | 0 | **ADD** 🆕 | split/XAPK/APKM merge |
| apk-mitm / android-unpinner | 3 | **ADD** 🆕 | cert-pinning removal |
| Frida + Objection | 5 | **ADD** 🆕 | dynamic validation |
| uber-apk-signer | 4 | **REPLACE** ⚠️ | demote to optional convenience |
| dex2jar | 1 | ⚠️ Legacy | only if jadx fails on a specific DEX |
| LurkerX / VEN0m | — | 🚨 Threat ref only | never execute; study for detection rules |

## What NOT to change

| Tool | Why keep it |
| --- | --- |
| **jadx** | no competitor matches DEX→Java quality + GUI + active development |
| **apktool** | only viable round-trippable smali↔APK tool |
| **MobSF** | industry-standard breadth; no OSS competitor matches it |
| **quark-engine** | unique behavioral scoring; complements MobSF |
| **apktriage** | best offline YARA + MITRE scanner |
| **APKiD** | only mature APK packer/obfuscator fingerprinter |
| **apksigner** | canonical Android signing tool, maintained by Google |

## Priority ranking — if you can only add 3

The top 3 additions by impact-to-effort:

| Priority | Tool | Impact | Effort |
| --- | --- | --- | --- |
| **1** | `mobsfscan` + `semgrep-rules-android-security` | catches code-level vulns MobSF misses; SARIF for CI | `pip` + `git clone`, 5 min |
| **2** | `Ghidra` + `JNIAnalyzer` | closes the native-code blind spot | 30 min setup |
| **3** | `Frida` + `Objection` | validates fixes at runtime; catches dynamic loading | `pip`, 10 min; needs device |
