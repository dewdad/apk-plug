# Stage 2 — Scan & Triage

## Table of Contents

- [Purpose](#purpose)
- [Scanner matrix (8 tools)](#scanner-matrix-8-tools)
- [MobSF headless API](#mobsf-headless-api)
- [Source-level scanners on jadx output](#source-level-scanners-on-jadx-output)
- [OBB scan note](#obb-scan-note)
- [Decision tree](#decision-tree)
- [Unified output: threat-report.json](#unified-output-threat-reportjson)
- [Verification gate](#verification-gate)

---

## Purpose

Identify malicious/suspicious components: injected services/receivers, hardcoded
C2 endpoints, over-broad permissions, known malware signatures, packer/obfuscator
fingerprints, and behavioral risk scores. `apk-plug scan` runs every available
scanner and merges their heterogeneous outputs into ONE schema-validated
`threat-report.json`.

---

## Scanner matrix (8 tools)

| # | Tool | What it catches | Output | When |
| --- | --- | --- | --- | --- |
| 1 | **MobSF** | permissions, manifest, trackers, secrets, malware indicators | JSON/PDF | always (backbone, binary scan) |
| 2 | **mobsfscan** | OWASP MASVS code patterns in Java/Kotlin source | JSON/SARIF | always (on jadx output) |
| 3 | **semgrep** + MASTG rules | MASTG static tests, taint-tracked data flows | JSON/SARIF | always (on jadx output) |
| 4 | **apktriage** | YARA signatures, MITRE ATT&CK mapping, APKiD fingerprint | YARA/JSON | always (offline/air-gap) |
| 5 | **quark**-engine | behavioral sequences, weighted malware score 0–100 | JSON/HTML | always |
| 6 | **APKLeaks** | URIs, endpoints, secrets, cloud URLs | JSON/TXT | always (fast, targeted) |
| 7 | **APKiD** | packer/obfuscator/compiler identification | text | always (triage) |
| 8 | **Ghidra** + JNIAnalyzer | native `.so` logic, JNI calls, hidden network/crypto | Ghidra project | when native libs present |

Any scanner absent at run time is logged and marked `not_run` in the report —
`apk-plug scan` never hard-crashes on a partial toolchain.

---

## MobSF headless API

```bash
MOBSF_URL="http://localhost:8000"
API_KEY="<from MobSF UI → API Key>"
APK="input/target.apk"

# Upload
HASH=$(curl -s -F "file=@${APK}" -H "Authorization: ${API_KEY}" \
  "${MOBSF_URL}/api/v1/upload" | jq -r '.hash')

# Scan
curl -s -X POST -H "Authorization: ${API_KEY}" \
  -d "hash=${HASH}&scan_type=apk" \
  "${MOBSF_URL}/api/v1/scan" > scan/mobsf/report.json

# Extract critical findings
jq '{permissions, malicious_code: .malicious_code, secrets, trackers, manifest_analysis}' \
  scan/mobsf/report.json > scan/mobsf/critical.json
```

When MobSF is unreachable, `apk-plug scan` skips it and notes `not_run`.

---

## Source-level scanners on jadx output

```bash
# mobsfscan (source-level SAST) on the jadx Java tree
mobsfscan decompile/java/ --sarif -o scan/mobsfscan/report.sarif

# semgrep with the Android MASTG rule pack
semgrep -c "$HOME/.local/share/semgrep-rules-android-security/rules/" \
  decompile/java/ --sarif -o scan/semgrep/report.sarif

# APKLeaks: endpoint/secret extraction straight off the APK
apkleaks -f input/target.apk -o scan/apkleaks/report.json

# quark behavioral score, APKiD packer fingerprint, apktriage YARA+MITRE
quark -a input/target.apk -s -o scan/quark/
apkid input/target.apk | tee scan/apkid.txt
apktriage input/target.apk --out scan/apktriage/
```

Exclude well-known libraries (semgrep `.semgrepignore`) to cut false positives.

---

## OBB scan note

Any `input/obb/*.obb` is unzipped and scanned for a **hidden `.dex` payload** —
an OBB is a common malware-hiding surface (a `classes.dex` or secondary DEX
smuggled inside an expansion file that the app loads at runtime). A DEX inside an
OBB is flagged in the raw scan outputs and surfaced as a finding in
`threat-report.json`.

---

## Decision tree

```
threat-report.json → aggregate_risk / quark score
├── quark ≥ 80  OR MobSF flags "malicious"
│     → confirmed malware → Stage 3 (neutralize) or discard
├── quark 40–79  OR suspicious permissions + hardcoded URLs
│     → manual review in jadx → confirm intent → Stage 3 if confirmed
├── packer detected (APKiD: Bangcle, Jiagu, 360, ...)
│     → unpack first (FRIDA-DEXDump / BlackDex) → re-run Stage 1–2
└── clean / low score
      → no remediation; archive report
```

---

## Unified output: threat-report.json

`apk-plug scan` merges MobSF JSON + quark score + semgrep SARIF + APKLeaks JSON +
APKiD text + apktriage YARA/MITRE + Ghidra native findings into one document with
`components`, `urls`, `permissions`, `mitre_techniques`, per-tool `findings` with
severity, and an `aggregate_risk` block. Schema:
`assets/threat-report.schema.json`. Stage 3 reads THIS one structure, not six
tool-specific formats.

---

## Verification gate

`apk-plug verify --stage 2`:

- [ ] `threat-report.json` generated and schema-valid
- [ ] MobSF `critical.json` reviewed (or MobSF marked `not_run`)
- [ ] apktriage YARA rules saved; MITRE techniques noted
- [ ] quark score recorded; APKiD fingerprint logged (packed? which protector?)
- [ ] **Threat summary written**: offending components (class names, manifest
      entries, URLs, permissions)
