---
name: apk-remediation-pipeline
description: >-
  Guides an agent through a five-stage static-analysis, threat-identification,
  manual code-remediation, rebuild, and validation workflow for Android APKs,
  driven by the bundled apk-plug CLI and a unified threat-report.json. Triggers
  on "remediate this APK", "decompile and rebuild an APK", "scan an APK for
  malware", "remove a malicious receiver or service", "neutralize hardcoded C2",
  and "strip certificate pinning and rebuild". Use when working with a single
  .apk, .aab, .xapk, or .apkm file that must be statically analyzed, patched,
  re-signed, and re-validated. Not for team-mode security audits, dynamic
  runtime pentesting, iOS apps, or device forensics.
license: Apache-2.0
compatibility: >-
  Runtime host must be Linux, WSL2, or macOS (the toolchain is POSIX). Requires
  JDK 17+, Docker (for MobSF), Android SDK build-tools (zipalign, apksigner),
  Python 3.10+, and the bundled apk-plug CLI (pipx install ./cli). Author host
  may be Windows; do not port scripts/install-toolchain.sh to PowerShell.
metadata:
  version: 1.0.0
---

# APK Remediation Pipeline

Static analysis → threat identification → manual code remediation → rebuild &
sign → validation, for a single Android app package. The deterministic seams are
driven by the bundled **`apk-plug`** CLI; the irreducible reasoning (Stage 3
remediation) stays with you.

## ⚠️ Legal gate — read before running anything

**Only operate on APKs you own, have explicit written authorization to modify,
or are analyzing in an isolated research lab.** Redistribution or installation of
modified third-party apps may violate copyright, the CFAA, DMCA §1201, or local
equivalents. Confirm lawful authorization for THIS specific APK before Stage 0.
If authorization is unclear, stop and ask the human — do not proceed on
assumption. This gate is restated at the top of
[stage3-remediate.md](references/stage3-remediate.md) because remediation is the
point of no return.

## When to use

- A single `.apk` / `.aab` / `.xapk` / `.apkm` must be statically triaged, a
  malicious component neutralized, and the app rebuilt and re-signed.
- Certificate-pinning removal, C2 neutralization, over-broad-permission
  stripping, injected-receiver/service removal on one package.
- Confirming a static fix held (re-scan + optional dynamic check).

## When NOT to use

- **Team-mode multi-target security audit** → use the `security-research` skill
  (parallel hunters + PoC engineers). This skill is single-APK, sequential.
- **Dynamic pentest / live exploitation** → out of scope; Stage 5 uses Frida
  only to *validate* a static fix, not to author exploits.
- **iOS, Windows PE, device forensics (MVT)** → out of scope.
- **Building scanner tools** → the CLI orchestrates existing OSS; it never
  reimplements a scanner.

## Prerequisites

Host matrix, pinned tool versions, and the one-shot bootstrap live in
[prerequisites.md](references/prerequisites.md). Install everything with
`scripts/install-toolchain.sh` (bootstraps external OSS **and** runs
`pipx install ./cli`). The CLI degrades gracefully: any absent scanner is marked
`not_run` in the report rather than crashing, so a partial toolchain is usable.

## Pipeline overview

`apk-plug` wraps every deterministic stage. It **halts after `scan`** — Stage 3
(remediation) is agent/human work — then resumes at `rebuild`. There is
deliberately **no `fix`/`patch`/`remediate` subcommand**.

```
apk-plug init      → Stage 0  input normalization      (references/stage0-input.md)
apk-plug decompile → Stage 1  decompile (+1.5 native)  (references/stage1-decompile.md, stage1.5-native.md)
apk-plug scan      → Stage 2  scan → threat-report.json (references/stage2-scan.md)
     ── HALT ──       Stage 3  YOU read the report, reason, patch smali/manifest
                               (references/stage3-remediate.md)  ← NOT wrapped
apk-plug rebuild   → Stage 4  rebuild → align → sign    (references/stage4-rebuild-sign.md)
apk-plug validate  → Stage 5  re-scan + dynamic check    (references/stage5-validate.md)
```

Verify any stage's exit criteria with `apk-plug verify --stage N`.

## Stage 0 — Normalize input (`apk-plug init <input>`)

Route by format (detail + rationale in [stage0-input.md](references/stage0-input.md)):

- `.aab` → **bundletool** `build-apks --mode=universal`, extract `universal.apk`.
- `.xapk` / `.apkm` / `.apks` / `.zip` / loose split set → **APKEditor** `m`
  (merge to one standalone APK). bundletool CANNOT read these third-party
  split formats — do not try.
- `.apk` → pass through.
- Any bundled `.obb` expansion file → extracted to `input/obb/`. OBBs are both a
  malware-hiding surface (scanned in Stage 2) and a runtime dependency (pushed in
  Stage 5). Do not discard them.
- `.aab` companion data → the raw bundle is unzipped to `input/aab-raw/` and its
  feature modules + Play Asset Delivery asset packs are inventoried, because
  `--mode=universal` DROPS on-demand/conditional feature modules (`fusing=false`)
  and non-install-time asset packs. Those dropped surfaces are scan blind spots
  (Stage 2 scans them directly) and cannot be carried through the rebuild (Stage
  4/5 warn). bundletool-preferred flag reading, heuristic fallback when absent.

`init` scaffolds a timestamped `workspace/<apk>_<ts>/` and records state so later
subcommands are resumable and order-checked.

## Stage 1 — Decompile (`apk-plug decompile`)

Produces two parallel views: **jadx** Java (`--deobf --show-bad-code`, read-only,
for understanding) and **apktool** smali + resources (`d -f`, the editable
representation). Native `lib/*.so` are extracted to `decompile/native/`. Detail,
flags, and the OOM / `resources.arsc` / obfuscation / split troubleshooting
matrix in [stage1-decompile.md](references/stage1-decompile.md).

**Stage 1.5 — native analysis (only when `.so` present):** load the `.so` into
**Ghidra** + **JNIAnalyzer** to map JNI signatures and inspect `JNI_OnLoad` /
`RegisterNatives`. Detail in [stage1.5-native.md](references/stage1.5-native.md).

Gate: `apk-plug verify --stage 1` (valid manifest XML, ≥1 `.java`, ≥1 `.smali`).

## Stage 2 — Scan & triage (`apk-plug scan`)

Runs every available scanner and **merges their heterogeneous outputs into one
schema-validated `threat-report.json`** (the CLI centerpiece): MobSF, mobsfscan,
semgrep + MASTG rules, apktriage, quark-engine, APKLeaks, APKiD, and Ghidra
(native). A companion-data pass scans every surface outside the target APK —
`input/obb/*.obb`, AAB feature modules and asset packs dropped from the universal
APK (`input/aab-raw/`), and DEX smuggled in the APK's own `assets/` — for hidden
DEX/ELF payloads. Full 8-scanner matrix, MobSF headless API, and companion-data
scan note in [stage2-scan.md](references/stage2-scan.md).

The report carries: `components`, `urls`, `permissions`, `mitre_techniques`,
per-tool `findings` with severity, and an `aggregate_risk` score.

Gate: `apk-plug verify --stage 2` (report generated + threat summary written).

## Stage 3 — Remediate (manual, agent/human only — NOT a CLI command)

**Read `threat-report.json`, then reason.** The CLI does not patch. Route by the
decision tree below, then apply the minimal smali/manifest edit. Prefer
`return-void` / `const-string ""` over deletion to avoid verification errors.
Patterns table, grep workflow, cert-pinning tool choice (`apk-mitm` vs
`android-unpinner`), the LLM reasoning-aid template
([assets/llm-analysis-prompt.md](assets/llm-analysis-prompt.md)), and the legal
restatement are in [stage3-remediate.md](references/stage3-remediate.md). Log
every edit with rationale in `patches/CHANGELOG.md`.

### Master decision tree (driven by threat-report.json)

```
aggregate_risk / quark score
├── quark ≥ 80  OR MobSF flags "malicious"
│     → confirmed malware: neutralize the offending component, or discard the APK
├── quark 40–79  OR suspicious permissions + hardcoded URLs
│     → manual review in jadx → confirm intent → remediate only if confirmed
├── APKiD reports a packer (Bangcle, Jiagu, 360, ...)
│     → unpack first (FRIDA-DEXDump / BlackDex) → re-run Stage 1–2
└── clean / low score
      → no remediation; archive the report
```

Gate: `apk-plug verify --stage 3` (every Stage-2 threat has a matching edit; no
dangling references to deleted classes; manifest still valid XML).

## Stage 4 — Rebuild, align & sign (`apk-plug rebuild`)

`apktool b` → `zipalign -p 4` → `apksigner sign` (v1+v2+v3), **in that order,
enforced in code** so signing an unaligned APK is unreachable. `apksigner` is
primary; `uber-apk-signer` is optional convenience only. You cannot reuse the
original developer's signature — the rebuilt APK has a different signer, so it
installs as a fresh app, not an update. Keystore generation, the critical
constraints table, and the v1-for-legacy note in
[stage4-rebuild-sign.md](references/stage4-rebuild-sign.md).

Gate: `apk-plug verify --stage 4` (`apktool b` exit 0, alignment confirmed,
`apksigner verify` shows valid v2/v3 signature).

## Stage 5 — Validate (`apk-plug validate`)

Re-run mobsfscan/apktriage/quark on the rebuilt APK, diff permissions
(original vs fixed — fail if broader), grep for residual C2 strings, and run
optional Frida/Objection runtime checks. **If `input/obb/` is non-empty**, the
smoke test must `adb push` each OBB to `Android/obb/<pkg>/` or the app crashes on
launch (a false-negative). For `.aab` inputs, `validate` also warns that on-demand
feature modules (`fusing=false`) and non-install-time asset packs are absent from
the rebuilt universal APK — so a passing smoke test is not full coverage. Detail
in [stage5-validate.md](references/stage5-validate.md).

Gate: `apk-plug verify --stage 5` — but the true acceptance is a re-scan showing
the threat gone AND the app still launching.

## Verification gates (summary)

| Stage | `apk-plug verify --stage` | Pass criteria |
| --- | --- | --- |
| 1 Decompile | `--stage 1` | Manifest valid XML; ≥1 `.java`; ≥1 `.smali` |
| 2 Scan | `--stage 2` | `threat-report.json` present; threat summary written |
| 3 Remediate | `--stage 3` | Each threat edited; no dangling refs; manifest valid |
| 4 Rebuild | `--stage 4` | Build exit 0; aligned; `apksigner verify` valid |
| 5 Validate | `--stage 5` | Re-scan clean; permission set not broader; app launches |

Any failed gate exits non-zero and names the gate. Never proceed past a red gate.

## Safety posture

Legal gate up front; Stage 3 stays manual (no auto-patching of malicious logic);
keystores are gitignored; the CLI has no destructive `fix` subcommand. Preserve
all four.

## References

- [prerequisites.md](references/prerequisites.md) — host matrix + full install
- [stage0-input.md](references/stage0-input.md) — AAB/XAPK/APKM/split/OBB routing
- [stage1-decompile.md](references/stage1-decompile.md) — jadx + apktool + gates
- [stage1.5-native.md](references/stage1.5-native.md) — Ghidra + JNIAnalyzer
- [stage2-scan.md](references/stage2-scan.md) — 8-scanner matrix + MobSF API
- [stage3-remediate.md](references/stage3-remediate.md) — patterns + cert-pinning
- [stage4-rebuild-sign.md](references/stage4-rebuild-sign.md) — build/align/sign
- [stage5-validate.md](references/stage5-validate.md) — re-scan + dynamic checks
- [tool-disposition.md](references/tool-disposition.md) — keep/add/replace matrix
- [assets/cheatsheet.md](assets/cheatsheet.md) — one-glance command reference
- [assets/llm-analysis-prompt.md](assets/llm-analysis-prompt.md) — smali analysis aid
