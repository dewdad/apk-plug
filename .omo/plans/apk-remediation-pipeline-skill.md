# Implementation Plan — `apk-remediation-pipeline` OpenCode Agent Skill

**Source:** `drafting.md` (925-line research synthesis: original v1.0.0 draft + best-in-breed OSS additions) **Target:** A production-grade OpenCode Agent Skill package, spec-compliant per `skill-creator`, installable via `skillshare`. **Author host:** Windows (`win32`, pwsh 7+). **Skill runtime host:** Linux/WSL2/macOS (the pipeline tools are POSIX). This split matters — see Constraint C4.

---

## 1. Objective & Definition of Done

Convert the `drafting.md` research into a **reusable, model-invoked skill** that guides an agent through the 5-stage APK static-analysis → remediation → rebuild → validation workflow.

**Done when ALL are true:**

1. Skill folder `apk-remediation-pipeline/` exists with `SKILL.md` + `references/` + `cli/` + `scripts/` + `assets/`.
2. `SKILL.md` body is dense, imperative, ≤500 lines, ≤\~5k tokens; frontmatter has `name` (== folder), `description` (3rd-person, what+when, ≥3 trigger phrases, no angle brackets), `license`, `compatibility`.
3. Every stage in the draft is represented — including the merged additions (Stage 0 input-normalization, Stage 1.5 native analysis, expanded Stage 2 scanners, Stage 5 dynamic validation) and the tool-disposition decisions (`uber-apk-signer` demoted, `apksigner` primary).
4. A **Python CLI** `apk-plug` wraps the deterministic seams (Stages 0, 1/1.5, 2, 4, 5 + verification gates) with subcommands `init / decompile / scan / verify / rebuild / validate`. It emits a **unified** `threat-report.json` conforming to `assets/threat-report.schema.json`. Stage 3 (remediation) is NOT wrapped — the CLI stops after `scan`, the agent reasons and patches, then `rebuild` resumes.
5. `cli/` is `pip`/`pipx`-installable (`pyproject.toml`, entry point `apk-plug`), has unit tests over the normalizer + gates (golden-file fixtures), and every external tool is invoked through one guarded subprocess runner (timeout, captured stderr, actionable errors — never a raw stack trace).
6. `scripts/install-toolchain.sh` bootstraps external OSS tools (pinned versions) AND installs the CLI (`pipx install ./cli`). `chmod +x`, forward-slash, `set -euo pipefail`, no voodoo constants.
7. `skill-validator check --strict` (or `npx skills-ref validate`) passes clean.
8. Three eval runs completed (baseline-without / with-skill / unseen-task) and logged in `TESTING.md`.
9. Legal gate is preserved verbatim as the first substantive content the agent sees.

**Explicitly OUT of scope (unchanged from draft):** dynamic Frida *authoring* beyond validation snippets, iOS, Windows PE, device forensics (MVT), building the actual scanner tools (the CLI orchestrates existing OSS, never reimplements them), and any auto-patching of malicious logic (Stage 3 is agent/human only).

---

## 2. Design Decisions (decision-complete — no further interview needed)

| ID | Decision | Rationale |
| --- | --- | --- |
| D1 | **Skill type = problem-first (sequential workflow)** | User describes an outcome ("remediate this APK"); skill orchestrates a fixed stage pipeline. |
| D2 | **Folder name =** `apk-remediation-pipeline` (matches draft Skill ID and required `name`) | skill-creator: folder name MUST equal `name`. |
| D3 | **Author location = repo root:** `./apk-remediation-pipeline/` | Repo `apk-plug` is dedicated to this one skill; keep the package self-contained at root. |
| D4 | **Deploy location = cross-platform** `~/.agents/skills/` **(via skillshare), NOT** `.opencode` **only** | Emerging cross-platform convention; skillshare handles fan-out. Symlink, don't copy, during dev. |
| D5 | **SKILL.md body = orchestration spine only** (overview, legal gate, when-to-use, 5-stage flow as imperative steps, master decision tree, links). All command detail, matrices, troubleshooting → `references/`. | Keep activation cost low; resources are effectively free. |
| D6 | **Merge the two halves of the draft.** The "best-in-breed additions" section is authoritative and supersedes the v1.0.0 tool choices where they conflict (e.g. Stage 0 exists, Stage 5 exists, `uber-apk-signer`→`apksigner`, add mobsfscan/semgrep/APKLeaks/Ghidra+JNIAnalyzer/Frida). | The additions doc is the newer, researched verdict. |
| D7 | **CLI is advisory-runnable, not silently destructive.** The pipeline halts after `apk-plug scan`; the agent performs Stage 3 remediation, then invokes `apk-plug rebuild`. No auto-patching of malicious logic. | Stage 3 is inherently manual; matches draft intent + safety. |
| D8 | **Pin every external tool version as a named variable** in `install-toolchain.sh` (`JADX_VER`, `APKTOOL_VER`, `BT_VER`, etc.); the CLI reads tool paths from PATH/env, never hard-codes versions inline. | skill-creator: no voodoo constants; reproducibility; separation of bootstrap vs runtime. |
| D9 | `allowed-tools` **omitted;** `disable-model-invocation` **NOT set.** Skill is guidance, not a destructive auto-runner, so normal model invocation is fine. | The skill instructs; the human/agent runs `apk-plug`. |
| D10 | **Legal gate placed immediately after frontmatter in SKILL.md body**, restated at top of `references/stage3-remediate.md`. | Highest-visibility placement for the authorization/lawfulness constraint. |
| **D11** | **Wrap deterministic work in a scoped Python CLI** `apk-plug` (subcommands `init/decompile/scan/verify/rebuild/validate`). Wrap ONLY: input-normalization, decompile+native-extract, scan-orchestration+output-normalization, verification gates, and rebuild→align→sign. Do NOT wrap: smali remediation, ambiguous-finding triage, native/Ghidra interpretation, YARA authoring. | Offloads token-wasteful, error-prone, footgun-heavy mechanical work (heterogeneous scanner-output parsing, zipalign-before-sign ordering) to deterministic code; keeps irreducible reasoning with the agent. Aligns with skill-creator "scripts for deterministic ops where token-generating equivalent is unreliable/wasteful". |
| **D12** | **The** `threat-report.json` **normalizer is the CLI centerpiece.** `apk-plug scan` runs all applicable scanners and merges MobSF JSON + quark score + semgrep SARIF + APKLeaks JSON + APKiD text + apktriage YARA/MITRE into ONE schema-validated report (components, URLs, permissions, MITRE techniques, per-tool severity, aggregate risk). Schema published at `assets/threat-report.schema.json`. | Single output contract → agent parses one structure, not 6 tool-specific formats. This is the highest-value lever and the thing bash+jq does worst. |
| **D13** | **Language = Python, not bash, for the CLI.** androguard (already a transitive dep of quark/apktriage) available; Python wins decisively for JSON/SARIF parsing, schema validation, diffing, and unit-testing. Bash retained ONLY for the `install-toolchain.sh` bootstrap. | Right tool per job; testability. |
| **D14** | **Stage 0 format routing is tool-specific — bundletool does NOT cover XAPK/APKM.** Route by input type: `.aab` → **bundletool** `build-apks --mode=universal` → extract `universal.apk`; `.xapk`/`.apkm`/`.apks`/`.zip`/loose split set → **APKEditor** `m` (merge to standalone APK); `.apk` → pass through. `.obb` expansion files → extract into `input/obb/`, scan in Stage 2, and carry through to the Stage 5 smoke test (app crashes without them). | bundletool only handles Google's `.aab`/`.apks`; XAPK (APKPure) and APKM (APKMirror) are third-party ZIP-of-splits formats that bundletool cannot read. APKEditor (REAndroid, \~2K★, active v1.4.9 May 2026, aapt-independent) is the best-in-breed OSS merger for all split formats. OBB payloads are both a malware-hiding surface and a runtime dependency. |

---

## 3. Target Package Layout

```
apk-remediation-pipeline/
├── SKILL.md                      # dense spine, ≤500 lines
├── TESTING.md                    # eval log (Phase 5)
├── references/
│   ├── prerequisites.md          # host matrix + full install detail + dir scaffold
│   ├── stage0-input.md           # AAB→bundletool; XAPK/APKM/split→APKEditor; OBB handling
│   ├── stage1-decompile.md       # jadx + apktool + verification + troubleshooting
│   ├── stage1.5-native.md        # Ghidra + JNIAnalyzer (.so analysis)
│   ├── stage2-scan.md            # full scanner matrix, MobSF API, decision tree, gates
│   ├── stage3-remediate.md       # remediation patterns table + workflow + LLM template + cert-pinning tools
│   ├── stage4-rebuild-sign.md    # apktool b / zipalign / apksigner, keystore, constraints
│   ├── stage5-validate.md        # post-fix re-scan + Frida/Objection dynamic checks
│   └── tool-disposition.md       # keep/add/replace/elevate matrix + priority-3 ranking
├── cli/                          # the `apk-plug` Python CLI (deterministic-work offload)
│   ├── pyproject.toml            # entry point: apk-plug = apk_plug.__main__:main; deps pinned
│   ├── src/apk_plug/
│   │   ├── __init__.py
│   │   ├── __main__.py           # subcommand dispatch (init/decompile/scan/verify/rebuild/validate)
│   │   ├── workspace.py          # scaffold + state: workspace/<apk>_<ts>/, resumable
│   │   ├── runner.py             # single guarded subprocess helper: timeout, captured stderr, actionable errors
│   │   ├── stage0_input.py       # .aab→bundletool, .xapk/.apkm/.apks/.zip/splits→APKEditor; extract .obb
│   │   ├── stage1_decompile.py   # jadx + apktool + native lib extract
│   │   ├── stage2_scan.py        # run applicable scanners, hand raw outputs to normalize.py
│   │   ├── normalize.py          # ★ CENTERPIECE: heterogeneous scanner outputs → threat-report.json
│   │   ├── report.py             # ThreatReport model + schema validation
│   │   ├── verify.py             # per-stage gates → exit codes (draft §2.3/§3.5/§4.5/§5.4)
│   │   ├── stage4_rebuild.py     # apktool b → zipalign → apksigner (correct order enforced)
│   │   └── stage5_validate.py    # re-scan + permission diff + C2-string grep
│   └── tests/
│       ├── fixtures/             # sample MobSF/quark/semgrep/apkleaks/apkid/apktriage outputs
│       ├── test_normalize.py     # golden-file: fixtures → expected threat-report.json
│       └── test_verify.py        # gate pass/fail on synthetic workspaces
├── scripts/
│   └── install-toolchain.sh      # bootstrap external OSS (pinned vers) + `pipx install ./cli`
└── assets/
    ├── llm-analysis-prompt.md    # smali-analysis reasoning-aid template (draft §4.4)
    ├── cheatsheet.md             # one-glance `apk-plug` command reference (draft §10, updated)
    ├── threat-report.schema.json # ★ unified output contract for `apk-plug scan`
    └── yara/                     # placeholder for custom YARA rules (draft §7 gap-closing)
        └── README.md
```

**References are exactly one level deep from SKILL.md** (skill-creator constraint). Any reference &gt;100 lines gets a TOC at top. The `cli/` package is a bundled resource: SKILL.md tells the agent to *run* `apk-plug` subcommands, not to read the source.

---

## 4. Phased Work Breakdown

Each task lists WHERE · WHAT · ACCEPTANCE. Execute phases in order; tasks within a phase may parallelize where noted.

### Phase 0 — Scaffold (blocking, do first)

- **0.1** `apk-remediation-pipeline/` + all subdirs — create the directory tree from §3. **Accept:** `Test-Path` true for every dir; `assets/yara/` present.
- **0.2** `.gitignore` at repo root — add `keystores/`, `workspace/`, `*.jks`, `*.keystore`, `.env`. **Accept:** grep confirms all five patterns; keystore paths never committable.

### Phase 1 — SKILL.md spine (blocking; gates everything else)

- **1.1** Frontmatter. `name: apk-remediation-pipeline`; `license: Apache-2.0`; `compatibility` note (Linux/WSL2/macOS host, JDK 17+, Docker, Android SDK build-tools). **Accept:** YAML on lines 1–N, parses, no `<>`/XML in description.
- **1.2** `description` field. One-line what + Triggers on: ≥3 quoted phrases (e.g. `"remediate this APK"`, `"decompile and rebuild an APK"`, `"scan an APK for malware"`, `"remove a malicious receiver/service"`, `"neutralize hardcoded C2"`) + "Use when" clause + out-of-scope disambiguation (not dynamic pentest, not iOS, not device forensics). ≤1024 chars, third-person. **Accept:** validator description checks pass; ≥3 triggers present.
- **1.3** Legal gate (D10) — verbatim authorization/lawfulness warning as first body content. **Accept:** present before any command guidance.
- **1.4** "When to use / when NOT to use" section. **Accept:** distinguishes from adjacent skills (security-research team mode, dynamic pentest).
- **1.5** 5-stage workflow as dense imperative steps (Stage 0→5), each step naming the `apk-plug` subcommand that drives it (`init`→`decompile`→`scan`→ \[agent Stage 3\] →`rebuild`→`validate`) and linking to its `references/` file for detail. Make the Stage 2→3 handoff explicit: "read `threat-report.json`, then reason about remediation — the CLI does NOT patch." Include the **master decision tree** (draft §3.4: quark≥80 / 40–79 / packer / clean routing) driven by `threat-report.json` fields. **Accept:** every stage links to exactly one reference and names its `apk-plug` command (except Stage 3, explicitly agent-only); body stays ≤500 lines.
- **1.6** Verification-gate summary table + pointer to `apk-plug verify --stage N` (exit-code gate). **Accept:** each stage has pass/fail criteria referenced to a `verify` invocation.

### Phase 2 — references/ (parallelizable across files after Phase 1)

Content is a **restructure of existing draft prose** — do not invent new tooling. Map:

- **2.1** `prerequisites.md` ← draft §1.1–1.3 (host matrix, dir scaffold) + §"Updated Installation Script". TOC required (&gt;100 lines). **Accept:** every tool in the final matrix has an install line; versions pinned.
- **2.2** `stage0-input.md` ← additions "Stage 0 — Input Normalization" + D14 routing. Document the format→tool matrix: `.aab`→bundletool `build-apks --mode=universal`; `.xapk`/`.apkm`/`.apks`/`.zip`/loose splits→**APKEditor** `m -i <in> -o target.apk`; `.apk`→pass through. Document `.obb` handling: extract to `input/obb/`, note it is scanned (Stage 2) and re-deployed (Stage 5). Correct the stale "bundletool does everything" claim — bundletool cannot read XAPK/APKM. **Accept:** covers `.aab`, `.xapk`, `.apkm`, `.apks`, `.obb`; APKEditor named as the split-merger; bundletool scoped to `.aab` only.
- **2.3** `stage1-decompile.md` ← draft §2 (jadx `--deobf --show-bad-code`, apktool `d`, verification gate, troubleshooting table incl. OOM, resources.arsc, obfuscation, split APKs).
- **2.4** `stage1.5-native.md` ← additions "Stage 1.5 Native Analysis" (Ghidra + JNIAnalyzer, extract `lib/*`, JNI_OnLoad/RegisterNatives workflow). **Accept:** notes "only when `.so` present".
- **2.5** `stage2-scan.md` ← draft §3 + additions "Stage 2" — the **updated 8-row scanner matrix** (MobSF, mobsfscan, semgrep+MASTG rules, apktriage, quark, APKLeaks, APKiD, Ghidra), MobSF headless API script, decision tree, verification gate/threat-summary. Add an **OBB scan note**: any `input/obb/*.obb` is unzipped and scanned for hidden DEX/payloads (malware-hiding surface). TOC required. **Accept:** all 8 scanners present; MobSF API snippet intact; OBB scan note present.
- **2.6** `stage3-remediate.md` ← draft §4 (7-row remediation-patterns table, grep workflow, verification gate, CHANGELOG requirement) + additions cert-pinning tools (`apk-mitm` vs `android-unpinner` decision table). LLM template lives in assets (link it). Legal gate restated (D10). **Accept:** patterns table complete; "manual, no auto-patch" stated.
- **2.7** `stage4-rebuild-sign.md` ← draft §5 (apktool b → zipalign → apksigner v1/v2/v3, keystore gen, critical-constraints table, verification gate). Reflect D6: `apksigner` primary, `uber-apk-signer` optional-only. **Accept:** "zipalign BEFORE sign" and "cannot reuse original signature" constraints present.
- **2.8** `stage5-validate.md` ← draft §6 + additions "Stage 5" (re-run mobsfscan/apktriage/quark on rebuilt APK, permission diff, C2-string grep, Frida/Objection runtime checks). Add **OBB carry-through note**: if `input/obb/` is non-empty, the smoke test must push OBBs to `Android/obb/<pkg>/` (`adb push`) or the app crashes on launch — a functional-validation false negative otherwise. **Accept:** both static re-scan and dynamic checks present; OBB push step documented.
- **2.9** `tool-disposition.md` ← draft §8 + additions Executive Summary + "What NOT to Change" + "Priority-3 if selective". **Accept:** every tool tagged keep/add/replace/elevate; priority-3 list present.

**Phase 2 QA (run from the package dir:** `cd apk-remediation-pipeline` **first;** `rg` **= ripgrep, cross-platform). Each command's expected result is stated — a run producing fewer matches FAILS the task:**

```
# 2.1 prerequisites: every core tool named + TOC present
rg -c "jadx|apktool|zipalign|apksigner|MobSF|mobsfscan|semgrep|apktriage|quark|APKiD|APKLeaks|Ghidra|bundletool|APKEditor|frida|objection" references/prerequisites.md   # expect >=1 line, all tools findable
rg -n "^## |Table of Contents|^- \[" references/prerequisites.md | head -1                                                                                       # expect a TOC (file >100 lines)
# 2.2 stage0: all input formats + correct tool routing + OBB
rg -c "\.aab" references/stage0-input.md && rg -c "\.xapk" references/stage0-input.md && rg -c "\.apkm" references/stage0-input.md && rg -c "\.apks|split" references/stage0-input.md   # expect each >=1
rg -n "bundletool build-apks" references/stage0-input.md                                                                                                          # expect >=1 (scoped to .aab)
rg -ni "APKEditor" references/stage0-input.md                                                                                                                     # expect >=1 (split-merger)
rg -ni "\.obb|expansion" references/stage0-input.md                                                                                                               # expect >=1 (OBB handling)
# 2.3 stage1: flags + gate + troubleshooting
rg -n "jadx.*--deobf.*--show-bad-code" references/stage1-decompile.md && rg -n "apktool d" references/stage1-decompile.md                                         # expect both
rg -ci "OOM|resources.arsc|obfusc|split" references/stage1-decompile.md                                                                                           # expect >=3 (troubleshooting rows)
rg -n "xmllint --noout" references/stage1-decompile.md                                                                                                            # verification gate present
# 2.4 stage1.5: native workflow + gating note
rg -n "Ghidra|JNIAnalyzer|JNI_OnLoad|RegisterNatives" references/stage1.5-native.md | wc -l                                                                       # expect >=3
rg -ni "only when|if .*\.so.* present" references/stage1.5-native.md                                                                                              # expect >=1 (conditional-use note)
# 2.5 stage2: all 8 scanners + MobSF API + decision tree + OBB scan note
rg -c "MobSF|mobsfscan|semgrep|apktriage|quark|APKLeaks|APKiD|Ghidra" references/stage2-scan.md                                                                   # 8 scanners referenced
rg -n "/api/v1/upload|/api/v1/scan" references/stage2-scan.md                                                                                                     # MobSF API intact
rg -ni "quark.*80|>=\s*80|decision" references/stage2-scan.md                                                                                                     # decision tree present
rg -ni "\.obb|expansion|hidden.*dex|dex.*payload" references/stage2-scan.md                                                                                       # OBB scan note present
# 2.6 stage3: patterns table + manual/no-auto-patch + cert-pinning tools + legal restatement
rg -c "return-void|const-string|<receiver>|<service>|uses-permission|System.loadLibrary" references/stage3-remediate.md                                            # >=5 pattern rows
rg -ni "manual|no auto-?patch|inherently manual" references/stage3-remediate.md                                                                                   # >=1
rg -c "apk-mitm|android-unpinner" references/stage3-remediate.md                                                                                                  # both cert-pinning tools
rg -ni "authoriz|own|legal|lawful" references/stage3-remediate.md                                                                                                 # legal gate restated (D10)
# 2.7 stage4: order + non-reuse constraints + apksigner primary
rg -ni "zipalign.*before.*sign|BEFORE.*sign" references/stage4-rebuild-sign.md                                                                                    # ordering constraint
rg -ni "cannot reuse|different signer|original.*signature" references/stage4-rebuild-sign.md                                                                       # non-reuse constraint
rg -n "apksigner sign" references/stage4-rebuild-sign.md && rg -ni "uber-apk-signer.*optional|optional.*uber" references/stage4-rebuild-sign.md                     # D6 reflected
# 2.8 stage5: static re-scan + dynamic + OBB carry-through
rg -c "mobsfscan|apktriage|quark" references/stage5-validate.md && rg -c "frida|objection|Objection|Frida" references/stage5-validate.md                            # both static + dynamic
rg -ni "aapt dump permissions|permission diff|grep.*http" references/stage5-validate.md                                                                            # re-scan checks
rg -ni "adb push|Android/obb|\.obb" references/stage5-validate.md                                                                                                 # OBB carry-through step present
# 2.9 tool-disposition: tagging + priority-3
rg -c "KEEP|ADD|REPLACE|ELEVATE|Keep|Add|Replace|Elevate" references/tool-disposition.md                                                                          # tags present
rg -ni "priority|if you can only add 3|top 3" references/tool-disposition.md                                                                                       # priority-3 list present
```

### Phase 3 — `apk-plug` CLI + installer (after Phase 2; CLI encodes the documented commands)

Build the deterministic-work offload as a `pip`/`pipx`-installable Python package (D11–D13). Wrap ONLY the deterministic seams; Stage 3 stays with the agent.

- **3.1** `cli/pyproject.toml` — package `apk_plug`, entry point `apk-plug = apk_plug.__main__:main`, pinned runtime deps (argparse or click; `jsonschema` for schema validation; `androguard` optional/transitive). Requires Python ≥3.10. **Accept:** `pip install -e cli/` succeeds; `apk-plug --help` lists all 6 subcommands.
- **3.2** `runner.py` — one guarded subprocess helper used by every stage: explicit `timeout`, captured stdout/stderr, non-zero → raise typed error with actionable message (missing tool → "install X via install-toolchain.sh"), never a raw traceback to the user. **Accept:** unit test: missing-binary path returns actionable error string, not `FileNotFoundError` stack.
- **3.3** `workspace.py` — create/resolve timestamped `workspace/<apk>_<ts>/` scaffold (dirs from draft §1.3), persist stage state so subcommands are resumable and order-checked (`scan` refuses to run before `decompile`). **Accept:** `apk-plug init <apk>` creates scaffold; running `scan` on a fresh ws errors "decompile first".
- **3.4** `stage0_input.py` (`apk-plug init`) — detect format by extension + content signature; route per D14: `.aab`→bundletool `build-apks --mode=universal` (extract `universal.apk`); `.xapk`/`.apkm`/`.apks`/`.zip`/loose split set→**APKEditor** `m -i <in> -o target.apk`; `.apk`→pass through. Extract any bundled `.obb` into `input/obb/` and record them in workspace state (`manifest.json` from XAPK, if present, informs package name + OBB list). **Accept:** unit tests: fixture `.aab`→single `target.apk` (bundletool path); fixture `.xapk` and `.apkm`→single merged `target.apk` (APKEditor path); `.xapk` carrying an `.obb`→file lands in `input/obb/`; plain `.apk`→pass through unchanged.
- **3.5** `stage1_decompile.py` (`apk-plug decompile`) — jadx (`--deobf --show-bad-code`) + apktool `d` + native `lib/*` extract. **Accept:** on a benign fixture APK produces `decompile/java/` and `decompile/smali/`; `lib/*` extracted when present.
- **3.6** `stage2_scan.py` (`apk-plug scan`) — run applicable scanners (skip unavailable with a logged warning, not a crash); MobSF via API when reachable, else skip-and-note. Also unzip + scan any `input/obb/*.obb` for hidden DEX/payloads (D14 malware-hiding surface). Hands raw outputs to `normalize.py`. **Accept:** with any single scanner present, produces raw outputs + proceeds to normalize; an `.obb` fixture containing a DEX is flagged in the raw outputs.
- **3.7** `normalize.py` + `report.py` (★ centerpiece, D12) — merge MobSF JSON + quark score + semgrep SARIF + APKLeaks JSON + APKiD text + apktriage YARA/MITRE into one `threat-report.json` (components, URLs, permissions, MITRE techniques, per-tool severity, aggregate risk); validate against `assets/threat-report.schema.json`. Missing scanners degrade gracefully (fields marked `not_run`). **Accept:** `test_normalize.py` golden-file: `tests/fixtures/*` → byte-stable `threat-report.json`; output validates against schema.
- **3.8** `verify.py` (`apk-plug verify --stage N`) — encode per-stage gates (draft §2.3/§3.5/§4.5/§5.4): manifest XML validity, `.java`/`.smali` presence, dangling-reference grep, `apksigner verify`. Exit non-zero on any failed gate. **Accept:** `test_verify.py`: synthetic broken workspace → non-zero + which gate failed named.
- **3.9** `stage4_rebuild.py` (`apk-plug rebuild`) — apktool `b` → `zipalign -p 4` → `apksigner sign` (v1+v2+v3), keystore from args/env, **order enforced in code** (align before sign) so the footgun is unreachable. **Accept:** unit test asserts zipalign invoked before apksigner; missing keystore → actionable error.
- **3.10** `stage5_validate.py` (`apk-plug validate`) — re-run mobsfscan/apktriage/quark on rebuilt APK, permission diff (original vs fixed), residual C2-string grep. If `input/obb/` is non-empty, emit the `adb push <obb> /sdcard/Android/obb/<pkg>/` commands (or run them when a device is attached) so the smoke test does not false-negative on a missing-expansion crash (D14). **Accept:** produces `reports/post-fix/` + a diff summary; exits non-zero if new-vs-baseline permission set is unexpectedly broader; OBB push commands emitted when `input/obb/` is populated.
- **3.11** `assets/threat-report.schema.json` — author the JSON Schema the normalizer validates against. **Accept:** `jsonschema` validates the golden `threat-report.json`; schema `$id` + `required` fields present.
- **3.12** `scripts/install-toolchain.sh` — bootstrap external OSS (draft §1.2 + additions installer, pinned version vars at top incl. `APKEDITOR_VER` + jar download from REAndroid/APKEditor releases, D8, `set -euo pipefail`, idempotent `ln -sf`/`mkdir -p`, guard `ANDROID_HOME`/`GHIDRA_HOME` with actionable errors) THEN `pipx install ./cli`. `chmod +x`, forward-slash, LF line endings (C4). **Accept:** `bash -n` clean; `APKEDITOR_VER` present as a pinned var + APKEditor jar fetched; missing-env prints actionable error not a trace; after run, `apk-plug --help` works.

**Phase 3 QA (run from the package dir):**

```
python -m pytest cli/tests -q                         # all normalizer + gate + stage unit tests green
apk-plug --help                                        # lists init/decompile/scan/verify/rebuild/validate
python -c "import json,jsonschema; jsonschema.validate(json.load(open('cli/tests/fixtures/expected-threat-report.json')), json.load(open('assets/threat-report.schema.json')))"   # golden report validates
bash -n scripts/install-toolchain.sh                   # installer parses clean
rg -n "zipalign" cli/src/apk_plug/stage4_rebuild.py && rg -n "apksigner" cli/src/apk_plug/stage4_rebuild.py   # align+sign both present (order asserted by test)
rg -ni "APKEditor" cli/src/apk_plug/stage0_input.py && rg -ni "bundletool" cli/src/apk_plug/stage0_input.py   # D14: both merge routes present
rg -ni "obb" cli/src/apk_plug/stage0_input.py cli/src/apk_plug/stage2_scan.py cli/src/apk_plug/stage5_validate.py   # OBB extract+scan+carry-through wired
rg -n "APKEDITOR_VER" scripts/install-toolchain.sh    # APKEditor pinned + fetched
```

### Phase 4 — assets/

- **4.1** `llm-analysis-prompt.md` ← draft §4.4 template (scanner context → smali block → jadx Java → 4 tasks). **Accept:** all 4 tasks + "prefer return-void/const-string over deletion" guidance present.
- **4.2** `cheatsheet.md` ← two columns: the `apk-plug` one-liner per stage (`init/decompile/scan/verify/rebuild/validate`) as the primary path, plus the underlying raw tool commands (draft §10, extended: Stage 0 normalize, Stage 2 mobsfscan/semgrep/apkleaks, Stage 5 re-scan) as the fallback/"what it runs under the hood". **Accept:** every `apk-plug` subcommand present; Stage 0–5 covered; Stage 3 shown as the manual/agent gap between `scan` and `rebuild`.
- **4.3** `assets/yara/README.md` — explain the draft §7 gap-closing exercise (LurkerX detection rule authoring); directory holds custom `.yar` files. **Accept:** references apktriage YARA integration.

**Phase 4 QA (run from the package dir:** `cd apk-remediation-pipeline` **first; each stated expectation must hold or the task FAILS):**

```
# 4.1 llm-analysis-prompt: all 4 tasks + neutralize-over-delete guidance
rg -c "^\s*[1-4]\.|Explain|Identify|Propose|List" assets/llm-analysis-prompt.md                                                                                   # >=4 (the four tasks)
rg -ni "return-void|const-string|prefer.*over deletion|avoid.*verification" assets/llm-analysis-prompt.md                                                          # >=1 guidance line
rg -c "smali|jadx|MobSF|Quark|MITRE" assets/llm-analysis-prompt.md                                                                                                # scanner-context slots present
# 4.2 cheatsheet: apk-plug subcommands + raw tools + Stage 0-5 + manual Stage 3 gap
rg -c "apk-plug init|apk-plug decompile|apk-plug scan|apk-plug verify|apk-plug rebuild|apk-plug validate" assets/cheatsheet.md                                     # all 6 subcommands present
rg -ci "bundletool|jadx|apktool|mobsfscan|semgrep|apkleaks|zipalign|apksigner|re-scan" assets/cheatsheet.md                                                        # >=6 underlying raw tools shown
rg -ni "STAGE 3|manual|agent|remediat" assets/cheatsheet.md                                                                                                       # Stage 3 shown as manual gap
# 4.3 yara README: apktriage YARA wording + LurkerX exercise
rg -ni "apktriage|YARA|\.yar" assets/yara/README.md                                                                                                              # >=1
rg -ni "LurkerX|gap|detection rule|custom rule" assets/yara/README.md                                                                                            # exercise referenced
```

### Phase 5 — Validation & Testing (gates Done)

- **5.1** Run `skill-validator check --strict ./apk-remediation-pipeline` (fallback `npx skills-ref validate ./apk-remediation-pipeline/SKILL.md`). Fix all errors/warnings. **Accept:** exit 0, no errors.
- **5.2** Token/line budget check on SKILL.md. **Accept:** ≤500 lines; if over, move detail to references.
- **5.3** Three evaluations → log in `TESTING.md`: (a) representative remediation task WITHOUT skill (note gaps), (b) same task WITH skill (gaps closed), (c) unseen task e.g. "remove cert pinning + rebuild" (trigger fires, instructions transfer). **Accept:** all three logged with observations.
- **5.4** Optional: `skillshare` install to `~/.agents/skills/` and confirm discovery in a fresh session. **Accept:** skill appears in available_skills; description triggers on a test phrase.

---

## 5. Cross-Cutting Constraints

- **C1** SKILL.md ≤500 lines / \~5k tokens; dense imperative voice, no polite-prose padding, no second person.
- **C2** `description` is the ONLY trigger surface — must carry the keywords; no `triggers:` field relied upon.
- **C3** References one level deep; forward slashes; TOC on any file &gt;100 lines.
- **C4** Skill authored on Windows but the CLI + installer target the POSIX runtime (Linux/WSL2/macOS). Do NOT rewrite the bootstrap as pwsh. Author `install-toolchain.sh` and all `cli/` files with LF line endings.
- **C5** No time-sensitive phrasing baked into SKILL.md body (dates/versions live in `prerequisites.md` and the installer's version vars, clearly marked as "verify latest").
- **C6** Preserve the safety posture: legal gate up front, Stage 3 stays manual, no auto-patching, keystores gitignored. The CLI intentionally has NO `fix`/`patch`/`remediate` subcommand.
- **C7** No voodoo constants: external tool versions are named vars in the installer; the CLI reads tool paths from PATH/env and never hard-codes versions.
- **C8** CLI scope discipline (D11): every subcommand must be a *deterministic* operation. If a proposed feature requires judgment (interpreting findings, choosing patches), it belongs in the agent/SKILL.md flow, NOT the CLI. Reject scope creep into Stage 3.
- **C9** Graceful degradation: any absent scanner/tool at `scan`/`validate` time is logged and marked `not_run` in `threat-report.json` — never a hard crash. The CLI must be useful with a partial toolchain.

---

## 6. Risks & Mitigations

| Risk | Mitigation |
| --- | --- |
| SKILL.md bloats past 500 lines when merging both draft halves | D5 spine-only rule; push ALL matrices/commands to references. |
| Version-pinned installers rot (URLs 404) | Versions as top-of-file vars + `prerequisites.md` "verify latest release" note; not hard-coded inline. |
| Windows-authored scripts get CRLF and break on Linux | C4: enforce LF; validator/`bash -n` on a POSIX host or WSL before Done. |
| Trigger phrases too generic → skill mis-fires vs `security-research` | 1.2 disambiguation clause: "static single-APK remediation, NOT team-mode audit / dynamic pentest". |
| Scanner tools require keys/Docker not present at author time | CLI graceful degradation (C9): absent tool → `not_run`, not crash; skill documents prerequisites, does not assume them installed. |
| CLI becomes a thin wrapper adding maintenance for no value | D11 scope rule: wrap ONLY normalization/orchestration/gates/ordering — the parts that waste tokens or invite footguns. Single-tool passthroughs stay minimal; the value lives in `normalize.py`. |
| `threat-report.json` schema drifts from normalizer output | 3.11 + Phase 3 QA: golden-file test + `jsonschema` validation gate the report against `assets/threat-report.schema.json` on every run. |
| Scope creep pulls remediation into the CLI | C8 hard rule: no `fix`/`patch` subcommand; pipeline halts after `scan`, resumes at `rebuild`. |

---

## 7. Execution Order Summary

```
Phase 0 (scaffold) → Phase 1 (SKILL.md spine) → Phase 2 (references, parallel)
→ Phase 3 (apk-plug CLI + installer) → Phase 4 (assets) → Phase 5 (validate + 3 evals) → DONE
```

Phase 1 blocks 2–4 (references + SKILL.md name the `apk-plug` commands; the CLI encodes what the references document). Within Phase 3, `runner.py` (3.2) and `workspace.py` (3.3) block the stage modules; `normalize.py`+schema (3.7/3.11) are the critical path. Phase 5 is the acceptance gate. No implementation begins until this plan is approved.