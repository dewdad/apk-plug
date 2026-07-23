# TESTING — Evaluation Log

Eval-driven development per the skill-creator playbook: three runs establish that
the skill closes real gaps and that its triggers/instructions transfer to unseen
tasks. Each run records the task, the observed behavior, and the verdict.

## Structural validation (gate for Done)

| Check | Command | Result |
| --- | --- | --- |
| Spec + links + tokens | `npx skills-ref validate ./SKILL.md` | **PASS** — `Valid skill`, exit 0 |
| SKILL.md line budget | `(Get-Content SKILL.md).Count` | **212** lines (≤500) |
| Description hygiene | YAML parse of frontmatter | 658 chars, no angle brackets, 6 trigger phrases |
| Reference QA (Phase 2) | plan `rg` gate suite | 32/32 PASS |
| Asset QA (Phase 4) | plan `rg` gate suite | 8/8 PASS |
| CLI tests (Phase 3) | `python -m pytest cli/tests -q` | see [CLI test evidence](#cli-test-evidence) |

These are **real agent runs** (fresh `general` subagent sessions), not analytical
projections. Task prompt held identical across A and B; only skill exposure
differed.

## Eval A — representative task WITHOUT the skill (baseline)

**Task:** given `app.xapk` with a malicious SMS-intercepting receiver + hardcoded
C2, neutralize both and rebuild/re-sign. No skill provided.
**Run:** session `ses_071ba20ddffePFtlPL7CyBrecD` (22s).

**Observed:** a strong model unaided is *partially* competent — it did normalize
the XAPK (manual `unzip` + `manifest.json`), zipalign **before** sign, re-sign
splits with one key, gut with `return-void`, and redirect C2 to loopback. But the
gaps the skill exists to close all showed up:

1. **Ad-hoc scanning only** — manual `grep` for `SMS_RECEIVED` + URLs. No unified
   report, no quark behavioral score, no MITRE mapping, no APKiD packer check, no
   MobSF. Triage is eyeballed, not scored.
2. **Fragile split handling** — manual `unzip`/`zip` of the XAPK rather than a
   purpose-built merger (APKEditor).
3. **No systematic gates** — no per-stage pass/fail exit-code gating; correctness
   is assumed, not verified.
4. **No OBB handling**, **no decision-tree triage** (quark ≥ 80 routing).

**Verdict:** usable sketch, but no unified threat model, no reproducible gate
framework — exactly Stage 2 (unified report), Stage 0 (APKEditor), and the
verify-gate spine.

## Eval B — same task WITH the skill (gaps closed)

**Run:** session `ses_071ba2165ffeovhRvlauNzjIW0` (34s), after reading SKILL.md +
references.

**Observed:** followed the 5-stage `apk-plug` flow verbatim — `init` (routes
`.xapk` → APKEditor, extracts `.obb`), `decompile`, `scan` → one
`threat-report.json`, the quark ≥ 80 decision tree, Stage 3 **manual** with
neutralize-over-delete + `grep` dangling refs + `patches/CHANGELOG.md`, `rebuild`
(enforced `apktool b → zipalign → apksigner` order + different-signer note),
`validate` (permission diff, residual-C2 grep, OBB `adb push`), and a
`verify --stage N` gate after every stage. Every Eval-A gap maps to a named
stage + gate.

**Verdict:** the systematic scan matrix, single-report contract, and gate spine
that the baseline lacked are all present and correctly sequenced.

## Eval C — unseen task (trigger fires, instructions transfer)

**Task:** "strip certificate pinning and rebuild."
**Run:** session `ses_071ba1869ffecU0rSt3KL0iTt4` (22s).

**Observed:** correctly judged the skill activates ("verbatim trigger"), chose
**apk-mitm** over **android-unpinner** with sound reasoning ("*strip … and
rebuild*" wants a permanent artifact, not a runtime Frida hook), mapped all five
stages with pinning-specific notes (XAPK → merge via APKEditor first; native
pinning → fall back to android-unpinner), and preserved both the legal gate and
the `verify --stage N` gates.

**Verdict:** trigger fires on unseen phrasing and the stage instructions transfer
without modification.

## CLI test evidence (Phase 3, verified on the author host)

| Acceptance | Command | Result |
| --- | --- | --- |
| A install | `python -m pip install -e cli` | Successfully installed apk-plug |
| B subcommands | `python -m apk_plug --help` | exactly 6: init, decompile, scan, verify, rebuild, validate — **no fix/patch/remediate** |
| C tests | `python -m pytest cli/tests -q` | **66 passed** |
| D/F schema | golden `expected-threat-report.json` vs `assets/threat-report.schema.json` | validate → exit 0 (`schema-validate: OK`) |
| E installer | `wsl bash -n scripts/install-toolchain.sh` | exit 0 |
| C4 line endings | CRLF byte scan of all `.py` + `.sh` | 0 CRLF (all LF) |
| py_compile | `python -m py_compile cli/src/**/*.py` | exit 0 |

### Real end-to-end usage (manual QA, not self-report)

```
python -m apk_plug init sample.apk -w <tmp>      → workspace scaffold created (all §1.3 dirs)
python -m apk_plug scan -w <fresh-ws>            → "Cannot run 'scan' — run 'apk-plug decompile' first" (exit 1, order guard)
python -m apk_plug verify --stage 1 -w <fresh>   → FAILED, names manifest/java/smali gates (exit 1)
python -m apk_plug verify --stage 2 (no report)  → FAILED: threat_report_exists (exit 1)
python -m apk_plug verify --stage 2 (golden)     → PASSED: exists + schema-valid (exit 0)
python -m apk_plug verify --stage 5 (empty)      → FAILED: postfix_report_exists (exit 1)
python -m apk_plug verify --stage 5 (artifact)   → PASSED (exit 0)
```

### RED→GREEN proof for the two verify gates added during QA

The CLI shipped `verify` for stages 1/3/4 only, while the docs advertise gates
for all five stages. Added `verify_stage2` (report exists + schema-valid) and
`verify_stage5` (post-fix artifact present) via TDD:

- **RED:** `test_verify.py` stage-2/5 tests → `5 failed` (`ValueError: Invalid
  stage number ... Valid stages: 1, 3, 4`).
- **GREEN:** implemented the two gates + extended dispatch to 1–5 → `61 passed`.

### Structural validator (complete package)

`npx skills-ref validate ./SKILL.md` → `Valid skill`, exit 0.

## Live integration on WSL2 (real toolchain, real APK)

Ran the pipeline on Ubuntu/WSL2 against a **real 12 MB APK** (F-Droid client) with
a **real toolchain** — portable OpenJDK 21 (Adoptium, no sudo), jadx 1.5.1,
apktool 2.10.0, keystore via `keytool`. Scanners and Android SDK build-tools were
intentionally absent to exercise graceful degradation. CLI installed editable
from source (`pip install --user -e cli`) and driven via `python -m apk_plug`.

| Stage | Command | Real result |
| --- | --- | --- |
| 0 init | `apk-plug init app.apk -w …` | `.apk` passthrough; workspace scaffolded; exit 0 |
| 1 decompile | `apk-plug decompile` | **jadx exit 1 (bad-code) tolerated → apktool ran**: 11 019 `.java`, 39 402 `.smali`, manifest present, 4 native libs; exit 0 |
| 1 gate | `verify --stage 1` | PASSED (manifest valid, java+smali present) |
| 2 scan | `apk-plug scan` | all scanners absent → each marked `not_run`; **schema-valid `threat-report.json` produced**; exit 0 (no crash) |
| 2 gate | `verify --stage 2` | PASSED (report present + schema-valid) |
| 4 rebuild | `apk-plug rebuild -k test.jks …` | **`apktool b` really rebuilt `app-unsigned.apk` (12 MB)** → `zipalign` absent → actionable error `zipalign not found on PATH — install it via scripts/install-toolchain.sh`; align-before-sign order stopped it correctly |
| 4 (no keystore) | `apk-plug rebuild` (bad path) | actionable `Keystore error … provide --keystore path or set APK_PLUG_KEYSTORE` |

### Two real bugs found by the integration run and fixed (TDD)

1. **jadx non-zero exit aborted decompile.** jadx returns exit 1 on real APKs
   (un-decompilable classes) while still emitting Java; the CLI treated that as
   fatal and skipped `apktool`, blocking the whole pipeline.
   *Fix:* `run_jadx`/`run_apktool` tolerate a non-zero exit **when output was
   produced**, run independently, and raise an actionable `DecompileError` only
   if neither produced anything. Tests: `test_stage1_decompile.py` (RED 3 → GREEN).
2. **`rebuild` was unreachable.** `STAGE_ORDER` listed a `"verify"` step between
   `scan` and `rebuild`, but nothing ever marks `"verify"` complete (it is a
   cross-cutting gate, and Stage 3 is manual). Every `rebuild` failed with "run
   'apk-plug verify' first".
   *Fix:* removed `"verify"` from the linear chain (`init→decompile→scan→rebuild→
   validate`). Tests: `test_workspace.py::test_rebuild_reachable_after_scan` +
   `test_validate_reachable_after_rebuild` (RED 2 → GREEN).

Final suite after both fixes: **66 passed**. basedpyright: **0 errors** on all
CLI modules.

<!-- EVIDENCE:CLI -->
