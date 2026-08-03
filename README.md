# apk-plug — APK Remediation Pipeline

An [Agent Skill](https://agentskills.io/specification) plus a bundled **`apk-plug`
CLI** that take a single Android app package through a five-stage
**static analysis → threat identification → manual remediation → rebuild & sign →
validation** workflow to strip malware, spyware, adware, trackers, and over-broad
permissions — using best-of-breed open-source tooling.

Works with OpenCode and other skills-compatible agents (Claude Code, Cursor,
Codex, Copilot, Gemini CLI, Goose).

The deterministic seams are driven by the `apk-plug` CLI; the irreducible
reasoning — **Stage 3 remediation** — stays with the agent/human.

## What it does

`apk-plug` wraps every deterministic stage. It **halts after `scan`** — Stage 3 is
agent/human work — then resumes at `rebuild`.

| Stage | Command | Tools | Output |
|---|---|---|---|
| 0. Normalize input | `apk-plug init <input>` | bundletool (`.aab`), APKEditor (`.xapk`/`.apkm`/splits), OBB extraction | timestamped `workspace/<apk>_<ts>/` |
| 1. Decompile (+1.5 native) | `apk-plug decompile` | [jadx](https://github.com/skylot/jadx) (Java review) + [apktool](https://github.com/iBotPeaches/Apktool) (editable smali); [Ghidra](https://github.com/NationalSecurityAgency/ghidra) + JNIAnalyzer for `.so` | `decompile/java`, `decompile/smali`, `decompile/native` |
| 2. Scan & triage | `apk-plug scan` | [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF), [apktriage](https://github.com/gpamarthy/apktriage), [quark-engine](https://github.com/quark-engine/quark-engine), [APKiD](https://github.com/rednaga/APKiD), [APKLeaks](https://github.com/dwisiswant0/apkleaks); source SAST: [mobsfscan](https://github.com/MobSF/mobsfscan), [semgrep](https://github.com/semgrep/semgrep) + [MASTG rules](https://github.com/mindedsecurity/semgrep-rules-android-security) | one schema-validated `threat-report.json` |
| 3. Remediate | *manual — not a CLI command* | agent/human reads the report, patches smali/manifest | edited `decompile/smali`, `patches/CHANGELOG.md` |
| 4. Rebuild, align & sign | `apk-plug rebuild --keystore <path>` | `apktool b` → `zipalign` → `apksigner` (v1+v2+v3, order enforced in code) | signed APK |
| 5. Validate | `apk-plug validate` | re-scan + permission diff + residual-C2 grep + optional Frida/Objection | pass/fail + diff |

Verify any stage's exit criteria with `apk-plug verify --stage N` (N = 1–5). Any
absent scanner is marked `not_run` in the report rather than crashing, so a partial
toolchain is usable.

A single-file, self-contained offline **HTML dashboard**
([assets/dashboard.html](assets/dashboard.html)) visualizes `threat-report.json`
(risk gauge, scanner-status matrix, findings table) — no CDN, no network, opens
straight from disk.

## Layout

```
apk-plug/
├── SKILL.md                       # the skill (frontmatter + 5-stage orchestration workflow)
├── cli/                           # the apk-plug Python package (pipx install ./cli)
│   ├── pyproject.toml
│   ├── src/apk_plug/              # stage0_input, stage1_decompile, stage2_scan,
│   │                              #   normalize, report, runner, stage4_rebuild,
│   │                              #   stage5_validate, verify, workspace
│   └── tests/                     # pytest suite (66 tests) + golden fixtures
├── references/
│   ├── prerequisites.md           # host matrix + one-shot bootstrap
│   ├── stage0-input.md            # AAB/XAPK/APKM/split/OBB routing
│   ├── stage1-decompile.md        # jadx + apktool + gates
│   ├── stage1.5-native.md         # Ghidra + JNIAnalyzer
│   ├── stage2-scan.md             # 8-scanner matrix + MobSF API + companion-data scan
│   ├── detection-heuristics.md    # reading threat-report.json: perms, C2, MITRE, packers
│   ├── stage3-remediate.md        # remediation patterns + cert-pinning
│   ├── remediation-recipes.md     # copy-paste smali edits per culprit class
│   ├── stage4-rebuild-sign.md     # build/align/sign
│   ├── stage5-validate.md         # re-scan + dynamic checks
│   └── tool-disposition.md        # keep/add/replace tool matrix
├── assets/
│   ├── dashboard.html             # self-contained offline threat-report SPA
│   ├── threat-report.schema.json  # the unified report contract
│   ├── sample-reports/            # AGC / duolingo-mod / duolingo-xapk samples
│   ├── cheatsheet.md              # one-glance command reference
│   ├── llm-analysis-prompt.md     # smali analysis reasoning aid
│   └── yara/                      # YARA notes
└── scripts/
    └── install-toolchain.sh       # bootstraps external OSS + runs pipx install ./cli
```

## Install

Clone into your agent's skills directory:

```bash
git clone https://github.com/dewdad/apk-plug.git ~/.config/opencode/skills/apk-plug
# or ~/.claude/skills/, ~/.agents/skills/, .opencode/skills/ (project-scoped)
```

Then bootstrap the toolchain and the CLI in one shot:

```bash
bash scripts/install-toolchain.sh      # installs external OSS at pinned versions
                                       # AND runs `pipx install ./cli` (puts apk-plug on PATH)
```

Per-tool install detail and the host matrix are in
[references/prerequisites.md](references/prerequisites.md).

### Host requirements

The runtime host must be **Linux, WSL2, or macOS** — the toolchain is POSIX.
Requires JDK 17+, Docker (for MobSF), Android SDK build-tools (`zipalign`,
`apksigner`), and Python 3.10+. The author host may be Windows;
`scripts/install-toolchain.sh` is bash and is not ported to PowerShell.

## Usage

Ask your agent: *"remediate this APK"*, *"scan this APK for malware"*, *"decompile
and rebuild this APK"*, *"strip certificate pinning and rebuild"*. Or drive the
CLI directly:

```bash
apk-plug init    app.xapk -w work/     # Stage 0: normalize (routes .xapk → APKEditor, extracts .obb)
apk-plug decompile                     # Stage 1: jadx (Java) ∥ apktool (smali) [+ Ghidra if native]
apk-plug scan                          # Stage 2: run all scanners → one threat-report.json
apk-plug verify --stage 2              #   gate: report present + schema-valid
#   ── HALT ── Stage 3: read threat-report.json, patch decompile/smali/ (see references/)
apk-plug verify --stage 3              #   gate: each threat edited, no dangling refs, manifest valid
apk-plug rebuild --keystore my.jks     # Stage 4: apktool b → zipalign → apksigner (enforced order)
apk-plug validate                      # Stage 5: re-scan + permission diff + residual-C2 grep
```

## Verification gates

| Stage | `apk-plug verify --stage` | Pass criteria |
|---|---|---|
| 1 Decompile | `--stage 1` | Manifest valid XML; ≥1 `.java`; ≥1 `.smali` |
| 2 Scan | `--stage 2` | `threat-report.json` present + schema-valid |
| 3 Remediate | `--stage 3` | Each threat edited; no dangling refs; manifest valid |
| 4 Rebuild | `--stage 4` | Build exit 0; aligned; `apksigner verify` valid |
| 5 Validate | `--stage 5` | Re-scan clean; permission set not broader; app launches |

Any failed gate exits non-zero and names the gate. Never proceed past a red gate.

## Development

```bash
python -m pip install -e cli          # editable install
python -m pytest cli/tests -q         # 66 tests
```

## License

[Apache-2.0](LICENSE)
