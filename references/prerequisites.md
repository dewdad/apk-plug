# Prerequisites & Environment

## Table of Contents

- [Host requirements](#host-requirements)
- [Tool matrix (what each stage needs)](#tool-matrix-what-each-stage-needs)
- [One-shot bootstrap](#one-shot-bootstrap)
- [Manual / per-tool install detail](#manual--per-tool-install-detail)
- [Directory scaffold](#directory-scaffold)
- [Verifying the install](#verifying-the-install)
- [Version pinning policy](#version-pinning-policy)

> All versions below are the pins current at authoring time. They are declared
> as named variables at the top of `scripts/install-toolchain.sh`; **verify the
> latest release** before a fresh bootstrap rather than trusting these numbers.

---

## Host requirements

| Requirement | Minimum | Recommended |
| --- | --- | --- |
| OS | Linux (Ubuntu 22.04+), macOS 13+, WSL2 | Ubuntu 24.04 LTS |
| RAM | 8 GB | 16 GB (MobSF + jadx concurrent) |
| Disk | 20 GB free | 50 GB (Docker images + APK caches) |
| Python | 3.10+ | 3.12 |
| Java (JDK) | 17 | 21 (jadx/apktool target) |
| Docker | 24+ (for MobSF) | 27+ |
| Android SDK build-tools | 34.0.0 | 35.0.0 (`zipalign`, `apksigner`) |

The author host may be Windows, but the pipeline tools are POSIX. Run the
runtime on Linux/WSL2/macOS. `install-toolchain.sh` is bash — do not port it to
PowerShell.

---

## Tool matrix (what each stage needs)

| Stage | Tool | Role | Install channel |
| --- | --- | --- | --- |
| 0 Input | **bundletool** | `.aab` → universal `.apk` | Android SDK cmdline-tools |
| 0 Input | **APKEditor** | merge `.xapk`/`.apkm`/`.apks`/splits → one APK | jar from REAndroid/APKEditor releases |
| 1 Decompile | **jadx** | DEX → Java (read-only review) | GitHub release zip |
| 1 Decompile | **apktool** | DEX → smali (round-trippable edit) | GitHub release jar |
| 1 Decompile | **dex2jar** | legacy fallback only if jadx fails | package manager |
| 1.5 Native | **Ghidra** | disassemble/decompile `.so` | ghidra-sre.org |
| 1.5 Native | **JNIAnalyzer** | Ghidra plugin: map JNI signatures | build from source vs `GHIDRA_HOME` |
| 2 Scan | **MobSF** | backbone: perms, secrets, manifest, malware | Docker image |
| 2 Scan | **mobsfscan** | source-level SAST on jadx output | pipx |
| 2 Scan | **semgrep** + MASTG rules | taint analysis, MASTG static tests | pipx + git clone |
| 2 Scan | **apktriage** | YARA + MITRE + APKiD, offline | pipx |
| 2 Scan | **quark**-engine | behavioral scoring 0–100 | pipx |
| 2 Scan | **APKLeaks** | URI/endpoint/secret extraction | pipx |
| 2 Scan | **APKiD** | packer/obfuscator fingerprint | pipx |
| 3 Fix | **apk-mitm** | automated cert-pinning removal (rebuild) | npm |
| 3 Fix | **android-unpinner** | runtime cert-pinning bypass (Frida) | pipx |
| 4 Sign | **zipalign** + **apksigner** | align + sign (primary) | Android SDK build-tools |
| 4 Sign | **uber-apk-signer** | optional one-shot debug sign | GitHub release jar |
| 5 Validate | **frida** + **objection** | dynamic runtime validation | pipx |

`androguard` underlies apktriage/quark and is pulled transitively.

---

## One-shot bootstrap

```bash
# From the skill package directory:
bash scripts/install-toolchain.sh
```

This bootstraps every external OSS tool at its pinned version, guards
`ANDROID_HOME` / `GHIDRA_HOME` with actionable errors, then runs
`pipx install ./cli` so the `apk-plug` command is on PATH.

---

## Manual / per-tool install detail

### jadx (DEX → Java)

```bash
JADX_VER="1.5.1"
curl -sL "https://github.com/skylot/jadx/releases/download/v${JADX_VER}/jadx-${JADX_VER}.zip" -o /tmp/jadx.zip
unzip -qo /tmp/jadx.zip -d "$HOME/.local/share/jadx"
ln -sf "$HOME/.local/share/jadx/bin/jadx" "$HOME/.local/bin/jadx"
```

### apktool (DEX → smali, round-trippable)

```bash
APKTOOL_VER="2.10.0"
curl -sL "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VER}/apktool_${APKTOOL_VER}.jar" -o "$HOME/.local/share/apktool.jar"
printf '#!/bin/sh\nexec java -jar "%s" "$@"\n' "$HOME/.local/share/apktool.jar" > "$HOME/.local/bin/apktool"
chmod +x "$HOME/.local/bin/apktool"
```

### Android SDK build-tools (zipalign + apksigner)

```bash
BT="$ANDROID_HOME/build-tools/35.0.0"
ln -sf "$BT/zipalign"  "$HOME/.local/bin/zipalign"
ln -sf "$BT/apksigner" "$HOME/.local/bin/apksigner"
```

### APKEditor (split/XAPK/APKM merger)

```bash
APKEDITOR_VER="1.4.9"
curl -sL "https://github.com/REAndroid/APKEditor/releases/download/V${APKEDITOR_VER}/APKEditor-${APKEDITOR_VER}.jar" -o "$HOME/.local/share/APKEditor.jar"
printf '#!/bin/sh\nexec java -jar "%s" "$@"\n' "$HOME/.local/share/APKEditor.jar" > "$HOME/.local/bin/apkeditor"
chmod +x "$HOME/.local/bin/apkeditor"
```

### bundletool (AAB only)

```bash
ln -sf "$ANDROID_HOME/cmdline-tools/latest/bin/bundletool" "$HOME/.local/bin/bundletool" 2>/dev/null || \
  echo "bundletool: download from https://developer.android.com/tools/bundletool"
```

### Scanners

```bash
docker pull opensecurity/mobile-security-framework-mobsf:latest   # MobSF
pipx install apktriage        # YARA + MITRE + APKiD, offline
pipx install quark-engine     # behavioral scoring
pipx install apkid            # packer fingerprint
pipx install mobsfscan        # source-level SAST
pipx install semgrep          # taint analysis
git clone https://github.com/mindedsecurity/semgrep-rules-android-security "$HOME/.local/share/semgrep-rules-android-security"
pipx install apkleaks         # endpoint/secret extraction
```

### Stage 1.5 native

```bash
# Ghidra: download from https://ghidra-sre.org/ and set GHIDRA_HOME
git clone https://github.com/Ayrx/JNIAnalyzer /tmp/JNIAnalyzer
cd /tmp/JNIAnalyzer && gradle -PGHIDRA_INSTALL_DIR="$GHIDRA_HOME"
# install the built .zip via Ghidra → File → Install Extensions
```

### Stage 3 cert-pinning + Stage 5 dynamic

```bash
npm install -g apk-mitm       # cert-pinning removal (rebuild)
pipx install android-unpinner # runtime pinning bypass
pipx install frida-tools      # dynamic instrumentation
pipx install objection        # Frida wrapper
```

### uber-apk-signer (optional)

```bash
UAS_VER="1.2.1"
curl -sL "https://github.com/patrickfav/uber-apk-signer/releases/download/v${UAS_VER}/uber-apk-signer-${UAS_VER}.jar" -o "$HOME/.local/share/uber-apk-signer.jar"
```

---

## Directory scaffold

`apk-plug init` creates this per-APK, timestamped, under `workspace/`:

```
workspace/<apk>_<ts>/
├── input/              # normalized target.apk
│   └── obb/            # extracted .obb expansion files
├── decompile/
│   ├── java/           # jadx output (read-only reference)
│   ├── smali/          # apktool output (editable)
│   └── native/         # extracted lib/*.so
├── scan/
│   ├── mobsf/  mobsfscan/  semgrep/  apktriage/  quark/  apkleaks/
├── patches/            # diffs, edited manifests, CHANGELOG.md
├── build/
│   ├── unsigned/  aligned/  signed/
├── keystores/          # .jks / .keystore  (NEVER commit — gitignored)
└── reports/
    └── post-fix/       # Stage 5 re-scan output
```

---

## Verifying the install

```bash
jadx --version && apktool --version && apksigner --version
apk-plug --help          # lists init/decompile/scan/verify/rebuild/validate
```

---

## Version pinning policy

Every external tool version is a named variable at the top of
`scripts/install-toolchain.sh` (`JADX_VER`, `APKTOOL_VER`, `BT_VER`,
`APKEDITOR_VER`, `UAS_VER`, ...). The `apk-plug` CLI never hard-codes a version;
it resolves tool paths from PATH/env. To bump a tool, edit the variable and
re-run the bootstrap. Confirm each pinned release still exists before relying on
it — release URLs rot.
