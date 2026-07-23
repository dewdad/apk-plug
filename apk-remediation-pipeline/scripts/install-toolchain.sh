#!/usr/bin/env bash
# install-toolchain.sh — Bootstrap external OSS tools for apk-plug pipeline
# Target: Linux/WSL2/macOS (POSIX)
# Run: chmod +x install-toolchain.sh && ./install-toolchain.sh

set -euo pipefail

# =============================================================================
# VERSION PINS — update these when upgrading tools
# =============================================================================
JADX_VER="1.5.1"
APKTOOL_VER="2.10.0"
BT_VER="35.0.0"                    # Android SDK build-tools version
UAS_VER="1.2.1"                    # uber-apk-signer (optional)
APKEDITOR_VER="1.4.9"              # REAndroid/APKEditor

# =============================================================================
# ENVIRONMENT CHECKS
# =============================================================================
err() {
    echo "ERROR: $*" >&2
    exit 1
}

warn() {
    echo "WARN: $*" >&2
}

info() {
    echo "INFO: $*"
}

# Check ANDROID_HOME
if [[ -z "${ANDROID_HOME:-}" ]]; then
    err "ANDROID_HOME is not set — install Android SDK and set ANDROID_HOME to its path"
fi

if [[ ! -d "$ANDROID_HOME" ]]; then
    err "ANDROID_HOME points to non-existent directory: $ANDROID_HOME"
fi

# Check Java
if ! command -v java &>/dev/null; then
    err "Java not found — install JDK 17+ and ensure 'java' is on PATH"
fi

JAVA_VER=$(java -version 2>&1 | head -1 | cut -d'"' -f2 | cut -d'.' -f1)
if [[ "$JAVA_VER" -lt 17 ]]; then
    warn "Java version $JAVA_VER detected; JDK 17+ recommended"
fi

# Check pipx
if ! command -v pipx &>/dev/null; then
    err "pipx not found — install via: python -m pip install --user pipx && pipx ensurepath"
fi

# =============================================================================
# DIRECTORY SETUP
# =============================================================================
LOCAL_BIN="$HOME/.local/bin"
LOCAL_SHARE="$HOME/.local/share"
mkdir -p "$LOCAL_BIN" "$LOCAL_SHARE"

# Ensure ~/.local/bin is on PATH
if [[ ":$PATH:" != *":$LOCAL_BIN:"* ]]; then
    warn "$LOCAL_BIN is not on PATH — add it to your shell profile"
fi

# =============================================================================
# JADX — DEX to Java decompiler
# =============================================================================
info "Installing jadx v$JADX_VER..."
JADX_URL="https://github.com/skylot/jadx/releases/download/v${JADX_VER}/jadx-${JADX_VER}.zip"
curl -fsSL "$JADX_URL" -o /tmp/jadx.zip
unzip -qo /tmp/jadx.zip -d "$LOCAL_SHARE/jadx"
ln -sf "$LOCAL_SHARE/jadx/bin/jadx" "$LOCAL_BIN/jadx"
ln -sf "$LOCAL_SHARE/jadx/bin/jadx-gui" "$LOCAL_BIN/jadx-gui"
rm -f /tmp/jadx.zip
info "jadx installed: $(jadx --version 2>/dev/null || echo 'OK')"

# =============================================================================
# APKTOOL — APK disassembler/reassembler
# =============================================================================
info "Installing apktool v$APKTOOL_VER..."
APKTOOL_URL="https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VER}/apktool_${APKTOOL_VER}.jar"
curl -fsSL "$APKTOOL_URL" -o "$LOCAL_SHARE/apktool.jar"

# Create wrapper script
cat > "$LOCAL_BIN/apktool" << 'WRAPPER'
#!/bin/sh
exec java -jar "$HOME/.local/share/apktool.jar" "$@"
WRAPPER
chmod +x "$LOCAL_BIN/apktool"
info "apktool installed: $(apktool --version 2>/dev/null || echo 'OK')"

# =============================================================================
# APKEDITOR — APK/split merger (REAndroid)
# =============================================================================
info "Installing APKEditor v$APKEDITOR_VER..."
APKEDITOR_URL="https://github.com/REAndroid/APKEditor/releases/download/V${APKEDITOR_VER}/APKEditor-${APKEDITOR_VER}.jar"
curl -fsSL "$APKEDITOR_URL" -o "$LOCAL_SHARE/APKEditor.jar"

cat > "$LOCAL_BIN/APKEditor" << 'WRAPPER'
#!/bin/sh
exec java -jar "$HOME/.local/share/APKEditor.jar" "$@"
WRAPPER
chmod +x "$LOCAL_BIN/APKEditor"
info "APKEditor installed"

# =============================================================================
# ANDROID SDK BUILD-TOOLS — zipalign, apksigner
# =============================================================================
info "Linking Android SDK build-tools v$BT_VER..."
BT_PATH="$ANDROID_HOME/build-tools/$BT_VER"

if [[ ! -d "$BT_PATH" ]]; then
    warn "Build-tools $BT_VER not found at $BT_PATH"
    warn "Install via: sdkmanager 'build-tools;$BT_VER'"
    warn "Skipping zipalign/apksigner symlinks"
else
    ln -sf "$BT_PATH/zipalign" "$LOCAL_BIN/zipalign"
    ln -sf "$BT_PATH/apksigner" "$LOCAL_BIN/apksigner"
    info "zipalign and apksigner linked"
fi

# =============================================================================
# BUNDLETOOL — AAB to APK converter
# =============================================================================
info "Linking bundletool..."
BUNDLETOOL_PATH="$ANDROID_HOME/cmdline-tools/latest/bin/bundletool"
if [[ -f "$BUNDLETOOL_PATH" ]]; then
    ln -sf "$BUNDLETOOL_PATH" "$LOCAL_BIN/bundletool"
    info "bundletool linked"
else
    warn "bundletool not found at $BUNDLETOOL_PATH"
    warn "Download from: https://github.com/google/bundletool/releases"
fi

# =============================================================================
# UBER-APK-SIGNER (optional) — one-shot align+sign
# =============================================================================
info "Installing uber-apk-signer v$UAS_VER (optional)..."
UAS_URL="https://github.com/patrickfav/uber-apk-signer/releases/download/v${UAS_VER}/uber-apk-signer-${UAS_VER}.jar"
curl -fsSL "$UAS_URL" -o "$LOCAL_SHARE/uber-apk-signer.jar" || warn "uber-apk-signer download failed (optional)"

# =============================================================================
# PYTHON TOOLS via pipx
# =============================================================================
info "Installing Python security tools via pipx..."

# apktriage — offline YARA + MITRE scanner
pipx install apktriage || warn "apktriage install failed"

# quark-engine — behavioral scoring
pipx install quark-engine || warn "quark-engine install failed"

# APKiD — packer/obfuscator fingerprinting
pipx install apkid || warn "apkid install failed"

# mobsfscan — source-level SAST
pipx install mobsfscan || warn "mobsfscan install failed"

# semgrep — pattern-based SAST
pipx install semgrep || warn "semgrep install failed"

# APKLeaks — endpoint/secret scanner
pipx install apkleaks || warn "apkleaks install failed"

# frida-tools — dynamic instrumentation
pipx install frida-tools || warn "frida-tools install failed"

# objection — Frida wrapper for mobile
pipx install objection || warn "objection install failed"

# =============================================================================
# SEMGREP ANDROID SECURITY RULES
# =============================================================================
info "Cloning semgrep-rules-android-security..."
SEMGREP_RULES_DIR="$LOCAL_SHARE/semgrep-rules-android-security"
if [[ -d "$SEMGREP_RULES_DIR" ]]; then
    (cd "$SEMGREP_RULES_DIR" && git pull --quiet) || warn "Failed to update semgrep rules"
else
    git clone --quiet https://github.com/mindedsecurity/semgrep-rules-android-security "$SEMGREP_RULES_DIR" || warn "Failed to clone semgrep rules"
fi

# =============================================================================
# GHIDRA (manual)
# =============================================================================
if [[ -z "${GHIDRA_HOME:-}" ]]; then
    warn "GHIDRA_HOME not set — for native .so analysis, install Ghidra and set GHIDRA_HOME"
else
    info "GHIDRA_HOME is set: $GHIDRA_HOME"
fi

# =============================================================================
# APK-PLUG CLI
# =============================================================================
info "Installing apk-plug CLI..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_DIR="$SCRIPT_DIR/../cli"

if [[ -d "$CLI_DIR" ]]; then
    pipx install "$CLI_DIR" --force || err "Failed to install apk-plug CLI"
    info "apk-plug CLI installed"
else
    warn "CLI directory not found at $CLI_DIR — skipping apk-plug install"
fi

# =============================================================================
# VERIFICATION
# =============================================================================
echo ""
echo "============================================="
echo "Installation complete. Verifying tools..."
echo "============================================="

check_tool() {
    if command -v "$1" &>/dev/null; then
        echo "  ✓ $1"
    else
        echo "  ✗ $1 (not found)"
    fi
}

check_tool jadx
check_tool apktool
check_tool APKEditor
check_tool zipalign
check_tool apksigner
check_tool bundletool
check_tool apktriage
check_tool quark
check_tool apkid
check_tool mobsfscan
check_tool semgrep
check_tool apkleaks
check_tool frida
check_tool objection
check_tool apk-plug

echo ""
echo "Done. Add $LOCAL_BIN to your PATH if not already present."
echo "Run 'apk-plug --help' to get started."
