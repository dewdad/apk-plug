# Stage 1.5 — Native Library Analysis

**Run only when `.so` files are present** in `decompile/native/` (i.e. the APK
shipped a `lib/` directory). This is the single biggest blind spot in a
smali-only pipeline: malware and sensitive logic increasingly move into native
`.so` libraries specifically to evade DEX-level analysis. If `decompile/native/`
is empty, skip this stage entirely.

## Tools

| Tool | Role |
| --- | --- |
| **Ghidra** (NSA, 69k★, Apache-2.0) | disassemble/decompile ARM/x86 native `.so` |
| **JNIAnalyzer** (Ghidra plugin) | auto-map JNI function signatures from the APK onto the native binary |

## Workflow

```bash
# Native libs were extracted in Stage 1:
ls decompile/native/lib/arm64-v8a/

# In Ghidra:
# 1. Import decompile/native/lib/arm64-v8a/libtarget.so
# 2. Run the JNIAnalyzer script → auto-applies JNI signatures
# 3. Inspect JNI_OnLoad and RegisterNatives → these register the Java↔native bridge
# 4. Follow exported functions for: network calls, file I/O, crypto, dynamic loading
```

## Why JNIAnalyzer specifically

It uses jadx to extract native method signatures from the APK and applies them to
the Ghidra binary, bridging the Java↔native boundary automatically. Without it
you manually correlate each `System.loadLibrary()` call with exported symbols and
guess at `RegisterNatives` argument types. `JNI_OnLoad` is the entry point the
loader calls first — start there.

## Feeding Stage 2

Findings from native analysis (hidden C2, crypto, dynamic DEX loading in the
`.so`) are recorded as Ghidra findings and merged into `threat-report.json` under
the `Ghidra` tool entry (see [stage2-scan.md](stage2-scan.md)).
