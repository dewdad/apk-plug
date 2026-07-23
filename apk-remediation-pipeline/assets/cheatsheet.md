# apk-plug Cheat Sheet

The `apk-plug` subcommand is the **primary path** for each stage. The raw tool
commands show **what it runs under the hood** (and are the fallback when driving
a tool directly).

## Primary path — the apk-plug pipeline

```
STAGE 0  NORMALIZE   apk-plug init <input.aab|.xapk|.apkm|.apk>   # → workspace/<apk>_<ts>/
STAGE 1  DECOMPILE   apk-plug decompile                          # jadx + apktool + native
STAGE 2  SCAN        apk-plug scan                               # → threat-report.json
── HALT ──  STAGE 3  REMEDIATE (manual / agent)                  # NO apk-plug command
                     read threat-report.json, patch smali+manifest by hand
STAGE 4  REBUILD     apk-plug rebuild --ks keystores/my.jks --alias mykey
STAGE 5  VALIDATE    apk-plug validate                           # re-scan + perm diff + OBB push
GATES    VERIFY      apk-plug verify --stage N                   # N = 1..5, exit-code gate
```

**Stage 3 is the manual gap** between `scan` and `rebuild`. The CLI has no
`fix`/`patch`/`remediate` subcommand — remediation is agent/human reasoning.

## Under the hood — raw tool commands

```
STAGE 0  bundletool build-apks --bundle=app.aab --mode=universal   # .aab only
         apkeditor m -i app.xapk -o target.apk                     # .xapk/.apkm/splits
STAGE 1  jadx --deobf --show-bad-code -d out_java app.apk
         apktool d -f -o out_smali app.apk
STAGE 2  mobsfscan out_java/ --sarif -o mobsfscan.sarif
         semgrep -c mastg-rules/ out_java/ --sarif -o semgrep.sarif
         apkleaks -f app.apk -o apkleaks.json
         apktriage app.apk --out apktriage/ && quark -a app.apk -s && apkid app.apk
         # MobSF: POST /api/v1/upload then /api/v1/scan
STAGE 3  edit out_smali/**/*.smali + AndroidManifest.xml           # manual
         npx apk-mitm app.apk    # or: android-unpinner all app.apk (cert pinning)
STAGE 4  apktool b out_smali -o unsigned.apk
         zipalign -f -p 4 unsigned.apk aligned.apk                 # align BEFORE sign
         apksigner sign --ks my.jks --out signed.apk aligned.apk
         apksigner verify --verbose signed.apk
STAGE 5  apktriage signed.apk --out post-fix/                      # re-scan, confirm clean
         quark -a signed.apk -s
         aapt dump permissions signed.apk                          # permission diff
         adb push main.obb /sdcard/Android/obb/<pkg>/              # OBB carry-through
         objection -g <pkg> explore                                # dynamic check
```
