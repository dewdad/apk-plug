# Custom YARA Rules

Drop custom `.yar` files here. apktriage integrates YARA scanning into Stage 2,
so any rule placed in this directory can be wired into the scan to close a
detection gap the built-in rules miss.

## Gap-closing exercise (LurkerX)

`LurkerX` is a threat-reference tool (studied, **never executed**) that injects
GPS/SMS/contacts exfil plus a C2 channel into a benign APK, then rebuilds and
signs it. Use it as a validation target:

1. Run a LurkerX-modified sample through MobSF + apktriage + quark.
2. Confirm all three flag the injection: the added `<receiver>`/`<service>`, the
   new `INTERNET` + `ACCESS_FINE_LOCATION` + `READ_SMS` permissions, and the
   hardcoded C2 string in `assets/`.
3. **If any scanner misses it, write a custom YARA detection rule here** to close
   the gap, then re-run apktriage with this directory on its rule path.

A detection rule authored this way makes the miss reproducible-caught on the next
sample, hardening the pipeline against that injection pattern.
