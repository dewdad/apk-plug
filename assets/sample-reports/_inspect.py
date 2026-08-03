import json, glob, os, collections

here = os.path.dirname(__file__)
for p in sorted(glob.glob(os.path.join(here, "*.threat-report.json"))):
    d = json.load(open(p, encoding="utf-8"))
    print("=" * 70)
    print("FILE:", os.path.basename(p))
    print("top-level keys:", list(d.keys()))
    print("aggregate_risk:", d["aggregate_risk"])
    print("tools:")
    for t, v in sorted(d["tools"].items()):
        print("   ", t, "->", v)
    print("findings tools:", list(d["findings"].keys()))
    for tool, lst in d["findings"].items():
        print(f"  -- findings[{tool}] count={len(lst)}")
        # show up to 2 distinct-shaped samples
        seen_keys = set()
        shown = 0
        for f in lst:
            k = tuple(sorted(f.keys()))
            if k not in seen_keys:
                seen_keys.add(k)
                print("      sample:", json.dumps(f, ensure_ascii=False)[:240])
                shown += 1
            if shown >= 3:
                break
        # rule frequency
        rules = collections.Counter(f.get("rule", "?") for f in lst)
        print("      top rules:", rules.most_common(5))
        sev = collections.Counter(f.get("severity", "?") for f in lst)
        print("      severities:", dict(sev))
    print("urls sample:", d["urls"][:3])
    print("permissions sample:", d["permissions"][:5])
    print("components count:", len(d["components"]), "mitre count:", len(d["mitre_techniques"]))
