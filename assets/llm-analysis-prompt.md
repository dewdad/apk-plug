# LLM Smali-Analysis Prompt Template

Use an LLM as a *reasoning aid* for Stage 3 — to explain smali and propose
patches — never as an auto-fixer. Fill the bracketed slots from
`threat-report.json` and the decompiled output, then send.

```
You are analyzing decompiled Android smali code for a security remediation task.

Context from scanners:
- MobSF flagged: [paste relevant MobSF finding]
- Quark behavior: [paste the weighted behavior sequence]
- MITRE technique: [e.g. T1437 - Application Layer Protocol]
- APKLeaks / semgrep hits: [paste endpoint or taint finding, if any]

Smali method in question:
​```smali
[paste the .method ... .end method block]
​```

Corresponding Java (from jadx):
​```java
[paste the decompiled Java method]
​```

Tasks:
1. Explain what this code does in plain English.
2. Identify the malicious/suspicious behavior.
3. Propose a minimal smali patch to neutralize it. Prefer return-void /
   const-string "" over deletion to avoid verification errors.
4. List any other files that reference this class/method that also need editing.
```

## Why these four tasks

1. **Explain** — force a plain-English model of the code before touching it.
2. **Identify** — name the exact malicious behavior, tied to the scanner finding.
3. **Propose** — a *minimal* patch. Neutralize-over-delete: replacing a method
   body with `return-void` or a URL with `const-string ""` keeps the DEX
   verifier happy, whereas deleting classes/methods often breaks references and
   the rebuild.
4. **List** — surface dangling references so Stage 3's `grep -r` gate passes.

The LLM proposes; you review and apply the edit by hand, then log it in
`patches/CHANGELOG.md`.
