# lobste.rs — wariant warunkowy (TYLKO jeśli masz konto; serwis invite-only)

Fact-checked 2026-07-22 przeciw FACTS.md (te same poprawki co show_hn_ready.md).
Lobste.rs preferuje treść techniczną bez pitchu — zero cen w poście; kultura
wymaga tagu `show`. Sugerowane tagi: `show`, `security`, `ai`.

## Tytuł

```
Gate.cat: deterministic action veto for AI coding agents (0 real misses across an 826k-command replay)
```

## Tekst (pole "Text")

```
gate.cat vetoes irreversible shell commands (rm -rf, DROP TABLE, terraform destroy, disk writes, secret exfiltration) before an AI coding agent executes them. Deterministic string + path analysis with an independent exec analyzer — no model call in the veto path, so prompt injection can't negotiate with it.

Enforcement points: a Claude Code hook (runs in the harness, outside the agent's control flow), a gated shell for any CLI agent (gatecat-shell), and a local OpenAI-API proxy (one base_url change covers Ollama/vLLM/OpenRouter).

Measurement over marketing: 826,644 unique real agent commands from 5 public datasets (lower bound, recounted 2026-07-28 with a global dedup) replayed through the full gate → 0 real misses after adjudication (the 2 catalog-flagged allows are disposable-artifact cleanups, adjudicated in the repo). The bypass suite catches 178/178 danger shapes it claims and prints 3 named regex-wall gaps (2 slip the whole product: a Unicode homoglyph and a printf-hex assembled rm; the 3rd, runtime-assembly, the delete-analyzer still catches) + 1 benign false-block in 129 cases. Every public number is pinned in FACTS.md to a reproducible artifact.

Honest limit: the gate is certain only about what it blocks — an unmatched action is unchecked, not safe. It's a complement to a sandbox, not a substitute.

Apache-2.0, zero-dependency core. pip install gate.cat
https://github.com/BGMLAI/gate.cat
```
