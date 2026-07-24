# How gate.cat compares

Honest positioning against the tools people will (rightly) mention. gate.cat is a **narrow**
tool — a deterministic, fail-closed veto for the irreversible-action class, enforced *outside*
the agent's control flow. It is not a general guardrail platform, and this page says so.

Ground rule (same as [FACTS.md](FACTS.md)): only claims we can back. Where a competitor is
*better* for a job, we say that.

## vs. approval flows — LangGraph `interrupt`, HumanLayer

These are the closest neighbors and the most common "you're reinventing this" comment.

| | LangGraph `interrupt` / HumanLayer | gate.cat |
|---|---|---|
| Where the check lives | In the agent's control flow (the agent must call it) | In the harness (Claude Code PreToolUse hook), outside the agent's control flow |
| Fires if the agent "forgets" / is injected | No — the call routes around it | Yes — the tool cannot execute until the gate returns |
| Determinism | Flow logic, app-defined | Deterministic deny-list; same command → same verdict |
| Best for | Rich human-in-the-loop UX, arbitrary approval logic | A hard floor under the approval step, for when it never got called |

**Honest limit:** gate.cat's *own* framework adapters (crewAI/LangGraph/AutoGen) are the **same
in-process trust class** as `interrupt` — a prompt injection can route around them. Only the
Claude Code hook is real enforcement. Use `interrupt`/HumanLayer for the UX; use gate.cat's hook
for the floor. Not "instead of" — underneath.

## vs. prompt-firewalls / detection — Lakera, Guardrails AI, NeMo Guardrails

These are broader I/O-validation frameworks (Guardrails AI and NeMo validate
inputs *and* outputs; Lakera leans input-detection). The contrast below is on the
axis that matters for the irreversible-action job, not a full feature comparison.

| | Detection / validation guardrails | gate.cat |
|---|---|---|
| Primary job | Detect or validate the model's *input/output* (prompt injection, jailbreak, PII, schema, toxicity) | Stop the destructive *action* at the tool boundary, regardless of how the model got there |
| Method | Often ML classifiers / probabilistic (some rule-based validators) | Deterministic deny-list + exec-check, fail-closed |
| Model coverage | Model-agnostic; tuned/marketed for frontier | Deliberately narrow — the uncertainty signal is strongest on 7–30B local models (the wedge frontier-first vendors don't target) |
| Fact-checking / hallucination | Some offer it | **No** — lookup channel is empty by default; not what this is for |

**Honest limit:** gate.cat does **not** do prompt-injection detection as its pitch (it's an
experimental, opt-in, off-headline layer). If your threat model is "detect the bad prompt," a
detection guardrail is the right tool. gate.cat's bet is the opposite end: *assume* the model
was talked into it, and stop the `terraform destroy` at the boundary anyway.

## vs. the "just use regexes yourself" objection

You could. gate.cat is 71 default policy walls for the irreversible-action class + an independent
exec analyzer + human-in-the-loop + a bypass suite that **prints its own known gaps** (base64
payloads, deletes via a language runtime, `curl|sh`) instead of pretending they don't exist,
+ the harness integration that makes it enforcement rather than advice. The value is the curation,
the fail-closed wiring, and the honest gap map — not the regex.

## What gate.cat is NOT

- Not a hallucination / fact-checker (lookup channel empty by default).
- Not a frontier-model guardrail (signal weakens there — AUC 0.68–0.71 vs 0.77–0.90 on 7–30B; internal measurement, artifact not yet published — FACTS F6/F7).
- Not blanket coverage: it owns OWASP **LLM06 (Excessive Agency)** and part of LLM01/05; it does
  not cover the other seven.
- Certain only about what it **blocks**. An unmatched action is *unchecked*, not *safe*.

See [OBJECTIONS.md](OBJECTIONS.md) for the two hardest objections answered in full.
