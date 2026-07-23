# Reply-bank: obiekcje pod żywymi wątkami (V4, 2026-07-23)

**Użycie:** wklej i DOSTOSUJ do wątku — nigdy nie auto-postuj, nigdy nie
wklejaj dwóch identycznych odpowiedzi w dwóch miejscach (HN/Reddit to
wyłapie). Kanałowo-agnostyczne (Reddit / X / LinkedIn / dev.to / HN-po-
reinstate). Wording z FACTS.md i OBJECTIONS.md. Publikuje wyłącznie owner.
Żadnych liczb gwiazdek/gwiazdkowych porównań (brak wiersza FACTS).

## 1. „LangGraph interrupt / HumanLayer już to robią" (skrót OBJECTIONS #1)

> Those are approval flows the agent has to remember to route through —
> in-process, inside the agent's control flow. gate.cat's Claude Code hook
> runs in the harness, outside that control flow: the tool call cannot
> execute until the gate returns, so there's nothing for a prompt injection
> or a forgotten wrapper to route around. It's not instead-of interrupt;
> it's the deterministic floor underneath it. Our own framework adapters
> are honestly labeled as the weaker trust class.

## 2. „To tylko regexy, LLM-judge byłby mądrzejszy" (skrót OBJECTIONS #2)

> On an irreversible action you want a firewall, not a witness — same
> verdict every time, fail-closed on errors, auditable, and impossible to
> talk out of its decision. A probabilistic judge can hallucinate a pass on
> the one terraform destroy that mattered. A smarter judge is a fine SECOND
> layer; the layer that stops the $0.03-command-that-costs-$106k should be
> the boring deterministic one.

## 3. „Vaporware / zero klientów"

> Fair — revenue is day-zero and we say so out loud. What exists and is
> checkable today: the full gate is on PyPI (Apache-2.0), and every public
> number has a row in FACTS.md pinned to a reproducible artifact — including
> 0 real recall misses across 1,085,159 real agent commands replayed through
> the full gate. Run `python -m gatecat.integrations.bypass_suite` yourself:
> it prints 178/178 caught plus its own named gap and its own false-block.
> Judge the evidence, not the customer count.

## 4. „Wystarczy sandbox / kontener"

> Use both — they answer different questions. A sandbox limits where damage
> lands; it can't tell you what the agent TRIED, and it won't stop a
> terraform destroy that has real credentials inside the sandbox. The gate
> stops the known-catastrophic shape before execution and logs every
> verdict. Defense-in-depth, not either/or — that's in our own docs, not a
> concession we make under pressure.

## 5. „Security theater — obfuskacja to obejdzie"

> Partly true, and we say it louder than our critics: the bypass suite in
> the repo prints its own named runtime-assembly gap, and the docs state
> that an unmatched action is unchecked, not safe. It's a deterministic
> wall in front of known-dangerous shapes — the class of mistake agents
> actually make daily — not a proof of safety. Theater hides its gaps;
> this ships a suite that prints them in CI.

## 6. „Open core → jutro paywall"

> The track record so far runs the other way: every time an audit found a
> catastrophic class missing (KMS/secret destroy, IAM escalation, backup
> destruction, identity/DNS HTTP-API), it was promoted INTO the free core —
> that rule is written in PRICING.md. Paid is only what an agent can't
> have by design: the off-machine, append-only copy of the veto history.
> The local gate is Apache-2.0; a paywall on safety would fork in a week
> and we know it.
