# gate.cat — canned answers to the two hardest objections

From the adversarial product council (rada#2, 2026-07-03). These are the two
objections most likely to land first on Hacker News / in a maintainer's reply.
Pre-written so the answer is calm and honest, not defensive. Reuse verbatim or
trim into a README FAQ.

Ground rule for every answer: **never overclaim.** The honest line ("the gate is
certain only about what it blocks; unchecked ≠ safe") is a feature here, not a
liability — it's what separates this from a guard that promises everything.

---

## Objection 1 — "LangGraph `interrupt` / HumanLayer already do this."

> **Short answer:** Those are approval *flows* you have to remember to call.
> gate.cat is a *deny-list* that fires whether or not the agent (or the
> developer) remembered to route the call through an approval step.

**Full answer:**

`interrupt` and HumanLayer are excellent when the agent *chooses* to pause for a
human. The autogen#7770 loss ($106k, Terraform to the wrong AWS account) happened
precisely because the agent *didn't* — the incident author's own words:
*"Prompt-based rules are documentation. They are not enforcement."*

The difference is where the check lives:

- **Approval flow (interrupt/HumanLayer):** in the agent's control flow. A
  prompt-injection, a forgotten wrapper, or a session relogin that drops the
  convention, and the dangerous call goes straight through.
- **gate.cat as a PreToolUse hook:** in the harness, *outside* the agent's
  control flow. The tool cannot execute without the gate returning first. The
  agent can't forget a hook it doesn't control.

We're honest about the ladder: our **framework adapters** (crewAI/LangGraph) are
in-process convention — same trust class as interrupt, and prompt-injection can
route around them. The **Claude Code hook** is real enforcement. If you want the
strong guarantee, use the hook; if you want convenience inside a framework, use
the adapter and know its limit. We document exactly which is which — see the
"Trust boundary" section of the README.

So it's not "instead of" `interrupt` — it's the deterministic floor underneath
it, for the case where the approval step never got called.

---

## Objection 2 — "It's just regexes / an LLM judge would be smarter."

> **Short answer:** On an irreversible action you want a firewall, not a witness.
> A firewall is "just rules" and that is exactly why you trust it in the
> enforcement path. A probabilistic judge can hallucinate a pass on the one
> `terraform destroy` that mattered.

**Full answer:**

For `terraform destroy` against prod, I don't want a smart guard — I want one
that behaves the *same way every time* and fails **closed**. Properties that
matter on an irreversible action, and which an LLM judge doesn't give you:

- **Deterministic** — the same command gets the same verdict, always. No
  temperature, no "it depends on the phrasing."
- **Fail-closed** — engine down, weird input, unreadable decision → block, never
  a silent allow.
- **Auditable** — every decision (allow *and* block) is one JSON line in
  `~/.gatecat/veto_log.jsonl`. You can prove after the fact what the gate saw.
- **Can't be talked out of it** — a deny pattern doesn't get persuaded by a
  cleverly worded prompt the way an LLM judge can.

And we publish the gate's limits instead of hiding them: the
[bypass suite](gatecat/integrations/bypass_suite.py)
runs in CI and prints its own map — on 0.4.18 (measured 2026-07-29) it catches
178/178 of the dangers it *claims*, false-blocks 1 of 129 benign commands, and
names **3 regex-wall gaps**, of which **2 slip the whole product**: a Unicode
homoglyph binary name (U+FF52 fullwidth `r` + `m`, which no `rm` pattern matches)
and `rm` bytes assembled by `printf` and piped to a shell. The third (`rm`
assembled into a shell variable at runtime) clears the regex wall but the
delete-analyzer still blocks it downstream. The honest line is mechanical: the
gate is certain only about what it **blocks**; everything else is *unchecked, not
safe*. (Register: F4 in [FACTS.md](FACTS.md).)

A smarter judge is a fine *second* layer for the fuzzy cases. But the layer that
actually stops the $0.03-command-that-costs-$106k should be the boring,
deterministic, fail-closed one. That's this.
