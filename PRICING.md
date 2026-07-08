# Pricing

The core is free forever. The gate you install with `pip install gate-cat` — the
deny-list, the exec analyzer, the Claude Code hook, the framework adapters, the
CLI dashboard — is Apache-2.0 and complete. It is not a trial and nothing in it
is rate-limited or held back.

What costs money is **gate.cat Cloud**: the hosted layer *around* the gate —
your veto history in one place, alerts, and a monthly audit report you can hand
to whoever asks "prove no agent could have done that."

> **Architecture promise (this is load-bearing):** Cloud is an optional
> *reporter* that sits beside the gate, never in its execution path. The gate
> stays local, deterministic and fail-closed. If Cloud is down, unreachable, or
> cancelled, your gate keeps blocking exactly as before. A security tool that
> phones home before acting would be a different — and worse — product.

## Tiers

| | **Free** | **Solo — $9/mo** | **Team — $199/mo** | **Enterprise pilot** |
|---|---|---|---|---|
| The gate itself (veto, hook, adapters) | ✅ full | ✅ full | ✅ full | ✅ full |
| Local CLI dashboard (`gate.cat`) | ✅ | ✅ | ✅ | ✅ |
| Hosted veto history + email alerts | — | ✅ | ✅ | ✅ |
| Monthly audit report ("what the gate stopped") | — | ✅ yours | ✅ fleet-wide, compliance-ready | ✅ + custom scope |
| Central policies pushed to a fleet | — | — | ✅ | ✅ |
| Priority support | — | email | ✅ | dedicated |
| Deployment on your infra + Gate Report | — | — | — | ✅ |
| | | [**Subscribe →**](https://buy.stripe.com/6oUaEQ0cZ6uYaly2Vo67S04) | [**Subscribe →**](https://buy.stripe.com/14AdR2gbX1aE1P2anQ67S05) | [email us](mailto:bogumil@bgml.ai?subject=gate.cat%20enterprise%20pilot) — $7,500/yr, 2–3 slots per quarter |

Prices in USD. Cancel anytime. **30-day full refund, no questions** — if the
first report doesn't tell you something you wanted to know, you shouldn't pay
for it.

## Honest note on "Founding" pricing

You are early, and the price reflects it in both directions:

- **What you get today:** the full local gate (free part), your monthly audit
  report generated from your gate logs and delivered by email, priority
  support, and a **price locked forever** at the founding rate.
- **What ships within this month:** the hosted dashboard (veto history, alerts,
  self-serve report download). Founding subscribers get it the day it's live,
  at the price they already pay.
- **Why charge before the dashboard exists:** because the report is the
  product; the dashboard is the delivery mechanism. If that ordering bothers
  you, wait a month — the gate stays free either way.

## Why the anchor is an incident, not a competitor

One runaway `terraform destroy` loop cost a team ~$106k. One agent dropped a
production database. The question this pricing answers is not "what do similar
tools cost" but "what does the *absence* of a deterministic stop cost, once."
$9/month against that number is not a hard decision, and it isn't meant to be.

---

*Every capability claim above is bounded by [FACTS.md](FACTS.md) — the gate is
certain only about what it blocks. Cloud reports what happened; it does not
make the gate smarter.*
