# Pricing

**The local gate is free forever. Cloud keeps the copy your agent can't touch.**

The core you install with `pip install gate-cat` — the deterministic policy
engine (deny-walls + an independent exec analyzer + human-in-the-loop), the
Claude Code hook, the framework adapters, the CLI dashboard, **and local
reports** (`gate.cat` CLI: stats, history, `why <cmd>`) — is Apache-2.0 and
complete. Not a trial; nothing is rate-limited or held back. The pip package
phones nowhere; Cloud is opt-in and **off by default**.

Why pay, then? Because a local log lives **inside the agent's blast radius**.
An agent with shell access can delete or rewrite the file that records what it
did — real incident reports include an agent that deleted a file and then hid
it from the user. The paid layer is the **off-machine, append-only copy of
your veto history** — the one thing the agent can't reach — plus alerts and a
monthly report generated from it. Same shape as offsite backup: you hope it's
boring, and you keep the receipts.

> **Architecture promise (load-bearing):** Cloud is an optional *reporter*
> beside the gate, never in its execution path. If Cloud is down, unreachable,
> or cancelled, the gate keeps blocking exactly as before. Policy sharing for
> teams works pull-only: a signed policy file your machines fetch and apply
> **after local review** — nothing remote ever executes or decides on your box.

## What leaves your machine (exact list)

| Sent to Cloud (only if you enable it) | Never sent |
|---|---|
| veto events: timestamp, policy id, verdict, and a **hash of the matched command (default)** — raw command text is a separate, explicit opt-in, because commands can contain secrets | file contents, env vars, keys, tokens |
| gate version + policy-set version | your code, prompts, model outputs |
| nothing else — the event schema is in the docs and the reporter is readable Python in the open repo | telemetry/analytics of any kind |

Retention: 12 months, export anytime (JSON), delete-account = hard delete.
One more honest boundary: the reporter's credentials live outside the agent's
transcript, but an agent with full shell access could kill the reporter
process. It cannot *rewrite* history that already left the machine — and a
silenced reporter shows up as a gap in the timeline, which is itself signal.
Full boundary, both directions: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Tiers

| | **Free** | **Solo — €19/mo** *(your agent, on the record)* | **Team — €149/mo flat, up to 10 machines** *(one policy, whole fleet)* | **Business** | **White-glove** |
|---|---|---|---|---|---|
| The gate: veto engine + **Claude Code hook** (enforcement in the harness) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Framework adapters (crewAI/LangGraph/AutoGen — in-process convention, honestly weaker than the hook) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Local CLI dashboard + local reports | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Off-machine veto history** (the copy the agent has no credentials for) + email alerts | — | ✅ | ✅ | ✅ | ✅ |
| Monthly report from the off-machine log | — | ✅ yours | ✅ fleet-wide | ✅ signed, + control mapping | ✅ custom scope |
| Shared signed policy file for a fleet (pull-only, local review) | — | — | ✅ *(rolling out)* | ✅ | ✅ |
| Evidence log self-hosted in **your** infra | — | — | — | ✅ | ✅ |
| Support | community | email | priority | dedicated | dedicated + custom policies |
| Price | €0 forever | €19/mo | €149/mo flat | €399/mo | custom |
| | | [**Start Solo →**](https://buy.stripe.com/7sY6oAaRD5qU79m2Vo67S09) | [**Start Team →**](https://buy.stripe.com/9B66oA5xj2eIaly2Vo67S0a) | [**Start Business →**](https://buy.stripe.com/7sYdR2e3PcTm2T6cvY67S0b) | [email us](mailto:bogumil@bgml.ai?subject=gate.cat%20white-glove) |

Stripe checkout is live and is the payment channel. Billing
includes automatic tax handling, cancellation at any time and a
**30-day full refund, no questions asked.**

## Policy Packs — €29 one-time (available now)

The 71 core policies are free forever and cover the universal, catastrophic
classes — that's the open-core rule: **safety everyone needs is never
paywalled** (KMS/secret destroy, IAM escalation, backup destruction and the
identity/DNS HTTP-API class were all *promoted into the free core* when audits
found them). Packs are stack-specific breadth on top, sold as one-time
products. Every rule is tested to fire on its danger and stay silent on the
benign twin — the same bar as the core gate.

| Pack | What it blocks | Buy |
|---|---|---|
| **Fintech** | refund creation, payouts/transfers, customer & billing-config deletion — Stripe CLI/SDK/REST, PayPal/Braintree/Adyen/Wise/Mercury (5 policies) | [**€29 →**](https://buy.stripe.com/dRm5kw6Bn3iMfFS1Rk67S0c) |
| **PaaS** | `vercel remove`, `netlify sites:delete`, `fly/heroku apps destroy`, `railway down`, `render/supabase delete` — deploy/list/info stay allowed | [**€29 →**](https://buy.stripe.com/3cI5kw3pbaLeeBO2Vo67S0d) |
| **HTTP-API Breadth** | destructive raw-HTTP calls to Datadog, Sentry, Slack admin, Atlassian, Docker Hub, PyPI, … — the modality CLI-verb walls never see (requires gate.cat ≥ 0.4.9) | [**€29 →**](https://buy.stripe.com/aFa8wIgbX06AdxK67A67S0e) |

Delivery is fully automated: pay → instant download page (wheel + install
instructions). Install = `pip install <wheel>` + one env var
(`GATECAT_EXTRA_POLICIES`). VAT is calculated automatically at checkout.
Packs load fail-closed: a pack that can't load blocks the gate rather than
silently running without it.

## Which anchor applies to you

- **Solo:** same shelf as the $3–10/mo peace-of-mind tools you already run —
  password vault, mesh VPN, offsite backup. There is a $5 competitor in this
  category; compare their published evidence with [FACTS.md](FACTS.md) (0 real
  recall misses across 1,085,159 real agent commands through the full gate; a
  bypass suite that prints its own gaps) and pick whichever you trust.
- **Team:** nearest per-seat alternatives price at $39–100 *per user per
  month* (market snapshot, 2026-07-08). Flat €149 costs less from the second
  developer onward and doesn't tax your team's growth up to 10 devs — larger
  fleets, email us.
- **Pilot & White-glove:** one runaway `terraform destroy` loop cost a team
  ~$106k; one agent dropped a production database. The pilot is priced at a
  fraction of a single incident.

## "Isn't a deny-list trivially bypassable?"

Partly — and we say so louder than our critics do. `python3 -c "import os;
os.unlink(...)"` is a named gap in our own published bypass map; the gate is a
wall in front of known-dangerous shapes, not a proof of safety, and an
unmatched action is *unchecked*, not *safe*. What we actually measure: the
full gate (not a regex list — six stages including an independent exec
analyzer) passed **0 real dangers out of 1,085,159 real agent commands**
(FACTS F1b, reproducible). Use it *with* your sandbox, not instead of one —
a sandbox can't tell you what the agent *tried*, and it won't stop a
`terraform destroy` that has real credentials inside the sandbox.

## The audit-readiness pilot, precisely

What a compliance buyer gets (and what we deliberately do not claim):

- **Evidence stays yours:** the veto log is collected append-only in **your**
  infrastructure (e.g. object storage with write-once retention — we provide
  the reference setup). We never hold the only copy of your evidence.
- **Signed monthly report** with explicit control mapping (which agent actions
  are gated, by which policy, with which verdicts) and a compensating-controls
  memo. Honest framing: this is **management evidence with reproducible
  artifacts your auditor can sample** — not a substitute for an independent
  audit.
- **Explicit scope:** coverage claims are limited to the enumerated danger
  classes in [RECALL.md](RECALL.md). Outside those classes = unchecked, and
  the report says so on page one.
- **Guarantee rider:** if the full gate passes a command from the covered
  classes in your logs during the pilot year, the next 12 months are service
  credit. Covered classes measure 100% recall (F1a) — the risk is known and
  honestly bounded to exactly what we claim.
- We are a solo-founder vendor without SOC2 today. That's why the evidence log
  is self-hosted and every report is reproducible from your own data — the
  trust model doesn't require believing us.

## Launch pricing

You are early, and the price reflects it in both directions:

- **Today:** the full local gate is free forever. Cloud checkout provisions the
  encrypted off-machine history account without a manual handoff.
- **Cloud:** the hosted dashboard includes history, alerts and self-serve report
  download. Team adds signed policy sharing and fleet reporting. **A redacted sample report —
  generated from our own real dogfood log, red-team caveats included — is
  [right here](docs/SAMPLE_REPORT.md)**, and the 30-day refund covers the rest
  of the doubt.
- **Fulfillment:** payment → API key → encrypted off-machine history → monthly
  report. The local gate and its blocking behavior never depend on payment or
  Cloud availability.

---

*Every capability claim above is bounded by [FACTS.md](FACTS.md) — the gate is
certain only about what it blocks. Cloud records what happened; it does not
make the gate smarter.*
