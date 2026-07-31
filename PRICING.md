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

Priced per **seat band** and per **protected environment**, not per machine.
Agents run headless and in CI now; the number of machines stopped tracking the
number of things that can go wrong. What tracks it is how many production
environments an agent can reach — your own, and each client's.

| | **Free** | **Solo — €19/mo** | **Team — €299/mo** *(one policy, whole fleet)* | **Business — €399/mo** *(evidence in your infra)* | **Compliance — from €900/mo** *(proof, not just a log)* |
|---|---|---|---|---|---|
| The gate: veto engine + **Claude Code hook** (enforcement in the harness) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Framework adapters (crewAI/LangGraph) + a framework-agnostic `guard_callable` for everything else, AutoGen included — in-process convention, honestly weaker than the hook | ✅ | ✅ | ✅ | ✅ | ✅ |
| Local CLI dashboard + local reports | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Off-machine veto history** (the copy the agent has no credentials for) + email alerts | — | ✅ | ✅ | ✅ | ✅ |
| Monthly report from the off-machine log | — | ✅ yours | ✅ fleet-wide | ✅ signed | ✅ signed, + control mapping |
| Shared signed policy file for a fleet (pull-only, local review) | — | — | ✅ | ✅ | ✅ |
| Seats | 1 | 1 | up to 25 | up to 25 | unlimited |
| Protected environments | — | 1 | 3 | 3 | 5 included, then per environment |
| Evidence log self-hosted in **your** infra | — | — | — | ✅ | ✅ |
| VAT invoice + bank transfer, DPA, sub-processor list, security one-pager | — | — | ✅ | ✅ | ✅ |
| Policy packs (versioned, with regression) | — | — | 1 included | all included | all included |
| **Proof of enforcement** — evidence the gate was *armed*, not just that the log is clean | — | — | — | — | ✅ *(see below — dated, and not shipping yet)* |
| Control mapping (SOC 2 CC6.1/CC7.2/CC8.1, ISO 27001 A.8.x, ISO 42001) + questionnaire support | — | — | — | — | ✅ |
| Support | community | email | priority | priority | dedicated, SLA |
| Price | €0 forever | €19/mo | €299/mo | €399/mo | €900–1,200/mo |
| | | [**Start Solo →**](https://buy.stripe.com/7sY6oAaRD5qU79m2Vo67S09) | ⟦STRIPE:team-299⟧ | [**Start Business →**](https://buy.stripe.com/7sYdR2e3PcTm2T6cvY67S0b) | [**Talk to us →**](mailto:bogumil@bgml.ai?subject=gate.cat%20Compliance) |

**Onboarding — €1,500–2,500 one-time.** Required for Compliance, optional for
Business: environment inventory, policy tuning against your real traffic
(usually a retro-scan of your existing agent sessions first), hook rollout,
evidence-log wiring into your infrastructure, and the first signed report.
We charge for it because it is real work, and because a buyer who won't pay for
onboarding won't do the rollout either — which produces an unhappy customer and
a refund three months later.

**Solo is an anchor, not a recommendation.** If you are one developer auditing
your own machine, you are also your own auditor, and an off-machine copy of
your own veto history is worth less to you than €19. The free gate is the
honest answer for that case and it is not crippled. Solo exists for the person
who wants the receipts anyway.

Stripe checkout is the payment channel for Solo and Business, with automatic
tax handling, cancellation at any time and a **30-day full refund, no questions
asked.** Team, Compliance and onboarding go through
[invoice and bank transfer](docs/sales/BUYING.md) — EU B2B reverse charge with
a valid VAT number.

### What "proof of enforcement" means, and why it isn't in the price yet

The uncomfortable version, stated by us first: **a clean veto log is
indistinguishable from a gate that was switched off.** Anyone with Apache-2.0
source can comment out the hook in ten seconds and produce a perfectly clean
log — because there was nothing to log. That is the same "an unfalsifiable
clean number" criticism we level at other vendors, and it applies to our own
paid tier as written today.

Moving the *log* off-machine was the easy half. Moving the *proof that the gate
was armed* is the half that a compliance buyer is actually paying for:
heartbeat with signed gate + policy-set version, gaps in the heartbeat surfaced
as findings rather than silence, and configuration attestation your auditor can
sample.

**Status: designed, not shipped.** It is what defines the Compliance tier and
it is why that tier is sold with a conversation and an onboarding engagement
rather than a checkout button. If you buy Compliance today you are a design
partner and we will say so in writing, with the dates. We would rather lose the
sale than have you discover this from your auditor.

## Policy Packs — €29 one-time, or €19/mo maintained

A one-time price on a security rule set was an order-of-magnitude mistake and
we are correcting it in the direction that costs the customer less to leave:
the **one-time €29 stays exactly as it is** — same wheel, same instant
delivery, and anyone who bought it keeps it forever, including the rules as
shipped. What it never included, and could not include, is the part that
actually decays: your stack's destructive surface changes every time a vendor
adds an API verb, and a pack pinned to 2026 is a pack that quietly stops
covering you.

**Maintained packs — €19/mo per pack (⟦STRIPE:pack-sub⟧)** add what a one-time
purchase structurally cannot: new rules as the vendor's API grows, a version
number you can cite in an audit, and a regression run proving each update still
fires on its danger and stays silent on its benign twin. Same model as Semgrep
and Snyk rule sets, for the same reason. **All packs are included in Team,
Business and Compliance** — if you are on a paid tier, do not buy these
separately.



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
  recall misses across 826,644 real agent commands through the full gate —
  recounted with a global dedup on 2026-07-28, artifact
  `results/million_recall_2026-07-28.json`; a bypass suite that prints its own
  gaps) and pick whichever you trust.
- **Team:** nearest per-seat alternatives price at $39–100 *per user per
  month* (market snapshot, 2026-07-08). Flat €299 for up to 25 seats is
  €12/seat at the top of the band, and it does not tax your team's growth.
- **Agency or software house running client infrastructure:** the number to
  compare against is not a tool budget, it is one clause in one SOW. If an
  agent with your credentials touches a client's production, the question in
  the room afterwards is who authorised the change — and "nothing did" is an
  answer you only get to give once. Compliance is roughly one billable day a
  month, and it is a line item you can pass through.
- **Compliance:** one runaway `terraform destroy` loop cost a team ~$106k; one
  agent dropped a production database. The tier is priced at a fraction of a
  single incident, and the onboarding fee is less than the cost of assembling
  the same evidence by hand for one audit cycle.

## Corpus, benchmark and OEM

Two things sit outside the subscription ladder because they are not
subscriptions:

- **Evaluation corpus licence — €10–40k/year.** The adjudicated corpus behind
  our published recall numbers, licensed for use in *your* evaluation. Built
  for agent-platform, harness and sandbox vendors who need to show their own
  safety figures and would rather not spend a quarter assembling a corpus.
  Terms: [LICENSE-CORPUS](LICENSE-CORPUS). Reading, re-running and publicly
  disputing our numbers stays free and needs no licence.
- **OEM / embedded — from €7k/month.** The gate embedded in your agent
  platform or developer product, with your policy set and your support
  boundary.

Both: bogumil@bgml.ai.

## "Isn't a deny-list trivially bypassable?"

Partly — and we say so louder than our critics do. `python3 -c "import os;
os.unlink(...)"` is a named gap in our own published bypass map; the gate is a
wall in front of known-dangerous shapes, not a proof of safety, and an
unmatched action is *unchecked*, not *safe*. What we actually measure: the
full gate (not a regex list — six stages including an independent exec
analyzer) passed **0 real dangers out of 826,644 real agent commands**
(FACTS F1b, recounted 2026-07-28 with a global dedup, reproducible). Use it
*with* your sandbox, not instead of one —
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
