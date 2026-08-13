# gate.cat — security one-pager

> **What this is:** the technical security summary of gate.cat and its optional
> Cloud layer, written to be forwarded to a security reviewer and to pre-answer
> a vendor questionnaire. **Who it is for:** whoever has to sign off on running
> this in your environment. **Version:** 1.0 · **Date:** 2026-07-31 ·
> **Product version:** 0.4.18.
>
> Read the [Limitations](#limitations) section first. It is deliberately placed
> before the mapping table, and it names our own gaps before you find them.

---

## 1. What the product is, and where it sits

A deterministic policy gate that inspects an action an AI coding agent is about
to take and blocks, warns on, or allows it **before** it executes. No model is
consulted; same input, same verdict; there is no prompt to inject into.

Two integration points, with honestly different strength:

- **Claude Code `PreToolUse` hook** — runs in the harness, **outside the
  agent's control flow**. This is real enforcement. The hook is **fail-closed**:
  malformed input, engine import failure, evaluation error, an internal
  20-second watchdog deadline, or any uncaught exception all exit `2` (block).
  It self-blocks before the harness's own 60-second hook timeout can fire,
  because a killed hook would be read as "no opinion".
- **Framework adapters** (crewAI, LangGraph, and a framework-agnostic
  `guard_callable`) — **in-process convention. Honestly weaker.** Code that
  chooses not to call them is not gated.

Internally an action flows through a six-stage pipeline, not a flat deny-list:
allow-list → target/effect resolution with a hardened exec sandbox →
self-consistency probe → rule-staleness monitor → arbiter → human. Fail-closed
everywhere: any error resolves to something other than `allow`. **71 default
policy walls; 73 presets including opt-in policies (measured on 0.4.18)**
(FACTS F10).

Scope: it guards environments where a mistake is irreversible. In a detected
ephemeral CI/sandbox container it disarms itself and logs a `disarmed` no-op
rather than crying wolf (`GATECAT_VETO_EPHEMERAL=0` forces it armed).

## 2. Data flow

### Free tier — nothing leaves

`pip install gate.cat` makes **no network call to us**. No telemetry, no
analytics, no licence check, no phone-home. The veto log is a local JSONL file
(`~/.gatecat/veto_log.jsonl`). You can run it fully air-gapped.

### Cloud tier — opt-in, off by default, activated only by setting an API key

Cloud is a **reporter beside the gate, never in its execution path**. It tails
the local log on its own schedule (cron / systemd timer). If Cloud is down,
unreachable or cancelled, the gate blocks exactly as before.

Every event is encrypted **on your machine** with AES-256-GCM before
transmission. The key is 32 random bytes in `~/.gatecat/cloud.key` (mode
`0600`), generated locally, **never transmitted** — or derived from a passphrase
via scrypt for a fleet. We never participate in key exchange.

| What we receive | What we can read |
|---|---|
| An AES-256-GCM ciphertext blob per event | Nothing inside it |
| A cleartext event timestamp and sequence number (ordering + retention) | Yes |
| A record-class tag, literally `ledger` or absent — any other value is dropped server-side | Yes |
| Your account identifier (the checkout email) and the SHA-256 of your API key | Yes |
| Source IP, in an in-memory rate-limit counter; the Cloud service writes no HTTP request log | Transiently |

Inside the ciphertext, by default: timestamp, source, policy id, verdict, a
reason string truncated to 256 chars, gate version, and a **SHA-256 hash of the
matched command** — not the command. Raw command text (≤4096 chars) is a
separate, explicit opt-in (`GATECAT_CLOUD_SEND_RAW=1`) because command lines can
contain secrets, and even then it is encrypted before it leaves.

**Never sent, in either tier:** file contents, environment variables, keys,
tokens, your code, prompts, model outputs, or telemetry of any kind.

The full list and the reporter are readable stdlib Python in the public repo: `gatecat/cloud_reporter.py`, `gatecat/cloud_crypto.py`,
`products/cloud/cloud_server.py`. Read them instead of believing this page.

## 3. Authentication and credentials

- Cloud requests carry a bearer API key (`gck_` plus a 32-byte URL-safe random token),
  issued on subscription. **We store only its SHA-256.** A leak of our accounts
  file does not expose live keys. Revocation is an append-only account record.
- A leaked API key lets an attacker append garbage or read **your ciphertext**,
  which they still cannot decrypt. Your encryption key is unaffected.
- Operational guidance we publish rather than assume: **do not export the API
  key into the agent's environment.** Run the reporter as a cron/systemd job
  under your user, with the key in a `0600` env file outside the project
  directory.
- The gate's own operation requires no credential at all.

## 4. Encryption

- **In transit:** TLS to the public endpoint (Let's Encrypt certificates; the
  endpoint is fronted by Cloudflare — see [sub-processors](../legal/SUBPROCESSORS.md)).
- **At rest:** application-layer. Every event body is ciphertext independent of
  the disk, encrypted with a key we have never seen. A full compromise of our
  server yields opaque blobs, timestamps and event counts.
- **Authenticated encryption:** AES-256-GCM with a fixed AAD label. Tampering
  with a stored blob fails authentication on decrypt.
- Host full-disk encryption: `[CONFIRM]`.

## 5. Retention, export, deletion

- **Retention: 12 months** ([PRICING.md](../../PRICING.md)). The server also
  enforces a per-plan retention window on read-back; confirm the window for your
  plan via `GET /v1/entitlement` before contracting.
- **Export:** `gate.cat cloud report` fetches the off-machine copy, decrypts it
  **locally**, and gives you JSON. Any time, no request to us.
- **Delete:** account deletion is a hard delete of your ciphertext. Backup lag:
  `[CONFIRM]`.
- **Correction is not available on individual events**, by design: the store is
  append-only and the server exposes no update and no delete route for a single
  event. That property is what makes the record worth having.

## 6. Tenancy and isolation

Every read and write is scoped to the account resolved from the presented key;
cross-tenant reads are covered by tests. Account identifiers are sanitised to a
filename-safe set before use in a storage path. Writes are serialised per
account. The Cloud service binds `127.0.0.1` and is reachable only through the
reverse proxy. Abuse controls: per-IP fixed-window rate limit, 8 MiB request
body ceiling, 64 KiB per-event ceiling, 500 events per batch.

**Business tier:** the evidence log can be collected append-only in **your**
infrastructure (e.g. object storage with write-once retention; we provide the
reference setup). We never hold the only copy of your evidence.

## 7. Supply chain

- **Apache-2.0**, public repository: `github.com/BGMLAI/gate.cat`.
- **0.4.18 is installable from PyPI and pinned by GitHub release v0.4.18**
  (FACTS F9). Reproducing the install: create an empty venv, `pip install
  --no-cache-dir gate.cat==0.4.18`, and check the distribution metadata and the
  policy counts (`len(DOGFOOD_DEFAULTS)` / `len(ALL_PRESETS)` → 71 / 73).
  Known cosmetic drift: the shipped `gatecat.__version__` string still reads
  `0.4.17` while the distribution is 0.4.18.
- **1,956 tests collected with 0 failures on 0.4.18, and the CI matrix is green
  on Python 3.11–3.13** (FACTS F3). CI runs on every push and pull request, with
  the gate forced armed (`GATECAT_VETO_EPHEMERAL=0`) so the veto tests exercise
  a live gate.
- **73% statement coverage, printed by CI on every run** (FACTS F12). Proxy and
  CLI paths are the least covered.
- The deterministic core is stdlib + a small dependency set; the ML stack is an
  optional extra and the gate does not need it. The Cloud reporter is
  stdlib-only on purpose. The Cloud server has zero third-party dependencies.
- No automated deploy and no automated PyPI publish runs from CI; there are no
  production credentials in the workflows.
- OpenSSF Scorecard is published on the repository.
- SBOM: `[NOT CURRENTLY PUBLISHED — ask if you need one]`.

## 8. Measured effectiveness

Every number here is bounded by [FACTS.md](../../FACTS.md), which is the claims
register: no public claim exists without a row, a source artifact and a
measurement date.

- **100% recall on all 43 known danger classes through the full gate, 0
  false-blocks on benign twins — reproduce with `scripts/recall_danger_axis.py`**
  (FACTS F1a).
- **0 real recall misses across 826,644 unique real agent commands through the
  full gate** (lower bound — two SWE-Gym sets were excluded by an upstream split
  rename, so the true corpus is 826,644–835,128; the 2 catalog-flagged allows
  are disposable-artifact cleanups the gate correctly permits — same shape
  blocks on a real target) (FACTS F1b, corpus re-run 2026-07-28 with a global
  dedup).
- **The reproducible bypass suite catches 178/178 danger shapes it claims, with
  one benign false-block in 129 cases and 3 published regex-wall gaps — 2 of
  them (a Unicode homoglyph and a printf-hex assembled `rm`) slip the whole
  product, the 3rd the delete-analyzer still blocks** (FACTS F4).
- **Intervenes on ~0.6% of real commands (two independent logs)** (FACTS F2) —
  a measure of how noisy it is in practice, not of your traffic.

## 9. Vulnerability reporting

Per [SECURITY.md](../../SECURITY.md):

- Deny-list gaps and false negatives: open a public issue — the bypass suite
  already prints its known gaps, so a gap report is not an embarrassment.
- Anything sensitive (a vulnerability in the hook itself, a fail-open path):
  email **`bgml@bgml.ai`**. **Reply within 72 hours.**
- In scope: deny-list gaps, analyzer false negatives, any error path that
  ALLOWS instead of blocking, hook-integration bypasses, false-positive classes.
- No bounty programme (solo, pre-revenue). If you intend to publish a working
  bypass, a 14-day heads-up is appreciated; most pattern fixes ship in days.
- Only the latest PyPI release receives fixes.
- Fixed gaps are credited in the CHANGELOG.

---

## Limitations

The known gaps, first, in plain words.

1. **Published regex-wall gaps.** Three are named and printed by our own bypass
   suite. Two of them — a Unicode-homoglyph binary name (`ｒm`, U+FF52) and an
   `rm` whose bytes are assembled by `printf` and piped to a shell — **slip the
   whole product**. The third (`rm` assembled into a shell variable at runtime)
   clears the regex wall but is still blocked by the delete analyzer. A
   `python3 -c "import os; os.unlink(...)"` shape is likewise a named gap in our
   published bypass map.
2. **The gate is certain only about what it blocks. An unmatched action is
   *unchecked*, not *safe*.** This is the doctrine, not a disclaimer. Coverage
   claims are bounded to the enumerated danger classes in
   [RECALL.md](../../RECALL.md); outside them, the gate has no opinion and says
   so.
3. **Only the Claude Code hook is enforcement outside the agent's control
   flow.** The crewAI and LangGraph adapters and `guard_callable` are in-process
   convention. An agent that can write and run arbitrary Python in the same
   process can route around them.
4. **The reporter's honest boundary.** An agent with full shell access can kill
   the reporter process or unset its environment, and new events stop flowing.
   It **cannot rewrite history that already left the machine** — the server has
   no update and no delete route for events — and a silenced reporter shows up
   as a **gap in the timeline**, which is itself signal. It can also rewrite the
   *local* log; that is precisely why the off-machine copy exists, and
   `gate.cat cloud verify` turns the discrepancy into a tamper alarm.
5. **A clean veto log is indistinguishable from a gate that was switched off.**
   This is the sharpest limitation on the page and we state it before you do.
   The client is Apache-2.0; anyone can comment out the hook and produce a
   perfectly clean log, because there was nothing to log. Moving the *log*
   off-machine was the easy half; moving the *proof that the gate was armed* —
   heartbeat with a signed gate and policy-set version, heartbeat gaps raised as
   findings rather than silence, and configuration attestation an auditor can
   sample — is **designed, not shipped** as of 2026-07-31. Until it ships,
   treat the record as evidence of what the gate *saw*, not as proof that it was
   running. See [PRICING.md](../../PRICING.md) for the dated status.
6. **We cannot protect a machine where the agent runs as root** and owns the
   box including the reporter's credentials and cron. Pair the gate with a
   sandbox and a least-privilege user. They are complements: the sandbox limits
   blast radius; the gate stops known-irreversible actions **and records the
   attempt**, which a sandbox never tells you — and a sandbox will not stop a
   `terraform destroy` run with real credentials from inside it.
7. **We see metadata.** Event counts and cleartext event timestamps per account,
   plus your account email address. That is the disclosed cost of an ordered,
   append-only, server-side timeline.
8. **Lose your encryption key and your off-machine history is unreadable — by
   anyone, including us.** By design. Back it up (`gate.cat cloud key export`).
9. **We are a solo-founder vendor with no SOC 2 report and no ISO 27001
   certificate,** no 24/7 on-call, and no independent penetration test
   commissioned to date. The compensating design is that the trust model does
   not require believing us: Apache-2.0 client, readable reporter and crypto,
   reproducible measurement scripts, and a Business tier that keeps the evidence
   log in your own infrastructure.
10. **The optional alert feed, if you enable it, carries cleartext metadata**
   (alert kind, machine identifier, a short reason string) so a notification can
   be sent without breaking event encryption. It does not carry command text,
   but it is not end-to-end encrypted either.
11. **We can never prove a negative.** The monthly report is management evidence
    with reproducible artifacts your auditor can sample. It is not a substitute
    for an independent audit, and page one of the report says so.

---

## Control mapping

What gate.cat supplies as *evidence* for controls you own. gate.cat does not
make anyone compliant or certified; compliance stays with your organisation.

| Control area | What gate.cat provides as evidence | Your control ids |
|---|---|---|
| Restricting destructive and privileged operations by non-human actors | Deterministic pre-execution policy gate; 71 default policy walls; fail-closed hook running outside the agent's control flow; per-verdict record naming the rule that fired | SOC 2 **CC6.1**; ISO 27001 **A.8.2** (privileged access rights), **A.8.3** (information access restriction), **A.8.16** (monitoring activities) |
| Detection of anomalous or unauthorised activity | Veto log of every block/warn with policy id, verdict and reason; `~0.6%` intervention rate as a signal-to-noise baseline; stagnation / loop-guard alerting | SOC 2 **CC7.2**; ISO 27001 **A.8.15** (logging), **A.8.16** |
| Tamper-evidence of the activity record | Off-machine append-only copy with no server-side update or delete route; hash-chained gate-toggle and override ledger verified **on the client**; `cloud verify` diff against the local log | SOC 2 **CC7.2**, **CC7.3**; ISO 27001 **A.8.15**, **A.8.34** (protection during audit testing) |
| Change management over the control itself | Public repo with full history; versioned policy set and gate version stamped into every event; CI green on Python 3.11–3.13 with 1,956 tests and 0 failures; published claims register (FACTS.md) tying every number to a re-runnable artifact | SOC 2 **CC8.1**; ISO 27001 **A.8.32** (change management), **A.8.28** (secure coding) |
| Cryptographic protection of the evidence record | Client-side AES-256-GCM, key never transmitted; API keys stored as SHA-256 only; TLS in transit | SOC 2 **CC6.7**; ISO 27001 **A.8.24** (use of cryptography) |
| Vendor / supply-chain assessment of gate.cat itself | This page, the [DPA](../legal/DPA.md), the [sub-processor list](../legal/SUBPROCESSORS.md), both threat models, and an Apache-2.0 source you can read | SOC 2 **CC9.2**; ISO 27001 **A.5.19**, **A.5.21** (ICT supply chain) |
| Operational control over AI systems in use | A record of what your AI agents attempted, what was refused and by which rule, with the scope of coverage stated explicitly | ISO/IEC **42001** — operational control and monitoring of AI systems in use. We do **not** assert a definitive clause mapping; map it against your own Statement of Applicability |

**On the EU AI Act.** Article 50 is **not** a reason to buy gate.cat, and we
will not sell it as one. Article 50 concerns transparency toward humans —
disclosing that a person is interacting with an AI system, and labelling
synthetic content. It imposes no duty to log the actions of an internal coding
agent. Where it appears in our documents, it appears as an obligation on *us*,
for disclosure in automated outreach. Any vendor telling you that Article 50
requires an agent action log is selling you something that is not in the text.

---

*Every capability claim above is bounded by [FACTS.md](../../FACTS.md). The gate
is certain only about what it blocks. Cloud records what happened; it does not
make the gate smarter.*
