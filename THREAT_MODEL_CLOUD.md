# gate.cat Cloud — threat model

Cloud is the **off-machine, append-only copy of your veto history**: the one
record an AI agent with shell access to your box cannot delete or rewrite,
because it has no credentials for our server. This document states, precisely,
what leaves your machine, what we can and cannot see, and what Cloud does *not*
protect against. It is load-bearing: a security tool that centralizes logs
without end-to-end encryption would itself be an exfiltration vector, so this is
the design the whole product is built around.

## One-line summary

**Your history is encrypted on your machine with a key we never receive. Our
server stores ciphertext and a timestamp. A full compromise of our server yields
opaque blobs — no commands, no policy ids, no reasons.**

## What leaves your machine

| Leaves (only if you enable Cloud) | Never leaves |
|---|---|
| For each veto: a **timestamp** (cleartext, for ordering/retention) and an **AES-256-GCM ciphertext** of the event | your **encryption key** (`~/.gatecat/cloud.key`, 0600) |
| your **API key** on each request — authenticates you, decrypts nothing | your **commands, policy ids, reasons, code, env, secrets** — all inside the ciphertext |
| nothing else | the gate's local decision path (Cloud is never in it) |

By default the ciphertext contains a **hash** of the matched command, not the
text. Raw command text is a separate explicit opt-in (`GATECAT_CLOUD_SEND_RAW=1`)
— and even then it is encrypted before it leaves, so the wire and the server
still see only ciphertext.

## What the server can and cannot do

- **Cannot** read any event content. It holds ciphertext encrypted with a key it
  has never seen. AES-256-GCM; a wrong key or any tampering fails authentication.
- **Can** see: how many events an account shipped and when (timestamps), for
  retention and billing. That metadata is the deliberate, disclosed cost of
  storing an ordered, append-only timeline server-side.
- **Cannot** modify your history undetectably: `gate.cat cloud verify` fetches the
  off-machine copy, decrypts it locally, and diffs it against your local log.

## The tamper story (why Cloud exists)

A local log lives inside the agent's blast radius — an agent that deleted a file
and then hid it from the user is a real, documented incident. The agent can
rewrite `~/.gatecat/veto_log.jsonl`. It **cannot** reach our server. So an event
that already shipped, then disappears locally, surfaces in `cloud verify` as a
tamper alarm. The off-machine copy is the source of truth.

Boundary, stated honestly: an agent with full shell access can **kill the
reporter process** so new events stop shipping. It cannot rewrite what already
left, and a silenced reporter shows up as a **gap in the timeline** — itself a
signal. Cloud shrinks the tamper surface; it does not make the local machine
trusted.

## Keys

- **Encryption key** — 32 random bytes on your machine (or derived from
  `GATECAT_CLOUD_PASSPHRASE` via scrypt, for a fleet that prefers a phrase). We
  never receive it. **Lose it and your off-machine history is unreadable — even
  to us.** `gate.cat cloud key export` backs it up; a Team shares it out of band.
- **API key** — issued on subscription; authenticates requests. We store only its
  SHA-256, so a leak of our accounts file does not expose live keys. If your API
  key leaks, an attacker can *append* garbage or *read your ciphertext* — which
  they still cannot decrypt. Rotate by re-subscribing / contacting us; your
  encryption key is unaffected.

## Threats considered

| Threat | Outcome |
|---|---|
| Our server / database is fully compromised | Attacker gets ciphertext + timestamps. No plaintext. |
| Network MITM | TLS in transit; AES-GCM means tampered payloads fail auth on decrypt. |
| Your AI agent rewrites the local log | Detected by `cloud verify` against the off-machine copy. |
| Your AI agent kills the reporter | New events stop; the gap is visible; already-shipped history is intact. |
| Your API key leaks | Read/append ciphertext only — undecryptable without your key. Rotatable. |
| You lose your encryption key | History unreadable by anyone, including us. By design. Back it up. |
| We (the operator) turn malicious | We hold ciphertext. We cannot read your history. |

## What Cloud is NOT

- **Not** part of the gate's safety. The local, deterministic, fail-closed gate
  is the whole enforcement. If Cloud is down, unreachable, or cancelled, the gate
  blocks exactly as before. Cloud is a *reporter beside the gate, never in its
  path*.
- **Not** telemetry. It is off by default; the free `pip install gate-cat`
  phones nowhere. Cloud activates only when you set an API key.
- **Not** a backup of your code or data — only of your veto **history**.

Retention: 12 months, export any time (`cloud report` reads it), delete-account
= hard delete of your ciphertext. Apache-2.0 client; the reporter and the crypto
are readable Python in the open repo — audit them.
