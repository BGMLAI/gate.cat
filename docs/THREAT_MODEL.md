# Threat model — one page, no hand-waving

The question every skeptical engineer asks: *"you claim the agent can't touch
the record — prove the boundary."* Here is the boundary, both directions.

## What a hostile-or-confused agent CAN do

| Capability | Consequence | Our answer |
|---|---|---|
| Delete or rewrite the **local** veto log (`~/.gatecat/veto_log.jsonl`) | local history is inside the blast radius | that is exactly why the paid layer exists: the off-machine copy |
| **Kill the reporter process** or unset its env | new events stop flowing | it cannot *rewrite* what already shipped; a silent gap in the off-machine timeline is itself visible signal |
| Run a command the gate doesn't match | executes unchecked | **unmatched ≠ safe** — printed in the README, the report, and here. The gate is a wall in front of known-dangerous shapes, not a proof of safety |
| Use a named-gap bypass (e.g. deletes via a language runtime, base64 assembly) | may evade the pattern layer | the gaps are published in the bypass map ([bypass suite](../gatecat/integrations/bypass_suite.py) prints them); the full six-stage gate — not a regex list — measured 0 real misses on 1,085,159 real agent commands (FACTS F1b) |
| Read the Cloud API key **if you export it into the agent's environment** | could ship fake events to pollute the timeline | don't give the agent the key: run the reporter as a cron/systemd timer under your user, key in a `0600` env file outside the project dir. Fake-event pollution cannot *remove* real events (append-only) |

## What the agent CANNOT do

| Boundary | Why it holds |
|---|---|
| Influence a verdict through Cloud | Cloud is a **reporter**: the server has no route that reaches the client's decision path; the gate never waits for the network |
| Rewrite off-machine history | the server exposes **no update or delete route** for events — append-only by construction (verify: [`server` source is readable Python](../products/cloud/cloud_server.py)) |
| Recover the bearer token from a server breach | keys are stored as sha256 hashes only |
| See another tenant's events | every query is scoped to the authenticated key id (tested) |
| Exfiltrate your command text via the reporter | **hash mode is the default**: the command line never leaves the machine unless you explicitly set `GATECAT_CLOUD_SEND_RAW=1` |
| Talk the gate out of a verdict | the gate is deterministic — same command, same verdict; there is no prompt to inject into |

## What WE cannot do (vendor honesty)

- We cannot prove a negative. The report shows what the gate saw and blocked —
  it is management evidence with reproducible artifacts, **not** a substitute
  for an independent audit.
- We cannot protect a machine where the agent runs as root and owns the whole
  box including the reporter's credentials and cron. Pair the gate with a
  sandbox and least-privilege user — they are complements: the sandbox limits
  the blast radius, the gate stops known-irreversible actions *and records the
  attempt*, which a sandbox alone never tells you.
- Enforcement strength depends on the integration point: the **Claude Code
  hook runs in the harness, outside the model's control flow** — that is real
  enforcement. The crewAI/LangGraph/AutoGen adapters are in-process
  convention: honestly weaker.

## Verify instead of trusting

- Recall & false-positive numbers: [FACTS.md](../FACTS.md) → reproduce with `scripts/recall_danger_axis.py`.
- Bypass map: run the bypass suite; it prints what it catches **and what it doesn't**.
- Reporter behavior: it's ~100 lines of stdlib Python — read it.
- A sample of the actual monthly report (from our own dogfood log, red-team caveats included): [SAMPLE_REPORT.md](SAMPLE_REPORT.md).
