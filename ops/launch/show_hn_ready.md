# Show HN — paste-ready (fact-checked 2026-07-22 przeciw FACTS.md)

Poprawki vs docs/LAUNCH_KIT_2026-07-14.md (fixy sędziów panelu 2026-07-22):
konflacja "1M replay → 1 false-block" rozdzielona na F1b (0 real misses) i F4
(bypass suite, 1/129 benign); 69→71 policies (F10); €9→€19 (PRICING.md);
"zero dependencies"→"zero-dependency core" (pyproject: `dependencies = []`,
extras opt-in). Wersja: 0.4.18 (F9 re-pin 2026-07-23).

**KIEDY:** najlepiej PO merge PR #26 + deploy (USER-2) — ruch ma trafiać na
działające gate.cat/teams.html. Optymalnie wt–czw, 14:00–16:00 UTC.
Po publikacji: odpowiadaj na komentarze przez pierwsze 3–4 h (to decyduje
o frontpage), link "1 false-block" masz w RECALL.md/FACTS.md.

---

## Tytuł (67 znaków)

```
Show HN: Gate.cat – deterministic action veto for AI coding agents
```

## Body

```
gate.cat blocks irreversible shell commands before an AI coding agent executes them — it vetoes the execution itself, not a log line after the fact.

Three integration points:

- Claude Code hook — the strongest one: enforcement runs in the harness, outside the agent's control flow
- gatecat-shell — a gated shell for any CLI agent that ultimately runs `sh -c "<command>"` (Codex, aider, anything honoring $SHELL)
- a local proxy for anything speaking the OpenAI API (Ollama, vLLM, OpenRouter, LM Studio): your agent changes one base_url

The check is deterministic string + path analysis plus an independent exec analyzer — no model call in the path, so prompt injection can't talk the gate into allowing something.

Numbers, measured not claimed (every public number has a row in FACTS.md in the repo, pinned to a reproducible artifact):

- 1,085,159 unique real agent commands (5 public datasets) replayed through the full 6-stage gate: 0 real misses after adjudication — the 4 catalog-flagged allows are disposable-artifact cleanups the gate correctly permits, and the adjudication is in the repo
- the reproducible bypass suite catches 178/178 danger shapes it claims — and prints its own known gap (runtime assembly) plus 1 benign false-block in 129 cases; we publish the misses instead of hiding them
- 71 default policy walls (73 presets incl. opt-in), ~0.6% intervention rate on real commands (two independent logs)
- Apache-2.0, zero-dependency core, 0.4.18 on PyPI

Honest limits, because that's the whole brand: the gate is certain only about what it blocks — an unmatched action is unchecked, not safe. It's a wall in front of known-dangerous shapes, not a proof of safety. Use it with your sandbox, not instead of one: a sandbox can't tell you what the agent tried, and it won't stop a terraform destroy that has real credentials inside the sandbox.

Install: pip install gate.cat
Repo: https://github.com/BGMLAI/gate.cat

What I actually want from HN: does publishing our own bypass map and false-block build more trust than a clean number would? That was the hardest design call.
```

## Pierwszy komentarz (wklej od razu po publikacji, jako autor)

```
Author here — business model up front, since HN will (rightly) ask:

The local gate is free forever (Apache-2.0). Nothing is rate-limited, and safety is never paywalled — every time an audit found a catastrophic class missing (KMS/secret destroy, IAM escalation, backup destruction), it was promoted INTO the free core, not into a pack.

Paid is the one thing an agent can't have: an off-machine, append-only copy of the veto history. A local log lives inside the agent's blast radius — real incident reports include an agent deleting a file and then hiding it from the user. Cloud keeps the receipts, plus alerts and a monthly report. Solo €19/mo, Team €149/mo flat (up to 10 machines), Business €399/mo, and one-time €29 policy packs for stack-specific breadth (Fintech / PaaS / raw HTTP-API calls — full scope listed before checkout: https://gate.cat/packs.html?source=hn). Stripe checkout, 30-day no-questions refund.

Exactly what leaves your machine (only if you enable Cloud): veto event timestamps, policy id, verdict, and a HASH of the matched command by default — raw text is a separate explicit opt-in, because commands contain secrets. Never file contents, env vars, or your code. Details: https://gate.cat/teams.html?source=hn and PRICING.md in the repo.
```

Uwaga: świadomie linkuję stronę cenową zamiast surowych linków buy.stripe.com —
na HN goły checkout-link w komentarzu autora czytany jest jako spam i zbiera
downvoty; checkout jest 1 klik od teams.html/#pricing. Surowe linki masz
w PRICING.md, gdybyś wolał inaczej.

---

## Gałęzie odpowiedzi modów HN (V1, 2026-07-23; mail second-chance wysłany 07:33 UTC)

**Gałąź B — DEFAULT (odmowa modów ALBO cisza >72h od maila, tj. do 2026-07-26 07:33 UTC):**
NIC więcej na HN. Wątek zamykamy w LEDGER jako closed-flagged. Żadnego
repostu z tego konta ani świeżego konta — drugi post pod flagą to ryzyko
bana domeny gate.cat na HN. Resubmit dopiero przy MATERIALNEJ nowości
(np. release 0.4.19 z `gate.cat setup claude-code` — wtedy nowy tytuł
o setup-one-command, nie odgrzewka tego samego posta).

**Gałąź A — reinstate (modzi przywracają post):** wklej NATYCHMIAST
przygotowany pierwszy komentarz (sekcja wyżej — nigdy nie wszedł, więc
jest świeży), okno aktywnej obsługi komentarzy 3–4h liczone OD MOMENTU
reinstatement (nie od pierwotnej publikacji), zero próśb o głosy,
zero linków buy.stripe w komentarzach (tylko strony ?source=hn).
