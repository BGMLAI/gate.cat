# Show HN draft — gate.cat

> Publikujesz TY (Twoje konto HN). Wklej gdy masz dogfood N≥30 + min. 1 veto-story.
> Tytuł Show HN musi zaczynać się od "Show HN:". Bez emoji, bez hype.

---

## Tytuł (wybierz jeden — max ~80 znaków)

1. `Show HN: gate.cat – a deny-list that blocks irreversible AI-agent actions`
2. `Show HN: Stop your AI agent before rm -rf / terraform destroy (pip install gate.cat)`
3. `Show HN: A deterministic veto for AI agents – block the action, don't judge the model`

**Rekomendacja: #1** — konkretne, mówi CO robi w 6 słowach, "deny-list" sygnalizuje deterministyczność (nie kolejny LLM-wrapper).

---

## Pierwszy komentarz (wklej od razu po opublikowaniu — kontekst od autora)

> I built this after reading autogen#7770: someone's AI agent applied Terraform
> to the wrong AWS target and destroyed their management account — a ~$0.03
> operation that cost $106k. The reporter's conclusion was the thing that stuck
> with me: *"Prompt-based rules are documentation. They are not enforcement."*
>
> gate.cat is the enforcement layer. It sits between the agent and the real world
> as a **deny-list** — `rm -rf`, `terraform destroy`, force-pushes, payments,
> outbound email. Deterministic rules (regex + an independent interpreter check),
> **fail-closed** (engine error → block, never a silent allow), and every decision
> — allow *and* block — lands in a JSONL audit log.
>
> The deliberate design choice people push back on: it's "just rules." That's the
> point. A firewall is just rules and that's exactly why you trust it in the
> enforcement path. A probabilistic guard can hallucinate a pass on the one
> `terraform destroy` that mattered — and now you have to guard the guard.
>
> **Honest line, up front:** the gate is certain only about what it *blocks*. An
> action it doesn't match is *unchecked*, not *safe*. There's a bypass suite in
> the repo that publishes exactly what it catches and what it misses
> (base64-encoded payloads, delete-via-language-runtime, curl|sh, …) — no
> "detects lies", no "guarantees safety".
>
> Drop-in as a Claude Code PreToolUse hook, or a crewAI / LangGraph adapter.
> `pip install gate.cat`. Built for the cheap/local agent stack (7–30B via
> Ollama/vLLM), which is where the frontier-first guardrail vendors don't aim.
>
> Repo: https://github.com/BGMLAI/gate.cat — feedback very welcome, especially
> on the gap map and on which framework adapter to harden next.

---

## Odpowiedzi na przewidywalne komentarze (z OBJECTIONS.md — miej pod ręką)

**"LangGraph interrupt / HumanLayer already do this."**
> Those are approval *flows* you have to remember to call. #7770 happened because
> the agent didn't. As a PreToolUse hook this lives in the harness, outside the
> agent's control flow — the agent can't forget a hook it doesn't control. (The
> in-process framework adapters are weaker — same trust class as interrupt — and
> the README says so explicitly.)

**"Regex will never catch everything."**
> Correct, and I don't claim it does — that's the published bypass suite. It's a
> deny-list for the known-irreversible classes, fail-closed, not an oracle. The
> honest line is mechanical, not marketing: certain only about what it blocks.

**"Why not just an LLM judge?"**
> On an irreversible action I want the same verdict every time and a fail-closed
> default, not a smart guard that's right 98% of the time. A judge is a fine
> *second* layer for fuzzy cases; the layer that stops the $106k command should be
> the boring deterministic one.

---

## Timing (rada#2 — nie łam kolejności)

1. NIE publikuj zanim: `pip install gate.cat` daje działające veto (✅ jest), README ma honest line w 1. akapicie (✅), bypass-suite w repo (✅).
2. NIE publikuj zanim masz **dogfood N≥30 + min. 1 prawdziwą veto-story** — pierwszy komentarz na HN to "ile razy fałszywie zablokuje", i bez liczby przegrasz wątek.
3. Publikuj wtorek–czwartek, ~15:00–17:00 UTC (rano US East). Bądź przy klawiaturze pierwsze 2h, odpowiadaj na KAŻDY komentarz.
