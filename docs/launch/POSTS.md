# Social + outreach posts — gate.cat

> Publikujesz TY, ze swoich kont, gdy masz dogfood N≥30. Każdy wariant stoi sam.
> Zero hype, honest line zawsze obecna (to jest brand — nie łam go w marketingu).

## X / Twitter (thread, 3 posty)

**1/**
An AI agent applied Terraform to the wrong AWS account and destroyed it — a
$0.03 command that cost $106k (autogen#7770). The reporter's line stuck with me:
"Prompt-based rules are documentation. They are not enforcement."

So I built the enforcement layer. 🧵

**2/**
gate.cat is a deny-list between your agent and the real world: rm -rf, terraform
destroy, force-push, payments. Deterministic, fail-closed (error = block), every
decision logged. Drop-in Claude Code hook / crewAI / LangGraph.

pip install gate.cat

**3/**
Honest line, up front: it's certain only about what it BLOCKS. Unmatched ≠ safe.
The repo publishes a bypass suite showing exactly what it catches and misses — no
"detects lies", no "guarantees safety".

https://github.com/BGMLAI/gate.cat

---

## LinkedIn (1 post, dłuższy, ton profesjonalny)

Agents that can run shell commands, deploy infra, or move money have a failure
mode prompts can't fix: the agent treats your safety rules as suggestions. One
public case (autogen#7770) cost $106k when an agent applied Terraform to the
wrong AWS target.

I released **gate.cat** — a deterministic action-veto that sits between the agent
and the irreversible action. Deny-list for rm -rf / terraform destroy /
force-push / payments, fail-closed (any error blocks), full JSONL audit trail.
Drop-in as a Claude Code hook or a crewAI/LangGraph adapter.

It's intentionally "just rules" — like a firewall, and for the same reason: on an
irreversible action you want the same verdict every time, not a probabilistic
guard that might wave through the one that mattered.

Honest about its limits: it's certain only about what it blocks; the repo ships a
bypass map of what it can't catch. Built for the cheap/local agent stack (7–30B).

pip install gate.cat · https://github.com/BGMLAI/gate.cat

---

## Reddit r/LocalLLaMA / r/LLMDevs (ton społeczności, nie sprzedażowy)

**Title:** Deterministic action-veto for local-model agents — blocks rm -rf /
terraform destroy before they run (open source)

**Body:**
If you run agents on local/cheap models (Ollama/vLLM, 7–30B) and let them touch a
shell or cloud APIs, you've probably had the "wait, don't run that" moment.
Prompt-based rules don't enforce — the agent can ignore them.

gate.cat is a small deny-list layer: policy regex + an independent interpreter
check, fail-closed, JSONL audit log. Works as a Claude Code PreToolUse hook or a
crewAI/LangGraph wrapper. Deliberately deterministic — I'd rather a firewall than
an LLM judge on `terraform destroy`.

It's honest about coverage (there's a published bypass suite of what it misses),
so no overclaiming. Curious what dangerous action-classes you'd want covered that
aren't in the default presets.

pip install gate.cat — https://github.com/BGMLAI/gate.cat

---

## Framework docs PR (rada#2: przykład/PR, NIE komentarz-z-linkiem pod cudzym issue)

Zamiast komentować pod issue #7770 (spam-ryzyko), otwórz **PR z działającym
przykładem** do docs frameworka, gdy adapter jest dopieszczony:

- **crewAI**: PR do `docs/` z sekcją "Guarding irreversible tool calls" +
  `examples/veto_crewai.py` (już w repo gate.cat). Ból realny: crewAI#5802
  (duplicate payments), #5888 (tool-call authorization).
- **LangGraph**: PR pokazujący veto jako guard przed tool-node → interrupt /
  human-in-the-loop (przykład `examples/veto_langgraph.py`).

Zasada: PR dokłada wartość do ICH docs (jak zabezpieczyć akcje), gate.cat jest
środkiem, nie tematem. Link do repo w treści przykładu, nie w nagłówku.
