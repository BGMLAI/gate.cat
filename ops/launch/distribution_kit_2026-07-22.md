# Pakiet dystrybucyjny — WSZYSTKO paste-ready (fact-check: FACTS.md, 2026-07-22)

Zastępuje sekcje 2–6 z docs/LAUNCH_KIT_2026-07-14.md (tamte mają stale liczby:
€9, 69 policies, konflację 1M-replay z false-blockiem). Show HN osobno:
`ops/launch/show_hn_ready.md`. Liczby tu użyte: F1b (0 real misses / 1,085,159),
F4 (178/178 + 1/129 benign + named gap), F10 (71/73), F2 (~0.6%), PRICING (€19/149/399, packi €29).

## KOLEJNOŚĆ PUBLIKACJI (ważne — nie wszystko naraz)

1. **Dzień 1, 14:00–16:00 UTC:** Show HN + wątek X (godzinę po HN, z linkiem do wątku HN).
2. **Dzień 1 wieczór LUB dzień 2:** r/ClaudeAI (najbardziej docelowa grupa).
3. **Dzień 2–3:** r/LocalLLaMA, potem r/Python (odstęp ≥24h; crossposty tego samego
   dnia wyglądają jak spam i podcinają się nawzajem w feedach).
4. **Równolegle, bez pośpiechu:** 4 PR-y do awesome-list (to commity, nie posty).
5. Każdy live URL dopisz do issue #9 (publication gate).

---

## 1. r/ClaudeAI

**Tytuł:**
```
gate.cat — a PreToolUse hook that vetoes Claude Code's destructive commands before they run
```

**Body:**
```
Claude Code runs shell commands. Sometimes the wrong ones. gate.cat is a PreToolUse hook that vetoes irreversible commands (rm -rf, DROP TABLE, terraform destroy, dd to disk, secret exfiltration) BEFORE the shell executes them — enforcement runs in the harness, outside the model's control flow, so a prompt injection can't talk it into allowing something.

Setup: pip install gate.cat, add gatecat-hook to .claude/settings.json (matcher "Bash|Write|Edit"). That's it.

Measured, not claimed (every number is pinned in FACTS.md in the repo to a reproducible artifact):
- 1,085,159 unique real agent commands from 5 public datasets replayed through the full 6-stage gate: 0 real misses after adjudication
- the bypass suite catches 178/178 danger shapes it claims — and prints its own known gap (runtime assembly) plus 1 benign false-block in 129 cases; we publish the misses instead of hiding them
- 71 default policy walls, ~0.6% intervention rate on real commands (two independent logs)

Honest limit: the gate is certain only about what it blocks — an unmatched action is unchecked, not safe. Use it with your sandbox, not instead of one.

Free forever, Apache 2.0, zero-dependency core. There's an optional paid layer (off-machine copy of the veto history) but the hook above is the complete free product.

https://github.com/BGMLAI/gate.cat · https://gate.cat
```

## 2. r/LocalLLaMA

**Tytuł:**
```
gate.cat — deterministic veto for tool-using local models: one base_url change blocks rm -rf before it runs (Apache 2.0)
```

**Body:**
```
If you run local models with tool use (Ollama, vLLM, LM Studio, OpenRouter — anything speaking the OpenAI API), your agent can execute shell commands. gate.cat sits in front as a local proxy: your agent changes one base_url, and every proposed tool call is checked by a deterministic deny-list + independent exec analyzer before it executes. No model call in the veto path, sub-second, nothing leaves your machine.

Also works as a gated shell for CLI agents (gatecat-shell) and as a Claude Code hook.

Numbers with receipts (FACTS.md in the repo pins every claim to a reproducible artifact):
- 1,085,159 unique real agent commands replayed through the full gate → 0 real misses after adjudication
- bypass suite: 178/178 danger shapes caught, 1 benign false-block in 129, and it prints its own known gap — we'd rather you read our misses than trust a clean number
- 71 default policy walls covering recursive delete, disk wipe, DB drop, cloud teardown, git history destruction, secret exfil, fork bombs, guard self-defense

Honest limit: it's a wall in front of known-dangerous shapes, not a proof of safety. An unmatched action is unchecked, not safe. Complement to a sandbox, not a substitute.

pip install gate.cat — free forever, Apache 2.0, zero-dependency core.
https://github.com/BGMLAI/gate.cat
```

## 3. r/Python

**Tytuł:**
```
gate.cat — fail-closed action veto for AI agents (zero-dependency core, Apache 2.0)
```

**Body:**
```
Built a Python package that blocks AI agents from executing irreversible shell commands. Deterministic string + path analysis plus an independent exec analyzer — no ML in the critical path, and the core has literally zero dependencies (pyproject: dependencies = []).

pip install gate.cat

71 default policy walls: recursive delete, disk wipe, DB drop/truncate, cloud teardown (aws/gcloud/az), k8s delete, git force-push, secret exfiltration, guard self-defense (the agent can't kill the gate), fork bombs. Fail-closed: engine error or anything it can't parse → block, never a silent allow.

Three integration modes: Claude Code hook, gated shell wrapper for any CLI agent, local OpenAI-API proxy.

The part I'd actually like feedback on: we publish our own bypass map. The suite catches 178/178 danger shapes it claims, and prints its known gap (runtime assembly) plus 1 benign false-block in 129 cases. 1,085,159 real agent commands replayed → 0 real misses after adjudication. All pinned in FACTS.md with reproduction scripts — if your numbers disagree, that's a bug report we want.

https://github.com/BGMLAI/gate.cat · https://pypi.org/project/gate.cat/
```

## 4. Wątek X (8 tweetów)

```
1/ your AI agent can run `rm -rf /`.

gate.cat blocks it before the shell sees it.

1,085,159 real agent commands replayed → 0 real misses.
the bypass suite prints its own known gap.

deterministic. fail-closed. apache 2.0.

🧵
```
```
2/ three ways in:

→ claude code: gatecat-hook in settings.json — enforcement runs in the harness, outside the model's control flow
→ any CLI agent: shell = gatecat-shell
→ ollama / vllm / anything openai-api: one base_url change

the model can't route around a veto it never sees.
```
```
3/ the check is not an LLM call. deterministic string + path analysis + an independent exec analyzer.

71 default policy walls: recursive delete, disk wipe, DB drop, cloud teardown, git force-push, secret exfil, fork bombs, guard self-defense.

~0.6% intervention rate on real traffic. it gets out of the way.
```
```
4/ the design call I'm most proud of: we publish our own misses.

bypass suite: 178/178 danger shapes caught — AND it prints its known gap (runtime assembly) + 1 benign false-block in 129 cases.

one miss you can read > a clean number you can't.
```
```
5/ honest limit, said out loud: the gate is certain only about what it BLOCKS.

an unmatched action is unchecked, not safe.

it's a wall in front of known-dangerous shapes — use it WITH your sandbox. a sandbox can't tell you what the agent TRIED.
```
```
6/ install:

pip install gate.cat

free forever. blocking never expires, never phones home.
```
```
7/ the paid layer is the one thing an agent can't have: an off-machine, append-only copy of the veto history.

a local log lives inside the agent's blast radius — real incidents include an agent deleting a file and hiding it.

solo €19/mo · team €149/mo flat · packs €29 one-time.
```
```
8/ every number in this thread has a row in FACTS.md — claim → source artifact → allowed wording.

reproduce them. if your numbers disagree, that's a bug report we want.

https://gate.cat
https://github.com/BGMLAI/gate.cat
```

## 5. PR-y do awesome-list (4) — poprawione liczby

### awesome-ai-agents / awesome-security / awesome-python / awesome-claude-code
Wspólny opis (dostosuj długość do konwencji danej listy):
```
gate.cat — deterministic, fail-closed action veto for AI coding agents. Blocks irreversible shell commands (rm -rf, DROP TABLE, terraform destroy, secret exfil) before execution: Claude Code hook, gated shell, or OpenAI-API proxy. 71 default policies, zero-dependency core, Apache 2.0. Publishes its own bypass map: 178/178 claimed danger shapes caught (1 benign false-block in 129, known gap printed); 1,085,159 real agent commands replayed → 0 real misses. https://github.com/BGMLAI/gate.cat
```
Krótka wersja (awesome-python, jedna linia):
```
gate.cat — fail-closed action veto for AI agents: blocks irreversible shell commands before execution. Zero-dep core, Apache 2.0.
```
