# gate.cat Launch Kit — 10k downloads + 10 purchases

> Wszystko gotowe do kopiuj-wklej. Nie trzeba nic wymyślać.

---

## 1. SHOW HACKER NEWS

**Tytuł:**
```
Show HN: gate.cat – deterministic action veto for AI coding agents (178/178, 1 false-block in repo)
```

**Body:**
```
gate.cat blocks irreversible shell commands before your AI agent runs them — not after, not "flags them for review." It vetoes the execution itself.

Three integration points:
- Native hook for Claude Code / Cursor (settings.json → gatecat-hook)
- Gated shell for Codex / aider / any CLI agent (shell = gatecat-shell)
- Proxy for GitHub Copilot / Ollama / vLLM (base_url = gate.cat)

The check is deterministic string + path analysis. No model call in the path. Sub-millisecond.

Numbers (measured, not claimed):
- 178/178 dangerous commands blocked in the test suite
- 1,085,159 real agent commands replayed — 1 documented false-block (it's in the repo, we didn't hide it)
- 69 default policies, Apache 2.0, zero dependencies

Free forever. Cloud adds tamper-evident off-machine logs + fleet alerts (€9/mo founding).

Install:
  curl -fsSL https://gate.cat/install.sh -o /tmp/gatecat-install.sh
  sh /tmp/gatecat-install.sh

Or: pip install gate.cat

Repo: https://github.com/BGMLAI/gate.cat
Site: https://gate.cat

What I want to know from HN: does the "1 false-block in the repo" approach build more trust than a clean number? That was the hardest design call.
```

---

## 2. REDDIT r/LocalLLaMA

**Tytuł:**
```
gate.cat — block your local LLM from running rm -rf before it runs (deterministic, sub-ms, Apache 2.0)
```

**Body:**
```
If you're running local models with tool use (Ollama, llama.cpp, vLLM), your agent can execute shell commands. gate.cat sits between the model and the shell and vetoes irreversible actions — delete, disk wipe, DB drop, cloud teardown, secret exfiltration — before they execute.

No model call in the path. It's string + path analysis, deterministic, sub-millisecond. 178/178 dangerous commands blocked. 1 documented false-block (public in the repo).

Works three ways:
1. Proxy mode: point base_url at gate.cat — every tool call passes the gate
2. Gated shell: route any CLI agent's shell through gatecat-shell
3. Native hook: Claude Code / Cursor settings.json

Free, open source, zero deps. Cloud tier (€9/mo) adds tamper-evident logs on separate hardware + fleet alerts.

pip install gate.cat
https://gate.cat
https://github.com/BGMLAI/gate.cat

The "1 false-block" is deliberate — we put the miss in the repo rather than hiding it. Would rather have one miss you can read than a clean number you can't.
```

---

## 3. REDDIT r/ClaudeAI

**Tytuł:**
```
gate.cat — a kill switch for Claude Code that blocks destructive commands before execution
```

**Body:**
```
Claude Code can run shell commands. Sometimes it runs the wrong ones. gate.cat is a hook that vetoes irreversible commands (rm -rf, DROP TABLE, terraform destroy, dd to disk, secret exfiltration) BEFORE the shell executes them — not after.

Setup: add gatecat-hook to your .claude/settings.json. That's it. Every command Claude proposes goes through the gate first.

178/178 dangerous commands blocked in testing. 1,085,159 real commands replayed. 1 false-block — documented publicly in the repo with the fix and regression test.

Free, Apache 2.0, zero dependencies. Cloud adds tamper-evident off-machine logging (so the blocked process can't tamper with its own trail) + fleet alerts.

pip install gate.cat
https://gate.cat
```

---

## 4. REDDIT r/Python

**Tytuł:**
```
gate.cat — fail-closed action veto for AI agents (pip install gate.cat, Apache 2.0, zero deps)
```

**Body:**
```
Built a Python package that blocks AI agents from executing irreversible shell commands. Deterministic string + path analysis, no ML model in the critical path, sub-millisecond.

pip install gate.cat

69 default policies covering: recursive delete, disk wipe, DB drop/truncate, cloud teardown (aws/gcloud/az), k8s delete, git force push, secret exfiltration, guard self-defense (agent can't kill the gate), fork bombs.

Also: paid policy packs for domain-specific coverage (Fintech, PaaS, HTTP-API breadth) at €29 one-time.

Apache 2.0. Works as a Claude Code hook, a gated shell wrapper, or an API proxy.

178/178 test suite pass. 1 false-block — we put it in the repo instead of hiding it.

https://gate.cat
https://github.com/BGMLAI/gate.cat
https://pypi.org/project/gate.cat/
```

---

## 5. X/TWITTER WĄTEK (8 tweetów)

**Tweet 1:**
```
your AI agent can run `rm -rf /`.

gate.cat blocks it before the shell sees it.

178/178 dangerous commands blocked.
1,085,159 real commands replayed.
1 false-block — public in the repo.

deterministic. sub-millisecond. apache 2.0.

thread 🧵
```

**Tweet 2:**
```
three ways to use it:

→ claude code / cursor: add gatecat-hook to settings.json
→ codex / aider / any CLI: shell = gatecat-shell
→ copilot / ollama / vllm: point base_url at gate.cat

the veto fires outside the model. the model can't route around it.
```

**Tweet 3:**
```
the check is not an LLM call. it's deterministic string + path analysis.

sub-millisecond. zero dependencies. zero model cost.

69 default policies: recursive delete, disk wipe, DB drop, cloud teardown, git force-push, secret exfil, guard self-defense, fork bombs.
```

**Tweet 4:**
```
the hardest design call: we have 1 documented false-block.

we put it in the repo. the case, the fix, the regression test — all public.

one miss you can read > a clean number you can't.

that's the pitch.
```

**Tweet 5:**
```
install:

curl -fsSL https://gate.cat/install.sh -o /tmp/gatecat-install.sh
sh /tmp/gatecat-install.sh

or: pip install gate.cat

free forever. blocking never expires.
```

**Tweet 6:**
```
cloud tier (€9/mo founding) adds:

→ tamper-evident record of every block — on hardware the blocked process never touched
→ push + email alerts across your fleet
→ the blocked agent can't erase its own trail

blocking is always free. cloud is the audit layer.
```

**Tweet 7:**
```
also: one-time policy packs at €29.

→ Fintech (PCI, SOX, financial destructive patterns)
→ PaaS (k8s, docker, terraform breadth)
→ HTTP-API (curl/wget destructive patterns)

lifetime updates. stack on top of the free core.
```

**Tweet 8:**
```
gate.cat

→ https://gate.cat
→ https://github.com/BGMLAI/gate.cat
→ pip install gate.cat

apache 2.0 · zero deps · 178/178 · 1 false-block in the repo

your agent runs shell commands. gate.cat runs first.
```

---

## 6. AWESOME-LIST PRs (4)

### awesome-ai-agents
```
Title: Add gate.cat — deterministic action veto for AI agents

Body:
## gate.cat
- **Description:** Deterministic, fail-closed action veto for AI coding agents. Blocks irreversible shell commands (rm -rf, DROP TABLE, terraform destroy, dd, secret exfil) before execution. Sub-millisecond, zero dependencies, Apache 2.0.
- **GitHub:** https://github.com/BGMLAI/gate.cat
- **PyPI:** https://pypi.org/project/gate.cat/
- **Install:** `pip install gate.cat`
- **Integrations:** Claude Code hook, gated shell (Codex/aider), API proxy (Copilot/Ollama/vLLM)
- **Test coverage:** 178/178 dangerous commands blocked, 1,085,159 real commands replayed, 1 documented false-block (public in repo)
```

### awesome-security
```
Title: Add gate.cat — AI agent action veto (deterministic, fail-closed)

Body:
gate.cat blocks irreversible shell commands before AI coding agents execute them. Deterministic string + path analysis (no ML in the critical path). 69 policies covering: recursive delete, disk wipe, DB destruction, cloud teardown, k8s deletion, git history destruction, secret exfiltration, guard self-defense, fork bombs. Apache 2.0, zero deps.

https://github.com/BGMLAI/gate.cat
```

### awesome-python
```
Title: Add gate.cat — fail-closed action veto for AI agents

Body:
- Category: Security / AI Safety
- gate.cat: Deterministic veto that blocks irreversible shell commands before AI agents run them. Sub-ms, zero deps, Apache 2.0. Works as hook (Claude Code), shell wrapper (any CLI agent), or proxy (any API-based agent).
- pip install gate.cat
- https://github.com/BGMLAI/gate.cat
```

### awesome-claude-code
```
Title: Add gate.cat — action veto hook for Claude Code

Body:
gate.cat is a hook that blocks destructive shell commands before Claude Code executes them. Add `gatecat-hook` to `.claude/settings.json`. 178/178 dangerous commands blocked. 1 false-block documented in repo. Apache 2.0, zero deps.

pip install gate.cat
https://gate.cat
https://github.com/BGMLAI/gate.cat
```

---

## 7. NEWSLETTER PITCHES (3)

### TLDR
```
Subject: gate.cat — kill switch for AI agents that run shell commands

Hi TLDR team,

gate.cat blocks irreversible shell commands (rm -rf, DROP TABLE, terraform destroy) before AI coding agents execute them — not after.

Deterministic, sub-millisecond, zero dependencies, Apache 2.0. 178/178 test suite pass, 1,085,159 real commands replayed, 1 documented false-block (public in the repo).

Free core. Cloud tier €9/mo for tamper-evident off-machine logs + fleet alerts.

pip install gate.cat
https://gate.cat

Would this fit TLDR's AI or DevTools section?
```

### Bytes (The Stack)
```
Subject: gate.cat — fail-closed veto for AI agent shell commands

Hey Bytes team,

Built a tool that sits between AI coding agents (Claude Code, Cursor, Codex) and the shell, blocking irreversible commands before execution. No model call in the path — pure string + path analysis, sub-ms.

178/178 dangerous commands blocked. 1 false-block — deliberately public in the repo. Apache 2.0, zero deps, pip install gate.cat.

Three integration modes: native hook, gated shell, API proxy.

https://gate.cat

Good fit for Bytes?
```

### Console (JavaScript/Dev)
```
Subject: gate.cat — deterministic action veto for AI coding agents

Hi Console team,

gate.cat vetoes destructive shell commands before AI agents run them. Deterministic (no ML in critical path), sub-ms, Apache 2.0.

Works with Claude Code (hook), Codex/aider (gated shell), Copilot/Ollama (proxy). 178/178 test pass, 1 public false-block.

pip install gate.cat · https://gate.cat

Relevant for Console readers using AI coding tools?
```

---

## 8. EMAIL DO AGENT-BUILDERÓW (szablon)

```
Subject: your agent can rm -rf — gate.cat blocks it before it runs

Hey [name],

Saw your work on [project] — really impressive.

Quick thing: if your agent runs shell commands, it can run `rm -rf /`. I built gate.cat — a deterministic veto that blocks irreversible commands before execution. Sub-ms, no model call, Apache 2.0.

178/178 dangerous commands blocked. 1 false-block (public in the repo — that's the design call I'm most proud of).

pip install gate.cat · https://gate.cat · https://github.com/BGMLAI/gate.cat

Would love your take on the "1 public false-block" approach. Does it build trust or scare people off?

— Bogumił
```

---

## 9. CO WRZUCIĆ TERAZ (kolejność)

1. **Show HN** — wrzucisz tytuł + body z sekcji 1. Najlepiej rano PT (9am PT = 18:00 PL).
2. **r/LocalLLaMA** — sekcja 2. Najbardziej naturalna grupa.
3. **r/ClaudeAI** — sekcja 3. Claude Code użytkownicy = docelowi.
4. **r/Python** — sekcja 4. Szeroki zasięg.
5. **X wątek** — sekcja 5, 8 tweetów. Wrzucasz jako wątek.
6. **4 PR-y do awesome-list** — sekcja 6. Fork → dodaj → PR.
7. **3 newslettery** — sekcja 7. Wyślij email.
8. **5 emaili do agent-builderów** — sekcja 8. Spersonalizuj.

---

## 10. METRYKI — sprawdź każdego dnia

```bash
# Uruchom na VPS lub lokalnie:
python3 ~/gate.cat/scripts/launch_metrics.py
```

Albo ręcznie:
```bash
# PyPI downloads
curl -s "https://pypistats.org/api/packages/gate.cat/recent" | python3 -c "import sys,json; d=json.load(sys.stdin)['data']; print(f'Today: {d[\"last_day\"]} | Week: {d[\"last_week\"]} | Month: {d[\"last_month\"]}')"

# Stripe sessions (na VPS)
ssh root@204.168.129.200 'journalctl -u gatecat-cloud-activate --since today | grep -c "checkout\|activated\|fulfilled"'
```