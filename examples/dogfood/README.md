# Dogfooding gate.cat (collect your false-block rate)

The number that gates outreach: **of everything the gate blocked, how many were
false alarms?** Devs uninstall a guardrail after one bad block, so you publish
nothing about accuracy until you've measured this on real traffic (target: N≥30
adjudicated blocks).

## 1. Wire the hook into your own agent sessions

```bash
pip install gate.cat
```

Merge `settings.json` (in this folder) into your project's `.claude/settings.json`
and fix the absolute path to `veto_hook.py`. From now on every `Bash`/`Write`/`Edit`
tool call your agent makes runs through the veto gate first; every decision (allow
*and* block) appends to `~/.cacheback/veto_log.jsonl`.

## 2. Just work normally

Use Claude Code / Codex as usual for a few days. The log fills itself. Real
dangerous actions get blocked; the log records each one with the policy that fired.

## 3. Adjudicate + measure

```bash
python false_block_rate.py               # summary of the log so far
python false_block_rate.py --adjudicate  # rule on each block: real (should block) / false (wrongly blocked)
python false_block_rate.py               # re-run for the false-block rate
```

Adjudication is saved to `veto_log.adjudicated.jsonl` so you never lose your
rulings. Once N≥30, you have an honest false-block-rate to stand behind — and the
real "veto catches" become your best pitch (a true story beats any benchmark).

**Honest labels:** a founder-only self-test is a biased sample (you know your own
policies). The strongest evidence is one *other* dev running the hook and reporting
their own N≥20. Mark the source when you publish any number.
