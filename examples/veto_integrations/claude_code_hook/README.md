# Claude Code veto hook (A1)

A `PreToolUse` hook that runs every `Bash` / `Write` / `Edit` tool call through
the gatecat **veto gate** before it executes. Dangerous actions
(`terraform ... prod`, `DROP TABLE`, `rm -rf`, `git push --force`,
cloud deletes) are blocked with **exit code 2**; the reason lands on stderr
and is fed back to the model.

## 5-minute quickstart

1. Install the SDK with the veto engine (>= 0.3.0):

   ```bash
   pip install gate.cat
   ```

2. Merge `settings.example.json` into your `.claude/settings.json`
   (fix the absolute path to `veto_hook.py`).

3. Test it in a live session — ask Claude to run `rm -rf /tmp/x`:
   the call is blocked, and the model sees `VETO [RM_RF]: recursive force
   delete requires a human`.

Every decision (allow AND block) is appended to
`~/.gatecat/veto_log.jsonl` — that log is the raw material for
false-block-rate adjudication (B2 in VETO_PIPELINE_PLAN.md).

## Shadow mode (A8, opt-in)

Set `GATECAT_VETO_SHADOW=1` in the hook's environment to watch the gate
without it stopping anything: every would-be block is logged as
`shadow_block` and the hook exits 0. Run it this way for a day, read the log,
see what it *would* have caught — then drop the env var to enforce. Default is
enforce; malformed stdin still exits 2 even in shadow (the hook won't wave
through what it couldn't parse).

## What this hook sees / what it does not

- It sees the **textual tool call** (shell command, file path + content).
  It blocks only what a policy wall matches; everything else is passed
  to Claude Code's normal permission flow **unchecked — unchecked is not
  "verified safe"**.
- Fail-closed: if the veto engine is missing or errors out, the hook
  blocks (exit 2) rather than silently allowing.
- Fallback if the hook API ever changes shape: use the inline wrapper
  (`from gatecat.veto import VetoGate` directly in your agent code) —
  not an MCP server.

## Contract pinned by tests

`tests/test_hook_contract.py` runs this script as a subprocess with
simulated stdin and asserts exit codes 0/2, ASCII-only stderr (cp1252-safe),
and fail-closed behavior on engine absence and malformed input.
