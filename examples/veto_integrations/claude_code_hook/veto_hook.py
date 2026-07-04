#!/usr/bin/env python3
"""A1: Claude Code PreToolUse hook backed by the cacheback veto gate.

Contract (documented public Claude Code hooks API):
  stdin   : one JSON object with at least ``tool_name`` and ``tool_input``
  exit 0  : no opinion - Claude Code's own permission flow proceeds
  exit 2  : BLOCK - stderr is fed back to the model as the reason

Register in ``.claude/settings.json``  (see settings.example.json):

    {"hooks": {"PreToolUse": [{"matcher": "Bash|Write|Edit",
        "hooks": [{"type": "command",
                   "command": "python /abs/path/to/veto_hook.py"}]}]}}

Fail-closed: engine unavailable, malformed stdin, or evaluation error
=> exit 2. An unverifiable action is never waved through. Every decision
is appended to the audit log (D2, ``~/.cacheback/veto_log.jsonl``).

A8 (shadow mode): set ``CACHEBACK_VETO_SHADOW=1`` to log every would-be
block as ``shadow_block`` and exit 0 (nothing is stopped). Off by default -
the hook enforces. Malformed stdin is the one case that always exits 2, even
in shadow mode: if the hook cannot parse the event it cannot know what it is
letting through, so it refuses to guess.

All output is ASCII-safe (D1) - Windows cp1252 consoles must not crash
on a veto reason.
"""

from __future__ import annotations

import json
import os
import sys

# Allow running straight from a repo checkout without pip install.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from cacheback.integrations import (  # noqa: E402
    DOGFOOD_DEFAULTS,
    ActionVetoed,
    ascii_safe,
    check_action,
    log_decision,
)

SOURCE = "claude_code_hook"
BLOCK, ALLOW = 2, 0


def action_text(tool_name: str, tool_input: dict) -> str:
    """Flatten a tool call into one evaluable string."""
    if tool_name == "Bash":
        return str(tool_input.get("command", ""))
    if tool_name in ("Write", "Edit"):
        parts = [f"{tool_name.lower()} {tool_input.get('file_path', '')}"]
        for key in ("content", "new_string"):
            if tool_input.get(key):
                parts.append(str(tool_input[key])[:2000])
        return "\n".join(parts)
    return json.dumps(tool_input, ensure_ascii=True)[:2000]


def main() -> int:
    try:
        event = json.load(sys.stdin)
        tool_name = str(event.get("tool_name", ""))
        action = action_text(tool_name, event.get("tool_input") or {})
    except Exception as exc:  # malformed hook input: fail closed
        reason = f"veto hook could not parse hook input (fail-closed): {exc}"
        log_decision(source=SOURCE, decision="block", reason=reason, context="<unparseable>")
        print(ascii_safe(reason), file=sys.stderr)
        return BLOCK

    # One mechanism: check_action does evaluate + log (D2) + fail-closed +
    # ASCII-safe reason (D1). The hook only maps its result to an exit code.
    try:
        check_action(SOURCE, action, DOGFOOD_DEFAULTS)
    except ActionVetoed as exc:
        print(str(exc), file=sys.stderr)  # already ASCII-safe
        return BLOCK
    return ALLOW


if __name__ == "__main__":
    sys.exit(main())
