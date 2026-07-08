#!/usr/bin/env python3
"""Claude Code PreToolUse hook backed by the gate.cat veto gate.

Shipped INSIDE the package (F8) so ``pip install gate.cat`` delivers it —
no repo checkout, no sys.path tricks. Register via the ``gatecat-hook``
console script (see settings.example.json in the repo, or README).

Contract (documented public Claude Code hooks API):
  stdin   : one JSON object with at least ``tool_name`` and ``tool_input``
  exit 0  : no opinion - Claude Code's own permission flow proceeds
  exit 2  : BLOCK - stderr is fed back to the model as the reason

FAIL-CLOSED, for real (F1 — the 0.2.1 example hook failed OPEN here):

    stdin ──▶ parse ──▶ import engine ──▶ check_action ──▶ exit 0/2
                │            │                 │
                ▼            ▼                 ▼
             exc: 2       exc: 2            exc: 2
                └──────── watchdog: deadline hit ──▶ exit 2 ────┘

  * Engine import error/missing package  -> exit 2 (was: exit 1 = proceed!)
  * Malformed stdin                      -> exit 2
  * Evaluation error                     -> exit 2 (inside check_action)
  * Internal deadline exceeded           -> exit 2 (watchdog below)
  * ANY uncaught exception in main       -> exit 2 (outer guard)

Claude Code kills a hook that outlives its own timeout and treats the kill
as "no opinion" (proceed) — we cannot control a SIGKILL'd exit code. The
watchdog therefore self-blocks BEFORE the harness timeout can fire: default
deadline 20s (env ``GATECAT_HOOK_DEADLINE_S``), while Claude Code's default
hook timeout is 60s. A hung engine (e.g. onnxruntime WMI probe on some
Windows hosts) becomes a loud block, not a silent pass.

A8 (shadow mode): ``GATECAT_VETO_SHADOW=1`` logs would-be blocks as
``shadow_block`` and exits 0 — handled inside ``check_action``. Two cases
still exit 2 even in shadow mode: malformed stdin (cannot know what it would
let through) and engine-unavailable (cannot even observe, so refuses to
guess — an unobserved "shadow" is a lie).

All output is ASCII-safe (D1) - Windows cp1252 consoles must not crash
on a veto reason.
"""

from __future__ import annotations

import json
import os
import sys
import threading

SOURCE = "claude_code_hook"
BLOCK, ALLOW = 2, 0
_DEADLINE_ENV = "GATECAT_HOOK_DEADLINE_S"
_TEST_SLEEP_ENV = "GATECAT_HOOK_TEST_SLEEP_S"  # internal: watchdog contract test only


def _ascii(text: str) -> str:
    """Local ASCII fallback — usable BEFORE the engine imports."""
    return str(text).encode("ascii", "backslashreplace").decode("ascii")


def _start_watchdog() -> None:
    """Self-block before the harness timeout turns a hang into a silent pass.

    ``os._exit`` (not sys.exit): must fire from a daemon thread even if the
    main thread is wedged inside a C extension import.
    """
    try:
        deadline = float(os.environ.get(_DEADLINE_ENV, "20"))
    except ValueError:
        deadline = 20.0

    def _expire() -> None:
        sys.stderr.write(_ascii(
            f"gate.cat VETO [HOOK_DEADLINE]: evaluation exceeded {deadline}s "
            "(fail-closed: a hung gate must block, not silently pass)\n"))
        sys.stderr.flush()
        os._exit(BLOCK)

    timer = threading.Timer(deadline, _expire)
    timer.daemon = True
    timer.start()


def action_text(tool_name: str, tool_input: dict) -> str:
    """Flatten a tool call into one evaluable string.

    IMPORTANT: the returned string is the ONLY thing the gate sees, so it must
    never be truncated before the security-relevant part. A prior [:2000] cap let
    a padded payload smuggle a destructive command past the 2000th char (CSO
    hook-attack finding). The gate has its own O(n)-safe length cap downstream
    (fail-closed on over-limit), so we pass the FULL text here."""
    if tool_name == "Bash":
        return str(tool_input.get("command", ""))
    if tool_name in ("Write", "Edit"):
        parts = [f"{tool_name.lower()} {tool_input.get('file_path', '')}"]
        for key in ("content", "new_string"):
            if tool_input.get(key):
                parts.append(str(tool_input[key]))   # full, not truncated
        return "\n".join(parts)
    return json.dumps(tool_input, ensure_ascii=True)   # full MCP/tool payload


def main() -> int:
    _start_watchdog()

    # F1: the engine import is INSIDE the guarded path. In 0.2.1 the example
    # hook imported at module top-level, outside any try/except — a missing/
    # broken engine exited 1, which Claude Code treats as "proceed" (fail-OPEN
    # on the exact case the docstring promised fail-closed). Verified live:
    # `wipefs -af /dev/sda` passed. Never move this import back to the top.
    try:
        from gatecat.integrations import (
            DOGFOOD_DEFAULTS,
            ActionVetoed,
            ascii_safe,
            check_action,
            log_decision,
        )
    except BaseException as exc:  # noqa: BLE001 — ANY import failure blocks
        sys.stderr.write(_ascii(
            f"gate.cat VETO [ENGINE_UNAVAILABLE]: cannot import veto engine "
            f"(fail-closed): {exc!r}. Is gate.cat installed in this "
            "environment? pip install gate.cat\n"))
        return BLOCK

    if os.environ.get(_TEST_SLEEP_ENV):  # watchdog contract test only
        import time
        time.sleep(float(os.environ[_TEST_SLEEP_ENV]))

    try:
        event = json.load(sys.stdin)
        tool_name = str(event.get("tool_name", ""))
        action = action_text(tool_name, event.get("tool_input") or {})
        # D-narrow: the hook runs on the same machine as the agent, so the real
        # cwd (from the event) and the real environment (os.environ) let the
        # delete analyzer resolve $VAR targets by VALUE instead of fail-closing.
        cwd = str(event.get("cwd") or os.getcwd())
        env = dict(os.environ)
    except Exception as exc:  # malformed hook input: fail closed
        reason = f"veto hook could not parse hook input (fail-closed): {exc}"
        log_decision(source=SOURCE, decision="block", reason=reason, context="<unparseable>")
        print(ascii_safe(reason), file=sys.stderr)
        return BLOCK

    # One mechanism: check_action does evaluate + log (D2) + fail-closed +
    # ASCII-safe reason (D1) + shadow mode (A8, internally). Exit-code map:
    #   block -> exit 2 (stderr fed back to the model as the reason)
    #   warn  -> exit 0, but surface the "unchecked" notice on stderr + log it
    #   allow -> exit 0, silent
    try:
        decision = check_action(SOURCE, action, DOGFOOD_DEFAULTS, cwd=cwd, env=env)
    except ActionVetoed as exc:
        print(str(exc), file=sys.stderr)  # already ASCII-safe
        return BLOCK
    except Exception as exc:  # engine crashed mid-evaluation: fail closed
        print(_ascii(f"gate.cat VETO [ENGINE_ERROR]: evaluation failed "
                     f"(fail-closed): {exc!r}"), file=sys.stderr)
        return BLOCK
    if getattr(decision, "level", None) == "warn":
        # unchecked action: not hard-blocked, but the human/log must see it.
        print(ascii_safe(f"gate.cat WARN (unchecked): {decision.reason}"), file=sys.stderr)
    return ALLOW


def _entry() -> None:
    """Console-script entry (``gatecat-hook``): outer guard — a bug in main()
    itself must block, not crash with a stray exit code Claude Code reads as
    'proceed'."""
    try:
        code = main()
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 — last-resort fail-closed
        sys.stderr.write(_ascii(
            f"gate.cat VETO [HOOK_ERROR]: hook crashed (fail-closed): {exc!r}\n"))
        code = BLOCK
    sys.exit(code)


if __name__ == "__main__":
    _entry()
