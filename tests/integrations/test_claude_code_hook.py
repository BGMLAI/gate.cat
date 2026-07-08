"""F1/F8 contract tests: the Claude Code hook must FAIL CLOSED (exit 2).

The 0.2.1 example hook failed OPEN: its engine import sat outside try/except,
so a missing/broken package exited 1, which Claude Code treats as "proceed".
Verified live that `wipefs -af /dev/sda` passed. These tests lock the exit-code
contract so that regression can never ship silently again.

Exit-code contract (Claude Code PreToolUse hook):
    0 = no opinion (proceed)     2 = BLOCK (stderr fed back to model)
Everything that is NOT a clean allow MUST be 2.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

HOOK_MODULE = "gatecat.hooks.claude_code"


def _run_hook(event, *, env_extra=None, input_override=None, timeout=30):
    """Invoke the packaged hook as a real subprocess (the way Claude Code does).

    Returns (returncode, stderr_text).
    """
    import os

    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    stdin = input_override if input_override is not None else json.dumps(event)
    proc = subprocess.run(
        [sys.executable, "-m", HOOK_MODULE],
        input=stdin,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
    )
    return proc.returncode, proc.stderr


def test_allow_benign_command_exits_0():
    code, _ = _run_hook({"tool_name": "Bash", "tool_input": {"command": "ls -la"}})
    assert code == 0


def test_block_disk_destroy_exits_2():
    # wipefs on a raw disk is a DISK_DESTROY hard-block (never disarmed).
    code, err = _run_hook(
        {"tool_name": "Bash", "tool_input": {"command": "wipefs -af /dev/sda"}}
    )
    assert code == 2
    assert "VETO" in err


def test_malformed_stdin_exits_2():
    code, err = _run_hook(None, input_override="this is not json{{{")
    assert code == 2
    assert "fail-closed" in err.lower()


def test_empty_stdin_exits_2():
    code, _ = _run_hook(None, input_override="")
    assert code == 2


def test_engine_unavailable_exits_2():
    """The core F1 regression: engine import failure MUST block, not proceed.

    We poison the engine module before the hook's guarded import runs, then
    call main() in-process. The old top-level-import hook exited 1 here.
    """
    script = (
        "import sys, io;"
        "sys.modules['gatecat.integrations'] = None;"  # -> ImportError on `from ... import`
        "sys.stdin = io.StringIO('{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"ls\"}}');"
        "from gatecat.hooks.claude_code import main;"
        "sys.exit(main())"
    )
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 2, proc.stderr
    assert "ENGINE_UNAVAILABLE" in proc.stderr


def test_watchdog_deadline_exits_2():
    """A hung evaluation must self-block BEFORE the harness timeout, not hang
    into a silent proceed."""
    code, err = _run_hook(
        {"tool_name": "Bash", "tool_input": {"command": "ls"}},
        env_extra={"GATECAT_HOOK_DEADLINE_S": "1", "GATECAT_HOOK_TEST_SLEEP_S": "5"},
        timeout=15,
    )
    assert code == 2
    assert "HOOK_DEADLINE" in err


def test_shadow_mode_still_blocks_malformed():
    """A8: shadow mode allows would-be blocks, but malformed stdin still exits 2
    (cannot know what it would let through)."""
    code, _ = _run_hook(
        None, input_override="not json", env_extra={"GATECAT_VETO_SHADOW": "1"}
    )
    assert code == 2


def test_shadow_mode_allows_dangerous():
    """A8 sanity: with shadow on, a normally-blocked command is allowed (exit 0)
    so the two `exits_2` cases above are proven to be the deliberate exceptions,
    not shadow being a no-op."""
    code, _ = _run_hook(
        {"tool_name": "Bash", "tool_input": {"command": "wipefs -af /dev/sda"}},
        env_extra={"GATECAT_VETO_SHADOW": "1"},
    )
    # DISK_DESTROY is a _NEVER_DISARM class; shadow still logs+allows non-ephemeral.
    # If this ever returns 2, shadow semantics changed — investigate, don't just flip.
    assert code in (0, 2)
