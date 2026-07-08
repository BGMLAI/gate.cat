#!/usr/bin/env python3
"""Thin wrapper — the real hook now ships INSIDE the package (F8).

After `pip install gate.cat`, prefer the console script in your
.claude/settings.json (no path, no interpreter guess):

    {"hooks": {"PreToolUse": [{"matcher": "Bash|Write|Edit",
        "hooks": [{"type": "command", "command": "gatecat-hook"}]}]}}

This file remains only so an existing repo-checkout config keeps working.
It fails CLOSED (exit 2) if the package is not importable — the previous
version of this file failed OPEN here (module-level import outside
try/except → exit 1 → Claude Code proceeded on a disk-wipe). See
gatecat/hooks/claude_code.py for the full contract.
"""

from __future__ import annotations

import sys


def _fail_closed(exc: BaseException) -> "int":
    msg = (f"gate.cat VETO [ENGINE_UNAVAILABLE]: cannot import packaged hook "
           f"(fail-closed): {exc!r}. pip install gate.cat\n")
    sys.stderr.write(msg.encode("ascii", "backslashreplace").decode("ascii"))
    return 2


try:
    from gatecat.hooks.claude_code import main
except BaseException as exc:  # noqa: BLE001 — missing package must BLOCK, not pass
    sys.exit(_fail_closed(exc))


if __name__ == "__main__":
    sys.exit(main())
