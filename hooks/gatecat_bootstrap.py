#!/usr/bin/env python3
"""gate.cat plugin SessionStart bootstrap.

Ensures the gate.cat veto engine is importable so the PreToolUse hook works
right after ``/plugin install`` — the user does not have to ``pip install``
anything themselves. Idempotent and non-fatal:

  * If ``gatecat`` already imports in the current interpreter (a global/user
    install) -> no-op, exit 0.
  * Else build a dedicated venv under ${CLAUDE_PLUGIN_DATA} (falls back to
    ~/.gatecat/plugin) and ``pip install gate.cat`` into it. gate.cat's core
    has ZERO dependencies, so this is a small, fast download.
  * Any failure (offline, no ensurepip, etc.) is reported on stderr and exits
    0 — a SessionStart hook must never block the session. If the engine is
    still missing when a Bash/Write/Edit fires, the PreToolUse hook fails
    CLOSED with its own guidance.

The venv lives under the plugin DATA dir (persists across plugin updates), so
this pays the install cost once, not on every update.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

PACKAGE = os.environ.get("GATECAT_PACKAGE", "gate.cat")


def _data_dir() -> Path:
    d = os.environ.get("CLAUDE_PLUGIN_DATA")
    return Path(d) if d else (Path.home() / ".gatecat" / "plugin")


def _venv_python(venv: Path) -> Path:
    if os.name == "nt":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def main() -> int:
    # 1) Already importable here? Nothing to do.
    if importlib.util.find_spec("gatecat") is not None:
        return 0

    venv = _data_dir() / "venv"
    vpy = _venv_python(venv)

    # 2) Already built in a prior session and still imports?
    if vpy.exists():
        try:
            r = subprocess.run([str(vpy), "-c", "import gatecat"], capture_output=True)
            if r.returncode == 0:
                return 0
        except Exception:
            pass  # rebuild below

    # 3) Build the venv + install the (dependency-free) engine.
    try:
        venv.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [sys.executable, "-m", "venv", str(venv)],
            check=True, capture_output=True, timeout=120,
        )
        subprocess.run(
            [str(vpy), "-m", "pip", "install", "--disable-pip-version-check",
             "--upgrade", PACKAGE],
            check=True, capture_output=True, timeout=600,
        )
        sys.stderr.write(
            "gate.cat: veto engine installed for the Claude Code plugin "
            f"({venv}). Dangerous Bash/Write/Edit actions will now be gated.\n"
        )
    except Exception as exc:  # noqa: BLE001 — never block SessionStart
        sys.stderr.write(
            "gate.cat: could not auto-install the veto engine "
            f"({exc!r}). Install it manually so the gate can enforce: "
            "pip install gate.cat\n"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
