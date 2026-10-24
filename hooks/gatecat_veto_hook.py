#!/usr/bin/env python3
"""gate.cat Claude Code PLUGIN veto hook (PreToolUse).

Thin launcher that resolves the gate.cat veto engine and delegates to the
packaged, battle-tested ``gatecat.hooks.claude_code.main`` (the SAME engine as
the ``gatecat-hook`` console script — this plugin does not reimplement the
gate, it only wires it into Claude Code's plugin system).

Resolution order:
  1. Engine importable in the interpreter chosen by gatecat-python.sh?
     -> run it directly (covers a global/user ``pip install gate.cat``).
  2. Else re-exec the engine with the plugin-managed venv's python, which
     ``gatecat_bootstrap.py`` populates on SessionStart (frictionless install:
     the user only ran ``/plugin install`` — the engine was fetched for them).
  3. Else FAIL CLOSED (exit 2) with clear guidance. gate.cat never waves an
     action through it could not inspect.

Contract (Claude Code hooks API): stdin = one JSON tool call; exit 0 = no
opinion (Claude Code's own permission flow proceeds); exit 2 = BLOCK, stderr
fed back to the model as the reason.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

# Re-exec payload: import + run the packaged engine. main() reads stdin itself,
# and the subprocess inherits this process's stdin/stdout/stderr, so the JSON
# tool call and the exit code flow through untouched.
_RUN = "from gatecat.hooks.claude_code import main; import sys; sys.exit(main())"


def _plugin_venv_python() -> "Path | None":
    data = os.environ.get("CLAUDE_PLUGIN_DATA") or str(Path.home() / ".gatecat" / "plugin")
    if os.name == "nt":
        cand = Path(data) / "venv" / "Scripts" / "python.exe"
    else:
        cand = Path(data) / "venv" / "bin" / "python"
    return cand if cand.exists() else None


def _fail_closed(exc: "BaseException | None") -> int:
    msg = (
        "gate.cat VETO [ENGINE_UNAVAILABLE]: cannot load the veto engine "
        "(fail-closed) — the action is BLOCKED rather than run unchecked. "
        "The plugin installs the engine on SessionStart; if that did not run, "
        "install it manually: pip install gate.cat"
    )
    if exc is not None:
        msg += f"  [{exc!r}]"
    sys.stderr.write((msg + "\n").encode("ascii", "backslashreplace").decode("ascii"))
    return 2


def main() -> int:
    engine_main = None
    import_err: "BaseException | None" = None
    try:
        from gatecat.hooks.claude_code import main as engine_main  # type: ignore
    except BaseException as exc:  # noqa: BLE001 — missing engine must not pass
        import_err = exc

    if engine_main is not None:
        return engine_main()

    vpy = _plugin_venv_python()
    if vpy is not None:
        try:
            return subprocess.run([str(vpy), "-c", _RUN]).returncode
        except BaseException as exc:  # noqa: BLE001
            return _fail_closed(exc)

    return _fail_closed(import_err)


if __name__ == "__main__":
    sys.exit(main())
