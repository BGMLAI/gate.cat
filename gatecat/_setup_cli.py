"""`gate.cat setup claude-code` and `gate.cat doctor` — one-command hook install.

The README documents the PreToolUse block for manual paste; every activation
still depends on a human editing JSON by hand, and an unarmed hook is the
single biggest funnel leak (installs that never enforce). This automates
exactly what the README documents — nothing more.

Fail-closed contract (same spirit as the gate itself):
  * an unparsable settings.json is NEVER touched or overwritten — we print the
    manual-paste block and exit non-zero instead;
  * every modifying write makes a `<file>.gatecat.bak` copy first;
  * re-running is a no-op once `gatecat-hook` is registered (idempotent);
  * foreign keys, other hooks and unrelated settings survive byte-for-byte at
    the JSON level (we re-serialize, but never drop or reorder semantics).
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

# The exact block README.md and settings.example.json document.
HOOK_COMMAND = "gatecat-hook"
HOOK_ENTRY = {
    "matcher": "Bash|Write|Edit",
    "hooks": [{"type": "command", "command": HOOK_COMMAND}],
}

MANUAL_BLOCK = json.dumps(
    {"hooks": {"PreToolUse": [HOOK_ENTRY]}}, indent=2)


def _settings_path(global_: bool) -> Path:
    if global_:
        return Path(os.path.expanduser("~")) / ".claude" / "settings.json"
    return Path.cwd() / ".claude" / "settings.json"


def _hook_registered(data: dict) -> bool:
    try:
        for entry in data.get("hooks", {}).get("PreToolUse", []):
            for hook in entry.get("hooks", []):
                if HOOK_COMMAND in str(hook.get("command", "")):
                    return True
    except AttributeError:
        # hooks/PreToolUse of an unexpected shape: treat as not registered;
        # the merge below only APPENDS, so nothing existing is at risk.
        pass
    return False


def run_setup(args: list[str]) -> int:
    targets = [a for a in args if not a.startswith("-")]
    flags = {a for a in args if a.startswith("-")}
    unknown_flags = flags - {"--global", "--dry-run"}
    if targets != ["claude-code"] or unknown_flags:
        print("usage: gate.cat setup claude-code [--global] [--dry-run]\n"
              "  registers the gatecat-hook PreToolUse hook in ./.claude/settings.json\n"
              "  (--global: ~/.claude/settings.json instead)")
        return 2

    path = _settings_path("--global" in flags)
    dry = "--dry-run" in flags

    data: dict = {}
    if path.exists():
        try:
            data = json.loads(path.read_text())
            if not isinstance(data, dict):
                raise ValueError("settings.json is not a JSON object")
        except ValueError as exc:
            # Fail closed: we never overwrite a file we cannot parse.
            print(f"REFUSING to touch {path}: {exc}.\n"
                  "Fix the file, or paste this block into it yourself:\n"
                  + MANUAL_BLOCK)
            return 1

    if _hook_registered(data):
        print(f"gatecat-hook already registered in {path} - nothing to do.")
        return 0

    merged = dict(data)
    hooks = dict(merged.get("hooks") or {})
    pre = list(hooks.get("PreToolUse") or [])
    pre.append(HOOK_ENTRY)
    hooks["PreToolUse"] = pre
    merged["hooks"] = hooks
    serialized = json.dumps(merged, indent=2) + "\n"

    if dry:
        print(f"DRY RUN - would write {path}:\n{serialized}", end="")
        return 0

    path.parent.mkdir(parents=True, exist_ok=True)
    had_file = path.exists()
    if had_file:
        shutil.copyfile(path, str(path) + ".gatecat.bak")
    path.write_text(serialized)
    print(f"gatecat-hook registered in {path}"
          + (f" (backup: {path}.gatecat.bak)" if had_file else ""))
    if shutil.which(HOOK_COMMAND) is None:
        print("note: `gatecat-hook` is not on PATH in THIS shell - the hook "
              "will fail closed until the install's bin dir is on PATH.")
    return 0


def run_doctor(_args: list[str]) -> int:
    import gatecat
    from gatecat.integrations.protection import read_protection

    print(f"gate.cat {gatecat.__version__}")
    print(f"hook binary on PATH: "
          f"{shutil.which(HOOK_COMMAND) or 'NOT FOUND (pip install gate-cat)'}")

    found = False
    for label, path in (("project", _settings_path(False)),
                        ("global ", _settings_path(True))):
        state = "no settings.json"
        if path.exists():
            try:
                state = ("gatecat-hook registered"
                         if _hook_registered(json.loads(path.read_text()))
                         else "settings.json present, hook NOT registered")
            except ValueError:
                state = "settings.json UNPARSABLE"
        if "registered" in state and "NOT" not in state:
            found = True
        print(f"{label} {path}: {state}")

    print(f"protection: {read_protection()}"
          " (catastrophic classes always block, regardless)")
    if not found:
        print("hook not registered anywhere -> run: gate.cat setup claude-code")
    return 0
