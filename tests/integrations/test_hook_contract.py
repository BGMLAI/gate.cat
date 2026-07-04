"""A1 e2e contract test: run veto_hook.py as a real subprocess.

Pins the Claude Code PreToolUse contract on our side:
exit 0 = no opinion, exit 2 = block with ASCII stderr, fail-closed on
engine absence and malformed input, audit log written for every decision.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

HOOK = Path(__file__).resolve().parents[1] / "examples" / "claude_code_hook" / "veto_hook.py"


def run_hook(stdin: str, env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(HOOK)],
        input=stdin,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def event(tool_name: str, tool_input: dict) -> str:
    return json.dumps(
        {"hook_event_name": "PreToolUse", "tool_name": tool_name, "tool_input": tool_input}
    )


def read_log(env: dict[str, str]) -> list[dict]:
    path = Path(env["CACHEBACK_VETO_LOG"])
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_blocks_rm_rf(hook_env):
    proc = run_hook(event("Bash", {"command": "rm -rf /tmp/whatever"}), hook_env)
    assert proc.returncode == 2
    assert "VETO [RM_RF]" in proc.stderr
    records = read_log(hook_env)
    assert records[-1]["decision"] == "block"
    assert records[-1]["policy"] == "RM_RF"
    assert records[-1]["source"] == "claude_code_hook"


def test_blocks_terraform_prod_and_force_push(hook_env):
    for cmd, policy in [
        ("terraform destroy -var-file=prod.tfvars", "TERRAFORM_PROD"),
        ("git push --force origin master", "GIT_FORCE_PUSH"),
    ]:
        proc = run_hook(event("Bash", {"command": cmd}), hook_env)
        assert proc.returncode == 2, cmd
        assert policy in proc.stderr, cmd


def test_allows_force_with_lease(hook_env):
    proc = run_hook(
        event("Bash", {"command": "git push --force-with-lease origin feature"}), hook_env
    )
    assert proc.returncode == 0
    assert read_log(hook_env)[-1]["decision"] == "allow"


def test_allows_harmless_command(hook_env):
    proc = run_hook(event("Bash", {"command": "ls -la"}), hook_env)
    assert proc.returncode == 0
    assert proc.stderr == ""


def test_write_tool_with_destructive_sql_blocked(hook_env):
    proc = run_hook(
        event("Write", {"file_path": "migrate.sql", "content": "DROP TABLE users;"}), hook_env
    )
    assert proc.returncode == 2
    assert "DB_DESTRUCTIVE" in proc.stderr


def test_fail_closed_without_engine(hook_env, tmp_path):
    """Engine missing from PYTHONPATH => block, never allow."""
    env = dict(hook_env)
    env["PYTHONPATH"] = str(Path(HOOK).resolve().parents[2])  # package only, no fake engine
    proc = run_hook(event("Bash", {"command": "ls"}), env)
    assert proc.returncode == 2
    assert "fail-closed" in proc.stderr


def test_fail_closed_on_malformed_stdin(hook_env):
    proc = run_hook("this is not json", hook_env)
    assert proc.returncode == 2
    assert "fail-closed" in proc.stderr


def test_stderr_is_ascii_even_with_polish_reason(hook_env, fake_engine):
    """D1: a reason with Polish diacritics must reach stderr ASCII-escaped."""
    veto = fake_engine / "cacheback" / "veto.py"
    veto.write_text(
        veto.read_text().replace(
            'pol["reason"]', '"zniszczy\\u0142oby \\u015brodowisko produkcyjne"'
        )
    )
    proc = run_hook(event("Bash", {"command": "rm -rf /"}), hook_env)
    assert proc.returncode == 2
    proc.stderr.encode("ascii")  # raises if any non-ASCII slipped through
    assert "zniszczy" in proc.stderr


def test_log_context_truncated(hook_env):
    long_cmd = "rm -rf /tmp/x  # " + "y" * 5000
    run_hook(event("Bash", {"command": long_cmd}), hook_env)
    assert len(read_log(hook_env)[-1]["context"]) <= 400
