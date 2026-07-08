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

HOOK = (Path(__file__).resolve().parents[2] / "examples" / "veto_integrations"
        / "claude_code_hook" / "veto_hook.py")


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
    path = Path(env["GATECAT_VETO_LOG"])
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_blocks_rm_rf(hook_env):
    # A recursive delete under a protected root (home) must block. (`rm -rf
    # /tmp/x` is deliberately NOT blocked - temp is regenerable; that was the
    # 92% false-block bug the target-anchored analyzer fixes.)
    proc = run_hook(event("Bash", {"command": "rm -rf ~/laptop-backup"}), hook_env)
    assert proc.returncode == 2
    assert "protected root" in proc.stderr
    records = read_log(hook_env)
    assert records[-1]["decision"] == "block"
    assert records[-1]["policy"] == "DELETE_ANALYZER"
    assert records[-1]["source"] == "claude_code_hook"


def test_allows_rm_rf_of_temp(hook_env):
    """The headline false-block fix: rm -rf of a temp/build dir must ALLOW."""
    proc = run_hook(event("Bash", {"command": "rm -rf /tmp/whatever"}), hook_env)
    assert proc.returncode == 0
    records = read_log(hook_env)
    assert records[-1]["decision"] == "allow"


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


def test_write_tool_content_is_data_not_action(hook_env):
    """Content-vs-command (0.4.0): AUTHORING migrate.sql is not RUNNING it.

    Pre-0.4.0 this exact event was pinned as a block - the FP class that broke
    writing any comment/doc/test mentioning a dangerous command. The DROP TABLE
    becomes an action only via a db client, which the Bash gate still blocks
    (next test). GATECAT_HOOK_SCAN_FILE_CONTENT=1 restores the old behavior.
    """
    proc = run_hook(
        event("Write", {"file_path": "migrate.sql", "content": "DROP TABLE users;"}), hook_env
    )
    assert proc.returncode == 0
    records = read_log(hook_env)
    assert records[-1]["decision"] == "allow"


def test_running_the_written_sql_still_blocks(hook_env):
    proc = run_hook(
        event("Bash", {"command": 'psql -c "DROP TABLE users;"'}), hook_env
    )
    assert proc.returncode == 2
    assert "DB_DESTRUCTIVE" in proc.stderr


def test_write_content_scan_opt_in(hook_env):
    env = dict(hook_env)
    env["GATECAT_HOOK_SCAN_FILE_CONTENT"] = "1"
    proc = run_hook(
        event("Write", {"file_path": "migrate.sql", "content": "DROP TABLE users;"}), env
    )
    assert proc.returncode == 2
    assert "DB_DESTRUCTIVE" in proc.stderr


def test_write_to_autoexec_location_warns_not_blocks(hook_env):
    """A write TARGETING code-that-runs-later (git hook) exits 0 but surfaces
    the AUTOEXEC_WRITE warn on stderr - never a silent allow."""
    proc = run_hook(
        event("Write", {"file_path": ".git/hooks/pre-commit",
                        "content": "#!/bin/sh\necho hi"}), hook_env
    )
    assert proc.returncode == 0
    assert "AUTOEXEC_WRITE" in proc.stderr


def test_fail_closed_without_engine(engine_absent_env):
    """Veto engine unimportable => block, never allow.

    ``engine_absent_env`` makes ``gatecat.veto`` raise on import while keeping
    ``gatecat.integrations`` available, so this exercises fail-closed
    deterministically even when the real gatecat is installed editable in the
    dev environment (a bare PYTHONPATH swap would not remove an editable install).
    """
    proc = run_hook(event("Bash", {"command": "ls"}), engine_absent_env)
    assert proc.returncode == 2
    assert "fail-closed" in proc.stderr


def test_fail_closed_on_malformed_stdin(hook_env):
    proc = run_hook("this is not json", hook_env)
    assert proc.returncode == 2
    assert "fail-closed" in proc.stderr


def test_stderr_is_ascii_even_with_polish_reason(hook_env, fake_engine):
    """D1: a reason with Polish diacritics must reach stderr ASCII-escaped."""
    veto = fake_engine / "gatecat" / "veto.py"
    veto.write_text(
        veto.read_text().replace(
            'pol["reason"]', '"zniszczy\\u0142oby \\u015brodowisko produkcyjne"'
        )
    )
    # Use a NON-delete action so it goes through the engine (whose reason we
    # injected), not the delete analyzer. D1 must hold on the engine path.
    proc = run_hook(event("Bash", {"command": "terraform destroy -auto-approve"}), hook_env)
    assert proc.returncode == 2
    proc.stderr.encode("ascii")  # raises if any non-ASCII slipped through
    assert "zniszczy" in proc.stderr


def test_log_context_truncated(hook_env):
    long_cmd = "rm -rf /tmp/x  # " + "y" * 5000
    run_hook(event("Bash", {"command": long_cmd}), hook_env)
    assert len(read_log(hook_env)[-1]["context"]) <= 400
