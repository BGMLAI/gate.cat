"""Write/Edit content-vs-command (0.4.0): file content is data, not an action.

Before 0.4.0 the Claude Code hook flattened Write/Edit FILE CONTENT into the
evaluated action, so writing a comment, docstring, test, or doc that merely
MENTIONS a dangerous command hard-blocked - authoring "rm -rf /" in a Python
comment executes nothing, yet it vetoed. The Bash side has always treated the
same bytes as inert data (`echo "rm -rf /" > notes.md` allows - see
test_content_vs_command.py); this pins the symmetric rule for Write/Edit:

  * content mentions        -> allow (the action is "write to <path>")
  * auto-exec TARGET PATH   -> warn  (AUTOEXEC_WRITE: git hooks, shell rc,
                                      cron, systemd, .claude/settings*.json -
                                      code armed to run with no Bash step)
  * the same command RUN    -> still blocks (Bash gating unchanged)
  * GATECAT_HOOK_SCAN_FILE_CONTENT=1 -> old paranoid behavior, opt-in
"""

from __future__ import annotations

import pytest

from gatecat.hooks.claude_code import action_text
from gatecat.integrations._engine import ActionVetoed
from gatecat.integrations.guard import check_action
from gatecat.integrations.policies import DOGFOOD_DEFAULTS

CWD = "/home/dev/project"


def _verdict(action: str) -> str:
    try:
        return check_action("t", action, DOGFOOD_DEFAULTS, cwd=CWD).level
    except ActionVetoed:
        return "block"


def _write(path: str, content: str) -> str:
    return action_text("Write", {"file_path": path, "content": content})


def _edit(path: str, new_string: str) -> str:
    return action_text("Edit", {"file_path": path, "new_string": new_string})


# a dangerous command MENTIONED in authored file content -> must not block
CONTENT_MENTIONS = [
    ("tests/test_gate.py", 'def test_rm():\n    # must veto: rm -rf /\n    assert veto("rm -rf /") == BLOCK'),
    ("docs/SECURITY.md", "Never run `DROP TABLE users` or `gh repo delete` in prod."),
    ("gate.py", '"""Blocks wipefs -af /dev/sda and terraform destroy -auto-approve."""'),
    ("migrate.sql", "DROP TABLE users;"),           # authoring SQL is not running it
    ("cleanup.sh", '#!/bin/sh\nrm -rf "$TMPDIR/build"'),  # authoring a script is not running it
]


@pytest.mark.parametrize("path,content", CONTENT_MENTIONS)
def test_written_content_is_data_not_action(path, content):
    assert _verdict(_write(f"{CWD}/{path}", content)) == "allow", \
        f"false-block on authored content: {path}"


@pytest.mark.parametrize("path,content", CONTENT_MENTIONS)
def test_edited_content_is_data_not_action(path, content):
    assert _verdict(_edit(f"{CWD}/{path}", content)) == "allow", \
        f"false-block on edited content: {path}"


def test_action_text_default_omits_content(monkeypatch):
    """The gate must not even SEE the content by default - path only."""
    monkeypatch.delenv("GATECAT_HOOK_SCAN_FILE_CONTENT", raising=False)
    text = _write(f"{CWD}/x.md", "rm -rf /")
    assert text == f"write {CWD}/x.md"


def test_opt_in_restores_content_scanning(monkeypatch):
    monkeypatch.setenv("GATECAT_HOOK_SCAN_FILE_CONTENT", "1")
    text = _write(f"{CWD}/x.md", "rm -rf /")
    assert "rm -rf /" in text
    assert _verdict(text) == "block"


# a write whose TARGET is executed later without any visible Bash step -> warn
# on BOTH pathways (Write/Edit tool AND bash redirect/tee/cp), never silently.
AUTOEXEC_TARGETS = [
    _write(f"{CWD}/.git/hooks/pre-commit", "#!/bin/sh\necho hi"),
    _write("/home/dev/.bashrc", "export X=1"),
    _edit(f"{CWD}/.claude/settings.json", '{"hooks": {}}'),
    'echo "alias x=1" >> ~/.bashrc',
    'echo "* * * * * root sh /tmp/x" | tee /etc/cron.d/job',
    "cp x.service /etc/systemd/system/x.service",
    "crontab evil.cron",
]


@pytest.mark.parametrize("action", AUTOEXEC_TARGETS)
def test_autoexec_target_write_is_surfaced(action):
    assert _verdict(action) == "warn", f"auto-exec write not surfaced: {action!r}"


# normal dev traffic around those same locations -> no warn (read is not write)
BENIGN_NEARBY = [
    "cat ~/.bashrc",
    "source ~/.bashrc",
    "ls .git/hooks/",
    "git diff .git/hooks/pre-commit",
    "crontab -l",
    "crontab -e",
    "pip install requests",
    'git commit -m "edit bashrc note"',
    "echo test >> notes.md",
    _write(f"{CWD}/src/app.py", "print('hello')"),
]


@pytest.mark.parametrize("action", BENIGN_NEARBY)
def test_benign_neighbors_do_not_warn(action):
    assert _verdict(action) == "allow", f"false-warn on benign action: {action!r}"


# the SAME commands the content merely mentioned, actually RUN -> still block.
# This is the invariant the 0.4.0 change must not move: enforcement lives at
# RUN time, and dropping content scanning must not weaken the Bash gate.
STILL_BLOCKS = [
    "rm -rf /srv/data",
    "wipefs -af /dev/sda",
    "terraform destroy -auto-approve",
    "git push --force origin master",
    'psql -c "DROP TABLE users;"',
]


@pytest.mark.parametrize("cmd", STILL_BLOCKS)
def test_running_the_mentioned_command_still_blocks(cmd):
    assert _verdict(cmd) == "block", f"HOLE: Bash gating weakened: {cmd!r}"
