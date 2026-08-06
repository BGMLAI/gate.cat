"""Tests for `gate.cat setup claude-code` / `gate.cat doctor` (gatecat._setup_cli).

The contract under test is fail-closed hook activation: never overwrite what
we cannot parse, never lose foreign keys, always back up before modifying,
and stay a no-op once registered.
"""
import json
import os

import pytest

from gatecat import _setup_cli as sc
from gatecat.integrations.dashboard import main as cli_main


@pytest.fixture()
def isolated(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    return tmp_path


def _settings(tmp_path):
    return tmp_path / ".claude" / "settings.json"


def test_fresh_dir_setup_registers_hook(isolated, capsys):
    rc = sc.run_setup(["claude-code"])

    assert rc == 0
    data = json.loads(_settings(isolated).read_text())
    assert data["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "gatecat-hook"
    assert "registered" in capsys.readouterr().out


def test_second_run_is_noop(isolated, capsys):
    sc.run_setup(["claude-code"])
    before = _settings(isolated).read_text()
    capsys.readouterr()

    rc = sc.run_setup(["claude-code"])

    assert rc == 0
    assert "already registered" in capsys.readouterr().out
    assert _settings(isolated).read_text() == before
    # no backup for a no-op run
    assert not os.path.exists(str(_settings(isolated)) + ".gatecat.bak")


def test_foreign_keys_and_hooks_survive_merge(isolated):
    target = _settings(isolated)
    target.parent.mkdir(parents=True)
    existing = {
        "permissions": {"allow": ["Bash(ls:*)"]},
        "hooks": {
            "PreToolUse": [{"matcher": "Bash",
                            "hooks": [{"type": "command", "command": "other-guard"}]}],
            "PostToolUse": [{"matcher": "*", "hooks": []}],
        },
    }
    target.write_text(json.dumps(existing))

    assert sc.run_setup(["claude-code"]) == 0

    data = json.loads(target.read_text())
    assert data["permissions"] == {"allow": ["Bash(ls:*)"]}          # foreign key
    assert data["hooks"]["PostToolUse"] == [{"matcher": "*", "hooks": []}]
    commands = [h["command"] for e in data["hooks"]["PreToolUse"] for h in e["hooks"]]
    assert commands == ["other-guard", "gatecat-hook"]               # appended, not replaced
    # backup of the pre-merge file exists and holds the ORIGINAL content
    bak = json.loads(open(str(target) + ".gatecat.bak").read())
    assert bak == existing


def test_dry_run_touches_nothing(isolated, capsys):
    rc = sc.run_setup(["claude-code", "--dry-run"])

    assert rc == 0
    assert "DRY RUN" in capsys.readouterr().out
    assert not _settings(isolated).exists()


def test_unparsable_settings_refused_and_untouched(isolated, capsys):
    target = _settings(isolated)
    target.parent.mkdir(parents=True)
    target.write_text("{not json!!")

    rc = sc.run_setup(["claude-code"])

    assert rc == 1
    assert target.read_text() == "{not json!!"                       # untouched
    out = capsys.readouterr().out
    assert "REFUSING" in out and "gatecat-hook" in out               # manual block shown


def test_global_flag_targets_home(isolated):
    rc = sc.run_setup(["claude-code", "--global"])

    assert rc == 0
    global_settings = isolated / "home" / ".claude" / "settings.json"
    assert "gatecat-hook" in global_settings.read_text()


def test_usage_error_on_unknown_target(isolated, capsys):
    assert sc.run_setup(["cursor"]) == 2
    assert "usage:" in capsys.readouterr().out


def test_doctor_reports_version_and_registration(isolated, capsys):
    import gatecat
    sc.run_setup(["claude-code"])
    capsys.readouterr()

    rc = sc.run_doctor([])

    assert rc == 0
    out = capsys.readouterr().out
    assert gatecat.__version__ in out
    assert "gatecat-hook registered" in out
    assert "protection:" in out


def test_doctor_points_at_setup_when_unregistered(isolated, capsys):
    rc = sc.run_doctor([])

    assert rc == 0
    assert "run: gate.cat setup claude-code" in capsys.readouterr().out


def test_dispatcher_routes_setup_and_doctor(isolated, capsys):
    assert cli_main(["setup", "claude-code", "--dry-run"]) == 0
    assert "DRY RUN" in capsys.readouterr().out
    assert cli_main(["doctor"]) == 0
    assert "protection:" in capsys.readouterr().out
