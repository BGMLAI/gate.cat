"""Tests for the once-a-day CLI Solo nudge (gatecat._nudge.maybe_nudge_cli).

Contract (same bar as the post-veto nudge): stderr only, opt-out respected,
best-effort (never raises), silent for Cloud customers and for empty logs,
at most one nudge of ANY kind per process, at most one per day across runs.
"""
import os

import gatecat._nudge as nudge
from gatecat.integrations.dashboard import render_report


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(nudge, "_LAST", str(tmp_path / ".gatecat" / "nudge_last"))
    monkeypatch.setattr(nudge, "_fired_this_run", False)
    monkeypatch.delenv("GATECAT_NO_NUDGE", raising=False)
    monkeypatch.delenv("GATECAT_QUIET", raising=False)
    monkeypatch.delenv("GATECAT_CLOUD_API_KEY", raising=False)


def test_fires_once_with_interventions(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch)

    nudge.maybe_nudge_cli("status", 7)

    err = capsys.readouterr().err
    assert "7 intervention(s)" in err
    assert "https://gate.cat/teams.html?source=cli" in err
    assert "gate.cat report" in err  # discovery line for the free local report
    assert "GATECAT_NO_NUDGE=1" in err
    assert os.path.exists(str(tmp_path / ".gatecat" / "nudge_last"))


def test_never_two_nudges_in_one_process(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch)

    nudge.maybe_nudge_cli("status", 3)
    nudge.maybe_nudge_cli("stats", 3)

    err = capsys.readouterr().err
    assert err.count("teams.html?source=cli") == 1


def test_daily_rate_limit_across_processes(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch)
    nudge.maybe_nudge_cli("status", 3)
    capsys.readouterr()

    # simulate a fresh process the same day: only the in-memory guard resets
    monkeypatch.setattr(nudge, "_fired_this_run", False)
    nudge.maybe_nudge_cli("status", 3)

    assert capsys.readouterr().err == ""


def test_silent_without_interventions(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch)

    nudge.maybe_nudge_cli("status", 0)

    assert capsys.readouterr().err == ""
    assert not os.path.exists(str(tmp_path / ".gatecat" / "nudge_last"))


def test_silent_for_cloud_customers(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setenv("GATECAT_CLOUD_API_KEY", "k")

    nudge.maybe_nudge_cli("status", 9)

    assert capsys.readouterr().err == ""


def test_optout_env_is_silent(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setenv("GATECAT_NO_NUDGE", "1")

    nudge.maybe_nudge_cli("status", 9)

    assert capsys.readouterr().err == ""


def test_post_veto_nudge_blocks_cli_nudge_same_run(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(nudge, "_FLAG", str(tmp_path / ".gatecat" / ".nudged"))

    nudge.maybe_nudge_after_veto()
    nudge.maybe_nudge_cli("status", 5)

    err = capsys.readouterr().err
    assert "gate.cat vetoed that locally" in err
    assert "source=cli" not in err


def test_never_raises_when_state_dir_unwritable(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    blocker = tmp_path / "blocked"
    blocker.write_text("file, not a dir")
    monkeypatch.setattr(nudge, "_LAST", str(blocker / "nudge_last"))

    nudge.maybe_nudge_cli("status", 5)  # must not raise


def test_report_footer_links_offmachine_copy():
    out = render_report([{"ts": "2026-07-01T10:00:00Z", "decision": "block",
                          "policy": "DELETE_ANALYZER", "context": "rm -rf x"}],
                        month="2026-07")
    assert "https://gate.cat/teams.html?source=report" in out
    assert "EUR 19/mo" in out
    out.encode("ascii")  # report stays paste-safe (same bar as test_dashboard)
