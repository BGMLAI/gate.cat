"""FEATURE 3 - FREE-CORE stagnation, local half (warn / optional soft-halt).

Repeated identical no-progress commands routed through the gated shell emit a
VISIBLE stderr warning and a decision='stagnation' log record. Warn-only by
default; GATECAT_STAGNATION_HALT=1 turns on a soft halt (the gated shell returns
BLOCK). Honest scope: warns on repeated shell commands; does not kill externals.
State is disk-persisted per-session so it survives the one-process-per-command
model the real gated shell uses.
"""
import contextlib
import io
import json
import os

import pytest

from gatecat.integrations import shell_stagnation as S


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("GATECAT_STAGNATION_DIR", str(tmp_path))
    monkeypatch.setenv("GATECAT_VETO_LOG", str(tmp_path / "veto.jsonl"))
    monkeypatch.setenv("GATECAT_SESSION", "unit-test")
    monkeypatch.delenv("GATECAT_STAGNATION_HALT", raising=False)
    return tmp_path


def _surface(cmd):
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        reason = S.surface(cmd)
    return reason, buf.getvalue()


def test_repeated_command_trips_with_visible_warning(isolated):
    assert _surface("npm test")[0] is None      # 1st
    assert _surface("npm test")[0] is None      # 2nd
    reason, err = _surface("npm test")           # 3rd -> trips
    assert reason and "repeat_action" in reason
    assert "no progress" in err and "stuck loop" in err


def test_stagnation_logged_for_dashboard(isolated):
    for _ in range(3):
        _surface("cargo build")
    records = [json.loads(l) for l in open(os.environ["GATECAT_VETO_LOG"])]
    stag = [r for r in records if r["decision"] == "stagnation"]
    assert stag and "cargo build" in (stag[0].get("context") or "")


def test_different_commands_do_not_trip(isolated):
    assert _surface("ls")[0] is None
    assert _surface("pwd")[0] is None
    assert _surface("whoami")[0] is None         # all distinct -> no trip


def test_persists_across_processes(isolated):
    # each surface() reloads streak from disk, emulating separate shell processes.
    _surface("pytest -x")
    _surface("pytest -x")
    # a brand-new module-level call still sees the streak on disk:
    reason, _ = _surface("pytest -x")
    assert reason and "repeat_action" in reason


def test_halt_off_by_default_on_by_env(isolated, monkeypatch):
    assert S.halt_enabled() is False
    monkeypatch.setenv("GATECAT_STAGNATION_HALT", "1")
    assert S.halt_enabled() is True


def test_gated_shell_soft_halt_when_enabled(isolated, monkeypatch):
    """End-to-end through shell._decide: with halt on, the 3rd identical command
    returns BLOCK; with halt off it returns ALLOW but still warns."""
    from gatecat import shell
    # warn-only (default): always ALLOW, but the 3rd trips a warning.
    assert shell._decide("make all") == shell.ALLOW
    assert shell._decide("make all") == shell.ALLOW
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        code = shell._decide("make all")
    assert code == shell.ALLOW
    assert "no progress" in err.getvalue()

    # now with halt on, a fresh session trips to BLOCK on the 3rd.
    monkeypatch.setenv("GATECAT_SESSION", "halt-sess")
    monkeypatch.setenv("GATECAT_STAGNATION_HALT", "1")
    assert shell._decide("make deploy") == shell.ALLOW
    assert shell._decide("make deploy") == shell.ALLOW
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        code = shell._decide("make deploy")
    assert code == shell.BLOCK
    assert "HALT" in err.getvalue()
