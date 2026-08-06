"""Tests for the one-time post-veto Team nudge (gatecat/_nudge.py).

The nudge must be invisible-by-default and best-effort: once per machine, opt-out
via GATECAT_NO_NUDGE/GATECAT_QUIET, and it must NEVER raise -- a failure here can
never be allowed to affect a veto verdict or exit code.
"""
import builtins
import os

import gatecat._nudge as nudge


def _point_flag_at(tmp_path, monkeypatch):
    flag = tmp_path / ".gatecat" / ".nudged"
    monkeypatch.setattr(nudge, "_FLAG", str(flag))
    return flag


def _clear_optouts(monkeypatch):
    monkeypatch.delenv("GATECAT_NO_NUDGE", raising=False)
    monkeypatch.delenv("GATECAT_QUIET", raising=False)
    monkeypatch.delenv("GATECAT_CLOUD_API_KEY", raising=False)


def test_cloud_customer_is_silent_and_writes_no_flag(tmp_path, monkeypatch, capsys):
    """A paying Cloud customer already has the off-machine record the nudge
    pitches -- do not sell them what they bought. And write NO flag, so the
    nudge returns if they ever drop Cloud."""
    flag = _point_flag_at(tmp_path, monkeypatch)
    _clear_optouts(monkeypatch)
    monkeypatch.setenv("GATECAT_CLOUD_API_KEY", "gk_live_x")

    nudge.maybe_nudge_after_veto()

    assert capsys.readouterr().err == ""
    assert not os.path.exists(str(flag))


def test_first_veto_writes_flag_and_emits(tmp_path, monkeypatch, capsys):
    flag = _point_flag_at(tmp_path, monkeypatch)
    _clear_optouts(monkeypatch)

    nudge.maybe_nudge_after_veto()

    err = capsys.readouterr().err
    assert "gate.cat vetoed that locally" in err
    assert "https://gate.cat/teams.html" in err
    assert "GATECAT_NO_NUDGE=1" in err
    # honest copy: no overclaim words
    assert "tamper-evident" not in err
    assert os.path.exists(str(flag))


def test_second_veto_is_silent(tmp_path, monkeypatch, capsys):
    _point_flag_at(tmp_path, monkeypatch)
    _clear_optouts(monkeypatch)

    nudge.maybe_nudge_after_veto()
    capsys.readouterr()  # drain the first (real) nudge
    nudge.maybe_nudge_after_veto()

    assert capsys.readouterr().err == ""


def test_opt_out_env_is_silent_and_writes_no_flag(tmp_path, monkeypatch, capsys):
    flag = _point_flag_at(tmp_path, monkeypatch)
    monkeypatch.setenv("GATECAT_NO_NUDGE", "1")

    nudge.maybe_nudge_after_veto()

    assert capsys.readouterr().err == ""
    assert not os.path.exists(str(flag))


def test_quiet_env_is_silent(tmp_path, monkeypatch, capsys):
    _point_flag_at(tmp_path, monkeypatch)
    monkeypatch.delenv("GATECAT_NO_NUDGE", raising=False)
    monkeypatch.setenv("GATECAT_QUIET", "1")

    nudge.maybe_nudge_after_veto()

    assert capsys.readouterr().err == ""


def test_never_raises_when_state_dir_unwritable(tmp_path, monkeypatch):
    _point_flag_at(tmp_path, monkeypatch)
    _clear_optouts(monkeypatch)

    def boom(*a, **k):
        raise OSError("read-only filesystem")

    monkeypatch.setattr(builtins, "open", boom)
    # Must swallow the error: the verdict path must never see an exception.
    nudge.maybe_nudge_after_veto()
