"""Tests for the one-time policy-pack hint (gatecat._pack_hint).

Same bar as the nudge tests: once per machine, opt-out respected, never
raises, never stacks with another nudge in the same process.
"""
import os

import gatecat._nudge as nudge
import gatecat._pack_hint as ph


def _isolate(tmp_path, monkeypatch, which=lambda cli: None):
    monkeypatch.setattr(ph, "_FLAG", str(tmp_path / ".gatecat" / ".pack_nudged"))
    monkeypatch.setattr(nudge, "_fired_this_run", False)
    monkeypatch.setattr(ph.shutil, "which", which)
    monkeypatch.delenv("GATECAT_NO_NUDGE", raising=False)
    monkeypatch.delenv("GATECAT_QUIET", raising=False)


def test_stripe_cli_triggers_fintech_pack(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch, which=lambda c: "/usr/bin/stripe" if c == "stripe" else None)

    ph.maybe_pack_hint()

    err = capsys.readouterr().err
    assert "Fintech" in err
    assert "`stripe` is installed" in err
    assert "https://buy.stripe.com/dRm5kw6Bn3iMfFS1Rk67S0c" in err
    assert "GATECAT_NO_NUDGE=1" in err
    assert os.path.exists(str(tmp_path / ".gatecat" / ".pack_nudged"))


def test_vercel_cli_triggers_paas_pack(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch, which=lambda c: "/usr/bin/vercel" if c == "vercel" else None)

    ph.maybe_pack_hint()

    err = capsys.readouterr().err
    assert "PaaS" in err
    assert "https://buy.stripe.com/3cI5kw3pbaLeeBO2Vo67S0d" in err


def test_silent_when_no_stack_cli(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch)

    ph.maybe_pack_hint()

    assert capsys.readouterr().err == ""
    assert not os.path.exists(str(tmp_path / ".gatecat" / ".pack_nudged"))


def test_once_per_machine(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch, which=lambda c: "/usr/bin/stripe" if c == "stripe" else None)
    ph.maybe_pack_hint()
    capsys.readouterr()

    monkeypatch.setattr(nudge, "_fired_this_run", False)  # fresh process, same machine
    ph.maybe_pack_hint()

    assert capsys.readouterr().err == ""


def test_never_stacks_with_cli_nudge_same_run(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch, which=lambda c: "/usr/bin/stripe" if c == "stripe" else None)
    monkeypatch.setattr(nudge, "_LAST", str(tmp_path / ".gatecat" / "nudge_last"))
    monkeypatch.delenv("GATECAT_CLOUD_API_KEY", raising=False)

    nudge.maybe_nudge_cli("status", 5)   # fires first
    ph.maybe_pack_hint()                 # must stay silent this run

    err = capsys.readouterr().err
    assert "source=cli" in err
    assert "policy pack" not in err
    assert not os.path.exists(str(tmp_path / ".gatecat" / ".pack_nudged"))


def test_optout_env_is_silent(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch, which=lambda c: "/usr/bin/stripe")
    monkeypatch.setenv("GATECAT_QUIET", "1")

    ph.maybe_pack_hint()

    assert capsys.readouterr().err == ""


def test_never_raises_when_state_dir_unwritable(tmp_path, monkeypatch):
    blocker = tmp_path / "blocked"
    blocker.write_text("file, not a dir")
    _isolate(tmp_path, monkeypatch, which=lambda c: "/usr/bin/stripe")
    monkeypatch.setattr(ph, "_FLAG", str(blocker / ".pack_nudged"))

    ph.maybe_pack_hint()  # must not raise
