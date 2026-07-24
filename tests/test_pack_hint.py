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
    monkeypatch.delenv("GATECAT_EXTRA_POLICIES", raising=False)


def test_stripe_cli_triggers_fintech_pack(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch, which=lambda c: "/usr/bin/stripe" if c == "stripe" else None)

    ph.maybe_pack_hint()

    err = capsys.readouterr().err
    assert "Fintech" in err
    assert "`stripe` is installed" in err
    assert "https://gate.cat/packs.html?source=hint#fintech" in err
    assert "buy.stripe.com" not in err          # preview before checkout, always
    assert "GATECAT_NO_NUDGE=1" in err
    assert os.path.exists(str(tmp_path / ".gatecat" / ".pack_nudged"))


def test_vercel_cli_triggers_paas_pack(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch, which=lambda c: "/usr/bin/vercel" if c == "vercel" else None)

    ph.maybe_pack_hint()

    err = capsys.readouterr().err
    assert "PaaS" in err
    assert "https://gate.cat/packs.html?source=hint#paas" in err


def test_datadog_ci_triggers_http_api_pack(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch,
             which=lambda c: "/usr/bin/datadog-ci" if c == "datadog-ci" else None)

    ph.maybe_pack_hint()

    err = capsys.readouterr().err
    assert "HTTP-API Breadth" in err
    assert "`datadog-ci` is installed" in err
    assert "https://gate.cat/packs.html?source=hint#http-api" in err


def test_sentry_cli_triggers_http_api_pack(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch,
             which=lambda c: "/usr/bin/sentry-cli" if c == "sentry-cli" else None)

    ph.maybe_pack_hint()

    err = capsys.readouterr().err
    assert "HTTP-API Breadth" in err


def test_universal_clis_never_trigger(tmp_path, monkeypatch, capsys):
    """docker/gh/curl are on every dev box - matching them would destroy the
    precision that justifies a once-per-machine interruption."""
    _isolate(tmp_path, monkeypatch,
             which=lambda c: f"/usr/bin/{c}" if c in ("docker", "gh", "curl") else None)

    ph.maybe_pack_hint()

    assert capsys.readouterr().err == ""
    assert not os.path.exists(str(tmp_path / ".gatecat" / ".pack_nudged"))


def test_hint_is_ascii_only(tmp_path, monkeypatch, capsys):
    """stderr hint must survive any terminal encoding (same rule as _nudge)."""
    for cli in ("stripe", "vercel", "datadog-ci"):
        _isolate(tmp_path, monkeypatch,
                 which=lambda c, cli=cli: f"/usr/bin/{cli}" if c == cli else None)
        # fresh machine per iteration: the once-per-machine flag must not carry
        monkeypatch.setattr(ph, "_FLAG", str(tmp_path / cli / ".pack_nudged"))
        ph.maybe_pack_hint()
        err = capsys.readouterr().err
        assert err and err == err.encode("ascii", "ignore").decode()


def test_silent_when_no_stack_cli(tmp_path, monkeypatch, capsys):
    _isolate(tmp_path, monkeypatch)

    ph.maybe_pack_hint()

    assert capsys.readouterr().err == ""
    assert not os.path.exists(str(tmp_path / ".gatecat" / ".pack_nudged"))


def test_silent_when_pack_already_owned(tmp_path, monkeypatch, capsys):
    """A buyer who loaded the Fintech pack must NOT be pitched the Fintech pack.
    Suppress-only: the stripe CLI is present, but the pack module is loaded."""
    _isolate(tmp_path, monkeypatch,
             which=lambda c: "/usr/bin/stripe" if c == "stripe" else None)
    monkeypatch.setenv("GATECAT_EXTRA_POLICIES", "gatecat_packs.fintech")

    ph.maybe_pack_hint()

    assert capsys.readouterr().err == ""
    # no flag written: if they later drop the pack, the hint can return
    assert not os.path.exists(str(tmp_path / ".gatecat" / ".pack_nudged"))


def test_owned_pack_is_skipped_but_other_still_hints(tmp_path, monkeypatch, capsys):
    """Owning Fintech silences only Fintech — a PaaS CLI still hints PaaS.
    (This is suppression, not cross-selling: the PaaS hint would fire anyway.)"""
    _isolate(tmp_path, monkeypatch,
             which=lambda c: "/usr/bin/vercel" if c == "vercel" else None)
    monkeypatch.setenv("GATECAT_EXTRA_POLICIES", "gatecat_packs.fintech")

    ph.maybe_pack_hint()

    assert "PaaS" in capsys.readouterr().err


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
