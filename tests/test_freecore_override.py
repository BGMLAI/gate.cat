"""FEATURE 2 - FREE-CORE per-command manual override (local, TTL'd, single-use).

`gate.cat allow "<cmd>"` pre-approves that EXACT command for a short window. A
would-be BLOCK whose exact normalized command has a valid override AND whose policy
is NOT catastrophic passes ONCE (allow-with-audit, hash-chained). Catastrophic
classes can NEVER be overridden. Overrides expire and are single-use.
"""
import os

import pytest

from gatecat import ActionVetoed, check_action
from gatecat.integrations import protection as P

_PROD = dict(cwd="/srv/app",
             env={"HOME": "/home/deploy", "PATH": "/usr/bin", "USER": "deploy"},
             home="/home/deploy")
_FF = "git " + "push --" + "force origin main"


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("GATECAT_PROTECTION_FILE", str(tmp_path / "protection.json"))
    monkeypatch.setenv("GATECAT_OVERRIDES_FILE", str(tmp_path / "overrides.json"))
    monkeypatch.setenv("GATECAT_VETO_LOG", str(tmp_path / "veto.jsonl"))
    return tmp_path


def _verdict(cmd):
    try:
        d = check_action("agent", cmd, **_PROD)
    except ActionVetoed:
        return "block"
    if getattr(d, "blocked", False):
        return "block"
    return "warn" if getattr(d, "level", "") == "warn" else "allow"


def test_override_lets_blocked_command_through_once(isolated):
    assert _verdict(_FF) == "block"
    P.add_override(_FF, ttl_s=300, who="deploy")
    assert _verdict(_FF) == "allow"     # pre-approved: passes once
    assert _verdict(_FF) == "block"     # single-use: consumed, blocks again


def test_override_is_exact_command_only(isolated):
    P.add_override(_FF, ttl_s=300)
    # a DIFFERENT force-push (different branch) is NOT covered by the override.
    other = "git " + "push --" + "force origin production"
    assert _verdict(other) == "block"


def test_whitespace_normalized_match(isolated):
    P.add_override(_FF, ttl_s=300)
    spaced = "git   push   --" + "force   origin   main"
    assert _verdict(spaced) == "allow"  # incidental spacing normalized


def test_override_cannot_bypass_catastrophic(isolated):
    P.add_override("rm -rf /", ttl_s=300)
    assert _verdict("rm -rf /") == "block"
    P.add_override("vastai destroy 999", ttl_s=300)
    assert _verdict("vastai destroy 999") == "block"
    # and the override is NOT consumed on a catastrophic command (never looked up)
    assert P.has_valid_override("rm -rf /")


def test_expired_override_does_not_pass(isolated):
    P.add_override(_FF, ttl_s=-1)   # already expired
    assert not P.has_valid_override(_FF)
    assert _verdict(_FF) == "block"


def test_ttl_boundary_is_not_truncation_dependent(isolated, monkeypatch):
    # Grant at a FRACTIONAL wall-clock time so the boundary can only be right if
    # expiry is compared as float seconds on both sides (no lossy int() on one).
    clock = {"t": 1000.9}
    monkeypatch.setattr(P.time, "time", lambda: clock["t"])
    P.add_override(_FF, ttl_s=10)   # expires_at == 1010.9

    # strictly within TTL -> valid, and consumed exactly once
    clock["t"] = 1010.8
    assert P.has_valid_override(_FF)
    assert _verdict(_FF) == "allow"
    assert _verdict(_FF) == "block"   # single-use consumed

    # re-grant and step to exactly the boundary instant -> still valid (>= now)
    P.add_override(_FF, ttl_s=10)     # granted at 1010.8 -> expires_at 1020.8
    clock["t"] = 1020.8
    assert P.has_valid_override(_FF)

    # one tick PAST the boundary -> expired, blocks, and never disarmed
    clock["t"] = 1020.8 + 1e-6
    assert not P.has_valid_override(_FF)
    assert _verdict(_FF) == "block"


def test_override_records_who_and_hash_chained(isolated):
    import json, re
    P.add_override(_FF, ttl_s=300, who="deploy")
    assert _verdict(_FF) == "allow"
    records = [json.loads(l) for l in open(os.environ["GATECAT_VETO_LOG"])]
    grants = [r for r in records if r["decision"] == "override_grant"]
    allows = [r for r in records if r["decision"] == "override_allow"]
    assert grants and allows
    # the allow-with-audit record carries who + a chain link
    assert "deploy" in allows[0]["reason"]
    assert re.search(r"prev=\w+ self=\w+", allows[0]["reason"])
