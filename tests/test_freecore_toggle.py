"""FEATURE 1 - FREE-CORE on/off protection toggle (local, no cloud, no entitlement).

A human can disarm ORDINARY rules on THEIR OWN machine; catastrophic / irreversible
classes (rm -rf /, cloud/disk destroy, guard/security tamper, secret/DB wipe, the
state files themselves) STILL hard-block even with protection OFF. Every flip is a
tamper-evident hash-chained audit record; never a silent flip.
"""
import json
import os

import pytest

from gatecat import ActionVetoed, check_action
from gatecat.integrations import protection as P


_PROD = dict(cwd="/srv/app",
             env={"HOME": "/home/deploy", "PATH": "/usr/bin", "USER": "deploy"},
             home="/home/deploy")


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


def test_default_is_on(isolated):
    assert P.read_protection() == "on"
    assert not P.is_protection_off()


def test_ordinary_block_downgraded_when_off(isolated):
    # git force-push is an ordinary (non-catastrophic) block.
    ff = "git " + "push --" + "force origin main"
    assert _verdict(ff) == "block"
    P.set_protection("off")
    assert P.is_protection_off()
    assert _verdict(ff) == "allow"
    # re-arm restores enforcement
    P.set_protection("on")
    assert _verdict(ff) == "block"


def test_off_still_hard_blocks_catastrophic(isolated):
    P.set_protection("off")
    assert _verdict("rm -rf /") == "block"                       # DELETE_ANALYZER
    assert _verdict("vastai destroy 999") == "block"             # CLOUD_DESTROY
    assert _verdict("aws ec2 terminate-instances --instance-ids i-1") == "block"
    assert _verdict("dd if=/dev/zero of=/dev/sda") == "block"    # DISK_DESTROY
    # the state files themselves are never-disarm
    assert _verdict("echo off > ~/.gatecat/protection.json") == "block"


def test_flip_is_never_silent_and_hash_chained(isolated):
    P.set_protection("off")
    P.set_protection("on")
    records = [json.loads(l) for l in open(os.environ["GATECAT_VETO_LOG"])]
    flips = [r for r in records if r["decision"] in ("disarmed", "armed")]
    assert len(flips) >= 2
    # each carries a chain prev= and self=; the 2nd's prev == the 1st's self.
    import re
    def sig(r):
        m = re.search(r"prev=(\w+) self=(\w+)", r["reason"])
        return m.group(1), m.group(2)
    p1, s1 = sig(flips[0])
    p2, s2 = sig(flips[1])
    assert p1 == "GENESIS"[:16]
    assert p2 == s1  # chained: record 2's prev is record 1's self


def test_off_toggle_needs_no_cloud_key_or_entitlement(isolated, monkeypatch):
    # explicitly strip anything cloud/entitlement-shaped
    for k in list(os.environ):
        if "CLOUD" in k or "ENTITLE" in k or "STRIPE" in k or "GATECAT_TIER" in k:
            monkeypatch.delenv(k, raising=False)
    P.set_protection("off")
    assert P.is_protection_off()  # worked with zero cloud state
