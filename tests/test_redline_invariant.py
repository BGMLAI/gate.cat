"""FEATURE 5 - THE RED-LINE INVARIANT.

The brand-defining promise: 100% of SAFETY is free, and LOCAL CONTROL is never
paywalled. This test proves that with NO cloud key and NO entitlement/env of any
kind, ALL of the free-core local layer works end-to-end:

  (1) local on/off toggle           - downgrades ordinary rules, never touches
                                        catastrophic classes
  (2) per-command manual override    - one exact command, TTL'd, single-use
  (3) local hash-chained audit       - every flip/override logged, chained
  (4) local stagnation warning       - repeated no-progress commands warn

If any `if tier != paid` ever creeps onto a local-control path, this test breaks -
which is exactly the screenshot ("safety = paid") we refuse to ship.
"""
import contextlib
import io
import json
import os

import pytest

from gatecat import ActionVetoed, check_action
from gatecat.integrations import protection as P
from gatecat.integrations import shell_stagnation as S

_PROD = dict(cwd="/srv/app",
             env={"HOME": "/home/deploy", "PATH": "/usr/bin", "USER": "deploy"},
             home="/home/deploy")
_FF = "git " + "push --" + "force origin main"


@pytest.fixture
def no_cloud_env(tmp_path, monkeypatch):
    # isolate state, then STRIP every cloud / entitlement / subscription signal.
    monkeypatch.setenv("GATECAT_PROTECTION_FILE", str(tmp_path / "protection.json"))
    monkeypatch.setenv("GATECAT_OVERRIDES_FILE", str(tmp_path / "overrides.json"))
    monkeypatch.setenv("GATECAT_VETO_LOG", str(tmp_path / "veto.jsonl"))
    monkeypatch.setenv("GATECAT_STAGNATION_DIR", str(tmp_path))
    monkeypatch.setenv("GATECAT_SESSION", "redline")
    for k in list(os.environ):
        if any(t in k.upper() for t in ("CLOUD", "ENTITLE", "STRIPE", "TIER",
                                        "SUBSCRIB", "LICENSE", "API_KEY")):
            monkeypatch.delenv(k, raising=False)
    # also make sure no cloud key file is reachable
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def _verdict(cmd):
    try:
        d = check_action("agent", cmd, **_PROD)
    except ActionVetoed:
        return "block"
    if getattr(d, "blocked", False):
        return "block"
    return "warn" if getattr(d, "level", "") == "warn" else "allow"


def test_redline_all_local_features_work_without_cloud(no_cloud_env):
    tmp = no_cloud_env

    # there must be no cloud key present
    assert not (tmp / ".gatecat" / "cloud.key").exists()

    # (1) local on/off toggle
    assert _verdict(_FF) == "block"
    P.set_protection("off")
    assert P.is_protection_off()
    assert _verdict(_FF) == "allow"                 # ordinary rule disarmed locally
    assert _verdict("rm -rf /") == "block"          # catastrophic STILL blocks
    assert _verdict("vastai destroy 999") == "block"
    P.set_protection("on")
    assert _verdict(_FF) == "block"                 # re-armed

    # (2) per-command manual override (TTL'd, single-use)
    P.add_override(_FF, ttl_s=300, who="deploy")
    assert _verdict(_FF) == "allow"                 # passes once
    assert _verdict(_FF) == "block"                 # consumed
    P.add_override("rm -rf /", ttl_s=300)
    assert _verdict("rm -rf /") == "block"          # never override-able

    # (3) local hash-chained audit - all of the above is on disk, chained
    records = [json.loads(l) for l in open(os.environ["GATECAT_VETO_LOG"])]
    kinds = {r["decision"] for r in records}
    assert {"disarmed", "armed", "override_grant", "override_allow"} <= kinds
    import re
    chained = [r for r in records
               if r["decision"] in ("disarmed", "armed", "override_grant", "override_allow")]
    for r in chained:
        assert re.search(r"prev=\w+ self=\w+", r["reason"])  # every one is chained

    # (4) local stagnation warning (surface() returns the reason string or None)
    S.reset()
    assert S.surface("npm run build") is None
    assert S.surface("npm run build") is None
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        reason = S.surface("npm run build")
    assert reason and "no progress" in buf.getvalue()


def test_never_disarm_set_covers_the_catastrophic_classes():
    # the guardrail's promise depends on this exact set - assert its members.
    must = {"RM_RF", "DELETE_ANALYZER", "DISK_DESTROY", "DISK_ERASE_EXTRA",
            "CLOUD_DESTROY", "TERRAFORM_PROD", "GUARD_TAMPER",
            "SECURITY_CONTROL_DISABLE", "AUDIT_LOG_TAMPER", "STATE_FILE_TAMPER",
            "SECRET_FILE_DELETE", "SECRET_STORE_DELETE", "DB_DESTRUCTIVE"}
    assert must <= P.NEVER_DISARM
    assert P.is_never_disarm("CLOUD_DESTROY")
    assert not P.is_never_disarm("GIT_FORCE_PUSH")
    assert not P.is_never_disarm(None)
