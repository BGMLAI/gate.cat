"""Ephemeral disarm (council 5/5, "disarm-not-loosen"; refined Codex round-4).

In a throwaway environment (CI / disposable sandbox) gate.cat DISARMS the
reversible classes - a test-dir delete or test-DB drop becomes an audited no-op,
because nothing there is worth a human. The refinement (rule #11): a destroy of a
REAL external/irreplaceable resource - paid cloud infra, a raw disk, prod IaC -
is NEVER disarmed, even with a faked CI marker. The exemption is logged, so the
escape hatch stays visible, not stealthy, and can't wave through a `vastai
destroy` or `dd of=/dev/sda`.
"""
from __future__ import annotations

import pytest

from gatecat.integrations import DOGFOOD_DEFAULTS, ActionVetoed, check_action
from gatecat.integrations.guard import ephemeral_context


# --- detection --------------------------------------------------------------

def test_no_markers_is_armed():
    assert ephemeral_context({}) is None
    assert ephemeral_context({"HOME": "/home/x"}) is None


def test_ci_markers_detected():
    for marker in ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "SWE_AGENT"):
        assert ephemeral_context({marker: "1"}) is not None, marker


def test_explicit_force_off_arms_even_in_ci():
    # a team that wants the veto in their pipeline
    assert ephemeral_context({"CI": "true", "GATECAT_VETO_EPHEMERAL": "0"}) is None


def test_explicit_force_on():
    assert ephemeral_context({"GATECAT_VETO_EPHEMERAL": "1"}) is not None


# --- disarm behavior (the whole point) --------------------------------------

def test_ci_disarms_a_would_be_block():
    # rm ~/backup would BLOCK when armed; in CI it disarms to a logged no-op
    d = check_action("t", "rm -rf ~/laptop-backup", DOGFOOD_DEFAULTS,
                     cwd="/testbed", env={"CI": "true", "HOME": "/root"}, home="/root")
    assert d.blocked is False
    assert d.level == "allow"
    assert "disarmed" in d.reason


def test_armed_still_blocks_the_same_action():
    # same action, no CI markers -> armed -> blocks
    with_ci_removed = {"HOME": "/c/Users/bogum"}
    try:
        check_action("t", "rm -rf ~/laptop-backup", DOGFOOD_DEFAULTS,
                     cwd="/d", env=with_ci_removed, home="/c/Users/bogum")
        raised = False
    except ActionVetoed:
        raised = True
    assert raised, "armed gate must still block rm of a home/backup dir"


def test_disarm_exempts_hard_block_classes_only():
    """Disarm is SELECTIVE by design (Codex round-4 + rule #11): it waves through
    throwaway-scope actions (delete a test dir, drop a test DB) but a destroy of a
    REAL external/irreplaceable resource - paid cloud infra, a raw disk, prod IaC -
    is NEVER disarmed, even with a faked CI marker."""
    env = {"CI": "true", "HOME": "/root"}
    # still disarmed: CI legitimately deletes test dirs / test databases
    for action in ("rm -rf ~/laptop-backup", "DROP TABLE users"):
        d = check_action("t", action, DOGFOOD_DEFAULTS, cwd="/testbed",
                         env=env, home="/root")
        assert d.blocked is False and "disarmed" in d.reason, action
    # NEVER disarmed: destroying real paid infra / a disk / prod IaC must block
    for action in ("vastai destroy 123", "dd if=/dev/zero of=/dev/sda",
                   "terraform destroy -auto-approve"):
        with pytest.raises(ActionVetoed):
            check_action("t", action, DOGFOOD_DEFAULTS, cwd="/testbed",
                         env=env, home="/root")


def test_force_off_in_ci_restores_enforcement():
    # GATECAT_VETO_EPHEMERAL=0 in CI -> NOT disarmed -> the armed path runs,
    # so a home-dir delete blocks again instead of being waved through.
    env = {"CI": "true", "GATECAT_VETO_EPHEMERAL": "0", "HOME": "/root"}
    assert ephemeral_context(env) is None
    try:
        check_action("t", "rm -rf ~/laptop-backup", DOGFOOD_DEFAULTS,
                     cwd="/testbed", env=env, home="/root")
        raised = False
    except ActionVetoed:
        raised = True
    assert raised, "force-off in CI must re-arm and block a home-dir delete"
