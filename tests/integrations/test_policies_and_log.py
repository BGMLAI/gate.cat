"""A4 + D1/D2 unit tests: presets are sane data; the log is ASCII JSONL."""

from __future__ import annotations

import json
import re

from cacheback.integrations import ascii_safe, log_decision
from cacheback.integrations.policies import (
    ALL_PRESETS,
    DOGFOOD_DEFAULTS,
    PAYMENTS,
    Policy,
)


def test_all_presets_are_policy_instances():
    # ALL_PRESETS must be uniform: every value a Policy (no bare factory)
    assert all(isinstance(p, Policy) for p in ALL_PRESETS.values())
    assert ALL_PRESETS["PAYMENTS"].name == "PAYMENTS"


def test_every_preset_compiles_and_is_ascii():
    presets = list(ALL_PRESETS.values())
    presets.append(PAYMENTS(max_amount=100))
    for policy in presets:
        policy.reason.encode("ascii")  # D1: reasons must be cp1252-safe
        for pattern in policy.patterns:
            re.compile(pattern)  # every deny pattern is a valid regex
        d = policy.to_dict()
        assert d["name"] == policy.name and d["patterns"]


def test_payments_params_carried():
    p = PAYMENTS(max_amount=250, currency="EUR")
    assert p.params == {"max_amount": 250, "currency": "EUR"}
    assert "250" in p.reason and "EUR" in p.reason


def test_dogfood_defaults_cover_claude_md_rules():
    names = {p.name for p in DOGFOOD_DEFAULTS}
    assert {"TERRAFORM_PROD", "RM_RF", "GIT_FORCE_PUSH", "CLOUD_DESTROY"} <= names


def _matches(policy: Policy, text: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in policy.patterns)


def test_policy_patterns_block_and_dont_false_block():
    """Regression cases from the code review: catch the dangerous forms the
    old patterns missed, and DON'T block the benign forms the broadened
    CLOUD_DESTROY over-matched (false-block rate is the headline metric)."""
    from cacheback.integrations.policies import (
        CLOUD_DESTROY,
        GIT_FORCE_PUSH,
        RM_RF,
        TERRAFORM_PROD,
    )

    must_block = [
        (RM_RF, "rm -rfv /srv/data"),        # combined flag missed by old \b
        (RM_RF, "rm -Rfi /srv"),
        (RM_RF, "rm -r -f /srv"),
        (GIT_FORCE_PUSH, "git -C /repo push --force"),  # global opt before push
        (TERRAFORM_PROD, "terraform -chdir=envs/prod destroy -auto-approve"),
        (CLOUD_DESTROY, "aws ec2 terminate-instances --instance-ids i-1"),
        (CLOUD_DESTROY, "aws s3api delete-object --bucket b --key k"),
        (CLOUD_DESTROY, "gcloud compute instances delete my-vm"),
        (CLOUD_DESTROY, "az group delete --name rg"),
    ]
    must_allow = [
        (RM_RF, "rm -rv /srv"),
        (GIT_FORCE_PUSH, "git push --force-with-lease origin feat"),
        (TERRAFORM_PROD, "terraform plan"),
        (CLOUD_DESTROY, "aws s3 sync ./build s3://site --delete"),
        (CLOUD_DESTROY, "aws s3 ls s3://backups/delete-after-30-days/"),
        (CLOUD_DESTROY, "aws ec2 describe-instances"),
        (CLOUD_DESTROY, "gcloud compute instances list --filter=\"name~delete\""),
        (CLOUD_DESTROY, "az storage blob list --container delete-queue"),
    ]
    for policy, text in must_block:
        assert _matches(policy, text), f"{policy.name} should block: {text}"
    for policy, text in must_allow:
        assert not _matches(policy, text), f"{policy.name} false-blocked: {text}"


def test_shadow_enabled_resolution(monkeypatch):
    """A8: explicit arg wins; env var decides otherwise; default is enforce.
    Unrecognized env values must resolve to enforce (fail-safe direction)."""
    from cacheback.integrations import shadow_enabled

    monkeypatch.delenv("CACHEBACK_VETO_SHADOW", raising=False)
    assert shadow_enabled() is False  # default = enforce
    assert shadow_enabled(True) is True  # explicit overrides absent env
    assert shadow_enabled(False) is False

    for on in ("1", "true", "TRUE", "yes", "on", "shadow", " On "):
        monkeypatch.setenv("CACHEBACK_VETO_SHADOW", on)
        assert shadow_enabled() is True, on
    for off in ("0", "false", "no", "off", "", "enforce", "garbage"):
        monkeypatch.setenv("CACHEBACK_VETO_SHADOW", off)
        assert shadow_enabled() is False, off
        # explicit arg still overrides a set env var in either direction
        assert shadow_enabled(True) is True, on


def test_ascii_safe_escapes_polish():
    out = ascii_safe("zniszczyłoby środowisko")
    out.encode("ascii")
    assert "zniszczy" in out


def test_log_decision_writes_schema(tmp_path, monkeypatch):
    log = tmp_path / "veto_log.jsonl"
    monkeypatch.setenv("CACHEBACK_VETO_LOG", str(log))
    log_decision(
        source="crewai",
        decision="block",
        reason="płatność wymaga człowieka",
        policy="PAYMENTS",
        context="pay_invoice INV-1 350 żłób",
    )
    [record] = [json.loads(l) for l in log.read_text().splitlines()]
    assert set(record) == {"ts", "source", "policy", "decision", "reason", "context"}
    assert record["decision"] == "block" and record["policy"] == "PAYMENTS"
    json.dumps(record).encode("ascii")  # whole record survives cp1252 pipelines
