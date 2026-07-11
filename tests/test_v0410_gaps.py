"""0.4.10 — two disclosed gaps closed (colleague's multi-model gauntlet, 2026-07-11).

1. terraform interactive-prompt bypass: an autonomous agent defeats the
   `Enter a value: yes` confirmation by piping it in (`yes | terraform destroy`).
   That is an irreversible teardown with no human in the loop -> block. The bare
   interactive form (a human answers the prompt) stays allowed: low false-positive.
2. proxy enforcement visibility: /health exposes whether the action-veto is on,
   so a misconfigured (veto-off) proxy is detectable instead of looking healthy.
"""
import re

import pytest

from gatecat import check_action, ActionVetoed
from gatecat.integrations.policies import TERRAFORM_PROD


DANGEROUS = [
    "terraform destroy -auto-approve",
    "terraform apply -destroy -auto-approve",
    "yes | terraform destroy",
    "echo yes | terraform destroy",
    "echo 'yes' | terraform destroy",       # quoted 'yes' -> engine inerts it, so
    "printf 'yes\\n' | tofu destroy",       # the pattern keys on the pipe TARGET
    "yes | sudo terraform destroy",
    "cat approve.txt | terraform destroy",  # any pipe into destroy = auto-confirm
]

# Must NOT fire — preserving the low-false-positive contract that keeps the gate
# installed. A human running the interactive destroy is fine; plan is read-only;
# piping destroy's OUTPUT onward is not the same as feeding its prompt.
BENIGN = [
    "terraform plan",
    "terraform apply",
    "terraform validate",
    "terraform plan -destroy",
    "terraform destroy",              # bare: terraform stops for a human "yes"
    "yes | grep terraform",           # 'yes' + terraform but no destroy
    "terraform destroy | tee run.log",  # destroy pipes OUT (still interactive)
    "terraform plan | grep destroy",  # plan, 'destroy' only as a grep needle
    "echo 'destroying old logs' | tee out.txt",
]


@pytest.mark.parametrize("cmd", DANGEROUS)
def test_terraform_agent_bypass_blocks(cmd):
    with pytest.raises(ActionVetoed):
        check_action("agent", cmd)


@pytest.mark.parametrize("cmd", BENIGN)
def test_terraform_benign_passes(cmd):
    # No raise = allowed (warn-level policies don't raise from check_action either,
    # but none of these are destroy-class prod/auto/piped shapes).
    check_action("agent", cmd)


def test_terraform_pattern_matrix():
    pats = TERRAFORM_PROD.patterns
    blocks = lambda c: any(re.search(p, c) for p in pats)
    assert all(blocks(c) for c in DANGEROUS)
    assert not any(blocks(c) for c in BENIGN)


def test_proxy_health_exposes_action_veto():
    from fastapi.testclient import TestClient
    from gatecat.proxy.app import create_app
    from gatecat.proxy.config import ProxyConfig

    app = create_app(ProxyConfig.from_env())
    with TestClient(app) as client:
        body = client.get("/health").json()
    assert "action_veto" in body
    assert body["action_veto"]["mode"] == "block"
    assert body["action_veto"]["enforcing"] is True
    assert body["action_veto"]["policies"] >= 28
