"""B5: reproduce the autogen#7770 $106k loss as a `block` verdict.

The incident (microsoft/autogen#7770, verified 2026-07-03): over 56 days an AI
agent applied Terraform to the WRONG AWS target and destroyed the management
account - a single ~$0.03 operation that cost the developer $106,000+. The
author's own conclusion:

    "Prompt-based rules are documentation. They are not enforcement."

That sentence is gate.cat's whole thesis. This script shows the veto gate
turning that exact class of action into a BLOCK, and - honestly - shows the
forms it would NOT have caught, so the demo can't overclaim.

Run it (no real engine needed for the demo - it uses the same policy-wall
matching the engine uses; the fake gate stands in):

    python examples/repro_autogen_7770.py

With the real engine installed (`pip install gate.cat`, >=0.1.0) the same
`check_action` call routes through the real VetoGate instead - identical API,
identical verdict on the caught cases.

Honest line: the gate is certain only about what it BLOCKS. The "would NOT
block" section below is disclosed on purpose (see bypass_suite.py / A7).
"""

from __future__ import annotations

import os
import sys

# Run straight from a checkout without installing the package.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# --- demo shim: stand in a fake engine ONLY if the real one is absent --------
# The real gate.cat engine ships `cacheback.veto`; when it's installed this
# block is skipped and the exact same code runs against the real VetoGate.
try:
    import cacheback.veto  # noqa: F401  (real engine present)
except ImportError:
    import types
    import re as _re

    _fake = types.ModuleType("cacheback")
    _veto = types.ModuleType("cacheback.veto")

    class ActionVetoed(RuntimeError):
        pass

    class _Decision:
        def __init__(self, blocked, reason, policy=None):
            self.blocked, self.reason, self.policy = blocked, reason, policy

    class VetoGate:
        def __init__(self, policies):
            self._policies = policies

        def before_action(self, action, source=""):
            for pol in self._policies:
                for pattern in pol["patterns"]:
                    if _re.search(pattern, action, _re.IGNORECASE):
                        return _Decision(True, pol["reason"], pol["name"])
            return _Decision(False, "allowed", None)

    _veto.ActionVetoed = ActionVetoed
    _veto.VetoGate = VetoGate
    _fake.veto = _veto
    sys.modules["cacheback"] = _fake
    sys.modules["cacheback.veto"] = _veto
    print("[demo] real engine absent - using fake policy-wall gate "
          "(same matching the engine uses). Install gate.cat for the real path.\n")

from cacheback.integrations import ActionVetoed, check_action  # noqa: E402
from cacheback.integrations.policies import TERRAFORM_PROD  # noqa: E402

SOURCE = "autogen"
POLICIES = [TERRAFORM_PROD]


# The action from the incident: Terraform applied to a production/management
# target. The agent thought a system prompt would stop it; it didn't.
INCIDENT_ACTION = "terraform apply -auto-approve -var-file=environments/prod/mgmt.tfvars"


def would_block(action: str) -> bool:
    """True if the gate BLOCKS *action* (enforce mode). Never raises out."""
    try:
        check_action(SOURCE, action, POLICIES)
        return False
    except ActionVetoed as exc:
        print(f"  BLOCK  {action}\n         -> {exc}")
        return True


def main() -> int:
    print("autogen#7770 repro - $106k Terraform-to-wrong-target loss")
    print("=" * 60)
    print('Incident: "Prompt-based rules are documentation. They are not')
    print(' enforcement." The agent applied Terraform to the mgmt account.')
    print()

    print("[1] The exact incident action, under the veto gate:")
    caught = would_block(INCIDENT_ACTION)
    print()

    print("[2] Sibling forms the same policy also stops:")
    also = [
        "terraform destroy -auto-approve",
        "terraform -chdir=envs/prod apply -auto-approve",
        "tofu apply -auto-approve -var env=prod",
    ]
    also_caught = all(would_block(a) for a in also)
    print()

    print("[3] Honest edge - a form this regex policy does NOT catch (A7 gap):")
    # `terraform apply` WITHOUT -auto-approve and without a prod marker relies on
    # an interactive 'yes' the agent could still auto-answer; the deny pattern
    # requires prod/-auto-approve, so a bare `terraform apply` is unchecked.
    bare = "terraform apply"
    slipped = not would_block(bare)
    if slipped:
        print(f"  ALLOW  {bare}")
        print("         -> no prod marker / no -auto-approve: UNCHECKED, not safe.")
        print("            Closing this is claim-decomposition (C2), not more regex.")
    print()

    print("=" * 60)
    ok = caught and also_caught and slipped
    verdict = "PASS" if ok else "UNEXPECTED"
    print(f"[{verdict}] incident action -> BLOCK; siblings -> BLOCK; "
          f"bare apply -> disclosed gap.")
    print("The $106k action is one the gate turns into a human-in-the-loop stop.")
    print("What it can't see, it says so. That is the pitch, honestly.")
    # exit 0 on the expected outcome so CI / a reader can trust the demo
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
