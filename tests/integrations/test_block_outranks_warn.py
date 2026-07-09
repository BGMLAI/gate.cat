"""BLOCK outranks WARN in policy attribution, regardless of list order.

The engine folds every policy's patterns into one deny list; ``_which_policy``
then attributes the hit to a preset name, and ``check_action`` downgrades to a
warn when the attributed policy is level="warn". Before this fix the
attribution was first-match-in-list-order, so a warn-level policy sitting
earlier in the list silently DOWNGRADED a hard danger that a later block-level
policy also matched. Real case: the core generic net ``HTTP_API_DELETE_GENERIC``
(warn) pre-empted an operator pack's block rule on the same ``curl -X DELETE``,
because ``GATECAT_EXTRA_POLICIES`` appends packs after the built-ins — the
exact enforcement the customer installed the pack for.
"""

from __future__ import annotations

import pytest

from gatecat.integrations import ActionVetoed, check_action
from gatecat.integrations.policies import DOGFOOD_DEFAULTS, Policy

WARN_NET = Policy(
    name="XW_GENERIC_NET",
    level="warn",
    patterns=(r"\bxw-tool\b",),
    reason="xw-tool call - unchecked, review before running",
)
BLOCK_SPECIFIC = Policy(
    name="XW_HARD_DESTROY",
    level="block",
    patterns=(r"\bxw-tool\s+destroy\b",),
    reason="xw-tool destroy is irreversible - requires a human",
)


def test_block_wins_when_warn_sits_earlier_in_the_list():
    # warn-level policy FIRST, block-level SECOND — the pack-appended-after-core
    # shape. Attribution must still pick the block.
    with pytest.raises(ActionVetoed) as ei:
        check_action("test", "xw-tool destroy --prod", [WARN_NET, BLOCK_SPECIFIC])
    assert "XW_HARD_DESTROY" in str(ei.value)


def test_warn_only_match_still_warns_not_blocks():
    # Only the warn-level policy matches -> stays a warn (no raise, level=warn).
    decision = check_action("test", "xw-tool status", [WARN_NET, BLOCK_SPECIFIC])
    assert decision.level == "warn"
    assert "XW_GENERIC_NET" in (decision.policy or "") or "XW_GENERIC_NET" in decision.reason


def test_real_shape_core_defaults_plus_appended_pack_block():
    # The exact production shape: DOGFOOD_DEFAULTS (contains the generic
    # external-DELETE warn) + a pack block rule appended AFTER, both matching
    # one curl -X DELETE to a SaaS host. Must hard-block via the pack rule.
    saas_block = Policy(
        name="XW_SAAS_DESTROY",
        level="block",
        patterns=(r"\b(?:curl|wget)\b[^\n]*DELETE\b[^\n]*api\.xw-saas\.example",),
        reason="deleting a SaaS resource is irreversible - requires a human",
    )
    policies = list(DOGFOOD_DEFAULTS) + [saas_block]
    with pytest.raises(ActionVetoed) as ei:
        check_action(
            "test",
            "curl -X DELETE https://api.xw-saas.example/v1/dashboards/42",
            policies,
        )
    assert "XW_SAAS_DESTROY" in str(ei.value)
