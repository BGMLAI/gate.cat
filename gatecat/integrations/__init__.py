"""gatecat-integrations: framework integrations for the gatecat veto pipeline.

Staging package - merges into the gatecat SDK as ``gatecat/integrations/``
and ``gatecat/policies.py`` (see README.md for the merge map). Zero runtime
dependencies; frameworks are extras with lazy imports; all engine contact goes
through the ``_engine`` seam.
"""

from gatecat.integrations._audit import (
    AuditRecord,
    HumanOversight,
    audit_dir,
    record_decision,
    redact_entry,
    verify_chain,
)
from gatecat.integrations._engine import ActionVetoed, Decision, EngineUnavailable, evaluate
from gatecat.integrations._log import ascii_safe, log_decision
from gatecat.integrations.extra_policies import (
    ExtraPolicyError,
    load_extra_policies,
    policies_with_extras,
)
from gatecat.integrations.guard import (
    check_action,
    ephemeral_context,
    flatten_call,
    guard_callable,
    shadow_enabled,
)
from gatecat.integrations.policies import (
    ALL_PRESETS,
    CLOUD_DESTROY,
    DB_DESTRUCTIVE,
    DOGFOOD_DEFAULTS,
    EMAIL_SEND,
    GIT_FORCE_PUSH,
    PAYMENTS,
    PAYMENTS_DEFAULT,
    RM_RF,
    TERRAFORM_PROD,
    Policy,
)

__all__ = [
    # engine seam
    "ActionVetoed",
    "Decision",
    "EngineUnavailable",
    "evaluate",
    # guard (the one mechanism adapters and the hook delegate to)
    "check_action",
    "guard_callable",
    "flatten_call",
    "shadow_enabled",
    "ephemeral_context",
    # logging / D1
    "ascii_safe",
    "log_decision",
    # GATECAT_EXTRA_POLICIES loader (fold operator packs into the hook/proxy)
    "ExtraPolicyError",
    "load_extra_policies",
    "policies_with_extras",
    # compliance split-log (skeleton hash-chain + redactable PII sidecar)
    "AuditRecord",
    "HumanOversight",
    "record_decision",
    "verify_chain",
    "redact_entry",
    "audit_dir",
    # policies
    "Policy",
    "ALL_PRESETS",
    "DOGFOOD_DEFAULTS",
    "TERRAFORM_PROD",
    "DB_DESTRUCTIVE",
    "EMAIL_SEND",
    "CLOUD_DESTROY",
    "PAYMENTS",
    "PAYMENTS_DEFAULT",
    "GIT_FORCE_PUSH",
    "RM_RF",
]

__version__ = "0.1.0"
