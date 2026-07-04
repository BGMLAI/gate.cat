"""cacheback-integrations: framework integrations for the cacheback veto pipeline.

Staging package - merges into the cacheback SDK as ``cacheback/integrations/``
and ``cacheback/policies.py`` (see README.md for the merge map). Zero runtime
dependencies; frameworks are extras with lazy imports; all engine contact goes
through the ``_engine`` seam.
"""

from cacheback.integrations._engine import ActionVetoed, Decision, EngineUnavailable, evaluate
from cacheback.integrations._log import ascii_safe, log_decision
from cacheback.integrations.guard import (
    check_action,
    flatten_call,
    guard_callable,
    shadow_enabled,
)
from cacheback.integrations.policies import (
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
    # logging / D1
    "ascii_safe",
    "log_decision",
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
