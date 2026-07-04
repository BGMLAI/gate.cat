"""A4: ready-made veto policy presets.

Policies are DATA ONLY. Matching/decision logic lives in the engine's
policy wall (one mechanism - VETO_PIPELINE_PLAN.md). Patterns come from
real incidents in agent-framework issue trackers (e.g. the $106k AutoGen
runaway, autogen#7770; duplicate payments, crewAI#5802).

Honest line: a veto policy is only certain about what it BLOCKS, never
about what it lets through. Actions outside these patterns are NOT
"verified safe" - they are unchecked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Policy:
    """A named set of deny patterns handed to the engine's policy wall."""

    name: str
    patterns: tuple[str, ...]
    reason: str  # ASCII only (D1): shown on cp1252 consoles and hook stderr
    description: str = ""
    params: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "patterns": list(self.patterns),
            "reason": self.reason,
            "description": self.description,
            "params": dict(self.params),
        }


TERRAFORM_PROD = Policy(
    name="TERRAFORM_PROD",
    patterns=(
        # apply/destroy may sit after global opts (e.g. `terraform -chdir=envs/prod
        # destroy`); lookahead requires the verb, then match prod or -auto-approve
        r"\b(terraform|tofu)\b(?=.*\b(apply|destroy)\b).*(\bprod|-auto-approve)",
    ),
    reason="terraform apply/destroy against production requires a human",
    description="Blocks Terraform/OpenTofu apply/destroy touching prod or auto-approved.",
)

DB_DESTRUCTIVE = Policy(
    name="DB_DESTRUCTIVE",
    patterns=(
        r"\bDROP\s+(TABLE|DATABASE|SCHEMA)\b",
        r"\bTRUNCATE\s+TABLE\b",
        r"\bDELETE\s+FROM\b(?![\s\S]*\bWHERE\b)",
    ),
    reason="destructive SQL (DROP/TRUNCATE/unbounded DELETE) requires a human",
    description="Blocks schema-destroying SQL and DELETE without a WHERE clause.",
)

EMAIL_SEND = Policy(
    name="EMAIL_SEND",
    patterns=(
        r"\b(sendmail|mailx?)\b",
        r"\bsmtplib\b",
        r"messages\.send|sendEmail|send_email",
    ),
    reason="outbound email from an agent requires a human",
    description="Blocks agents from sending email autonomously.",
)

CLOUD_DESTROY = Policy(
    name="CLOUD_DESTROY",
    patterns=(
        # AWS destructive ops are `<verb>-<noun>` subcommands (terminate-instances,
        # delete-bucket) or `s3 rb`; the negative lookbehind keeps benign `--delete`
        # flags and `.../delete-after/` path segments from false-blocking
        r"\baws\b.*(?<![\w/-])(delete-|terminate-|remove-)\w+",
        r"\baws\s+s3\s+rb\b",
        # gcloud/az: bare positional `delete` verb; excluded when it is part of a
        # filter (~delete, :delete), a flag (--delete), or a hyphenated value
        r"\bgcloud\b.*(?<![\w~:=/-])delete(?![\w-])",
        r"\baz\b.*(?<![\w~:=/-])delete(?![\w-])",
        r"\bvastai\s+destroy\b",
        r"\bkubectl\s+delete\s+(ns|namespace|deploy|deployment)\b",
    ),
    reason="cloud resource deletion requires a human",
    description="Blocks delete/terminate calls to AWS/GCP/Azure/vast.ai/k8s.",
)


def PAYMENTS(max_amount: float = 0.0, currency: str = "USD") -> Policy:
    """Payment guard. With the default ``max_amount=0`` every payment-shaped
    action is blocked; a higher ceiling is recorded in ``params`` for the
    engine's policy wall to enforce (duplicate-payment class, crewAI#5802).
    """
    return Policy(
        name="PAYMENTS",
        patterns=(
            # underscore-tolerant: real tool names look like create_payment,
            # payment.create, execute_transfer - \b alone misses those
            r"(charge|payment|payout|transfer|refund)s?[\s_.:-]*(create|execute|send|post)",
            r"(create|execute|send|post|make)[\s_.:-]*(charge|payment|payout|transfer|refund)",
            r"stripe\.(charges|paymentintents|transfers)",
        ),
        reason=f"payment above {max_amount:g} {currency} (or unparseable) requires a human",
        description="Blocks payment execution; ceiling enforced by the engine policy wall.",
        params={"max_amount": max_amount, "currency": currency},
    )


# B1a dogfooding set - mirrors the founder's own CLAUDE.md safety rules.
GIT_FORCE_PUSH = Policy(
    name="GIT_FORCE_PUSH",
    # `push` may follow global opts (`git -C /repo push --force`); require a
    # force flag that is not --force-with-lease
    patterns=(r"\bgit\b(?=.*\bpush\b).*(--force(?!-with-lease)|(?<!\w)-f(?!\w))",),
    reason="git push --force (without --force-with-lease) requires a human",
    description="Blocks history-destroying force pushes.",
)

RM_RF = Policy(
    name="RM_RF",
    # combined flags in any order incl. extra letters (-rf, -rfv, -Rfi, -fr) and
    # split flags (-r -f); the old trailing \\b let `-rfv` slip through
    patterns=(r"\brm\b(?=.*(-\w*r\w*f|-\w*f\w*r|-r\b.*-f\b|-f\b.*-r\b))",),
    reason="recursive force delete requires a human",
    description="Blocks rm -rf and flag-order variants.",
)

DOGFOOD_DEFAULTS: tuple[Policy, ...] = (
    TERRAFORM_PROD,
    DB_DESTRUCTIVE,
    CLOUD_DESTROY,
    GIT_FORCE_PUSH,
    RM_RF,
)

# Default payment policy instance (blocks every payment-shaped action).
# For a real ceiling call the PAYMENTS(max_amount=...) factory directly.
PAYMENTS_DEFAULT = PAYMENTS()

# Every value is a Policy INSTANCE (uniform shape - safe to iterate and
# .to_dict() without isinstance guards). PAYMENTS the factory lives beside
# this dict, not inside it.
ALL_PRESETS: dict[str, Policy] = {
    "TERRAFORM_PROD": TERRAFORM_PROD,
    "DB_DESTRUCTIVE": DB_DESTRUCTIVE,
    "EMAIL_SEND": EMAIL_SEND,
    "CLOUD_DESTROY": CLOUD_DESTROY,
    "PAYMENTS": PAYMENTS_DEFAULT,
    "GIT_FORCE_PUSH": GIT_FORCE_PUSH,
    "RM_RF": RM_RF,
}
