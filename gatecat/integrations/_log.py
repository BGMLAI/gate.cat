"""D1 + D2: ASCII-safe text handling and the veto audit log (JSONL).

D1 - known bug class: Polish characters in ``ActionVetoed.reason`` crash
``print()`` on Windows cp1252. Every string this package emits to
stdout/stderr goes through :func:`ascii_safe`.

D2 - official audit log: one JSON object per line appended to
``~/.gatecat/veto_log.jsonl`` (override with ``GATECAT_VETO_LOG``).
Record schema (council: ARCHITEKT - metadata so false-block adjudication
in B2 does not require guessing):

    ts       ISO-8601 UTC timestamp
    source   claude_code_hook | crewai | langgraph | <custom>
    policy   name of the policy wall that fired (null if none)
    decision "block" | "allow"
    reason   ASCII-safe justification
    context  short excerpt of the evaluated action (<=400 chars)
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

_LOG_ENV = "GATECAT_VETO_LOG"
_DEFAULT_LOG = Path.home() / ".gatecat" / "veto_log.jsonl"
_CONTEXT_LIMIT = 400


def ascii_safe(text: str) -> str:
    """Return *text* with every non-ASCII char backslash-escaped (D1).

    Safe for cp1252 consoles, hook stderr, and JSONL logs.
    """
    return text.encode("ascii", errors="backslashreplace").decode("ascii")


def log_path() -> Path:
    return Path(os.environ.get(_LOG_ENV, str(_DEFAULT_LOG)))


def log_decision(
    *,
    source: str,
    decision: str,
    reason: str,
    policy: str | None = None,
    context: str = "",
    stages: "list | tuple | None" = None,
) -> None:
    """Append one audit record. Best-effort: logging must never turn an
    allow into a crash (the *decision* itself is already made by the gate).

    Two sinks, kept deliberately separate:

    1. ``veto_log.jsonl`` - the STABLE flat 6-field telemetry line. Its shape is
       a contract (adapters, hook, older tooling read it); this function never
       changes it. That is why the compliance fields live elsewhere.
    2. the compliance split-log (:mod:`_audit`) - skeleton (hash-chained,
       non-personal) + PII sidecar (redactable). Populated from the SAME call so
       a deployer under EU AI Act / GDPR / China CSL / etc. gets an audit-grade
       record with no extra wiring, while the flat log stays byte-compatible.

    Both are best-effort; a failure in either never affects the gate's verdict.
    """
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": source,
        "policy": policy,
        "decision": decision,
        "reason": ascii_safe(reason),
        # truncate BEFORE escaping so the cut never lands inside a
        # backslash-escape sequence and corrupts the excerpt
        "context": ascii_safe(context[:_CONTEXT_LIMIT]),
    }
    try:
        path = log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="ascii") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        pass  # best-effort; never mask or alter the gate's decision

    # Mirror into the compliance split-log. Imported lazily and wrapped so a
    # missing/broken _audit can never regress the flat log above or the gate.
    try:
        from gatecat.integrations._audit import AuditRecord, record_decision

        record_decision(
            AuditRecord(
                decision=decision,
                reason=reason,
                source=source,
                rule_id=policy,
                rule_version=None,
                raw_action=context,        # the command; redacted unless opted in
                actor_id=source,           # framework/agent id; sidecar, opt-in
                actor_role="agent",
                region=_audit_region(),
                stages=tuple(tuple(s) for s in stages) if stages else (),
            )
        )
    except Exception:
        pass  # compliance mirror is additive; never let it break telemetry


def _audit_region() -> str | None:
    """Jurisdiction routing key for the compliance log (env-provided). Kept here
    so the flat-log path has no hard dependency on :mod:`_audit` internals."""
    import os

    return os.environ.get("GATECAT_AUDIT_REGION") or None
