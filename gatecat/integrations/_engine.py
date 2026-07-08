"""Engine seam: the ONLY place this package touches the real gatecat veto engine.

Everything else in gatecat-integrations (hook, adapters, presets, logging,
tests) is engine-agnostic and final. When merging into the gatecat SDK,
wire the two TODO(local) points below against the real ``gatecat.veto``
API and delete nothing else.

Contract this seam expects from the engine (per VETO_PIPELINE_PLAN.md):
  - ``gatecat.veto.VetoGate`` - constructed with policy data
  - a "before action" evaluation returning a decision with (at least):
      blocked: bool     - True => the action must NOT run
      reason: str       - human-readable justification
      policy: str|None  - name of the policy wall that fired (if any)
  - ``gatecat.veto.ActionVetoed`` - exception raised on blocked actions

Fail-closed semantics (three walls: policy/koryto/human):
  - engine import fails        -> EngineUnavailable -> callers must BLOCK
  - evaluation raises          -> callers must BLOCK
  - decision shape unreadable  -> callers must BLOCK
An unverifiable action is never allowed through. unchecked != safe.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

# ONE ActionVetoed for the whole package (0.4.1). Historically this layer kept
# its own string-based class, so a user catching top-level gatecat.ActionVetoed
# missed blocks raised by check_action. The unified class lives in
# gatecat.exceptions - a stdlib-only module that imports even when the veto
# ENGINE (gatecat.veto) is not importable, so the fail-closed EngineUnavailable
# path below still works. It accepts both a plain ASCII-safe reason string
# (this layer's _raise_block) and a VetoDecision (the engine).
from gatecat.exceptions import ActionVetoed


class EngineUnavailable(RuntimeError):
    """The gatecat veto engine cannot be imported. Callers must fail closed."""


@dataclass(frozen=True)
class Decision:
    """Normalized veto decision consumed by hook and adapters.

    ``level`` adds a third state to the block/allow binary:
      "block" -> must not run (blocked=True).
      "warn"  -> UNCHECKED: the analyzer cannot see the target (remote ssh,
                 opaque $()/pipe, unresolved $VAR). Surfaced + logged, but not
                 hard-blocked (blocked=False).
      "allow" -> safe to run.
    ``blocked`` is kept in sync (True only for "block") for back-compat with
    callers that branch on it."""

    blocked: bool
    reason: str
    policy: str | None = None
    level: str | None = None  # "block"|"warn"|"allow"; derived from blocked if unset
    # Full per-stage trace: every gate stage that ran, its verdict, and why.
    # Each entry is (stage, verdict, detail). This is the audit/observability
    # trail (AI Act Art.12 traceability) - it makes the decision path explainable
    # AND lets a recall audit see whether ANY stage flagged an allowed action.
    # Empty for old two-arg callers; populated by check_action.
    stages: tuple[tuple[str, str, str], ...] = ()

    def __post_init__(self) -> None:
        # keep level in sync with blocked when a caller didn't pass one, so
        # old two-arg Decision(blocked, reason) callers get the right level.
        if self.level is None:
            object.__setattr__(self, "level", "block" if self.blocked else "allow")

    def with_stages(self, stages: "list[tuple[str, str, str]]") -> "Decision":
        """Return a copy carrying the full stage trace (Decision is frozen)."""
        return Decision(blocked=self.blocked, reason=self.reason,
                        policy=self.policy, level=self.level,
                        stages=tuple(stages))

    def to_dict(self) -> dict[str, Any]:
        return {"blocked": self.blocked, "reason": self.reason,
                "policy": self.policy, "level": self.level,
                "stages": [list(s) for s in self.stages]}


def _load_veto_module():
    try:
        from gatecat import veto  # type: ignore
    except ImportError as exc:
        raise EngineUnavailable(
            "gatecat veto engine not importable (pip install gate.cat "
            "with the veto module). Fail-closed: blocking."
        ) from exc
    return veto


def evaluate(source: str, action: str, policies: Sequence[Any]) -> Decision:
    """Evaluate one action through the real ``gatecat.veto`` engine. One
    mechanism, no verification logic on this side of the seam.

    Wired to the real engine (``gatecat/veto.py``): the integrations' list of
    ``policies.Policy`` (each a bundle of deny-regex ``patterns``) is folded into
    one ``ActionPolicy(deny=[...])`` and evaluated via ``VetoGate.evaluate``.
    ``VetoDecision.allowed`` is inverted to our ``blocked``.

    A ``before_action`` fake engine (contract tests) is also supported: if the
    constructed gate exposes ``before_action`` as a *method*, we call it instead.

    Args:
        source: where the action comes from (``claude_code_hook`` / ``crewai`` /
            ``langgraph`` / ...) - recorded in the audit log.
        action: textual form of the action (shell command, tool call repr).
        policies: iterable of ``policies.Policy``.

    Raises:
        EngineUnavailable: engine missing - caller must block.
    """
    gate, kind = _gate_for(tuple(policies))
    if kind == "fake":
        # contract-test fake: VetoGate(policies=[dict]).before_action(action, source=)
        raw = gate.before_action(action, source=source)
        return _normalize_fake(raw)
    # real engine: VetoGate(ActionPolicy).evaluate(call_repr, args, kwargs)
    raw = gate.evaluate(action, (), {})
    return _normalize_real(raw, action, policies)


# Cache the constructed gate per distinct policy set. The real engine's
# VetoGate.__init__ builds a Koryto (exec/calc interpreters), so rebuilding it
# on every tool call in a long-lived agent is O(tool_calls) waste when the
# policies never change. Keyed on a hashable projection (Policy.patterns).
_GATE_CACHE: dict[tuple, tuple[Any, str]] = {}


def _gate_for(policies: tuple) -> tuple[Any, str]:
    key = tuple((p.name, p.patterns) for p in policies)
    cached = _GATE_CACHE.get(key)
    if cached is None:
        veto = _load_veto_module()
        VetoGate = veto.VetoGate
        if hasattr(veto, "ActionPolicy"):
            # real engine: fold every Policy's deny-patterns into one ActionPolicy.
            deny: list[str] = []
            for p in policies:
                deny.extend(p.patterns)
            gate = VetoGate(veto.ActionPolicy(deny=tuple(deny)))
            kind = "real"
        else:
            # contract-test fake that takes policies=[dict] and has before_action.
            gate = VetoGate(policies=[p.to_dict() for p in policies])
            kind = "fake"
        cached = (gate, kind)
        _GATE_CACHE[key] = cached
    return cached


def _which_policy(action: str, policies: Sequence[Any]) -> str | None:
    """Map a real-engine block back to the integrations preset that owns the
    matching pattern, so the audit log records ``RM_RF`` not the engine's
    generic ``policy-deny``. Best-effort: first Policy whose pattern hits."""
    import re

    for p in policies:
        for pat in p.patterns:
            try:
                if re.search(pat, action, re.IGNORECASE):
                    return p.name
            except re.error:
                return p.name  # a bad pattern is what fail-closed-blocked us
    return None


def _normalize_real(raw: Any, action: str, policies: Sequence[Any]) -> Decision:
    """Translate the engine's ``VetoDecision`` (``allowed``/``reason``/``mur``)
    into our ``Decision`` (``blocked``/``reason``/``policy``). Unreadable => block."""
    allowed = getattr(raw, "allowed", None)
    if allowed is None:
        return Decision(True, "veto decision unreadable (fail-closed)", None)
    blocked = not bool(allowed)
    reason = str(getattr(raw, "reason", None) or ("blocked by veto gate" if blocked else "allowed"))
    # engine reports which WALL fired (mur); resolve to the preset name on a block
    # so the audit stays human-readable, falling back to the mur if unresolved.
    if blocked:
        policy = _which_policy(action, policies) or getattr(raw, "mur", None)
    else:
        policy = None
    return Decision(blocked=blocked, reason=reason, policy=policy)


def _normalize_fake(raw: Any) -> Decision:
    """Duck-type a fake engine's decision (blocked/reason/policy). Contract tests
    only. Unreadable => block."""
    if isinstance(raw, Decision):
        return raw
    blocked = getattr(raw, "blocked", None)
    if blocked is None and isinstance(raw, dict):
        blocked = raw.get("blocked")
    if blocked is None:
        return Decision(True, "veto decision unreadable (fail-closed)", None)
    reason = getattr(raw, "reason", None) or (
        raw.get("reason") if isinstance(raw, dict) else None
    ) or ("blocked by veto gate" if blocked else "allowed")
    policy = getattr(raw, "policy", None) or (
        raw.get("policy") if isinstance(raw, dict) else None
    )
    return Decision(blocked=bool(blocked), reason=str(reason), policy=policy)
