"""gatecat.veto — action-veto: stop an agent BEFORE it takes an irreversible action.

The problem (from real agent-framework issues): an agent with tool access runs an
action it shouldn't — and the action is IRREVERSIBLE. Seen in the wild: duplicate
payments / trades (crewAI #5802), an agent that destroyed an AWS account by
deploying Terraform to the wrong target ($106k loss, autogen #7770), missing
tool-call authorization (crewAI #5888). This is not a token-cost problem — it is a
problem of CONTROL over an action before it touches the world.

GatedLoop (gatecat.agent) watches the RIVER: the model hesitates (sample spread) →
pause the loop. Veto watches the ACTION: before a tool function runs, the action
must flow through a deterministic KORYTO (riverbed): policy + an independent check.
Confident-wrong at the ACTION level is invisible to the spread signal (the model is
CERTAIN it must pay / deploy) — only the policy + interpreter catch it, not the
uncertainty signal.

Three walls (fail-closed — an error in any of them = VETO, not pass-through):
  1. POLICY — deterministic rules: deny / amount threshold / requires-a-human.
  2. KORYTO — when the action has a checkable atom, an interpreter verifies it
              INDEPENDENTLY of the model (gatecat.koryto, recall 1.0, 0% false-pass
              in the proxy).
  3. HUMAN  — when policy demands a human and no approval is given → action blocked.

HONESTY (the boundary — no pretending):
  - Veto blocks actions matching a rule / contradicting the deterministic check.
    That is DETECTION+BLOCKING of known patterns, NOT a guarantee every bad action
    is caught.
  - Veto only needs to be certain about what it BLOCKS (known patterns, a
    contradiction with the interpreter), never about what it PASSES. Hence
    fail-closed: doubt → veto.
  - A policy is only as good as its rules. An empty policy with no koryto passes
    everything (honestly surfaced by `VetoGate(strict=True)`, which requires ≥1 wall).

Usage:
    from gatecat.veto import before_action, ActionPolicy, ActionVetoed

    policy = ActionPolicy(
        deny=[r"terraform.*(destroy|apply).*prod", r"drop\\s+table"],
        require_human=[r"charge_card", r"send_wire"],
        max_amount=100.0,
    )

    @before_action(policy, human_approve=lambda call: ask_user(call),
                   amount_of=lambda **k: k.get("amount"))
    def charge_card(*, customer, amount):
        return payment_api.charge(customer, amount)

    try:
        charge_card(customer="acme", amount=5000)
    except ActionVetoed as e:
        log.warning("action blocked: %s", e.reason)   # the irreversible never became fact
"""
from __future__ import annotations

import functools
import inspect
import math
import re
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional, Sequence

from gatecat.exceptions import ActionVetoed
from gatecat.koryto import Koryto, KorytoVerdict


@dataclass
class VetoDecision:
    """Result of the veto gate for a single action attempt (for the audit trail)."""
    allowed: bool
    mur: str                       # "policy-deny" | "policy-amount" | "koryto" | "human" | "allow"
    reason: str = ""
    verdict: Optional[KorytoVerdict] = None

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "mur": self.mur,
            "reason": self.reason,
            "koryto": self.verdict.to_dict() if self.verdict else None,
        }


# ActionVetoed lives in gatecat.exceptions (0.4.1): ONE class for both the engine
# and the integrations layer, so `except gatecat.ActionVetoed` catches a veto from
# any layer. The import at the top of this file re-exports it here — `from
# gatecat.veto import ActionVetoed` works as before, and so does constructing it
# from a VetoDecision.


@dataclass
class ActionPolicy:
    """Declarative action riverbed: what is ALLOWED, what needs a human, what is forbidden.

    Rules are regex patterns matched against the call representation (`fn(args, kwargs)`).
    Priority order: deny (hard block) > amount threshold > requires-a-human.

    Args:
        deny:          patterns for actions FORBIDDEN unconditionally (veto immediately).
        require_human: patterns requiring human approval (veto without an approve).
        max_amount:    amount threshold — an action with `amount > max_amount` needs a human.
    """
    deny: Sequence[str] = field(default_factory=tuple)
    require_human: Sequence[str] = field(default_factory=tuple)
    max_amount: Optional[float] = None

    # ReDoS guard (audit 2026-06-27 should-fix): catastrophic backtracking scales
    # with the LENGTH of the matched text. Patterns come from the operator (not from
    # traffic), but a long call_repr (large arguments) could hang a bad pattern. We
    # trim the input to a safe length — matching a name/action needs no more.
    _MAX_MATCH_LEN = 4096

    def classify(self, call_repr: str, amount: Optional[float]) -> VetoDecision:
        """Return the policy decision. Fail-closed: a bad regex → treat as a match (veto)."""
        call_repr = call_repr[:self._MAX_MATCH_LEN]
        for pat in self.deny:
            try:
                hit = re.search(pat, call_repr, re.I)
            except re.error:
                return VetoDecision(False, "policy-deny",
                                    f"invalid deny pattern /{pat}/ - fail-closed veto")
            if hit:
                return VetoDecision(False, "policy-deny",
                                    f"action matches denied pattern /{pat}/")
        if self.max_amount is not None and amount is not None:
            try:
                amt_f = float(amount)
            except (TypeError, ValueError):
                return VetoDecision(False, "policy-amount",
                                    f"amount {amount!r} not comparable to cap - fail-closed veto")
            # NaN/inf slip past the '>' comparison (IEEE 754: nan > x is always False) → fail-closed.
            # Without this, charge(amount=float('nan')) would pass over the cap. (audit 2026-06-27 #1)
            if math.isnan(amt_f) or math.isinf(amt_f):
                return VetoDecision(False, "policy-amount",
                                    f"amount {amount!r} is not a finite number - fail-closed veto")
            over = amt_f > float(self.max_amount)
            if over:
                return VetoDecision(False, "policy-amount",
                                    f"amount {amount} > cap {self.max_amount} - requires human approval")
        for pat in self.require_human:
            try:
                hit = re.search(pat, call_repr, re.I)
            except re.error:
                return VetoDecision(False, "human",
                                    f"invalid require_human pattern /{pat}/ - fail-closed veto")
            if hit:
                return VetoDecision(False, "human",
                                    f"/{pat}/ requires human approval")
        return VetoDecision(True, "allow", "policy: allowed")


class VetoGate:
    """Action-veto gate: evaluates an action attempt through three walls, BEFORE it runs.

    Args:
        policy:        ActionPolicy (deny/threshold/human). None = no policy rules.
        koryto:        Koryto for the independent check (defaults to a new exec+calc one).
        human_approve: Callable[[call_repr], bool] asked when policy demands a human.
                       Absent → every requires-a-human ends in a veto (fail-closed).
        amount_of:     Callable(*args, **kwargs) → Optional[float] extracting the amount.
        exec_check:    Callable(*args, **kwargs) → Optional[Sequence[str]] returning
                       statements for koryto to run (when the action has a checkable atom).
        strict:        when True, requires ≥1 active wall (policy with rules / exec_check),
                       else raises ValueError at construction (an empty gate passes everything).
    """

    def __init__(
        self,
        policy: Optional[ActionPolicy] = None,
        *,
        koryto: Optional[Koryto] = None,
        human_approve: Optional[Callable[[str], bool]] = None,
        amount_of: Optional[Callable[..., Optional[float]]] = None,
        exec_check: Optional[Callable[..., Optional[Sequence[str]]]] = None,
        strict: bool = False,
    ):
        self.policy = policy
        self.koryto = koryto or Koryto(enable_exec=True, enable_calc=True)
        self.human_approve = human_approve
        self.amount_of = amount_of
        self.exec_check = exec_check
        has_rules = bool(policy and (policy.deny or policy.require_human or policy.max_amount is not None))
        if strict and not (has_rules or exec_check):
            raise ValueError(
                "VetoGate(strict=True): an empty gate would allow everything - "
                "provide a policy with rules or an exec_check"
            )

    def evaluate(self, call_repr: str, args: tuple, kwargs: dict,
                 fn: Optional[Callable] = None) -> VetoDecision:
        """Evaluate the action. Returns a VetoDecision (allowed True/False). Does not run it.

        `fn` (optional): the tool function — lets us bind POSITIONAL arguments to
        parameter names. Without it `charge(5000)` (LLMs often generate positionally)
        bypassed the max_amount threshold, because the amount was only read from
        kwargs['amount'] (workflow review 2026-07-02, P1 fail-open)."""
        amount = None
        if self.amount_of is not None:
            try:
                amount = self.amount_of(*args, **kwargs)
            except Exception as e:
                return VetoDecision(False, "policy-amount",
                                    f"amount_of raised {e!r} - fail-closed veto")
        else:
            bound = dict(kwargs)
            if fn is not None and args:
                try:
                    bound = dict(inspect.signature(fn).bind_partial(*args, **kwargs).arguments)
                except (TypeError, ValueError):
                    pass  # can't bind — fall back to kwargs only
            if "amount" in bound:
                amount = bound["amount"]

        # WALL 1: policy (deny / threshold)
        if self.policy is not None:
            dec = self.policy.classify(call_repr, amount)
            if not dec.allowed and dec.mur in ("policy-deny", "policy-amount"):
                return dec
            policy_wants_human = (not dec.allowed and dec.mur == "human")
        else:
            policy_wants_human = False

        # WALL 2: koryto (independent check when the action has a checkable atom)
        if self.exec_check is not None:
            try:
                stmts = self.exec_check(*args, **kwargs)
            except Exception as e:
                return VetoDecision(False, "koryto",
                                    f"exec_check raised {e!r} - fail-closed veto")
            if stmts:
                expected = kwargs.get("expect")
                try:
                    v = self.koryto.verify(call_repr, str(expected if expected is not None else ""),
                                            exec_stmts=list(stmts))
                except Exception as e:
                    return VetoDecision(False, "koryto",
                                        f"koryto.verify raised {e!r} - fail-closed veto", None)
                if v.caught:
                    return VetoDecision(False, "koryto",
                                        f"interpreter says {v.truth!r}, agent claimed {expected!r}", v)

        # MUR 3: human-in-the-loop
        if policy_wants_human:
            approved = False
            if self.human_approve is not None:
                try:
                    approved = bool(self.human_approve(call_repr))
                except Exception as e:
                    return VetoDecision(False, "human",
                                        f"human_approve raised {e!r} - fail-closed veto")
            if not approved:
                return VetoDecision(False, "human",
                                    "requires human approval - no approval given, veto")

        return VetoDecision(True, "allow", "all walls passed")


def before_action(
    policy: Optional[ActionPolicy] = None,
    *,
    koryto: Optional[Koryto] = None,
    human_approve: Optional[Callable[[str], bool]] = None,
    amount_of: Optional[Callable[..., Optional[float]]] = None,
    exec_check: Optional[Callable[..., Optional[Sequence[str]]]] = None,
    strict: bool = False,
    on_veto: Optional[Callable[[VetoDecision], Any]] = None,
):
    """Veto-gate decorator for an agent's tool function. Checks BEFORE the function runs.

    Works on both sync and async functions. When an action is vetoed:
      - if `on_veto` is given → it is called with the VetoDecision and its result is
        returned instead of the action;
      - otherwise → ActionVetoed is raised (the action is NOT run).

    See VetoGate for a description of the walls and arguments.
    """
    gate = VetoGate(policy, koryto=koryto, human_approve=human_approve,
                    amount_of=amount_of, exec_check=exec_check, strict=strict)

    def deco(fn: Callable):
        call_name = getattr(fn, "__name__", "action")

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def awrapped(*args, **kwargs):
                call_repr = f"{call_name}(args={args!r}, kwargs={kwargs!r})"
                dec = gate.evaluate(call_repr, args, kwargs, fn=fn)
                if not dec.allowed:
                    if on_veto is not None:
                        return on_veto(dec)
                    raise ActionVetoed(dec)
                return await fn(*args, **kwargs)
            awrapped.veto_gate = gate
            return awrapped

        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            call_repr = f"{call_name}(args={args!r}, kwargs={kwargs!r})"
            dec = gate.evaluate(call_repr, args, kwargs, fn=fn)
            if not dec.allowed:
                if on_veto is not None:
                    return on_veto(dec)
                raise ActionVetoed(dec)
            return fn(*args, **kwargs)
        wrapped.veto_gate = gate
        return wrapped

    return deco
