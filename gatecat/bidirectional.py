"""bidirectional — BidirectionalGate: a bidirectional gate (PROVIDER + GUARDIAN) on a shared engine.

10-vote council (2026-06-28) TOP-3: the same truth engine (koryto), but SEPARATE INTERFACES.
Reason: a provider error (stale cache) must NOT contaminate the guardian; the guardian can VETO an action
based on a faulty HARD from the provider. Blast-radius isolation.

  Provider.provide_truth(op, args)   — direction 1: supplies the agent a verified fact (read-only).
  Guardian.veto(action, ...)         — direction 2: vetoes an action BEFORE it executes (fail-closed).

The disagreement gate (uncertainty, SOFT) lives separately in gate.py — that's a different mechanism.
Here: the ACTION/TRUTH gate (the agent's bidirectional loop).

Core is 100% stdlib + koryto + veto + provider (all stdlib). Zero API/model at runtime.
"""
from __future__ import annotations

from typing import Optional

from gatecat.koryto import Koryto
from gatecat.veto import VetoGate, ActionPolicy, VetoDecision
from gatecat.provider import (
    provide_truth as _provide_truth,
    provide_hint as _provide_hint,
    verify_proof as _verify_proof,
    Verified, Hint,
)


class Provider:
    """Direction 1 — TRUTH PROVIDER. Read-only, pure functions (if it mutates ⇒ Actor, not Oracle).
    Gives the agent a Verified (HARD, exec/calc) or a Hint (SOFT, cache). NEVER executes an action."""

    def __init__(self, koryto: Optional[Koryto] = None):
        # engine shared with the Guardian (council TOP-3) — but the Provider only READS it
        self.koryto = koryto or Koryto(enable_exec=True, enable_calc=True)

    def provide_truth(self, op: str, args: str) -> Optional[Verified]:
        """Return a Verified (HARD) or None. Only exec/calc — proof from execution."""
        return _provide_truth(op, args)

    def provide_hint(self, value: str, sim: float, source: str = "lookup") -> Hint:
        """Return a Hint (SOFT) — from cache/lookup. NEVER HARD (even at sim=1.0)."""
        return _provide_hint(value, sim, source)

    @staticmethod
    def verify_proof(verified: Verified) -> bool:
        """The agent reproduces the proof independently (does not trust the gate blindly)."""
        return _verify_proof(verified)


class Guardian:
    """Direction 2 — GUARDIAN. Vetoes an action BEFORE it executes. Fail-closed.
    Wraps the existing VetoGate (does NOT replace it) — separates the interface from the provider."""

    def __init__(self, veto_gate: Optional[VetoGate] = None,
                 koryto: Optional[Koryto] = None):
        self._veto = veto_gate or VetoGate(koryto=koryto)

    def veto(self, action: str, args=(), kwargs=None) -> VetoDecision:
        """Evaluate the action. allowed=False ⇒ do NOT execute. Fail-closed on any exception."""
        return self._veto.evaluate(action, tuple(args), dict(kwargs or {}))


class BidirectionalGate:
    """One koryto engine, two interfaces (council TOP-3). The full loop:
      1. provider.provide_truth() — the gate GIVES truth to the agent (decision input)
      2. the agent reasons over trusted data
      3. guardian.veto() — the gate CHECKS the action (output, fail-closed)

    A shared Koryto = a single truth; separate Provider/Guardian = isolated blast-radius.
    """

    def __init__(self, policy: Optional[ActionPolicy] = None,
                 koryto: Optional[Koryto] = None):
        self.koryto = koryto or Koryto(enable_exec=True, enable_calc=True)
        self.provider = Provider(koryto=self.koryto)
        self.guardian = Guardian(
            veto_gate=VetoGate(policy=policy, koryto=self.koryto))

    # convenience shortcuts
    def provide_truth(self, op: str, args: str) -> Optional[Verified]:
        return self.provider.provide_truth(op, args)

    def veto(self, action: str, args=(), kwargs=None) -> VetoDecision:
        return self.guardian.veto(action, args, kwargs)
