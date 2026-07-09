"""stagnation — stagnation-by-state: watches the KORYTO (channel), not the river.

ARCHITECTURE (Axiom 1 / theory τ, user-designed REGISTER 2026-06-26):
  "The koryto watches the river, STAGNATION watches the koryto."

Two roles, do NOT confuse them:
  - GatedLoop (gatecat.agent): watches the RIVER — interrupts a runaway agent when
    the model is guessing in a loop (sample scatter). Signal = river HESITATION.
  - StagnationMonitor (HERE): watches the KORYTO — detects when the koryto REJECTS
    answer after answer without progress. Signal = no-progress-despite-rejections =
    THE KORYTO HAS ROTTED (a stale/bad database rejects GOOD answers), not the river
    getting it wrong.

WHY (measured, REGISTER 2026-06-27): a koryto-lookup BY ITSELF can be confident-wrong —
a broken/outdated database introduces its own error (koryto-stale: Casablanca instead
of Rabat → rejects the model's correct answer = bad-block). A plain scatter counter will
NOT catch this (the koryto is deterministic, zero scatter). Stagnation-by-state is an
OBJECTIVE counter: a run of rejections by the koryto without any acceptance = signal "this
koryto has rotted". In that case escalate to a web-arbiter (it decides WHO is right) instead
of blindly trusting the koryto.

Lightweight, no dependencies. Holds state (a window of recent verdicts) and says WHEN to
stop trusting the koryto and reach for an arbiter.

Usage:
    from gatecat.stagnation import StagnationMonitor

    mon = StagnationMonitor(window=5, refute_ratio=0.8)
    for q, ans in stream:
        kv = koryto.verify(q, ans)
        st = mon.observe(kv)            # pass in the koryto verdict
        if st.koryto_suspect:
            # the koryto rejects too much without any acceptance → it may have rotted itself
            # → do NOT block on the koryto, escalate to a web-arbiter
            ...
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class StagnationState:
    """Snapshot of the monitor state after observing a single verdict."""
    koryto_suspect: bool          # whether the koryto looks rotted (too many rejections without progress)
    refute_streak: int            # how many rejections IN A ROW (hard/soft combined)
    soft_refute_streak: int       # how many SOFT rejections (lookup, needs_arbiter) in a row — these are the ones that signal stale
    window_refute_ratio: float    # fraction of rejections in the window
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "koryto_suspect": self.koryto_suspect,
            "refute_streak": self.refute_streak,
            "soft_refute_streak": self.soft_refute_streak,
            "window_refute_ratio": round(self.window_refute_ratio, 3),
            "reason": self.reason,
        }


class StagnationMonitor:
    """Koryto state counter: detects "the koryto has rotted" via a run of rejections without progress.

    The signal deliberately focuses on SOFT rejections (lookup, needs_arbiter=True),
    because those are the ones that can be stale. HARD rejections (exec/calc) are a genuine
    confident-wrong of the river — a run of them is NOT suspicious toward the koryto (the
    interpreter does not get it wrong).

    Args:
        window: size of the window of recent verdicts (default 5).
        refute_ratio: fraction of rejections in the window above which the koryto is suspect (default 0.8).
        soft_streak_trigger: how many SOFT rejections in a row = immediately suspect (default 3).
                             Soft = lookup/needs_arbiter (potentially stale database).
    """

    def __init__(self, *, window: int = 5, refute_ratio: float = 0.8,
                 soft_streak_trigger: int = 3):
        self.window = max(2, int(window))
        self.refute_ratio = float(refute_ratio)
        self.soft_streak_trigger = max(1, int(soft_streak_trigger))
        self._recent: deque = deque(maxlen=self.window)
        self._refute_streak = 0
        self._soft_refute_streak = 0

    def observe(self, verdict: Any) -> StagnationState:
        """Pass in a KorytoVerdict (or dict-like with .verdict/.hard/.needs_arbiter).
        Returns a StagnationState saying whether the koryto is suspect."""
        v = self._verdict_str(verdict)
        is_refute = (v == "refute")
        is_soft = is_refute and self._is_soft(verdict)

        # the window holds (verdict, is_soft) — so the window-ratio can tell hard from soft
        self._recent.append((v, is_soft))

        if is_refute:
            self._refute_streak += 1
        else:
            self._refute_streak = 0
        if is_soft:
            self._soft_refute_streak += 1
        else:
            self._soft_refute_streak = 0

        refutes = sum(1 for vv, _ in self._recent if vv == "refute")
        soft_refutes = sum(1 for vv, sf in self._recent if vv == "refute" and sf)
        ratio = refutes / len(self._recent) if self._recent else 0.0

        # SUSPECT when:
        #  (a) a run of SOFT rejections (lookup/needs_arbiter) >= threshold — stale database?
        #  (b) the window is full, high rejection fraction, AND it contains SOFT rejections.
        # KEY: purely HARD rejections (exec/calc) NEVER make the koryto suspect —
        # the interpreter does not get it wrong, that is a genuine confident-wrong of the river (not a rotted koryto).
        suspect = False
        reason = ""
        if self._soft_refute_streak >= self.soft_streak_trigger:
            suspect = True
            reason = (f"{self._soft_refute_streak} soft rejections in a row (lookup/needs_arbiter) "
                      f"→ the koryto may be stale; escalate to a web-arbiter")
        elif (len(self._recent) >= self.window and ratio >= self.refute_ratio
              and soft_refutes > 0):
            suspect = True
            reason = (f"rejection fraction {ratio:.0%} in window {self.window} ≥ {self.refute_ratio:.0%} "
                      f"({soft_refutes} soft) → no progress despite rejections; check whether the koryto has rotted")

        return StagnationState(
            koryto_suspect=suspect,
            refute_streak=self._refute_streak,
            soft_refute_streak=self._soft_refute_streak,
            window_refute_ratio=ratio,
            reason=reason,
        )

    def reset(self) -> None:
        self._recent.clear()
        self._refute_streak = 0
        self._soft_refute_streak = 0

    # --- adapters for various verdict shapes ---
    @staticmethod
    def _verdict_str(verdict: Any) -> str:
        if hasattr(verdict, "verdict"):
            return str(verdict.verdict)
        if isinstance(verdict, dict):
            return str(verdict.get("verdict", "unknown"))
        return str(verdict)

    @staticmethod
    def _is_soft(verdict: Any) -> bool:
        """Soft rejection = lookup/needs_arbiter (potentially stale), NOT exec/calc (hard)."""
        if hasattr(verdict, "needs_arbiter"):
            # hard (exec/calc) has hard=True; soft (lookup) has needs_arbiter=True
            hard = bool(getattr(verdict, "hard", False))
            return bool(getattr(verdict, "needs_arbiter", False)) or not hard
        if isinstance(verdict, dict):
            hard = bool(verdict.get("hard", False))
            return bool(verdict.get("needs_arbiter", False)) or not hard
        return True  # unknown shape → treat as soft (more cautious)
