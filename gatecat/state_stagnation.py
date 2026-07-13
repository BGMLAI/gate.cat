"""state_stagnation — stagnation-by-STATE: the deterministic no-progress detector.

Productized from the user's proven prototype (``scripts/stagnation_state_probe.py``
+ ``scratchpad/stagnation_detector.py``, REJESTR_PRAWD 2026-06-26/27). This is the
engine home of that ``StateStagnationDetector`` — same class name, same
``update() -> reason`` contract, same signals — plus the ``cost_without_progress``
signal its own docstring promised but the probe left unimplemented.

Two stagnation layers ship in gate.cat; do NOT confuse them:

  - ``gatecat.stagnation.StagnationMonitor`` watches the KORYTO (the retrieval
    channel): a run of rejections without acceptance = "the database has rotted".
  - ``StateStagnationDetector`` (HERE) watches the AGENT'S STATE across steps: it
    keeps running but the state does not move — the same action, the same error,
    an unchanged diff, or cost climbing with no gain. Deterministic, no model.

WHY IT IS NOT REDUNDANT with a disagreement/river gate (measured, the probe's
whole point): on a coding agent an error is often CONFIDENT-wrong — the model
re-proposes the same bad fix with zero sample scatter, so a probabilistic
disagreement gate (``cacheback.agent.GatedLoop``) sees nothing to stop. A
deterministic STATE comparison (same tool-call / same diff / same test error /
cost up without progress) catches that loop regardless of the model's confidence.
In the probe the disagreement gate ran to ``max_steps`` while this detector
stopped the confident loop on the 2nd repeat.

Signals (each threshold configurable; ``update`` returns the reason of the FIRST
that trips, else ``None``):
  - repeat_action:         the same ``action`` string N+1 times in a row
  - no_state_change:       the ``state_repr`` fingerprint unchanged N+1 steps
  - repeat_error:          the same ``error`` message N+1 times in a row
  - cost_without_progress: ``cost`` incurred for N+1 steps while a declared
                           ``progress`` metric never improves (needs both args)

Advisory, not a hard block — a runaway agent is wasted budget, not an
irreversible action. Zero dependencies; holds only a few streak counters.

Usage:
    from gatecat.state_stagnation import StateStagnationDetector

    det = StateStagnationDetector(max_repeat_action=2, max_no_change=2)
    for step in agent_loop():
        reason = det.update(action=step.tool_call, state_repr=step.diff,
                            error=step.error, cost=step.cost, progress=step.tests_passing)
        if reason:
            pause_and_report(reason)   # turn back / escalate; the loop is not moving
            break
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Callable, Optional

__all__ = ["StateStagnationDetector"]


def _higher_is_better(new: float, old: float) -> bool:
    return new > old


@dataclass
class StateStagnationDetector:
    """Deterministic no-progress detector over an agent's action stream.

    Args:
        max_repeat_action: identical ``action`` strings in a row before it trips
            (default 2 -> the 3rd identical action returns a reason).
        max_no_change: steps with an unchanged ``state_repr`` fingerprint before
            it trips (default 2).
        max_repeat_error: identical ``error`` messages in a row before it trips
            (default 2).
        max_cost_without_progress: steps that incur ``cost`` without the declared
            ``progress`` metric improving before it trips (default 3). Inactive
            unless BOTH ``cost`` and ``progress`` are supplied to ``update``.
        goal_better: for the progress metric, whether a value is "better" than the
            previous best. Default: higher is better (e.g. passing tests). Pass
            ``lambda new, old: new < old`` when LOWER is better (e.g. failing
            tests, lint errors, cost).
        min_progress_delta: how much ``progress`` must move to count as improving
            (default 0.0 -> any strict improvement counts).
    """

    max_repeat_action: int = 2
    max_no_change: int = 2
    max_repeat_error: int = 2
    max_cost_without_progress: int = 3
    goal_better: Callable[[float, float], bool] = _higher_is_better
    min_progress_delta: float = 0.0

    # --- internal streak state (not constructor args) ---
    _last_action: Optional[str] = field(default=None, repr=False)
    _action_streak: int = field(default=0, repr=False)
    _last_state_hash: Optional[str] = field(default=None, repr=False)
    _no_change_streak: int = field(default=0, repr=False)
    _last_error: Optional[str] = field(default=None, repr=False)
    _error_streak: int = field(default=0, repr=False)
    _best_progress: Optional[float] = field(default=None, repr=False)
    _cost_stall_streak: int = field(default=0, repr=False)

    def update(
        self,
        *,
        action: str = "",
        state_repr: str = "",
        error: str = "",
        cost: Optional[float] = None,
        progress: Optional[float] = None,
    ) -> Optional[str]:
        """Record one step; return the reason of the first tripped signal, else None.

        action:     the step's tool-call / command (repeat detection).
        state_repr: an OPTIONAL fingerprint of the resulting state (a diff, a test
                    output, a hash) — progress requires it to CHANGE.
        error:      an OPTIONAL error message for this step (repeat detection).
        cost:       an OPTIONAL per-step cost (tokens / dollars / seconds).
        progress:   an OPTIONAL declared metric that should improve (e.g. passing
                    tests). With ``cost``, drives the cost-without-progress signal.
        """
        # 1) repeated tool-call / command
        if action:
            if action == self._last_action:
                self._action_streak += 1
            else:
                self._action_streak = 0
                self._last_action = action
            if self._action_streak >= self.max_repeat_action:
                return f"repeat_action x{self._action_streak + 1}: {action[:60]}"

        # 2) state fingerprint not moving (same diff / output)
        if state_repr:
            h = hashlib.sha1(state_repr.encode("utf-8", "ignore")).hexdigest()[:12]
            if h == self._last_state_hash:
                self._no_change_streak += 1
            else:
                self._no_change_streak = 0
                self._last_state_hash = h
            if self._no_change_streak >= self.max_no_change:
                return f"no_state_change x{self._no_change_streak + 1}"

        # 3) the same error over and over
        if error:
            if error == self._last_error:
                self._error_streak += 1
            else:
                self._error_streak = 0
                self._last_error = error
            if self._error_streak >= self.max_repeat_error:
                return f"repeat_error x{self._error_streak + 1}: {error[:60]}"

        # 4) cost climbing without the goal metric improving (needs both signals).
        #    Promised by the prototype's docstring, implemented here.
        if cost is not None and progress is not None:
            if self._best_progress is None:
                improved = True
            else:
                improved = (self.goal_better(progress, self._best_progress)
                            and abs(progress - self._best_progress) >= self.min_progress_delta)
            if improved:
                self._best_progress = progress
                self._cost_stall_streak = 0
            elif cost > 0:
                self._cost_stall_streak += 1
                if self._cost_stall_streak >= self.max_cost_without_progress:
                    return (f"cost_without_progress x{self._cost_stall_streak}: "
                            f"spend continues, metric stuck at {self._best_progress}")

        return None

    def reset(self) -> None:
        """Forget all streak state (e.g. after a human turns the agent back)."""
        self._last_action = None
        self._action_streak = 0
        self._last_state_hash = None
        self._no_change_streak = 0
        self._last_error = None
        self._error_streak = 0
        self._best_progress = None
        self._cost_stall_streak = 0

    def snapshot(self) -> dict:
        """Current streak counters — for logging / a dashboard, not a decision."""
        return {
            "action_streak": self._action_streak,
            "no_change_streak": self._no_change_streak,
            "error_streak": self._error_streak,
            "cost_stall_streak": self._cost_stall_streak,
            "best_progress": self._best_progress,
        }
