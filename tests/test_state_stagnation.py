"""Tests for StateStagnationDetector — the deterministic no-progress detector.

Productized from the user's proven prototype. Distinct from the koryto
StagnationMonitor (which watches the retrieval channel). The contract: update()
returns the reason string of the first tripped signal, else None; a genuinely
progressing agent (novel actions, changing state, an improving metric) never
trips it.
"""

from __future__ import annotations

from gatecat.state_stagnation import StateStagnationDetector


# ---------- the prototype's headline case: a CONFIDENT loop ----------

def test_confident_repeat_loop_is_caught_deterministically():
    # same action + same error every step, zero scatter (a disagreement gate is
    # blind to this). The detector must stop it fast, on the 3rd identical action.
    det = StateStagnationDetector(max_repeat_action=2, max_no_change=2, max_repeat_error=2)
    action = "edit_file(solution.py, 'return a - b')"
    err = "AssertionError: add(2,3) expected 5 got -1"
    # original + 2 repeats: trips on the 2nd repeat (3rd occurrence), as the probe
    # measured ("stop na 2. powtorzeniu"). It must not run to max_steps.
    assert det.update(action=action, state_repr="return a - b", error=err) is None
    assert det.update(action=action, state_repr="return a - b", error=err) is None
    r3 = det.update(action=action, state_repr="return a - b", error=err)
    assert r3 is not None
    assert "repeat_action" in r3 or "no_state_change" in r3


# ---------- each signal in isolation ----------

def test_repeat_action_trips_on_third():
    det = StateStagnationDetector(max_repeat_action=2)
    assert det.update(action="ls") is None          # streak 0
    assert det.update(action="ls") is None           # streak 1
    r = det.update(action="ls")                       # streak 2 -> trip
    assert r is not None and "repeat_action" in r
    assert "x3" in r


def test_no_state_change_trips():
    det = StateStagnationDetector(max_no_change=2)
    assert det.update(action="a", state_repr="SAME") is None
    assert det.update(action="b", state_repr="SAME") is None   # streak 1
    r = det.update(action="c", state_repr="SAME")               # streak 2 -> trip
    assert r is not None and "no_state_change" in r


def test_repeat_error_trips():
    det = StateStagnationDetector(max_repeat_error=2)
    e = "ImportError: no module named foo"
    assert det.update(action="a", error=e) is None
    assert det.update(action="b", error=e) is None      # streak 1
    r = det.update(action="c", error=e)                  # streak 2 -> trip
    assert r is not None and "repeat_error" in r


# ---------- cost_without_progress (the completed 4th signal) ----------

def test_cost_without_progress_trips_when_metric_flat():
    det = StateStagnationDetector(max_cost_without_progress=3)
    # distinct actions so repeat_action never fires; cost each step, metric flat
    r = None
    for i in range(5):
        r = det.update(action=f"attempt-{i}", cost=0.02, progress=3)  # never improves
    assert r is not None and "cost_without_progress" in r


def test_cost_with_improving_metric_never_trips():
    det = StateStagnationDetector(max_cost_without_progress=3)
    for i, g in enumerate([1, 2, 3, 4, 5, 6]):
        r = det.update(action=f"attempt-{i}", cost=0.02, progress=g)  # climbs
        assert r is None


def test_cost_signal_lower_is_better():
    det = StateStagnationDetector(max_cost_without_progress=3,
                                  goal_better=lambda new, old: new < old)
    # failing tests DECREASE -> progress -> never trips
    for i, g in enumerate([10, 8, 5, 2, 0]):
        assert det.update(action=f"fix-{i}", cost=0.01, progress=g) is None
    # now flat at 0 -> cost keeps burning -> trips
    r = None
    for i in range(4):
        r = det.update(action=f"stuck-{i}", cost=0.01, progress=0)
    assert r is not None and "cost_without_progress" in r


def test_cost_signal_inactive_without_both_args():
    det = StateStagnationDetector(max_cost_without_progress=2)
    # cost but no progress metric -> signal cannot judge -> never trips on it
    for i in range(6):
        assert det.update(action=f"x-{i}", cost=1.0) is None


# ---------- a progressing agent never trips ----------

def test_novel_actions_with_changing_state_never_trip():
    det = StateStagnationDetector()
    for i in range(12):
        r = det.update(action=f"edit file{i}", state_repr=f"diff-{i}",
                       error="", cost=0.01, progress=i)
        assert r is None


# ---------- reset + snapshot ----------

def test_reset_clears_streaks():
    det = StateStagnationDetector(max_repeat_action=2)
    det.update(action="same")
    det.update(action="same")
    det.reset()
    assert det.update(action="same") is None    # streak restarted
    assert det.snapshot()["action_streak"] == 0


def test_snapshot_keys():
    det = StateStagnationDetector()
    det.update(action="x", error="e")
    s = det.snapshot()
    assert set(s) == {"action_streak", "no_change_streak", "error_streak",
                      "cost_stall_streak", "best_progress"}
