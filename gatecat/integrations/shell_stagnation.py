"""FREE-CORE stagnation, local half (2026-07-12): wire the deterministic
:class:`gatecat.state_stagnation.StateStagnationDetector` into the gated shell so
a stuck agent that keeps routing the SAME no-progress command through the shell
gets a VISIBLE warning (and, opt-in, a soft halt).

HONEST SCOPE (do NOT oversell): this warns on repeated no-progress commands that
pass THROUGH the gated shell. It does NOT reach out and kill an external process,
and it cannot see progress the shell never observes. It is "Detect + Alert" for
the shell's own command stream, not a circuit-breaker that stops a runaway agent
mid-flight. Halt is OFF by default (warn-only) so legit retries / polling loops
are not false-tripped; set GATECAT_STAGNATION_HALT=1 to turn the soft halt on.

The detector's streak state is persisted per-session on disk
(~/.gatecat/stagnation-<session>.json, session from GATECAT_SESSION or a stable
default) so it survives across the separate short-lived `gatecat-shell -c`
processes a real agent spawns - one process per command means an in-memory
detector would forget everything between steps.

Everything here is best-effort and fail-safe: any error leaves the gate's
verdict untouched (a stagnation-tracking bug must never turn an allow into a
crash or a block).
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Optional

_SESSION_ENV = "GATECAT_SESSION"
_HALT_ENV = "GATECAT_STAGNATION_HALT"
_DIR_ENV = "GATECAT_STAGNATION_DIR"  # test isolation for the streak files
_DEFAULT_SESSION = "default"
_MAX_REPEAT = 2  # the 3rd identical no-progress command trips (matches detector default)
_TRUTHY = frozenset({"1", "true", "yes", "on"})


def _session() -> str:
    raw = os.environ.get(_SESSION_ENV, "").strip() or _DEFAULT_SESSION
    # keep it filesystem-safe (a session id may come from an agent/run label).
    return re.sub(r"[^A-Za-z0-9_.-]", "_", raw)[:80] or _DEFAULT_SESSION


def _state_dir() -> Path:
    env = os.environ.get(_DIR_ENV)
    return Path(env) if env else Path.home() / ".gatecat"


def _streak_file(session: str) -> Path:
    return _state_dir() / f"stagnation-{session}.json"


def halt_enabled() -> bool:
    return os.environ.get(_HALT_ENV, "").strip().lower() in _TRUTHY


def _load(session: str) -> dict:
    try:
        return json.loads(_streak_file(session).read_text(encoding="ascii"))
    except (OSError, ValueError):
        return {}


def _save(session: str, data: dict) -> None:
    try:
        p = _streak_file(session)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data), encoding="ascii")
    except OSError:
        pass


def observe(command: str, *, error: str = "") -> Optional[str]:
    """Feed one gated command (and an optional prior error) to a disk-persisted
    per-session detector. Returns the stagnation reason string on a trip, else
    None. Rebuilds the detector from the persisted streak counters each call so
    it works across the one-process-per-command shell model.

    Fail-safe: any error returns None (no trip) so it can never break the gate.
    """
    try:
        from gatecat.state_stagnation import StateStagnationDetector
    except Exception:
        return None
    try:
        session = _session()
        st = _load(session)
        det = StateStagnationDetector(max_repeat_action=_MAX_REPEAT,
                                      max_repeat_error=_MAX_REPEAT)
        # restore streak counters from disk (the fields are private but stable).
        det._last_action = st.get("last_action")
        det._action_streak = int(st.get("action_streak", 0))
        det._last_error = st.get("last_error")
        det._error_streak = int(st.get("error_streak", 0))
        reason = det.update(action=command or "", error=error or "")
        _save(session, {
            "last_action": det._last_action,
            "action_streak": det._action_streak,
            "last_error": det._last_error,
            "error_streak": det._error_streak,
            "updated_at": int(time.time()),
        })
        return reason
    except Exception:
        return None


def surface(command: str, *, error: str = "", source: str = "gatecat_shell") -> Optional[str]:
    """Observe a command; on a stagnation trip print a VISIBLE stderr warning and
    log it (decision='stagnation', so it inherits the dashboard + E2EE cloud
    pipeline for free). Returns the reason if it tripped, else None. The caller
    decides whether to halt (see :func:`halt_enabled`)."""
    reason = observe(command, error=error)
    if not reason:
        return None
    # count of repeats from the reason (e.g. "repeat_action x3: ...").
    m = re.search(r"x(\d+)", reason)
    n = m.group(1) if m else "?"
    msg = (f"gate.cat: no progress for {n} steps - possible stuck loop "
           f"({reason[:80]})")
    try:
        sys.stderr.write(msg + "\n")
        sys.stderr.flush()
    except Exception:
        pass
    try:
        from gatecat.integrations._log import log_decision
        log_decision(source=source, decision="stagnation", reason=reason,
                     policy=None, context=command)
    except Exception:
        pass
    return reason


def reset(session: Optional[str] = None) -> None:
    """Forget the per-session streak (e.g. after a human turns the agent back)."""
    try:
        _streak_file(session or _session()).unlink()
    except OSError:
        pass
