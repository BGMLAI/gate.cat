"""LOCAL, FREE proxy safety: per-session budget cap + loop-guard (stagnation).

Both run IN-PROCESS on the proxy and are the LOCAL kill/cap the founder ruled
must never be paywalled. They are honest about scope:

  * The budget cap accumulates ``completion_tokens * per-model price`` per
    session key into a running USD total; once it exceeds the configured budget
    the proxy DENIES the next action (returns a veto completion). It does NOT
    reach out and kill an external process — it halts by refusing to serve the
    next call for traffic routed THROUGH this proxy.
  * The loop-guard feeds each request's flattened tool-call / a hash of the
    assistant message to a per-session :class:`StateStagnationDetector`; a trip
    means "the agent keeps proposing the same no-progress action". It halts the
    same way (deny next), or only warns, per config.

Session key: the ``X-Gatecat-Session`` header, else the client API key. State is
kept in-process (a plain dict); a proxy restart resets counters (acceptable for
a local, best-effort cap — the managed/remote budget tracking is the paid side).

STREAMING NOTE (feasibility scout): a non-streaming upstream response carries
``usage.completion_tokens`` directly. For a STREAMING response the proxy forces
``stream_options={"include_usage": true}`` on the upstream request so the final
chunk carries a usage block; if the provider still omits it we fall back to an
honest token ESTIMATE (chars/4). The estimate is marked so a caller can tell.
"""
from __future__ import annotations

import hashlib
import threading
from typing import Optional


def price_for_model(model: str, prices: dict) -> float:
    """USD per 1K completion tokens for *model*. Exact match, then a prefix match
    (so "gpt-4o-2024-08-06" uses the "gpt-4o" price), else the "default"."""
    if not model:
        return float(prices.get("default", 0.0))
    if model in prices:
        return float(prices[model])
    best = None
    for name, price in prices.items():
        if name == "default":
            continue
        if model.startswith(name) and (best is None or len(name) > len(best[0])):
            best = (name, price)
    return float(best[1]) if best else float(prices.get("default", 0.0))


def cost_of(completion_tokens: int, model: str, prices: dict) -> float:
    """Dollar cost of one completion (tokens * per-1k price)."""
    return (max(0, int(completion_tokens or 0)) / 1000.0) * price_for_model(model, prices)


def estimate_completion_tokens(text: str) -> int:
    """Honest fallback token estimate when a streaming provider omits usage:
    ~4 chars/token. Marked as an estimate by the caller."""
    return max(1, len(text or "") // 4)


class LocalGuardState:
    """Per-session in-process budget + stagnation state. Thread-safe."""

    def __init__(self):
        self._spend: dict = {}          # session -> USD accumulated
        self._detectors: dict = {}      # session -> StateStagnationDetector
        self._lock = threading.Lock()

    # ---- budget ----------------------------------------------------------
    def add_spend(self, session: str, usd: float) -> float:
        with self._lock:
            total = self._spend.get(session, 0.0) + max(0.0, float(usd))
            self._spend[session] = total
            return total

    def spend(self, session: str) -> float:
        with self._lock:
            return self._spend.get(session, 0.0)

    def over_budget(self, session: str, budget_usd: float) -> bool:
        """True once accumulated spend for the session exceeds the budget.
        budget_usd <= 0 disables the cap (never over budget)."""
        if budget_usd is None or budget_usd <= 0:
            return False
        return self.spend(session) > budget_usd

    # ---- stagnation ------------------------------------------------------
    def observe_action(self, session: str, action: str, max_repeat: int) -> Optional[str]:
        """Feed one action to the session's detector; return the trip reason or
        None. Fail-safe: any error returns None so the loop-guard can never turn
        an allow into a crash."""
        if not action:
            return None
        try:
            from gatecat.state_stagnation import StateStagnationDetector
        except Exception:
            return None
        try:
            with self._lock:
                det = self._detectors.get(session)
                if det is None:
                    det = StateStagnationDetector(
                        max_repeat_action=max_repeat,
                        max_repeat_error=max_repeat)
                    self._detectors[session] = det
            return det.update(action=action)
        except Exception:
            return None

    def reset(self, session: Optional[str] = None) -> None:
        with self._lock:
            if session is None:
                self._spend.clear()
                self._detectors.clear()
            else:
                self._spend.pop(session, None)
                self._detectors.pop(session, None)


def session_action_signature(resp_data: dict) -> str:
    """A stable 'action' string for the loop-guard from an upstream completion:
    the flattened tool-call if present, else a hash of the assistant text. Same
    tool-call / same answer twice in a row = no progress."""
    try:
        choice = (resp_data.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        tcs = msg.get("tool_calls") or []
        if tcs:
            parts = []
            for tc in tcs:
                fn = (tc or {}).get("function") or {}
                args = fn.get("arguments", "")
                if not isinstance(args, str):
                    import json as _json
                    try:
                        args = _json.dumps(args, sort_keys=True)
                    except Exception:
                        args = str(args)
                parts.append(f"{fn.get('name', '')}({args})")
            return "tool:" + "|".join(parts)
        content = msg.get("content") or ""
        return "text:" + hashlib.sha256(content.encode("utf-8", "ignore")).hexdigest()[:16]
    except Exception:
        return ""
