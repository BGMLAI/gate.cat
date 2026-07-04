"""Shared guard used by every framework adapter.

One mechanism: adapters never re-implement verification - they flatten the
action to text (:func:`flatten_call`), call the engine through the seam,
log the decision (D2), and raise :class:`ActionVetoed` on block.
Fail-closed: an unavailable or erroring engine blocks, it never allows.

A8 (shadow mode): the DEFAULT is enforce (block == block). Shadow mode is an
opt-in that turns every block into a logged-but-allowed decision - it lowers
adoption friction and harvests veto-stories, but it is NOT the product's
identity. A tool that advertises "an error is a block" must not ship defaulting
to a mode that blocks nothing, so shadow is never on unless a caller (or the
``CACHEBACK_VETO_SHADOW`` env var) explicitly asks for it.
"""

from __future__ import annotations

import functools
import os
from typing import Any, Callable, Sequence

from cacheback.integrations._engine import (
    ActionVetoed,
    Decision,
    EngineUnavailable,
    evaluate,
)
from cacheback.integrations._log import ascii_safe, log_decision
from cacheback.integrations.policies import DOGFOOD_DEFAULTS, Policy

_ACTION_LIMIT = 2000
_GUARDED_ATTR = "_cacheback_guarded"
_SHADOW_ENV = "CACHEBACK_VETO_SHADOW"
# Truthy spellings accepted for the env var; everything else (incl. unset) is
# enforce. Fail-safe direction: an unrecognized value must NOT silently disable
# blocking, so we allow-list the "on" tokens rather than blocklist the "off" ones.
_SHADOW_ON = frozenset({"1", "true", "yes", "on", "shadow"})


def shadow_enabled(explicit: bool | None = None) -> bool:
    """Resolve shadow mode. An explicit caller argument wins; otherwise the
    ``CACHEBACK_VETO_SHADOW`` env var decides; default is enforce (False).
    """
    if explicit is not None:
        return explicit
    return os.environ.get(_SHADOW_ENV, "").strip().lower() in _SHADOW_ON


def flatten_call(name: str, args: tuple, kwargs: dict) -> str:
    """Flatten a tool call into the single evaluable string the gate matches.

    Shared by every adapter so the security-relevant contract (how a call
    becomes deny-matchable text) can never drift between frameworks.
    """
    parts = [name]
    parts.extend(repr(a) for a in args)
    parts.extend(f"{k}={v!r}" for k, v in kwargs.items())
    return " ".join(parts)[:_ACTION_LIMIT]


def _raise_block(source: str, reason: str, action: str, policy: str | None) -> ActionVetoed:
    """Log a block (D2) and build the ASCII-safe exception (D1). Single
    place so every block path - engine-returned, engine-raised, fail-closed -
    is audited and cp1252-safe identically."""
    log_decision(source=source, decision="block", reason=reason, context=action, policy=policy)
    return ActionVetoed(ascii_safe(reason))


def _shadow_allow(source: str, reason: str, action: str, policy: str | None) -> None:
    """A8: record a would-be block that shadow mode is letting through.

    Distinct ``decision`` value (``shadow_block``) so B2 adjudication can tell
    real allows from actions that WOULD have been blocked in enforce mode -
    the raw material for a "what would we have caught" report before a team
    flips enforcement on.
    """
    log_decision(
        source=source,
        decision="shadow_block",
        reason=f"SHADOW (would block): {reason}",
        context=action,
        policy=policy,
    )


def check_action(
    source: str,
    action: str,
    policies: Sequence[Policy] = DOGFOOD_DEFAULTS,
    *,
    shadow: bool | None = None,
) -> Decision:
    """Evaluate *action*; log every decision; raise :class:`ActionVetoed` if
    blocked. Returns the (allowing) decision so callers can inspect it.

    A8: if shadow mode is on (``shadow=True``, or ``CACHEBACK_VETO_SHADOW``
    truthy), a block is logged as ``shadow_block`` and the action is ALLOWED
    instead of raising. Default is enforce - shadow never turns on implicitly.
    """
    shadow_on = shadow_enabled(shadow)
    try:
        decision = evaluate(source, action, policies)
    except EngineUnavailable as exc:
        reason = f"veto engine unavailable (fail-closed): {exc}"
        if shadow_on:
            _shadow_allow(source, reason, action, None)
            return Decision(blocked=False, reason=f"SHADOW: {ascii_safe(reason)}", policy=None)
        raise _raise_block(source, reason, action, None) from exc
    except ActionVetoed as exc:
        # Engine signalled a block by raising (documented seam behavior). Still
        # audit it and ASCII-escape the reason - otherwise this block escapes
        # the D2 log and a non-ASCII engine reason crashes cp1252 consoles.
        reason = f"VETO [gate]: {str(exc) or 'blocked by veto gate'}"
        if shadow_on:
            _shadow_allow(source, reason, action, None)
            return Decision(blocked=False, reason=f"SHADOW: {ascii_safe(reason)}", policy=None)
        raise _raise_block(source, reason, action, None) from exc
    except Exception as exc:
        reason = f"veto evaluation error (fail-closed): {type(exc).__name__}: {exc}"
        if shadow_on:
            _shadow_allow(source, reason, action, None)
            return Decision(blocked=False, reason=f"SHADOW: {ascii_safe(reason)}", policy=None)
        raise _raise_block(source, reason, action, None) from exc

    if decision.blocked:
        reason = f"VETO [{decision.policy or 'gate'}]: {decision.reason}"
        if shadow_on:
            _shadow_allow(source, reason, action, decision.policy)
            return Decision(
                blocked=False, reason=f"SHADOW: {ascii_safe(reason)}", policy=decision.policy
            )
        raise _raise_block(source, reason, action, decision.policy)
    log_decision(
        source=source,
        decision="allow",
        reason=decision.reason,
        policy=decision.policy,
        context=action,
    )
    return decision


def guard_callable(
    fn: Callable,
    policies: Sequence[Policy] = DOGFOOD_DEFAULTS,
    *,
    name: str | None = None,
    source: str = "guard",
    shadow: bool | None = None,
) -> Callable:
    """Wrap any tool callable so the gate runs before it executes.

    Framework-agnostic (AutoGen, plain functions, anything with a callable
    interface); framework adapters build on it. Idempotent-safe: the wrapper
    is tagged so higher-level helpers can skip double-wrapping.

    A8: ``shadow`` is forwarded to :func:`check_action` (default enforce).
    """
    tool_name = name or getattr(fn, "name", None) or getattr(fn, "__name__", "tool")

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        check_action(source, flatten_call(tool_name, args, kwargs), policies, shadow=shadow)
        return fn(*args, **kwargs)

    setattr(wrapper, _GUARDED_ATTR, True)
    return wrapper
