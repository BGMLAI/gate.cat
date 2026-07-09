"""GATECAT_EXTRA_POLICIES — load operator-supplied policy packs into the gate.

Why this exists (fail-closed, security tool): the Claude Code hook and the
proxy hard-code ``DOGFOOD_DEFAULTS`` in their ``check_action`` call. That is
the STRONGEST enforcement point — a PreToolUse block runs *before* the command
executes — but it had no seam for the free community packs
(``gatecat_packs.fintech`` & co.). A pack therefore only worked through the SDK,
never in the hook: an operator who dropped ``fintech.py`` next to their agent
and expected refunds to be blocked got NO protection in the mode that matters
most. This module adds that seam.

Set a comma-separated list of importable modules::

    GATECAT_EXTRA_POLICIES=gatecat_packs.fintech,mycompany.policies

From each module we collect :class:`~gatecat.integrations.policies.Policy`
objects by convention:

  * an explicit ``POLICIES`` attribute (a list/tuple of Policy), and/or
  * any module-level attribute whose name ends in ``_PACK`` (e.g. ``FINTECH_PACK``).

Every collected object MUST be a real ``Policy``.

FAIL-CLOSED CONTRACT — this is the whole point. A security tool must never run
*without* a policy the operator believes is enforced, so ANY of these raises
:class:`ExtraPolicyError`:

  * a named module cannot be imported (typo, missing dep, import-time crash),
  * a collected attribute is not a list/tuple of Policy,
  * a named module exports NO policies at all (nothing to load is not the same
    as "silently fine" — a named-but-empty pack is almost certainly a mistake).

Callers turn that into a hard stop: the hook exits 2 (BLOCK) and the proxy
refuses to start. We NEVER swallow it and fall back to ``DOGFOOD_DEFAULTS`` —
that silent gap is exactly what this guards against.
"""

from __future__ import annotations

import importlib
import os
from typing import Iterable

from gatecat.integrations.policies import DOGFOOD_DEFAULTS, Policy

ENV_VAR = "GATECAT_EXTRA_POLICIES"
_POLICIES_ATTR = "POLICIES"
_PACK_SUFFIX = "_PACK"


class ExtraPolicyError(Exception):
    """A ``GATECAT_EXTRA_POLICIES`` module could not be imported or yielded a
    non-Policy object. Fail-closed: callers BLOCK / refuse to start rather than
    run with a security gap the operator thinks is covered."""


def _as_policy_list(value: object, module_name: str, attr: str) -> list[Policy]:
    """Coerce one collected attribute into a validated list of ``Policy``.

    A bare ``Policy`` is tolerated (wrapped in a one-element list); anything that
    is not a Policy — or a list/tuple containing a non-Policy — is a fail-closed
    error naming exactly where it sat, so the operator can fix the offending
    attribute instead of guessing.
    """
    if isinstance(value, Policy):
        return [value]
    if not isinstance(value, (list, tuple)):
        raise ExtraPolicyError(
            f"{module_name}.{attr} is {type(value).__name__}, expected a "
            f"list/tuple of gatecat Policy objects"
        )
    out: list[Policy] = []
    for i, item in enumerate(value):
        if not isinstance(item, Policy):
            raise ExtraPolicyError(
                f"{module_name}.{attr}[{i}] is {type(item).__name__}, not a "
                f"gatecat Policy (import Policy from gatecat.integrations.policies)"
            )
        out.append(item)
    return out


def _collect_from_module(module: object, module_name: str) -> list[Policy]:
    """Collect ``Policy`` objects from an imported module by the pack convention:
    an explicit ``POLICIES`` list plus every ``*_PACK`` attribute.

    De-dupes by object identity so a module that exposes both ``FOO_PACK`` and a
    ``POLICIES`` (or aggregate) referencing the same objects does not
    double-count. Identity — not a ``set`` of the policies themselves — because
    ``Policy`` carries a dict field and so is not hashable.
    """
    attrs: list[str] = []
    if hasattr(module, _POLICIES_ATTR):
        attrs.append(_POLICIES_ATTR)
    # sorted for a deterministic order across runs/hosts (dir() order is stable
    # but sorting makes the loaded-policy order independent of definition order).
    attrs.extend(
        sorted(
            n for n in dir(module)
            if n.endswith(_PACK_SUFFIX) and n != _POLICIES_ATTR
        )
    )

    collected: list[Policy] = []
    seen: set[int] = set()
    for attr in attrs:
        for pol in _as_policy_list(getattr(module, attr), module_name, attr):
            if id(pol) in seen:
                continue
            seen.add(id(pol))
            collected.append(pol)
    return collected


def _split_modules(raw: str) -> list[str]:
    """Comma-separated module list -> trimmed names, empties dropped."""
    return [m.strip() for m in raw.split(",") if m.strip()]


def load_extra_policies(env: "dict | None" = None) -> list[Policy]:
    """Import every module named in ``GATECAT_EXTRA_POLICIES`` and return the
    ``Policy`` objects they export.

    Empty/unset env → ``[]``. Fail-closed: raises :class:`ExtraPolicyError` on
    any unimportable module, non-Policy object, or a named module that exports
    no policies at all. ``env`` defaults to ``os.environ`` (override for tests).
    """
    environ = os.environ if env is None else env
    raw = (environ.get(ENV_VAR) or "").strip()
    if not raw:
        return []

    extra: list[Policy] = []
    for module_name in _split_modules(raw):
        try:
            module = importlib.import_module(module_name)
        except BaseException as exc:  # noqa: BLE001 — a broken import must not silently drop policies
            raise ExtraPolicyError(
                f"cannot import policy module {module_name!r} named in "
                f"{ENV_VAR} (fail-closed): {exc!r}"
            ) from exc
        found = _collect_from_module(module, module_name)
        if not found:
            raise ExtraPolicyError(
                f"module {module_name!r} named in {ENV_VAR} exported no "
                f"policies — expected a {_POLICIES_ATTR} list or a *{_PACK_SUFFIX} "
                f"attribute of Policy objects (fail-closed: silently loading "
                f"nothing would hide a typo'd or wrong module name)"
            )
        extra.extend(found)
    return extra


def policies_with_extras(
    base: Iterable[Policy] = DOGFOOD_DEFAULTS,
    env: "dict | None" = None,
) -> tuple[Policy, ...]:
    """``base`` policies followed by every ``GATECAT_EXTRA_POLICIES`` pack.

    The one call the hook and proxy use in place of a bare ``DOGFOOD_DEFAULTS``.
    Propagates :class:`ExtraPolicyError` unchanged so those callers fail closed
    (hook exit 2 / proxy refuses to start). A caller that deliberately wants a
    soft failure can catch it explicitly — the default is to fail closed.
    """
    return tuple(base) + tuple(load_extra_policies(env))
