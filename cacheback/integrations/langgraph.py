"""A3: LangGraph adapter - veto gate as a guard in front of tool nodes.

Install: ``pip install cacheback-ai[langgraph]``. This module itself
imports NO framework code - the guard wraps plain callables and LangChain
tools by duck typing, so the zero-dependency core rule holds. On block it
raises ``ActionVetoed``; catch it in your graph to route into LangGraph's
human-in-the-loop ``interrupt`` (see ``examples/veto_langgraph.py``).

What this adapter sees / what it does not: the TOOL CALL only (name +
arguments), before execution. Everything else in the graph is unchecked -
and unchecked is not "verified safe".
"""

from __future__ import annotations

import copy
from typing import Any, Sequence

# guard_callable is framework-agnostic; it lives in guard.py and is
# re-exported here for the LangGraph-facing API.
from cacheback.integrations.guard import _GUARDED_ATTR, guard_callable
from cacheback.integrations.policies import DOGFOOD_DEFAULTS, Policy

SOURCE = "langgraph"

__all__ = ["guard_callable", "guard_tools"]


def guard_tools(
    tools: Sequence[Any],
    policies: Sequence[Policy] = DOGFOOD_DEFAULTS,
) -> list[Any]:
    """Return guarded copies of LangChain/LangGraph tools for ``ToolNode``.

    Duck typing: objects exposing ``.func`` (e.g. ``@tool``-decorated
    StructuredTool) are **shallow-copied** with a guarded ``func`` - the
    caller's original tool is left untouched, so keeping an unguarded
    reference stays unguarded and calling ``guard_tools`` twice does not
    double-wrap. Bare callables are wrapped directly::

        from langgraph.prebuilt import ToolNode
        node = ToolNode(guard_tools([search, deploy], policies=[TERRAFORM_PROD]))
    """
    guarded: list[Any] = []
    for tool in tools:
        func = getattr(tool, "func", None)
        if callable(func):
            if getattr(func, _GUARDED_ATTR, False):
                guarded.append(tool)  # already guarded - do not wrap again
                continue
            clone = copy.copy(tool)  # no in-place mutation of caller's object
            clone.func = guard_callable(
                func, policies, name=getattr(tool, "name", None), source=SOURCE
            )
            guarded.append(clone)
        elif callable(tool):
            if getattr(tool, _GUARDED_ATTR, False):
                guarded.append(tool)
            else:
                guarded.append(guard_callable(tool, policies, source=SOURCE))
        else:
            raise TypeError(
                f"cannot guard {tool!r}: expected a callable or an object with .func"
            )
    return guarded
