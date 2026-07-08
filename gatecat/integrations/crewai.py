"""A2: crewAI adapter - veto gate in front of crew tools.

Install: ``pip install gate.cat[crewai]``. crewAI is imported lazily
inside :func:`wrap_tool` only - importing this module never pulls the
framework (zero-dependency core rule).

What this adapter sees / what it does not: it evaluates the TOOL CALL
(tool name + arguments) before execution. Agent reasoning, LLM output and
tool side effects are out of scope - unchecked, and unchecked is not
"verified safe".

Two entry points:

* :func:`veto` - decorator for plain functions (works with crewAI's
  ``@tool`` factory: apply ``@veto(...)`` below ``@tool``).
* :func:`wrap_tool` - wraps an existing ``BaseTool`` instance
  (e.g. a payment tool guarded with ``PAYMENTS(max_amount=100)``).
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Sequence

from gatecat.integrations.guard import check_action, flatten_call
from gatecat.integrations.policies import DOGFOOD_DEFAULTS, Policy

SOURCE = "crewai"


def veto(
    policies: Sequence[Policy] = DOGFOOD_DEFAULTS,
    source: str = SOURCE,
) -> Callable:
    """Decorator: run the veto gate before the wrapped tool function.

    Example::

        from crewai.tools import tool
        from gatecat.integrations.crewai import veto
        from gatecat.integrations.policies import PAYMENTS

        @tool("Pay invoice")
        @veto(policies=[PAYMENTS(max_amount=100)])
        def pay_invoice(invoice_id: str, amount: float) -> str:
            ...
    """

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            check_action(source, flatten_call(fn.__name__, args, kwargs), policies)
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def wrap_tool(tool: Any, policies: Sequence[Policy] = DOGFOOD_DEFAULTS) -> Any:
    """Wrap a crewAI ``BaseTool`` instance so every ``_run`` passes the gate.

    Returns a new ``BaseTool`` named ``veto(<original name>)``. Raises
    ``ActionVetoed`` on block - surface it to a human instead of retrying.
    """
    from crewai.tools import BaseTool  # lazy: framework only in extras

    gate_policies = tuple(policies)
    inner = tool

    class VetoTool(BaseTool):
        name: str = f"veto({inner.name})"
        description: str = getattr(inner, "description", "") or inner.name

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            check_action(SOURCE, flatten_call(inner.name, args, kwargs), gate_policies)
            return inner._run(*args, **kwargs)

    return VetoTool()
