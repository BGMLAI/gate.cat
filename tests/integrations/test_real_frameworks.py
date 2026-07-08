"""Real-framework smoke tests (plan acceptance (e), framework side).

Run only when the real frameworks are installed (``pip install
gate.cat[crewai,langgraph]`` or the dev venv); CI without frameworks
skips them and relies on the mocked contract tests. The engine is still the
fake seam implementation - the real-ENGINE smoke stays a local step.

Verified here against crewai 1.15 / langgraph 1.2 / langchain-core 1.4:
pydantic BaseTool subclassing, StructuredTool ``.func`` wrapping, ToolNode
behavior on veto (inside a compiled graph the veto propagates ActionVetoed
out of ``app.invoke`` - fail-closed, nothing executes), and both shipped
examples end-to-end as subprocesses.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

from gatecat.integrations import ActionVetoed
from gatecat.integrations.policies import DOGFOOD_DEFAULTS, PAYMENTS

HAS_CREWAI = importlib.util.find_spec("crewai") is not None
HAS_LANGGRAPH = (
    importlib.util.find_spec("langgraph") is not None
    and importlib.util.find_spec("langchain_core") is not None
)

PKG_ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = PKG_ROOT / "examples" / "veto_integrations"

needs_crewai = pytest.mark.skipif(not HAS_CREWAI, reason="crewai not installed")
needs_langgraph = pytest.mark.skipif(not HAS_LANGGRAPH, reason="langgraph not installed")


# --- crewAI (real) ------------------------------------------------------------


@needs_crewai
def test_real_crewai_wrap_tool_blocks_and_allows(engine_on_path):
    from crewai.tools import BaseTool

    from gatecat.integrations.crewai import wrap_tool

    executed = []

    class PayInvoice(BaseTool):
        name: str = "pay_invoice"
        description: str = "Execute a payment for an approved invoice."

        def _run(self, note: str, amount: float) -> str:
            executed.append((note, amount))
            return f"paid: {note}"

    guarded = wrap_tool(PayInvoice(), policies=[PAYMENTS(max_amount=0)])
    assert guarded.name == "veto(pay_invoice)"

    with pytest.raises(ActionVetoed) as exc:
        guarded._run(note="create payment for INV-42", amount=350.0)
    assert "PAYMENTS" in str(exc.value)
    assert executed == []

    assert guarded._run(note="lookup only", amount=0.0) == "paid: lookup only"


@needs_crewai
def test_real_crewai_public_run_entrypoint(engine_on_path):
    """crewAI executes tools via .run() (validation layer) - must also gate."""
    from crewai.tools import BaseTool

    from gatecat.integrations.crewai import wrap_tool

    class Shell(BaseTool):
        name: str = "shell"
        description: str = "Run a shell command."

        def _run(self, cmd: str) -> str:
            return f"ran:{cmd}"

    guarded = wrap_tool(Shell(), policies=DOGFOOD_DEFAULTS)
    with pytest.raises(ActionVetoed):
        guarded.run(cmd="rm -rf /srv/data")
    assert "ran:echo ok" in str(guarded.run(cmd="echo ok"))


# --- LangGraph / LangChain (real) ---------------------------------------------


@needs_langgraph
def test_real_structuredtool_guarded_via_invoke(engine_on_path):
    from langchain_core.tools import tool

    from gatecat.integrations.langgraph import guard_tools

    @tool
    def deploy(cmd: str) -> str:
        """Deploy infrastructure."""
        return f"ran:{cmd}"

    [guarded] = guard_tools([deploy], policies=DOGFOOD_DEFAULTS)
    with pytest.raises(ActionVetoed) as exc:
        guarded.invoke({"cmd": "terraform destroy -var-file=prod.tfvars"})
    assert "TERRAFORM_PROD" in str(exc.value)
    assert guarded.invoke({"cmd": "terraform plan"}) == "ran:terraform plan"


@needs_langgraph
def test_real_toolnode_in_graph_veto_raises_fail_closed(engine_on_path):
    """Empirical behavior on langgraph 1.2: inside a compiled graph, a veto
    in a ToolNode-executed tool PROPAGATES ``ActionVetoed`` out of
    ``app.invoke`` - nothing executes (fail-closed). To hand the decision to
    a human instead of aborting, use the ``interrupt`` pattern from
    ``examples/veto_langgraph.py``. (Standalone ``ToolNode.invoke`` outside a
    graph is unsupported in this version - runtime injection required.)"""
    from langchain_core.messages import AIMessage
    from langchain_core.tools import tool
    from langgraph.graph import END, START, MessagesState, StateGraph
    from langgraph.prebuilt import ToolNode

    from gatecat.integrations.langgraph import guard_tools

    @tool
    def deploy(cmd: str) -> str:
        """Deploy infrastructure."""
        return f"ran:{cmd}"

    graph = StateGraph(MessagesState)
    graph.add_node("tools", ToolNode(guard_tools([deploy], policies=DOGFOOD_DEFAULTS)))
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    app = graph.compile()

    def msg(cmd: str, call_id: str):
        return AIMessage(
            content="",
            tool_calls=[{"name": "deploy", "args": {"cmd": cmd}, "id": call_id, "type": "tool_call"}],
        )

    with pytest.raises(ActionVetoed) as exc:
        app.invoke({"messages": [msg("rm -rf /srv/data", "1")]})
    assert "RM_RF" in str(exc.value)

    out = app.invoke({"messages": [msg("echo ok", "2")]})
    assert out["messages"][-1].content == "ran:echo ok"


# --- shipped examples end-to-end ----------------------------------------------


def _run_example(script: Path, fake_engine: Path, tmp_path: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(fake_engine), str(PKG_ROOT)])
    env["GATECAT_VETO_LOG"] = str(tmp_path / "veto_log.jsonl")
    return subprocess.run(
        [sys.executable, str(script)], env=env, capture_output=True, text=True, timeout=120
    )


@needs_crewai
def test_example_veto_crewai_runs(fake_engine, tmp_path):
    proc = _run_example(EXAMPLES / "veto_crewai.py", fake_engine, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "blocked as expected" in proc.stdout


@needs_langgraph
def test_example_veto_langgraph_runs(fake_engine, tmp_path):
    proc = _run_example(EXAMPLES / "veto_langgraph.py", fake_engine, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "executed: terraform plan" in proc.stdout


def test_example_veto_autogen_runs(fake_engine, tmp_path):
    """AutoGen example needs no framework at all (generic guard)."""
    proc = _run_example(EXAMPLES / "veto_autogen.py", fake_engine, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "blocked as expected" in proc.stdout
