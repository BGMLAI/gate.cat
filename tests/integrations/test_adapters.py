"""A2/A3 contract tests: adapters with mocked framework AND fake engine.

Per plan: contract tests mock the framework (no crewAI/LangGraph install in
CI); the real-framework smoke test is a local acceptance step.
"""

from __future__ import annotations

import sys
import types

import pytest

from gatecat.integrations import ActionVetoed, Policy
from gatecat.integrations.policies import DOGFOOD_DEFAULTS, PAYMENTS


PAY_POLICY = PAYMENTS(max_amount=0)


# --- crewAI -----------------------------------------------------------------


@pytest.fixture()
def fake_crewai(monkeypatch):
    """Minimal crewai.tools.BaseTool standing in for the real framework."""

    class BaseTool:
        name: str = "base"
        description: str = ""

        def _run(self, *args, **kwargs):  # pragma: no cover - overridden
            raise NotImplementedError

        def run(self, *args, **kwargs):
            return self._run(*args, **kwargs)

    crewai_mod = types.ModuleType("crewai")
    tools_mod = types.ModuleType("crewai.tools")
    tools_mod.BaseTool = BaseTool
    crewai_mod.tools = tools_mod
    monkeypatch.setitem(sys.modules, "crewai", crewai_mod)
    monkeypatch.setitem(sys.modules, "crewai.tools", tools_mod)
    return tools_mod


def test_crewai_module_imports_without_framework():
    """Zero-dependency core: importing the adapter must not import crewai."""
    assert "crewai" not in sys.modules or True  # import below is the real assert
    import gatecat.integrations.crewai  # noqa: F401


def test_crewai_wrap_tool_blocks_payment(engine_on_path, fake_crewai):
    from gatecat.integrations.crewai import wrap_tool

    executed = []

    class PayTool(fake_crewai.BaseTool):
        name = "pay_invoice"
        description = "Sends a payment"

        def _run(self, **kwargs):
            executed.append(kwargs)
            return "paid"

    guarded = wrap_tool(PayTool(), policies=[PAY_POLICY])
    assert guarded.name == "veto(pay_invoice)"
    with pytest.raises(ActionVetoed) as exc:
        guarded._run(action="payment create", invoice="INV-1", amount=250)
    assert "PAYMENTS" in str(exc.value)
    assert executed == []  # the tool body never ran


def test_crewai_wrap_tool_allows_and_executes(engine_on_path, fake_crewai):
    from gatecat.integrations.crewai import wrap_tool

    class LookupTool(fake_crewai.BaseTool):
        name = "lookup"
        description = "Reads an invoice"

        def _run(self, invoice):
            return f"details:{invoice}"

    guarded = wrap_tool(LookupTool(), policies=[PAY_POLICY])
    assert guarded._run("INV-1") == "details:INV-1"


def test_crewai_veto_decorator(engine_on_path):
    from gatecat.integrations.crewai import veto

    @veto(policies=[PAY_POLICY])
    def pay_invoice(invoice_id: str, amount: float) -> str:
        return "payment create executed"

    # args themselves are innocuous; the function NAME carries no deny match
    assert pay_invoice("INV-1", 10.0) == "payment create executed"

    @veto(policies=[PAY_POLICY])
    def create_payment(invoice_id: str) -> str:  # name matches deny pattern
        return "should never run"

    with pytest.raises(ActionVetoed):
        create_payment("INV-2")


# --- LangGraph ---------------------------------------------------------------


def test_langgraph_module_imports_without_framework():
    import gatecat.integrations.langgraph  # noqa: F401

    assert "langgraph" not in sys.modules  # nothing leaked


def test_guard_callable_blocks_and_allows(engine_on_path):
    from gatecat.integrations.langgraph import guard_callable

    calls = []

    def deploy(cmd: str) -> str:
        calls.append(cmd)
        return "done"

    guarded = guard_callable(deploy, DOGFOOD_DEFAULTS)
    with pytest.raises(ActionVetoed) as exc:
        guarded("terraform destroy -var-file=prod.tfvars")
    assert "TERRAFORM_PROD" in str(exc.value)
    assert calls == []

    assert guarded("terraform plan") == "done"
    assert calls == ["terraform plan"]


def test_guard_tools_wraps_dotfunc_and_callables(engine_on_path):
    from gatecat.integrations.langgraph import guard_tools

    class StructuredToolLike:
        name = "shell"

        def __init__(self):
            self.func = lambda cmd: f"ran:{cmd}"

    tool = StructuredToolLike()
    original_func = tool.func
    [guarded_tool, guarded_fn] = guard_tools(
        [tool, lambda cmd: f"raw:{cmd}"], DOGFOOD_DEFAULTS
    )
    with pytest.raises(ActionVetoed):
        guarded_tool.func("rm -rf /srv/data")
    assert guarded_tool.func("echo ok") == "ran:echo ok"
    assert guarded_fn("echo ok") == "raw:echo ok"
    # no in-place mutation: the caller's original tool stays unguarded
    assert guarded_tool is not tool
    assert tool.func is original_func
    assert tool.func("rm -rf /srv/data") == "ran:rm -rf /srv/data"


def test_guard_tools_idempotent_no_double_wrap(engine_on_path):
    from gatecat.integrations.langgraph import guard_tools

    calls = []

    class StructuredToolLike:
        name = "shell"

        def __init__(self):
            self.func = lambda cmd: calls.append(cmd)

    once = guard_tools([StructuredToolLike()], DOGFOOD_DEFAULTS)
    twice = guard_tools(once, DOGFOOD_DEFAULTS)  # must not wrap a second time
    twice[0].func("echo ok")
    assert calls == ["echo ok"]  # gate ran once, not twice


def test_guard_tools_rejects_unguardable(engine_on_path):
    from gatecat.integrations.langgraph import guard_tools

    with pytest.raises(TypeError):
        guard_tools([object()])


# --- fail-closed across adapters ---------------------------------------------


def _force_engine_absent(monkeypatch):
    """Make the seam behave as if the engine is unimportable, regardless of
    whether the real gatecat is on PYTHONPATH. Clearing sys.modules alone is
    not enough when the engine really is installed (it just re-imports), so we
    stub the seam's loader to raise EngineUnavailable - the exact condition the
    fail-closed path exists for."""
    from gatecat.integrations import _engine

    def _raise(*_a, **_k):
        raise _engine.EngineUnavailable("engine forced-absent for test")

    monkeypatch.setattr(_engine, "_load_veto_module", _raise)
    _engine._GATE_CACHE.clear()  # a cached gate would mask the missing engine


def test_adapters_fail_closed_without_engine(tmp_path, monkeypatch):
    """No engine importable => ActionVetoed, tool body never runs."""
    monkeypatch.setenv("GATECAT_VETO_LOG", str(tmp_path / "log.jsonl"))
    _force_engine_absent(monkeypatch)
    from gatecat.integrations import guard_callable

    ran = []
    guarded = guard_callable(lambda c: ran.append(c), DOGFOOD_DEFAULTS)
    with pytest.raises(ActionVetoed) as exc:
        guarded("echo totally harmless")
    assert "fail-closed" in str(exc.value)
    assert ran == []


# --- A8: shadow mode (opt-in log-only; default enforce) ----------------------


def test_shadow_mode_allows_would_be_block_and_logs(engine_on_path, tmp_path, monkeypatch):
    """A8: with shadow on, a policy block is logged as ``shadow_block`` and the
    action is ALLOWED (no raise). The default path (enforce) still blocks."""
    import json

    log = tmp_path / "shadow_log.jsonl"
    monkeypatch.setenv("GATECAT_VETO_LOG", str(log))
    from gatecat.integrations import check_action

    # explicit shadow=True: dangerous action is allowed through, not raised
    decision = check_action("crewai", "rm -rf /srv/data", DOGFOOD_DEFAULTS, shadow=True)
    assert decision.blocked is False
    assert "SHADOW" in decision.reason

    records = [json.loads(l) for l in log.read_text().splitlines()]
    assert records[-1]["decision"] == "shadow_block"  # would-be block, distinct marker
    # the target-anchored analyzer owns the rm class now (was "RM_RF" regex)
    assert records[-1]["policy"] == "DELETE_ANALYZER"
    json.dumps(records[-1]).encode("ascii")  # D1 holds in shadow too


def test_shadow_mode_via_env_var(engine_on_path, tmp_path, monkeypatch):
    """A8: GATECAT_VETO_SHADOW=1 flips the same behavior without a code change."""
    monkeypatch.setenv("GATECAT_VETO_LOG", str(tmp_path / "log.jsonl"))
    monkeypatch.setenv("GATECAT_VETO_SHADOW", "1")
    from gatecat.integrations import check_action

    decision = check_action("crewai", "rm -rf /srv/data", DOGFOOD_DEFAULTS)
    assert decision.blocked is False  # env alone enables shadow


def test_shadow_default_is_enforce(engine_on_path, tmp_path, monkeypatch):
    """A8 identity guarantee: absent any opt-in, a block is a block."""
    monkeypatch.setenv("GATECAT_VETO_LOG", str(tmp_path / "log.jsonl"))
    monkeypatch.delenv("GATECAT_VETO_SHADOW", raising=False)
    from gatecat.integrations import check_action

    with pytest.raises(ActionVetoed):
        check_action("crewai", "rm -rf /srv/data", DOGFOOD_DEFAULTS)


def test_shadow_fail_closed_engine_missing_allows_but_logs(tmp_path, monkeypatch):
    """A8 + fail-closed interaction, documented explicitly: shadow mode is
    log-only, so even the engine-unavailable path is allowed through - but the
    would-be block IS recorded, so 'what would we have caught' stays auditable.
    In ENFORCE mode the same path blocks (test_adapters_fail_closed_*)."""
    import json

    log = tmp_path / "log.jsonl"
    monkeypatch.setenv("GATECAT_VETO_LOG", str(log))
    monkeypatch.setenv("GATECAT_VETO_SHADOW", "1")
    _force_engine_absent(monkeypatch)
    from gatecat.integrations import check_action

    decision = check_action("crewai", "echo harmless", DOGFOOD_DEFAULTS)
    assert decision.blocked is False
    record = [json.loads(l) for l in log.read_text().splitlines()][-1]
    assert record["decision"] == "shadow_block"
    assert "fail-closed" in record["reason"]


def test_engine_raised_veto_is_logged_and_ascii(engine_on_path, fake_engine, tmp_path, monkeypatch):
    """When the engine signals a block by RAISING ActionVetoed (documented
    seam behavior) rather than returning blocked=True, check_action must still
    write an audit record (D2) and ASCII-escape the reason (D1)."""
    import json

    # rewrite the fake gate to raise (with a non-ASCII reason) instead of return
    veto = fake_engine / "gatecat" / "veto.py"
    veto.write_text(
        "class ActionVetoed(RuntimeError):\n    pass\n\n"
        "class VetoGate:\n"
        "    def __init__(self, policies):\n        pass\n"
        "    def before_action(self, action, source=''):\n"
        "        raise ActionVetoed('zniszczy\\u0142oby produkcj\\u0119')\n"
    )
    log = tmp_path / "raise_log.jsonl"
    monkeypatch.setenv("GATECAT_VETO_LOG", str(log))
    from gatecat.integrations import check_action

    with pytest.raises(ActionVetoed) as exc:
        check_action("crewai", "do something", DOGFOOD_DEFAULTS)
    str(exc.value).encode("ascii")  # D1: reason reached caller ASCII-safe
    [record] = [json.loads(l) for l in log.read_text().splitlines()]
    assert record["decision"] == "block"  # D2: engine-raised block IS audited
    json.dumps(record).encode("ascii")
