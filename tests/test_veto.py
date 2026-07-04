"""Testy action-veto — zatrzymaj agenta ZANIM zrobi nieodwracalną akcję.

Scenariusze prosto z realnych issues frameworków agentowych:
  - duplicate payment / kwota nad progiem (crewAI #5802, autogen #7492)
  - terraform apply na prod (autogen #7770 — $106k strata)
  - tool-call authorization (crewAI #5888)

Filozofia: fail-closed. Każdy błąd policy/koryto/human = VETO, nie przepuszczenie.
Veto musi być pewne tylko co BLOKUJE, nigdy co przepuszcza.
"""
import pytest

from cacheback.veto import (
    ActionPolicy, ActionVetoed, VetoGate, VetoDecision, before_action,
)


# --- ActionPolicy.classify: deterministyczne reguły ---

def test_deny_pattern_vetoes():
    p = ActionPolicy(deny=[r"terraform.*(destroy|apply).*prod"])
    d = p.classify("terraform apply prod", None)
    assert d.allowed is False and d.mur == "policy-deny"


def test_deny_miss_allows():
    p = ActionPolicy(deny=[r"drop\s+table"])
    assert p.classify("select * from t", None).allowed is True


def test_amount_over_threshold_vetoes():
    p = ActionPolicy(max_amount=100.0)
    d = p.classify("charge(amount=5000)", 5000)
    assert d.allowed is False and d.mur == "policy-amount"


def test_amount_under_threshold_allows():
    p = ActionPolicy(max_amount=100.0)
    assert p.classify("charge(amount=30)", 30).allowed is True


def test_require_human_vetoes():
    p = ActionPolicy(require_human=[r"charge_card"])
    d = p.classify("charge_card(...)", None)
    assert d.allowed is False and d.mur == "human"


def test_deny_takes_priority_over_amount():
    p = ActionPolicy(deny=[r"wire"], max_amount=100.0)
    # deny powinno wygrać niezależnie od kwoty
    d = p.classify("send_wire(amount=5)", 5)
    assert d.mur == "policy-deny"


# --- fail-closed: zły regex / nieporównywalna kwota → veto ---

def test_bad_deny_regex_fails_closed():
    p = ActionPolicy(deny=[r"("])   # niepoprawny regex
    d = p.classify("anything", None)
    assert d.allowed is False and "fail-closed" in d.reason


def test_uncomparable_amount_fails_closed():
    p = ActionPolicy(max_amount=100.0)
    d = p.classify("charge", object())   # nie da się porównać
    assert d.allowed is False and "fail-closed" in d.reason


def test_redos_guard_truncates_long_input():
    """audyt 2026-06-27 should-fix: catastrophic-backtracking wzorzec na DŁUGIM wejściu
    nie może zawiesić classify() — wejście przycinane do bezpiecznej długości."""
    import time
    p = ActionPolicy(deny=[r"(a+)+$"])   # klasyczny ReDoS pattern
    evil = "a" * 100000 + "b"            # długie wejście co normalnie zawiesza
    t0 = time.perf_counter()
    p.classify(evil, None)               # nie może wisieć
    assert time.perf_counter() - t0 < 1.0   # szybko (przycięte do 4096)


def test_nan_amount_fails_closed():
    """audyt 2026-06-27 #1: float('nan') > max_amount jest zawsze False (IEEE 754) →
    NaN omijał cap. Musi być fail-closed veto, nie przepuszczenie."""
    p = ActionPolicy(max_amount=100.0)
    d = p.classify("charge", float("nan"))
    assert d.allowed is False and d.mur == "policy-amount"


def test_inf_amount_fails_closed():
    """+inf też omijałby sensowny cap przez przepuszczenie odwrotnej logiki — fail-closed."""
    p = ActionPolicy(max_amount=100.0)
    d_pos = p.classify("charge", float("inf"))
    d_neg = p.classify("charge", float("-inf"))
    assert d_pos.allowed is False and d_pos.mur == "policy-amount"
    assert d_neg.allowed is False and d_neg.mur == "policy-amount"


def test_nan_amount_via_decorator_blocks_action():
    """E2E: charge(amount=nan) NIE wykonuje akcji (był to realny bypass spend-capa)."""
    ran = {"v": False}

    @before_action(ActionPolicy(max_amount=100.0), amount_of=lambda **k: k.get("amount"))
    def charge(*, amount):
        ran["v"] = True
        return "CHARGED"

    with pytest.raises(ActionVetoed):
        charge(amount=float("nan"))
    assert ran["v"] is False


# --- VetoGate.evaluate: pełna bramka, trzy mury ---

def test_gate_human_blocks_without_approve():
    gate = VetoGate(ActionPolicy(require_human=[r"charge"]))
    d = gate.evaluate("charge(args=(), kwargs={})", (), {})
    assert d.allowed is False and d.mur == "human"


def test_gate_human_allows_with_approve():
    gate = VetoGate(ActionPolicy(require_human=[r"charge"]),
                    human_approve=lambda call: True)
    d = gate.evaluate("charge(args=(), kwargs={})", (), {})
    assert d.allowed is True


def test_gate_amount_of_extractor():
    gate = VetoGate(ActionPolicy(max_amount=100.0),
                    amount_of=lambda **k: k.get("amount"))
    d = gate.evaluate("pay", (), {"amount": 9999})
    assert d.allowed is False and d.mur == "policy-amount"


def test_gate_amount_of_raises_fails_closed():
    def boom(**k): raise RuntimeError("x")
    gate = VetoGate(ActionPolicy(max_amount=100.0), amount_of=boom)
    d = gate.evaluate("pay", (), {})
    assert d.allowed is False and "fail-closed" in d.reason


def test_gate_human_approve_raises_fails_closed():
    def boom(call): raise RuntimeError("x")
    gate = VetoGate(ActionPolicy(require_human=[r"charge"]), human_approve=boom)
    d = gate.evaluate("charge(args=(), kwargs={})", (), {})
    assert d.allowed is False and "fail-closed" in d.reason


# --- MUR 2: koryto (niezależny check) ---

def test_gate_koryto_catches_wrong_atom():
    # akcja twierdzi że wynik = 5, interpreter liczy 4 → veto.
    # Statement = czyste wyrażenie ("2+2"), NIE print(...) — runner sam printuje
    # wartość ostatniego wyrażenia; print(2+2) dałby "4\r\nNone" (print zwraca None).
    gate = VetoGate(exec_check=lambda **k: ["2+2"])
    d = gate.evaluate("compute(args=(), kwargs={'expect': '5'})", (), {"expect": "5"})
    assert d.allowed is False and d.mur == "koryto"


def test_gate_koryto_confirms_right_atom():
    gate = VetoGate(exec_check=lambda **k: ["2+2"])
    d = gate.evaluate("compute(args=(), kwargs={'expect': '4'})", (), {"expect": "4"})
    assert d.allowed is True


def test_gate_exec_check_raises_fails_closed():
    def boom(**k): raise RuntimeError("x")
    gate = VetoGate(exec_check=boom)
    d = gate.evaluate("compute(args=(), kwargs={})", (), {})
    assert d.allowed is False and "fail-closed" in d.reason


# --- strict: pusta bramka jest jawnym błędem ---

def test_strict_empty_gate_raises():
    with pytest.raises(ValueError):
        VetoGate(strict=True)


def test_strict_with_rules_ok():
    VetoGate(ActionPolicy(deny=[r"x"]), strict=True)   # nie rzuca
    VetoGate(exec_check=lambda **k: None, strict=True)  # nie rzuca


# --- dekorator before_action: sync ---

def test_decorator_vetoes_and_does_not_execute():
    executed = {"ran": False}

    @before_action(ActionPolicy(deny=[r"prod"]))
    def deploy(*, target):
        executed["ran"] = True
        return f"deployed {target}"

    with pytest.raises(ActionVetoed):
        deploy(target="prod cluster")
    assert executed["ran"] is False   # akcja NIE wykonana


def test_decorator_allows_safe_action():
    @before_action(ActionPolicy(deny=[r"prod"]))
    def deploy(*, target):
        return f"deployed {target}"
    assert deploy(target="staging") == "deployed staging"


def test_decorator_on_veto_callback():
    @before_action(ActionPolicy(deny=[r"prod"]),
                   on_veto=lambda d: f"BLOCKED:{d.mur}")
    def deploy(*, target):
        return "deployed"
    assert deploy(target="prod") == "BLOCKED:policy-deny"


def test_decorator_exposes_gate():
    @before_action(ActionPolicy(deny=[r"x"]))
    def f(): ...
    assert isinstance(f.veto_gate, VetoGate)


# --- dekorator before_action: async ---

async def test_decorator_async_vetoes():
    ran = {"v": False}

    @before_action(ActionPolicy(require_human=[r"charge"]))
    async def charge(*, amount):
        ran["v"] = True
        return amount

    with pytest.raises(ActionVetoed):
        await charge(amount=10)
    assert ran["v"] is False


async def test_decorator_async_allows():
    @before_action(ActionPolicy(deny=[r"prod"]))
    async def deploy(*, target):
        return f"ok {target}"
    assert await deploy(target="staging") == "ok staging"


# --- ActionVetoed niesie decyzję do audytu ---

def test_action_vetoed_carries_decision():
    @before_action(ActionPolicy(deny=[r"prod"]))
    def deploy(*, target): ...
    try:
        deploy(target="prod")
    except ActionVetoed as e:
        assert e.mur == "policy-deny"
        assert isinstance(e.decision, VetoDecision)
        assert e.decision.to_dict()["allowed"] is False


# --- scenariusz E2E z realnych issues ---

def test_e2e_real_issue_scenarios():
    policy = ActionPolicy(
        deny=[r"terraform.*(destroy|apply).*prod", r"drop\s+table"],
        require_human=[r"charge_card", r"send_wire"],
        max_amount=100.0,
    )

    @before_action(policy, human_approve=lambda c: False,
                   amount_of=lambda **k: k.get("amount"))
    def charge_card(*, customer, amount):
        return "CHARGED"

    @before_action(policy)
    def terraform(*, cmd):
        return "DEPLOYED"

    # duplicate payment / mała kwota — wymaga człowieka → veto
    with pytest.raises(ActionVetoed):
        charge_card(customer="acme", amount=30)
    # kwota nad progiem → veto
    with pytest.raises(ActionVetoed):
        charge_card(customer="acme", amount=5000)
    # prod-destroy → veto
    with pytest.raises(ActionVetoed):
        terraform(cmd="terraform apply prod")
    # staging → przechodzi
    assert terraform(cmd="terraform apply staging") == "DEPLOYED"
