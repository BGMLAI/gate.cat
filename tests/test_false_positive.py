"""Regression guard for the product's #1 metric: false positives / false refutes.

gate.cat blocks irreversible AI actions. It must NOT block legitimate actions,
and the hard channels (exec/calc -- an interpreter) must NEVER refute a correct
answer. These tests pin both to zero. See scripts/audit_false_positive.py.
"""

from scripts.audit_false_positive import audit_koryto, audit_policy, main


def test_koryto_hard_no_false_refute():
    """exec channel is an interpreter -- it cannot wrongly refute a correct answer."""
    kor = audit_koryto()
    assert kor["hard_false_refute"] == 0, kor["false_refutes"]
    assert kor["hard_n"] >= 30  # corpus didn't silently shrink


def test_koryto_calc_no_false_refute():
    kor = audit_koryto()
    assert kor["calc_false_refute"] == 0, kor["false_refutes"]


def test_policy_no_false_positive_on_legal_actions():
    """No clean, legal action is blocked by a deny/amount rule."""
    pol = audit_policy()
    assert pol["allow_false_positive"] == 0, pol["false_positives"]
    assert pol["allow_n"] >= 20


def test_policy_gates_all_financial_actions():
    """Financial/trading verbs require human -- none silently leak through."""
    pol = audit_policy()
    assert pol["human_leaks"] == [], pol["human_leaks"]
    assert pol["human_correctly_gated"] == pol["human_n"]


def test_audit_overall_pass():
    result = main()
    assert result["pass"] is True
