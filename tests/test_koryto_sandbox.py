"""Testy sandboxa koryto-exec — każdy z ataków znalezionych przez pentesterów
(workflow exec-hardening, 26 udanych breaków) jako test-BLOKADY.

Filozofia: kod idzie Z RUCHU INTERNETOWEGO = wrogie wejście. Sandbox MUSI:
  - przepuścić legalny kod (arytmetyka, listy, lambda-comprehension),
  - ZABLOKOWAĆ każdy escape/exfil/DoS deterministycznie (fail-closed).
"""
import sys

import pytest

from cacheback.koryto_sandbox import ast_gate, run_sandboxed, SAFE_BUILTINS


# ---- ast_gate: ATAKI muszą być DROP ----

ESCAPE_ATTACKS = [
    ("'{0.__class__.__bases__}'.format(())", "format-string gadget"),
    ("[c for c in ().__class__.__base__.__subclasses__()]", "subclasses-chain"),
    ("__import__('os').system('echo X')", "import-os"),
    ("eval('1+1')", "eval"),
    ("exec('x=1')", "exec"),
    ("compile('1','','eval')", "compile"),
    ("open('/etc/passwd').read()", "fs-read"),
    ("type('X',(),{}).__base__", "type-gadget"),
    ("getattr(().__class__, 'foo')", "getattr-gadget"),
    ("().__class__.__mro__", "mro-attr"),
    ("(lambda: 0).__globals__", "func-globals"),
    ("vars()", "vars"),
    ("globals()", "globals"),
    ("license", "site-builtin-license"),
    ("breakpoint()", "breakpoint"),
]


@pytest.mark.parametrize("code,name", ESCAPE_ATTACKS)
def test_escape_attacks_blocked(code, name):
    g = ast_gate(code, "python")
    assert g.ok is False, f"ESCAPE PRZESZEDŁ: {name} ({code})"


DOS_ATTACKS = [
    "9**9**9",              # wieża potęg
    "10**9",                # płaska potęga (miliard)
    "10**10",
    "sum(range(10**10))",   # range z dużym arg przez potęgę
    "'a'*(10**9)",          # mnożenie str
    "[0]*(10**8)",          # mnożenie listy
    "2**64",                # wykładnik > cap
    "99999999999",          # literał int za duży
]


@pytest.mark.parametrize("code", DOS_ATTACKS)
def test_dos_attacks_blocked(code):
    g = ast_gate(code, "python")
    assert g.ok is False, f"DoS PRZESZEDŁ: {code}"


def test_while_loop_blocked():
    """while True (nieskończona pętla) → While nie na allow-liście → DROP."""
    assert ast_gate("x=0\nwhile True:\n x+=1", "python").ok is False


def test_attribute_always_blocked():
    """ast.Attribute zakazany BEZWARUNKOWO (rdzeń obrony przed gadget-chains)."""
    assert ast_gate("x.y", "python").ok is False
    assert ast_gate("'s'.upper()", "python").ok is False


def test_walrus_blocked():
    """NamedExpr (walrus :=) nie na allow-liście → DROP (mógłby omijać assign-tracking)."""
    assert ast_gate("(x := 5)", "python").ok is False


def test_fstring_blocked():
    """f-string (JoinedStr) DROP — może zawierać dowolne wyrażenie, w tym Call do open.
    Allow-list domyślnie zamyka go (nie na liście), więc nawet f'{open(1)}' blokowany."""
    assert ast_gate('f"{1+1}"', "python").ok is False
    assert ast_gate('f"{open(1)}"', "python").ok is False


def test_legal_starred_and_conditional_comprehension():
    """Legalne konstrukcje PASS: unpacking i comprehension z warunkiem."""
    assert ast_gate("[*range(3)]", "python").ok is True
    assert ast_gate("[x for x in range(3) if x > 0]", "python").ok is True


# ---- ast_gate: LEGALNY kod musi PASS ----

LEGAL_CODE = [
    "2+2",
    "[2, 2, 2]",
    "sum(range(10))",
    "sorted([3, 1, 2])",
    "len([1, 2, 3])",
    "2**10",
    "100**3",
    "[0]*3",
    "'ab'*5",
    "fns=[(lambda: i) for i in range(3)]\n[g() for g in fns]",   # flagowy lambda-comprehension
    "[x*2 for x in range(5)]",
    "max(1, 2, 3)",
    "{'a': 1}",
    "(1, 2, 3)",
    "x = 5\nx + 1",
]


@pytest.mark.parametrize("code", LEGAL_CODE)
def test_legal_code_passes(code):
    g = ast_gate(code, "python")
    assert g.ok is True, f"LEGALNY DROP: {code} ({g.reason})"


# ---- JS auto-exec domyślnie OFF ----

def test_js_exec_disabled():
    assert ast_gate("console.log(1)", "js").ok is False
    assert ast_gate("require('fs')", "node").ok is False


# ---- run_sandboxed: legalny kod WYKONUJE i daje wynik ----

def test_run_sandboxed_executes_legal():
    r = run_sandboxed("print(2+2)", timeout=10)
    assert r.ok is True
    assert "4" in (r.stdout or "")


def test_run_sandboxed_lambda_comprehension():
    """Flagowy confident-wrong: [g() for g in fns] → [2, 2, 2] (late binding)."""
    r = run_sandboxed("fns=[(lambda: i) for i in range(3)]\nprint([g() for g in fns])", timeout=10)
    assert r.ok is True
    assert "[2, 2, 2]" in (r.stdout or "")


def test_run_sandboxed_blocks_attack_at_execution_boundary():
    """Gate jest WEWNĄTRZ run_sandboxed: nawet bezpośrednie wywołanie z groźnym kodem
    → odrzucone (bramka na granicy wykonania, nie tylko u callera)."""
    r = run_sandboxed("__import__('os').system('echo PWNED')", timeout=10)
    assert r.ok is False
    assert "gate-drop" in r.reason


def test_run_sandboxed_dos_blocked_before_execution():
    """DoS odrzucony przez gate ZANIM odpali subprocess (nie czekamy na timeout)."""
    r = run_sandboxed("9**9**9", timeout=10)
    assert r.ok is False
    assert "gate-drop" in r.reason


# ---- safe builtins firewall ----

def test_safe_builtins_no_dangerous():
    """SAFE_BUILTINS NIE zawiera eval/exec/open/__import__/getattr/compile."""
    dangerous = {"eval", "exec", "open", "__import__", "getattr", "compile",
                 "globals", "locals", "vars", "type", "setattr", "delattr"}
    assert not (SAFE_BUILTINS & dangerous)
