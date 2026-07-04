"""Testy koryta — deterministyczny weryfikator atomu (łapie confident-wrong).

Nacisk na rzeczy, które w badaniu okazały się krytyczne (REJESTR 2026-06-27):
  - exec NIE jest tautologią: gold nie wchodzi do interpretera (sam liczy),
  - context-guard działa (osobne statementy odtwarzają kontekst),
  - calc liczy z TREŚCI pytania, nie z gold,
  - lookup może być STALE → needs_arbiter (nie blokuj twardo na samym lookupie),
  - granica: NL→wyrażenie i atom-spoza-bazy = verdict 'unknown' (przepuść).
"""
import os

import pytest

from cacheback.koryto import (
    Koryto, FactBase, KorytoVerdict,
    koryto_exec_python, koryto_calc, atoms_match, koryto_exec_node,
)


# ---- node-exec gating (audyt 2026-06-27 #10: RCE bez sandboxa) ----

def test_node_exec_disabled_by_default(monkeypatch):
    """Bez CACHEBACK_KORYTO_EXEC_NODE_UNSAFE node-exec MUSI zwrócić None (nie wykonać).
    JS nie jest sandboxowany jak Python → domyślnie OFF (fail-closed)."""
    monkeypatch.delenv("CACHEBACK_KORYTO_EXEC_NODE_UNSAFE", raising=False)
    # nawet trywialny kod nie wykonuje się bez opt-in
    assert koryto_exec_node("console.log(2+2)") is None


def test_node_exec_verify_path_disabled_by_default(monkeypatch):
    """Koryto.verify(exec_js=...) też nie wykonuje JS bez opt-in → verdict unknown/przepuść."""
    monkeypatch.delenv("CACHEBACK_KORYTO_EXEC_NODE_UNSAFE", raising=False)
    k = Koryto()
    v = k.verify("co zwraca?", "4", exec_js="console.log(2+2)")
    # bez node-exec żaden twardy werdykt z JS — spada na calc/lookup/unknown
    assert v.channel != "exec" or v.truth is None


# ---- KANAŁ 1: exec (twarde koryto) ----

def test_exec_catches_confident_wrong_lambda():
    """lambda late-binding: model pewnie mówi [0,1,2], interpreter daje [2,2,2]."""
    k = Koryto()
    v = k.verify(
        "fns=[lambda: i for i in range(3)]; [g() for g in fns]?",
        answer="[0, 1, 2]",
        exec_stmts=["fns=[lambda: i for i in range(3)]", "[g() for g in fns]"],
    )
    assert v.verdict == "refute"
    assert v.channel == "exec"
    assert v.hard is True
    assert "2, 2, 2" in v.truth


def test_exec_confirms_correct_answer():
    k = Koryto()
    v = k.verify("2+2?", answer="4", exec_stmts=["2+2"])
    assert v.verdict == "confirm"
    assert v.channel == "exec"


def test_exec_is_not_tautology_truth_comes_from_interpreter():
    """DOWÓD braku tautologii: gold NIE jest podany do verify. Prawda pochodzi
    WYŁĄCZNIE z wykonania interpretera. Gdyby exec patrzył na etykietę, ten test
    nie miałby skąd wziąć '[2, 2, 2]'."""
    k = Koryto()
    v = k.verify("x?", answer="cokolwiek-zlego",
                 exec_stmts=["fns=[lambda: i for i in range(3)]", "[g() for g in fns]"])
    assert v.truth == "[2, 2, 2]"        # policzone, nie podane
    assert v.verdict == "refute"


def test_exec_context_guard_separate_statements():
    """context-guard: a=257; b=257; a is b → False (osobne obiekty w REPL-semantyce).
    Naiwny jednoblokowy exec dałby True przez peephole — rubber-stamp błędu."""
    truth = koryto_exec_python(["a=257", "b=257", "a is b"])
    assert truth == "False"


def test_exec_disabled_falls_through():
    k = Koryto(enable_exec=False)
    v = k.verify("2+2?", answer="5", exec_stmts=["2+2"])
    assert v.channel != "exec"   # exec wyłączony → spada do calc/lookup/unknown


# ---- KANAŁ 2: calc (twarde koryto, z treści pytania) ----

def test_calc_order_of_operations():
    assert koryto_calc("Evaluate using standard order of operations: 6 / 2 * 3") == "9"
    assert koryto_calc("Evaluate: 2 + 3 * 4") == "14"
    assert koryto_calc("Evaluate: 100 - 10 ^ 2") == "0"


def test_calc_right_associative_power():
    assert koryto_calc("Evaluate: 2 ^ 3 ^ 2 (that is 2^(3^2))") == "512"


def test_calc_squared():
    assert koryto_calc("Evaluate: (2 + 3) squared") == "25"


def test_calc_catches_confident_wrong():
    k = Koryto()
    v = k.verify("Evaluate: 6 / 2 * 3", answer="1")   # częsty confident-wrong (zła kolejność)
    assert v.verdict == "refute"
    assert v.channel == "calc"
    assert v.truth == "9"


def test_calc_returns_none_on_word_problem():
    """NL→wyrażenie: wybór operacji należy do rzeki, nie koryta (granica uczciwa)."""
    assert koryto_calc("Convert 26.2 miles to km using 1 mile = 1.60934 km. Round to 2 decimals.") is None


# ---- KANAŁ 3: lookup (miękkie koryto, MOŻE BYĆ STALE) ----

def test_lookup_confirms_from_independent_base():
    k = Koryto(fact_base={"stolica polski": "Warszawa"})
    v = k.verify("Jaka jest stolica Polski?", answer="Warszawa")
    assert v.verdict == "confirm"
    assert v.channel == "lookup"
    assert v.hard is False                # lookup jest miękki


def test_lookup_refute_needs_arbiter():
    """Rozbieżność z miękkiego koryta → needs_arbiter=True (potwierdź zanim zablokujesz)."""
    k = Koryto(fact_base={"stolica polski": "Warszawa"})
    v = k.verify("Jaka jest stolica Polski?", answer="Kraków")
    assert v.verdict == "refute"
    assert v.needs_arbiter is True        # NIE blokuj twardo — koryto bywa stale


def test_lookup_stale_base_can_be_wrong():
    """KORYTO-STALE: baza ma błędny fakt (Casablanca), model ma rację (Rabat).
    Koryto 'refute' ale needs_arbiter=True → arbiter wykryłby że to KORYTO się myli.
    To realna klasa błędu (zmierzona) — koryto samo bywa źródłem confident-wrong."""
    stale = Koryto(fact_base={"stolica maroka": "Casablanca"})  # błąd: to Rabat
    v = stale.verify("Jaka jest stolica Maroka?", answer="Rabat")
    assert v.verdict == "refute"          # koryto błędnie odrzuca dobrą odpowiedź
    assert v.needs_arbiter is True        # ale flaga mówi: zweryfikuj zanim zaufasz


def test_lookup_miss_is_unknown():
    k = Koryto(fact_base={"stolica polski": "Warszawa"})
    v = k.verify("Jaka jest stolica Australii?", answer="Sydney")
    assert v.verdict == "unknown"         # atom spoza bazy → przepuść (uczciwy false-neg)


def test_lookup_longest_key_wins():
    """Najdłuższy pasujący klucz = najspecyficzniejszy (unika kolizji)."""
    fb = FactBase({"prawo": "ZŁE", "prawo do bycia zapomnianym": "art. 17 RODO"})
    assert fb.lookup("Który artykuł reguluje prawo do bycia zapomnianym?") == "art. 17 RODO"


# ---- granica / brak koryta ----

def test_no_koryto_returns_unknown():
    k = Koryto(enable_calc=False)         # bez bazy, bez calc, pytanie nie-wykonywalne
    v = k.verify("Napisz wiersz o jesieni", answer="...")
    assert v.verdict == "unknown"
    assert v.caught is False


def test_caught_property():
    k = Koryto()
    assert k.verify("2+2?", "5", exec_stmts=["2+2"]).caught is True
    assert k.verify("2+2?", "4", exec_stmts=["2+2"]).caught is False


# ---- atom matching ----

def test_atoms_match_word_boundary():
    assert atoms_match("The answer is 17 RODO.", "17 RODO") is True
    assert atoms_match("", "Warszawa") is False          # pusta pred nie matchuje
    assert atoms_match("Wellington", "Wellington", ["Welington"]) is True


def test_verdict_to_dict_serializable():
    k = Koryto()
    d = k.verify("2+2?", "4", exec_stmts=["2+2"]).to_dict()
    assert d["verdict"] == "confirm" and d["channel"] == "exec" and d["hard"] is True
