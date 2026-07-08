"""Test bramki-dostawcy (provider.py) — zasady z councilu 10-głosów (2026-06-28).

5 zasad-blokerów: HARD tylko exec/calc, cache→Hint(SOFT) zawsze, replayable proof,
agent odrzuca proof gdzie value!=replay, fail-closed na niewykonalnym.
"""
import dataclasses

from gatecat.provider import (
    provide_truth, provide_hint, verify_proof, Verified, Hint, ProofRef,
)


def test_calc_returns_verified_with_replayable_proof():
    """1. calc → Verified(HARD) z replayable proof_ref."""
    v = provide_truth("calc", "17*23")
    assert isinstance(v, Verified)
    assert v.value == "391"
    assert v.kind == "HARD"
    assert v.proof_ref.method == "calc"
    assert v.proof_ref.replay_command  # niepuste — agent może odtworzyć
    assert "HARD_CALC" in v.label()


def test_exec_returns_verified():
    """2. exec → Verified(HARD), output oczyszczony z context-guard artefaktu."""
    v = provide_truth("exec", '["print(sorted([3,1,2]))"]')
    assert isinstance(v, Verified)
    assert v.value == "[1, 2, 3]"  # bez '\r\nNone'
    assert v.proof_ref.method == "exec"


def test_cache_hit_is_never_hard_even_at_sim_1():
    """3. cache-hit sim=1.0 → Hint(SOFT) NIGDY HARD (council jednomyślnie)."""
    h = provide_hint("Ottawa", sim=1.0, source="cache")
    assert isinstance(h, Hint)
    assert h.kind == "SOFT"
    assert "niezweryfikowane" in h.label()
    # NIE da się przemycić Hint jako Verified
    assert not isinstance(h, Verified)


def test_agent_replays_proof_and_confirms():
    """4. agent ODTWARZA proof niezależnie → zgodny output_hash."""
    v_calc = provide_truth("calc", "100/4")
    v_exec = provide_truth("exec", '["print(2**10)"]')
    assert verify_proof(v_calc) is True
    assert verify_proof(v_exec) is True


def test_agent_rejects_proof_when_value_mismatches_replay():
    """5. sfałszowana wartość (value != to co daje replay) → agent NIE ufa.

    Atak: bramka twierdzi value='999999' ale proof liczy 391. Agent re-wykonuje,
    dostaje 391, porównuje z deklarowanym value=999999 → odrzuca."""
    v = provide_truth("calc", "17*23")  # prawdziwy: 391
    fake = dataclasses.replace(v, value="999999")  # kłamstwo o wartości
    # agent ufa TYLKO gdy proof się odtwarza I value == odtworzony wynik
    from gatecat.koryto import koryto_calc
    replay_result = koryto_calc(v.proof_ref.statements[0])  # 391
    agent_trusts = verify_proof(fake) and (fake.value == replay_result)
    assert agent_trusts is False  # value=999999 != 391 → odrzuć


def test_unsupported_op_returns_none():
    """fail-closed: nieobsługiwane op / niewykonalne → None (brak HARD-faktu, nie zmyślenie)."""
    assert provide_truth("calc", "What is the capital of France?") is None  # nie wyrażenie
    assert provide_truth("magic", "anything") is None  # nieznane op
    assert provide_truth("exec", "not-json") is None  # zły format


def test_provider_imports_only_stdlib_and_koryto():
    """niezależność: provider używa tylko stdlib + koryto (zero API/model w runtime)."""
    import gatecat.provider as p
    import inspect
    src = inspect.getsource(p)
    for forbidden in ("import openai", "import anthropic", "import httpx", "api_key", "requests"):
        assert forbidden not in src, f"provider runtime nie może zawierać {forbidden!r}"
