"""Test BidirectionalGate — pełna pętla dostawca+strażnik na wspólnym silniku (council TOP-3)."""
from cacheback.bidirectional import BidirectionalGate, Provider, Guardian
from cacheback.veto import ActionPolicy
from cacheback.provider import Verified, Hint


def test_provider_gives_hard_truth_with_proof():
    """Kierunek 1: provider daje Verified (HARD) z replayable proof."""
    gate = BidirectionalGate()
    v = gate.provide_truth("calc", "17*23")
    assert isinstance(v, Verified)
    assert v.value == "391"
    assert gate.provider.verify_proof(v)  # agent odtwarza


def test_provider_cache_is_soft():
    """Kierunek 1: cache → Hint(SOFT), nigdy HARD."""
    gate = BidirectionalGate()
    h = gate.provider.provide_hint("Ottawa", sim=1.0, source="cache")
    assert isinstance(h, Hint)
    assert not isinstance(h, Verified)


def test_guardian_vetoes_destructive_action():
    """Kierunek 2: strażnik wetuje akcję destrukcyjną (fail-closed)."""
    policy = ActionPolicy(deny=["drop table", "rm -rf"])
    gate = BidirectionalGate(policy=policy)
    d = gate.veto("drop table users")
    assert d.allowed is False
    # legalna akcja przechodzi
    d2 = gate.veto("select * from users")
    assert d2.allowed is True


def test_shared_engine_one_koryto():
    """Council TOP-3: provider i guardian dzielą TEN SAM silnik koryto (prawda jedna)."""
    gate = BidirectionalGate()
    assert gate.provider.koryto is gate.koryto
    assert gate.guardian._veto.koryto is gate.koryto


def test_full_loop_provide_then_veto():
    """Pełna pętla: agent dostaje prawdę (391), potem akcja na niej jest wetowana jeśli destrukcyjna."""
    policy = ActionPolicy(deny=["delete"])
    gate = BidirectionalGate(policy=policy)
    # 1. bramka daje prawdę
    truth = gate.provide_truth("calc", "100-9")
    assert truth.value == "91"
    # 2. agent decyduje akcję na podstawie prawdy; 3. strażnik ocenia
    safe = gate.veto("update orders set qty=91 where id=1")
    assert safe.allowed is True
    danger = gate.veto("delete from orders")
    assert danger.allowed is False


def test_bidirectional_exports():
    """Eksport z cacheback."""
    import cacheback
    assert hasattr(cacheback, "BidirectionalGate")
    assert hasattr(cacheback, "Provider")
    assert hasattr(cacheback, "Guardian")
