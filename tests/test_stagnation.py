"""Testy stagnation-by-state — pilnuje KORYTA (czy samo nie zgniło), nie rzeki.

Kluczowe rozróżnienie (architektura usera):
  - TWARDE odrzucenia (exec/calc): interpreter się nie myli → seria NIE jest
    podejrzana wobec koryta (to prawdziwy confident-wrong rzeki).
  - MIĘKKIE odrzucenia (lookup, needs_arbiter): baza bywa stale → seria sygnalizuje
    że to KORYTO mogło zgnić → eskaluj do web-rozjemcy.
"""
from gatecat.stagnation import StagnationMonitor, StagnationState
from gatecat.koryto import Koryto, KorytoVerdict


def _hard_refute():
    return KorytoVerdict(verdict="refute", channel="exec", truth="x", hard=True, needs_arbiter=False)


def _soft_refute():
    return KorytoVerdict(verdict="refute", channel="lookup", truth="x", hard=False, needs_arbiter=True)


def _confirm():
    return KorytoVerdict(verdict="confirm", channel="exec", truth="x", hard=True)


# ---- twarde odrzucenia NIE czynią koryta podejrzanym ----

def test_hard_refute_streak_not_suspect():
    """Seria exec-odrzuceń = prawdziwy confident-wrong rzeki, koryto OK."""
    mon = StagnationMonitor(window=5, soft_streak_trigger=3)
    st = None
    for _ in range(5):
        st = mon.observe(_hard_refute())
    assert st.koryto_suspect is False        # interpreter się nie myli
    assert st.refute_streak == 5
    assert st.soft_refute_streak == 0


# ---- miękkie odrzucenia z rzędu = koryto podejrzane ----

def test_soft_refute_streak_triggers_suspect():
    """3 lookup-odrzucenia z rzędu (needs_arbiter) → koryto może być stale."""
    mon = StagnationMonitor(window=5, soft_streak_trigger=3)
    st1 = mon.observe(_soft_refute())
    st2 = mon.observe(_soft_refute())
    assert st1.koryto_suspect is False
    assert st2.koryto_suspect is False       # jeszcze nie 3
    st3 = mon.observe(_soft_refute())
    assert st3.koryto_suspect is True        # 3 z rzędu → podejrzane
    assert "stale" in st3.reason.lower() or "arbiter" in st3.reason.lower()


def test_confirm_resets_streak():
    """Akceptacja (postęp) zeruje serię — koryto działa."""
    mon = StagnationMonitor(window=5, soft_streak_trigger=3)
    mon.observe(_soft_refute())
    mon.observe(_soft_refute())
    st = mon.observe(_confirm())
    assert st.soft_refute_streak == 0
    assert st.koryto_suspect is False
    # po resecie trzeba znów 3
    mon.observe(_soft_refute())
    mon.observe(_soft_refute())
    assert mon.observe(_soft_refute()).koryto_suspect is True


def test_window_ratio_trigger():
    """Okno pełne odrzuceń (mieszane) i wysoki odsetek → podejrzane."""
    mon = StagnationMonitor(window=4, refute_ratio=0.75, soft_streak_trigger=99)
    mon.observe(_soft_refute())
    mon.observe(_hard_refute())
    mon.observe(_soft_refute())
    st = mon.observe(_soft_refute())         # 4/4 refute, ratio=1.0 >= 0.75
    assert st.window_refute_ratio == 1.0
    assert st.koryto_suspect is True


# ---- integracja z realnym Koryto (stale baza) ----

def test_integration_stale_base_becomes_suspect():
    """Realny scenariusz: stale baza odrzuca poprawne odpowiedzi → monitor łapie."""
    stale = Koryto(fact_base={
        "stolica maroka": "Casablanca",     # błąd: to Rabat
        "stolica turcji": "Stambuł",         # błąd: to Ankara
        "stolica polski": "Krakow",          # błąd: to Warszawa
    })
    mon = StagnationMonitor(window=5, soft_streak_trigger=3)
    questions = [
        ("Jaka jest stolica Maroka?", "Rabat"),
        ("Jaka jest stolica Turcji?", "Ankara"),
        ("Jaka jest stolica Polski?", "Warszawa"),
    ]
    suspect = False
    for q, correct_answer in questions:
        kv = stale.verify(q, correct_answer)
        assert kv.verdict == "refute"        # stale baza odrzuca DOBRE odpowiedzi
        st = mon.observe(kv)
        suspect = suspect or st.koryto_suspect
    assert suspect is True                    # monitor wykrył że koryto zgniło


def test_state_serializable():
    mon = StagnationMonitor()
    d = mon.observe(_soft_refute()).to_dict()
    assert "koryto_suspect" in d and "soft_refute_streak" in d


def test_reset():
    mon = StagnationMonitor(soft_streak_trigger=2)
    mon.observe(_soft_refute())
    mon.observe(_soft_refute())
    mon.reset()
    assert mon.observe(_soft_refute()).koryto_suspect is False  # po reset liczy od zera
