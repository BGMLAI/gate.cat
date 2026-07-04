"""Testy realnych źródeł koryto-lookup — bramka jakości + filtr MCQ + multi-source.

ROZKAZ (REJESTR 2026-06-27): lookup MA pytać realne bazy z bramką jakości.
Test integracyjny UDERZA W ŻYWY ChromaDB (nie mock) — pomijany gdy baza offline,
ale gdy żywa weryfikuje realny przepływ (mock = bezwartościowy, poprzednia lekcja).
"""
import httpx
import pytest

from cacheback.koryto_sources import (
    is_mcq, http_cache_source, chroma_source, multi_source,
    _quality_ok, DEFAULT_MIN_SIM, minilm_factbase_source, minilm_factbase_from_jsonl,
)


# ---- filtr MCQ (skażenie lookup) ----

def test_mcq_detected_and_rejected():
    mcq = ("Q:\nWhat is X?\n\nOptions:\nA. foo\nB. bar\nC. baz\nD. qux\n\nA:\nbar")
    assert is_mcq(mcq) is True


def test_non_mcq_passes():
    prose = "The len() function returns the number of items in a container."
    assert is_mcq(prose) is False


def test_code_with_letters_not_false_mcq():
    code = "def f(a, b):\n    return a + b\n# returns sum"
    assert is_mcq(code) is False


# ---- bramka jakości ----

def test_quality_rejects_low_sim():
    assert _quality_ok("good answer", sim=0.50, min_sim=0.82, min_len=3) is False


def test_quality_rejects_short():
    assert _quality_ok("ok", sim=0.99, min_sim=0.82, min_len=3) is False


def test_quality_rejects_mcq_even_high_sim():
    mcq = "Q:\n?\nOptions:\nA. a\nB. b\nC. c\nA:\nb"
    assert _quality_ok(mcq, sim=0.99, min_sim=0.82, min_len=3) is False


def test_quality_accepts_good_prose():
    assert _quality_ok("len() zwraca liczbę elementów", sim=0.90, min_sim=0.82, min_len=3) is True


# ---- fail-safe: niedostępne źródło → None, nie crash ----

def test_http_source_dead_host_returns_none():
    fn = http_cache_source("http://127.0.0.1:9", timeout=0.5)  # martwy port
    assert fn("anything") is None


def test_chroma_source_dead_host_returns_none():
    fn = chroma_source("http://127.0.0.1:9", "no-col", timeout=0.5)
    assert fn("anything") is None


def test_multi_source_all_dead_returns_none():
    lookup = multi_source([
        http_cache_source("http://127.0.0.1:9", timeout=0.5),
        chroma_source("http://127.0.0.1:9", "x", timeout=0.5),
    ])
    assert lookup("anything") is None


def test_multi_source_priority_first_wins():
    lookup = multi_source([lambda q: "atom-A", lambda q: "atom-B"])
    assert lookup("q") == "atom-A"


def test_multi_source_skips_none_source():
    lookup = multi_source([lambda q: None, lambda q: "atom-B"])
    assert lookup("q") == "atom-B"


# ---- minilm_factbase_source (offline, lokalny embedder) ----

ATOMS_CODING = [
    ("How to sort a list in place?", "lst.sort()"),
    ("Convert string to integer in Python", "int(s)"),
    ("Check if key exists in dict", "key in d"),
    ("Get length of list", "len(lst)"),
]

MINILM_CACHE = "C:/Users/bogum/.bgml/models/embeddings"


def _minilm_available() -> bool:
    # Realny encode, nie sam konstruktor: model ładuje się leniwie w
    # _ensure_model(), więc rozjechane środowisko (np. niekompletny
    # tokenizers) wybucha dopiero tutaj — bez tego testy FAILują
    # zamiast SKIPować.
    try:
        import os
        os.environ.setdefault("HF_HUB_OFFLINE", "1")
        from cacheback.embedders import get_embedder
        embedder = get_embedder("minilm", cache_dir=MINILM_CACHE)
        vec = embedder.encode("availability probe")
        return len(vec) > 0
    except Exception:
        return False


@pytest.mark.skipif(not _minilm_available(), reason="MiniLM embedder offline/unavailable")
def test_minilm_factbase_finds_paraphrase():
    """Semantic lookup trafia parafrazę której substring nie znajdzie."""
    fn = minilm_factbase_source(ATOMS_CODING, cache_dir=MINILM_CACHE, min_sim=0.30)
    # "convert a str to int" = parafraza "Convert string to integer in Python"
    result = fn("convert a str to int")
    assert result is not None, "MiniLM nie trafił oczywistej parafrazy"
    assert "int" in result.lower()


@pytest.mark.skipif(not _minilm_available(), reason="MiniLM embedder offline/unavailable")
def test_minilm_factbase_rejects_low_sim():
    """Pytanie niepowiązane z bazą → None (próg similarity)."""
    fn = minilm_factbase_source(ATOMS_CODING, cache_dir=MINILM_CACHE, min_sim=0.82)
    result = fn("what is the capital of France")
    assert result is None, "MiniLM zwrócił atom dla niezwiązanego pytania"


@pytest.mark.skipif(not _minilm_available(), reason="MiniLM embedder offline/unavailable")
def test_minilm_factbase_empty_atoms_returns_none():
    fn = minilm_factbase_source([], cache_dir=MINILM_CACHE)
    assert fn("anything") is None


def test_minilm_factbase_bad_cache_fails_safe():
    """Błąd ładowania embeddera (zły path) → lookup_fn zwraca None, nie crash."""
    fn = minilm_factbase_source(ATOMS_CODING, cache_dir="Z:/nie/istnieje")
    assert fn("sort a list") is None


def test_minilm_factbase_from_jsonl_missing_file():
    """Brakujący plik JSONL → fail-safe, zwraca None."""
    fn = minilm_factbase_from_jsonl("Z:/no/such/file.jsonl", cache_dir="Z:/no")
    assert fn("anything") is None


@pytest.mark.skipif(not _minilm_available(), reason="MiniLM embedder offline/unavailable")
def test_minilm_in_multi_source():
    """minilm_factbase_source działa w multi_source jako priorytetowe źródło."""
    minilm_fn = minilm_factbase_source(ATOMS_CODING, cache_dir=MINILM_CACHE, min_sim=0.30)
    lookup = multi_source([minilm_fn, lambda q: "fallback"])
    result = lookup("sort list python")
    assert result is not None
    assert result != "fallback"  # MiniLM powinien trafić


# ---- INTEGRACYJNY: uderza w ŻYWY ChromaDB GTX1070 (nie mock) ----

GTX_BASE = "http://192.168.18.21:8775"
GTX_COL = "6c10ae89-d460-4fc2-ac1c-0a74fdd6b190"  # coding_cache_v1


def _gtx_alive() -> bool:
    try:
        r = httpx.get(f"{GTX_BASE}/api/v2/heartbeat", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


@pytest.mark.skipif(not _gtx_alive(), reason="ChromaDB GTX1070 offline")
def test_live_chroma_quality_gate_filters_mcq():
    """Realny przepływ: ChromaDB zawiera MCQ → bramka MUSI je odfiltrować.
    Bez tego lookup zwracałby MCQ i skażał koryto."""
    fn = chroma_source(GTX_BASE, GTX_COL, min_sim=0.0)  # próg 0 by przepuścić sim, testujemy filtr MCQ
    # to query trafi w MMLU-MCQ (baza ich pełna) → bramka MCQ musi zwrócić None
    atom = fn("Typical advertising regulatory bodies suggest that adverts must not")
    # albo None (odfiltrowane MCQ), albo czysta proza — NIGDY surowy MCQ
    if atom is not None:
        assert is_mcq(atom) is False, "lookup zwrócił MCQ — bramka jakości NIE działa!"
