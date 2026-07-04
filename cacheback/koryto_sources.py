"""koryto_sources — realne źródła faktów dla kanału lookup koryta.

ROZKAZ (REJESTR 2026-06-27): koryto-lookup MA korzystać ze WSZYSTKICH baz dobrej
jakości, nie z jednej walidacyjnej. Ten moduł buduje `lookup_fn` (callback który
FactBase przyjmuje, koryto.py:193) pytający REALNE bazy z BRAMKĄ JAKOŚCI.

ŹRÓDŁA (zinwentaryzowane na żywo 2026-06-27):
  - 4M Q&A cache na VPS (główne; recall 0.78-0.89 odróżnialne = dobra jakość, proza).
  - ChromaDB GTX1070 `coding_cache_v1` (2074; ⚠️ zawiera MCQ → TYLKO po filtrze MCQ).
  - F-coding-cache D:/ (10 wpisów = pusty szkielet → POMINIĘTE).

BRAMKA JAKOŚCI (bez niej baza-szum truje lookup — gotcha: web-szum psuje 2-3× mocniej):
  1. similarity ≥ próg (domyślnie 0.82 — trafny retrieval, nie luźny),
  2. filtr MCQ (odrzuć dokumenty wielokrotnego wyboru — skażają pomiar),
  3. odrzuć puste / za krótkie atomy.

FAIL-SAFE: niedostępne źródło → None (NIE crash). Lookup po prostu nie zna atomu.
Kanał lookup jest „miękki" (needs_arbiter) — web-rozjemca i tak rozsądza spór.
"""
from __future__ import annotations

import re
from typing import Callable, Optional, Sequence

# domyślne progi jakości
DEFAULT_MIN_SIM = 0.82          # trafny retrieval (recall trafnych 0.78-0.89; luźne 0.25-0.45)
DEFAULT_MIN_ATOM_LEN = 3        # krótszy atom = bezużyteczny
DEFAULT_TIMEOUT = 8.0

# wzorce MCQ — dokument który tak wygląda skaża lookup (kolidujące opcje A/B/C)
_MCQ_RE = re.compile(r"(?:^|\n)\s*(?:Options?:|[A-J][\.\)]\s)", re.IGNORECASE)


def is_mcq(text: str) -> bool:
    """Czy dokument to pytanie wielokrotnego wyboru (MMLU-style). Takie skażają lookup."""
    if not text:
        return False
    # >=3 markery 'A. B. C.' lub jawne 'Options:' = MCQ
    markers = len(re.findall(r"(?:^|\n)\s*[A-J][\.\)]\s", text))
    return bool(_MCQ_RE.search(text)) and markers >= 3


def _quality_ok(atom: Optional[str], sim: float, min_sim: float, min_len: int) -> bool:
    """Bramka jakości: sim, długość, nie-MCQ."""
    if atom is None:
        return False
    a = str(atom).strip()
    if len(a) < min_len:
        return False
    if sim < min_sim:
        return False
    if is_mcq(a):
        return False
    return True


# ---------------------------------------------------------------------------
# Źródło 1: HTTP semantic cache (4M VPS lub dowolny cacheback-proxy /lookup)
# ---------------------------------------------------------------------------

def http_cache_source(
    base_url: str,
    *,
    api_key: str = "",
    min_sim: float = DEFAULT_MIN_SIM,
    timeout: float = DEFAULT_TIMEOUT,
) -> Callable[[str], Optional[str]]:
    """Zbuduj lookup_fn pytający semantic cache po HTTP.

    Oczekuje endpointu zwracającego cached odpowiedź + similarity. Próbuje:
      POST {base_url}/lookup {"query": q}  → {"answer"/"response", "similarity"}
    Fail-safe: każdy błąd/timeout/miss → None.
    """
    import httpx

    def fn(question: str) -> Optional[str]:
        try:
            headers = {"Content-Type": "application/json"}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            r = httpx.post(f"{base_url.rstrip('/')}/lookup",
                           json={"query": question}, headers=headers, timeout=timeout)
            if r.status_code != 200:
                return None
            d = r.json()
            atom = d.get("answer") or d.get("response") or d.get("text")
            sim = float(d.get("similarity", d.get("sim", 0.0)) or 0.0)
            return atom if _quality_ok(atom, sim, min_sim, DEFAULT_MIN_ATOM_LEN) else None
        except Exception:
            return None

    return fn


# ---------------------------------------------------------------------------
# Źródło 2: ChromaDB (GTX1070 coding_cache_v1 lub lokalny) — po filtrze MCQ
# ---------------------------------------------------------------------------

def chroma_source(
    base_url: str,
    collection_id: str,
    *,
    tenant: str = "default_tenant",
    database: str = "default_database",
    min_sim: float = DEFAULT_MIN_SIM,
    timeout: float = DEFAULT_TIMEOUT,
) -> Callable[[str], Optional[str]]:
    """Zbuduj lookup_fn pytający ChromaDB v2 (cosine). Zwraca top-1 dokument
    TYLKO gdy: distance→sim ≥ próg I dokument NIE jest MCQ (filtr skażenia).
    Fail-safe: błąd/niedostępne → None.
    """
    import httpx

    url = (f"{base_url.rstrip('/')}/api/v2/tenants/{tenant}/databases/{database}"
           f"/collections/{collection_id}/query")

    def fn(question: str) -> Optional[str]:
        try:
            r = httpx.post(url, json={
                "query_texts": [question], "n_results": 1,
                "include": ["documents", "distances"],
            }, timeout=timeout)
            if r.status_code != 200:
                return None
            d = r.json()
            docs = (d.get("documents") or [[]])[0]
            dists = (d.get("distances") or [[]])[0]
            if not docs:
                return None
            atom = docs[0]
            # cosine distance → similarity = 1 - distance
            sim = 1.0 - float(dists[0]) if dists else 0.0
            return atom if _quality_ok(atom, sim, min_sim, DEFAULT_MIN_ATOM_LEN) else None
        except Exception:
            return None

    return fn


# ---------------------------------------------------------------------------
# Źródło 3: MiniLM lokalny embedder na statycznej bazie atomów (offline, 0 latency sieciowej)
# ---------------------------------------------------------------------------

def minilm_factbase_source(
    atoms: "Sequence[tuple[str, str]]",
    *,
    embedder=None,
    cache_dir: str = "C:/Users/bogum/.bgml/models/embeddings",
    min_sim: float = DEFAULT_MIN_SIM,
    min_len: int = DEFAULT_MIN_ATOM_LEN,
) -> "Callable[[str], Optional[str]]":
    """Zbuduj lookup_fn z lokalnej bazy atomów (lista par (question, answer)).

    Embeduje pytania bazy raz przy budowie (macierz N×384 w RAM), potem
    cosine per query: mat @ qv, argmax, próg. Offline, deterministyczne,
    ~0ms latency sieciowej. Wymaga onnxruntime + tokenizers (systemowy python3).

    Args:
        atoms: lista (question, answer) — pytania bazy i oczekiwane odpowiedzi.
        embedder: opcjonalny gotowy embedder (np. get_embedder('minilm')). Gdy None,
                  ładuje singleton z cache_dir.
        cache_dir: katalog z modelem ONNX (domyślnie ~/.bgml/models/embeddings).
        min_sim: próg cosine similarity (domyślnie DEFAULT_MIN_SIM=0.82).
        min_len: minimalny len odpowiedzi.

    Returns:
        lookup_fn: callable(question: str) → Optional[str]

    Fail-safe: błąd ładowania embeddera → None zawsze (nie crash).

    Przykład:
        from cacheback.koryto_sources import minilm_factbase_source, multi_source
        from cacheback.koryto import Koryto, FactBase

        atoms = [("How to sort a list?", "lst.sort()"), ...]
        lookup = minilm_factbase_source(atoms)
        koryto = Koryto(fact_base=FactBase(lookup_fn=lookup))
    """
    import numpy as np

    try:
        if embedder is None:
            from cacheback.embedders import get_embedder
            embedder = get_embedder("minilm", cache_dir=cache_dir)
        pairs = [(str(q), str(a)) for q, a in atoms if q and a]
        if not pairs:
            return lambda q: None
        questions = [q for q, _ in pairs]
        # encode_batch w chunkach po 8 - unikamy OOM na duzych bazach
        CHUNK = 8
        vecs = []
        for i in range(0, len(questions), CHUNK):
            vecs.extend(embedder.encode_batch(questions[i:i + CHUNK]))
        mat = np.array(vecs, dtype=np.float32)  # (N, 384), L2-norm
    except Exception:
        return lambda q: None

    def fn(question: str) -> Optional[str]:
        try:
            qv = np.array(embedder.encode(question), dtype=np.float32)
            sims = mat @ qv
            i = int(np.argmax(sims))
            atom = pairs[i][1]
            return atom if _quality_ok(atom, float(sims[i]), min_sim, min_len) else None
        except Exception:
            return None

    return fn


def minilm_factbase_from_jsonl(
    path: str,
    *,
    q_field: str = "q",
    a_field: str = "a",
    embedder=None,
    cache_dir: str = "C:/Users/bogum/.bgml/models/embeddings",
    min_sim: float = DEFAULT_MIN_SIM,
) -> "Callable[[str], Optional[str]]":
    """Wygodny wrapper: wczytaj atomy z pliku JSONL i zbuduj minilm_factbase_source.

    Format pliku: jedna linia = JSON {"q": "pytanie", "a": "odpowiedź", ...}.
    Ignoruje linie bez q_field / a_field.

    Przykład:
        lookup = minilm_factbase_from_jsonl("E:/atoms/conala/conala_atoms.jsonl")
        koryto = Koryto(fact_base=FactBase(lookup_fn=lookup))
    """
    import json
    from pathlib import Path

    p = Path(path)
    atoms = []
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                q, a = r.get(q_field, ""), r.get(a_field, "")
                if q and a:
                    atoms.append((q, a))
            except Exception:
                continue
    return minilm_factbase_source(atoms, embedder=embedder, cache_dir=cache_dir, min_sim=min_sim)


# ---------------------------------------------------------------------------
# Multi-source: pytaj WSZYSTKIE, weź pierwszy przechodzący bramkę jakości
# ---------------------------------------------------------------------------

def multi_source(sources: Sequence[Callable[[str], Optional[str]]]) -> Callable[[str], Optional[str]]:
    """Złóż wiele lookup_fn w jeden. Pyta po kolei (priorytet = kolejność),
    zwraca pierwszy atom przechodzący bramkę jakości danego źródła. None gdy żadne.

    Użycie:
        from cacheback.koryto_sources import http_cache_source, chroma_source, multi_source
        from cacheback.koryto import Koryto, FactBase

        lookup = multi_source([
            http_cache_source("http://vps:8000/v1/cache", api_key=KEY),   # 4M, główne
            chroma_source("http://gtx:8775", "coding_cache_v1_id"),       # coding, po filtrze MCQ
        ])
        koryto = Koryto(fact_base=FactBase(lookup_fn=lookup))
    """
    srcs = [s for s in sources if s is not None]

    def fn(question: str) -> Optional[str]:
        for src in srcs:
            try:
                atom = src(question)
            except Exception:
                atom = None
            if atom is not None:
                return atom
        return None

    return fn
