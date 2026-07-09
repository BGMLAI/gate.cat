"""koryto_sources — real fact sources for the koryto lookup channel.

DIRECTIVE (REGISTER 2026-06-27): koryto-lookup MUST use ALL good-quality
databases, not a single validation one. This module builds `lookup_fn` (the callback
that FactBase accepts, koryto.py:193) that queries REAL databases with a QUALITY GATE.

SOURCES (inventoried live 2026-06-27):
  - 4M Q&A cache on the VPS (primary; recall 0.78-0.89 discriminable = good quality, prose).
  - ChromaDB GTX1070 `coding_cache_v1` (2074; ⚠️ contains MCQ → ONLY after the MCQ filter).
  - F-coding-cache D:/ (10 entries = empty skeleton → SKIPPED).

QUALITY GATE (without it a noisy database poisons lookup — gotcha: web noise hurts 2-3× more):
  1. similarity ≥ threshold (default 0.82 — accurate retrieval, not loose),
  2. MCQ filter (reject multiple-choice documents — they contaminate the measurement),
  3. reject empty / too-short atoms.

FAIL-SAFE: unavailable source → None (NOT a crash). Lookup simply does not know the atom.
The lookup channel is "soft" (needs_arbiter) — the web arbiter settles the dispute anyway.
"""
from __future__ import annotations

import re
from typing import Callable, Optional, Sequence

# default quality thresholds
DEFAULT_MIN_SIM = 0.82          # accurate retrieval (recall for hits 0.78-0.89; loose 0.25-0.45)
DEFAULT_MIN_ATOM_LEN = 3        # shorter atom = useless
DEFAULT_TIMEOUT = 8.0

# MCQ patterns — a document that looks like this contaminates lookup (conflicting options A/B/C)
_MCQ_RE = re.compile(r"(?:^|\n)\s*(?:Options?:|[A-J][\.\)]\s)", re.IGNORECASE)


def is_mcq(text: str) -> bool:
    """Whether the document is a multiple-choice question (MMLU-style). Such documents contaminate lookup."""
    if not text:
        return False
    # >=3 markers 'A. B. C.' or an explicit 'Options:' = MCQ
    markers = len(re.findall(r"(?:^|\n)\s*[A-J][\.\)]\s", text))
    return bool(_MCQ_RE.search(text)) and markers >= 3


def _quality_ok(atom: Optional[str], sim: float, min_sim: float, min_len: int) -> bool:
    """Quality gate: sim, length, non-MCQ."""
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
# Source 1: HTTP semantic cache (4M VPS or any gatecat-proxy /lookup)
# ---------------------------------------------------------------------------

def http_cache_source(
    base_url: str,
    *,
    api_key: str = "",
    min_sim: float = DEFAULT_MIN_SIM,
    timeout: float = DEFAULT_TIMEOUT,
) -> Callable[[str], Optional[str]]:
    """Build a lookup_fn that queries a semantic cache over HTTP.

    Expects an endpoint returning a cached answer + similarity. Tries:
      POST {base_url}/lookup {"query": q}  → {"answer"/"response", "similarity"}
    Fail-safe: any error/timeout/miss → None.
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
# Source 2: ChromaDB (GTX1070 coding_cache_v1 or local) — after the MCQ filter
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
    """Build a lookup_fn that queries ChromaDB v2 (cosine). Returns the top-1 document
    ONLY when: distance→sim ≥ threshold AND the document is NOT MCQ (contamination filter).
    Fail-safe: error/unavailable → None.
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
# Source 3: MiniLM local embedder over a static atom database (offline, 0 network latency)
# ---------------------------------------------------------------------------

def minilm_factbase_source(
    atoms: "Sequence[tuple[str, str]]",
    *,
    embedder=None,
    cache_dir: str = "C:/Users/bogum/.bgml/models/embeddings",
    min_sim: float = DEFAULT_MIN_SIM,
    min_len: int = DEFAULT_MIN_ATOM_LEN,
) -> "Callable[[str], Optional[str]]":
    """Build a lookup_fn from a local atom database (a list of (question, answer) pairs).

    Embeds the database questions once at build time (an N×384 matrix in RAM), then
    cosine per query: mat @ qv, argmax, threshold. Offline, deterministic,
    ~0ms network latency. Requires onnxruntime + tokenizers (system python3).

    Args:
        atoms: list of (question, answer) — database questions and expected answers.
        embedder: optional ready-made embedder (e.g. get_embedder('minilm')). When None,
                  loads a singleton from cache_dir.
        cache_dir: directory with the ONNX model (default ~/.bgml/models/embeddings).
        min_sim: cosine similarity threshold (default DEFAULT_MIN_SIM=0.82).
        min_len: minimum answer length.

    Returns:
        lookup_fn: callable(question: str) → Optional[str]

    Fail-safe: embedder loading error → always None (no crash).

    Example:
        from gatecat.koryto_sources import minilm_factbase_source, multi_source
        from gatecat.koryto import Koryto, FactBase

        atoms = [("How to sort a list?", "lst.sort()"), ...]
        lookup = minilm_factbase_source(atoms)
        koryto = Koryto(fact_base=FactBase(lookup_fn=lookup))
    """
    import numpy as np

    try:
        if embedder is None:
            from gatecat.embedders import get_embedder
            embedder = get_embedder("minilm", cache_dir=cache_dir)
        pairs = [(str(q), str(a)) for q, a in atoms if q and a]
        if not pairs:
            return lambda q: None
        questions = [q for q, _ in pairs]
        # encode_batch in chunks of 8 - avoids OOM on large databases
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
    """Convenience wrapper: load atoms from a JSONL file and build minilm_factbase_source.

    File format: one line = JSON {"q": "question", "a": "answer", ...}.
    Ignores lines without q_field / a_field.

    Example:
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
# Multi-source: query ALL, take the first one that passes the quality gate
# ---------------------------------------------------------------------------

def multi_source(sources: Sequence[Callable[[str], Optional[str]]]) -> Callable[[str], Optional[str]]:
    """Compose multiple lookup_fn into one. Queries them in order (priority = order),
    returns the first atom that passes a given source's quality gate. None when none do.

    Usage:
        from gatecat.koryto_sources import http_cache_source, chroma_source, multi_source
        from gatecat.koryto import Koryto, FactBase

        lookup = multi_source([
            http_cache_source("http://vps:8000/v1/cache", api_key=KEY),   # 4M, primary
            chroma_source("http://gtx:8775", "coding_cache_v1_id"),       # coding, after the MCQ filter
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
