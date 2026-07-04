"""Vector index — HNSW-based approximate nearest neighbor search.

Dimension-agnostic: works with any embedder dimension (384, 512, etc.).
"""

import logging
import os
import threading
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

DEFAULT_EF_CONSTRUCTION = 200
DEFAULT_M = 16
DEFAULT_EF_SEARCH = 50
DEFAULT_MAX_ELEMENTS = 500_000


class VectorIndex:
    """HNSW vector index with thread-safe add/search and disk persistence."""

    def __init__(
        self,
        dim: int = 384,
        index_path: Optional[str] = None,
        max_elements: int = DEFAULT_MAX_ELEMENTS,
    ):
        self._dim = dim
        self._index_path = index_path
        self._max_elements = max_elements
        self._index = None
        self._count = 0
        self._lock = threading.Lock()

    def _ensure_index(self):
        if self._index is not None:
            return

        try:
            import hnswlib
        except ImportError:
            logger.warning("[cacheback] hnswlib not available, using brute-force fallback")
            self._index = _BruteForceIndex(self._dim)
            return

        if self._index_path and os.path.exists(self._index_path):
            try:
                self._index = hnswlib.Index(space="ip", dim=self._dim)
                self._index.load_index(self._index_path, max_elements=self._max_elements)
                self._count = self._index.get_current_count()
                self._index.set_ef(DEFAULT_EF_SEARCH)
                logger.info("[cacheback] Loaded %d vectors from %s", self._count, self._index_path)
                return
            except Exception as exc:
                logger.warning(
                    "[cacheback] Corrupt index %s: %s — rebuilding fresh",
                    self._index_path, exc,
                )
                try:
                    os.remove(self._index_path)
                except OSError:
                    pass

        self._index = hnswlib.Index(space="ip", dim=self._dim)
        self._index.init_index(
            max_elements=self._max_elements,
            ef_construction=DEFAULT_EF_CONSTRUCTION,
            M=DEFAULT_M,
        )
        self._index.set_ef(DEFAULT_EF_SEARCH)

    def add(self, embedding: np.ndarray, cache_id: int) -> None:
        with self._lock:
            self._ensure_index()
            if isinstance(self._index, _BruteForceIndex):
                self._index.add(embedding, cache_id)
                self._count += 1
                return
            if self._count >= self._max_elements:
                new_max = self._max_elements * 2
                self._index.resize_index(new_max)
                self._max_elements = new_max
            self._index.add_items(embedding.reshape(1, -1), np.array([cache_id]))
            self._count += 1

    def search(self, embedding: np.ndarray, k: int = 1, threshold: float = 0.92) -> list[tuple[int, float]]:
        with self._lock:
            self._ensure_index()
            if self._count == 0:
                return []
            if isinstance(self._index, _BruteForceIndex):
                return self._index.search(embedding, k, threshold)
            actual_k = min(k, self._count)
            labels, distances = self._index.knn_query(embedding.reshape(1, -1), k=actual_k)
            results = []
            for label, dist in zip(labels[0], distances[0]):
                similarity = 1.0 - dist
                if similarity >= threshold:
                    results.append((int(label), float(similarity)))
            results.sort(key=lambda x: x[1], reverse=True)
            return results

    def save(self) -> None:
        if self._index is None or not self._index_path:
            return
        if isinstance(self._index, _BruteForceIndex):
            return
        with self._lock:
            os.makedirs(os.path.dirname(self._index_path), exist_ok=True)
            self._index.save_index(self._index_path)

    @property
    def count(self) -> int:
        return self._count


class _BruteForceIndex:
    """Numpy brute-force fallback when hnswlib is unavailable."""

    def __init__(self, dim: int):
        self._dim = dim
        self._vectors: list[np.ndarray] = []
        self._ids: list[int] = []

    def add(self, embedding: np.ndarray, cache_id: int) -> None:
        self._vectors.append(embedding.astype(np.float32))
        self._ids.append(cache_id)

    def search(self, embedding: np.ndarray, k: int, threshold: float) -> list[tuple[int, float]]:
        if not self._vectors:
            return []
        mat = np.stack(self._vectors)
        query = embedding.astype(np.float32).reshape(1, -1)
        similarities = (mat @ query.T).flatten()
        results = []
        for i, sim in enumerate(similarities):
            if sim >= threshold:
                results.append((self._ids[i], float(sim)))
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:k]
