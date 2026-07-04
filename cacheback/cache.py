"""Semantic Cache — the kernel.

Orchestrates embedder + vector index + store to provide:
  - lookup(query) → Optional[str]  (cache HIT or None)
  - populate(query, response) → None  (store for future queries)

Supports pluggable embedders for multimodal caching (text, image, voice).
"""

import logging
import os
import time
from typing import Any, Optional

import numpy as np

from cacheback.embedders import BaseEmbedder, get_embedder
from cacheback.index import VectorIndex
from cacheback.store import CacheStore

logger = logging.getLogger(__name__)

DEFAULT_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cacheback")
DEFAULT_THRESHOLD = 0.92
MIN_RESPONSE_LENGTH = 20


class SemanticCache:
    """Semantic cache — embed, search, store, retrieve.

    Args:
        cache_dir: Directory for SQLite DB, hnswlib index, and model files.
        similarity_threshold: Minimum cosine similarity for cache hit (0-1).
        negative_threshold: Minimum similarity for negative cache hit.
        max_entries: Maximum cache entries before LRU eviction.
        ttl_seconds: Time-to-live for cache entries (default: 24 hours).
        enabled: Set to False to disable caching (passthrough mode).
        embedder: Embedder name ("minilm", "clip", "clap", "whisper") or BaseEmbedder instance.
        on_negative_hit: Policy for negative cache hits ("raise", "skip", or callable).
    """

    def __init__(
        self,
        cache_dir: str = DEFAULT_CACHE_DIR,
        similarity_threshold: float = DEFAULT_THRESHOLD,
        negative_threshold: float = 0.85,
        max_entries: int = 100_000,
        ttl_seconds: int = 24 * 3600,
        enabled: bool = True,
        embedder: str | BaseEmbedder = "minilm",
        on_negative_hit: str = "raise",
    ):
        self._enabled = enabled
        self._threshold = similarity_threshold
        self._negative_threshold = negative_threshold
        self._cache_dir = cache_dir
        self._max_entries = max_entries
        self._on_negative_hit = on_negative_hit

        # Resolve embedder
        if isinstance(embedder, str):
            model_dir = os.path.join(cache_dir, "models")
            self._embedder = get_embedder(embedder, cache_dir=model_dir)
        else:
            self._embedder = embedder

        self._index = VectorIndex(
            dim=self._embedder.dim,
            index_path=os.path.join(cache_dir, "index.bin"),
        )
        self._store = CacheStore(
            db_path=os.path.join(cache_dir, "cache.db"),
            ttl_seconds=ttl_seconds,
        )

        # Negative cache (lazy import to avoid circular)
        self._negative = None

        # Metrics
        self._hits = 0
        self._misses = 0
        self._populations = 0
        self._initialized = False

    @property
    def negative(self):
        """Lazy-loaded negative cache API."""
        if self._negative is None:
            from cacheback.negative import NegativeCacheAPI
            self._negative = NegativeCacheAPI(
                cache_dir=self._cache_dir,
                embedder=self._embedder,
                threshold=self._negative_threshold,
            )
        return self._negative

    def _lazy_init(self):
        """Rebuild index from store on first use."""
        if self._initialized:
            return
        self._initialized = True

        entries = self._store.get_all_embeddings(self._embedder.dim)
        if entries and self._index.count == 0:
            logger.info("[cacheback] Rebuilding index from %d stored entries...", len(entries))
            for cache_id, vec in entries:
                self._index.add(vec, cache_id)
            logger.info("[cacheback] Rebuilt index: %d vectors", len(entries))

    def _embed(self, input_data: Any) -> np.ndarray:
        """Embed input data using the configured embedder, with graceful degradation."""
        try:
            return self._embedder.encode(input_data)
        except Exception as e:
            logger.error("[cacheback] Embedder failed: %s", e)
            raise

    def lookup(self, query: Any) -> Optional[str]:
        """Check cache for a semantically similar query.

        Args:
            query: The input data to look up (text string, PIL.Image, audio bytes, etc.)

        Returns:
            Cached response text on HIT, None on MISS.

        Raises:
            CachebackBlocked: If query matches negative cache and on_negative_hit="raise".
        """
        if not self._enabled:
            return None
        if isinstance(query, str) and (not query or len(query) < 5):
            return None

        try:
            self._lazy_init()
            start = time.time()

            embedding = self._embed(query)

            # Check negative cache first
            if self._negative is not None or self._on_negative_hit != "skip":
                neg_hit = self.negative.check_embedding(embedding)
                if neg_hit is not None:
                    from cacheback.exceptions import CachebackBlocked
                    if self._on_negative_hit == "raise":
                        raise CachebackBlocked(
                            query=str(query)[:200],
                            reason=neg_hit.get("reason", ""),
                            similarity=neg_hit.get("similarity", 0.0),
                        )
                    elif callable(self._on_negative_hit):
                        self._on_negative_hit(query, neg_hit)
                        return None
                    else:  # "skip"
                        return None

            # Positive cache lookup
            results = self._index.search(embedding, k=1, threshold=self._threshold)

            if not results:
                self._misses += 1
                return None

            cache_id, similarity = results[0]
            entry = self._store.get(cache_id)
            if not entry:
                self._misses += 1
                return None

            self._hits += 1
            self._store.record_hit(cache_id)
            latency = (time.time() - start) * 1000

            logger.debug(
                "[cacheback] HIT (sim=%.4f, %.1fms, hits=%d) %s",
                similarity, latency, entry.hit_count + 1, str(query)[:80],
            )
            return entry.response_text

        except Exception as e:
            from cacheback.exceptions import CachebackBlocked
            if isinstance(e, CachebackBlocked):
                raise
            # Graceful degradation: cache failure → passthrough
            logger.warning("[cacheback] Lookup failed, passing through: %s", e)
            self._misses += 1
            return None

    def lookup_for_synthesis(
        self,
        query: Any,
        threshold: float = 0.80,
        top_k: int = 5,
    ) -> list[tuple[int, float]]:
        """Find top-K cached entries for synthesis (lower threshold than verbatim).

        Used by CAS (Cache-Augmented Synthesis) to find similar cached Q&A pairs
        that can be synthesized into a fresh response.

        Args:
            query: The input to look up.
            threshold: Minimum similarity for synthesis candidates (default: 0.80).
            top_k: Maximum number of candidates to return.

        Returns:
            List of (cache_id, similarity) tuples, sorted by similarity descending.
            Empty list if disabled or no candidates found.
        """
        if not self._enabled:
            return []
        if isinstance(query, str) and (not query or len(query) < 5):
            return []

        try:
            self._lazy_init()
            embedding = self._embed(query)
            return self._index.search(embedding, k=top_k, threshold=threshold)
        except Exception as e:
            logger.warning("[cacheback] Synthesis lookup failed: %s", e)
            return []

    def get_entry(self, cache_id: int):
        """Get a cache entry by ID. Used by synthesis to retrieve Q&A pairs."""
        return self._store.get(cache_id)

    def populate(self, query: Any, response: str, model: str = "", tokens: int = 0) -> bool:
        """Add a response to the cache.

        Args:
            query: The original input (text, image, audio).
            response: The LLM/API response text to cache.
            model: Model name that generated the response.
            tokens: Number of tokens in the response.

        Returns:
            True if cached, False if skipped.
        """
        if not self._enabled:
            return False
        if not response or len(response) < MIN_RESPONSE_LENGTH:
            return False
        if isinstance(query, str) and (not query or len(query) < 5):
            return False

        try:
            self._lazy_init()

            embedding = self._embed(query)

            # Skip near-duplicates
            existing = self._index.search(embedding, k=1, threshold=0.98)
            if existing:
                return False

            modality = self._embedder.modality

            cache_id = self._store.store(
                query_text=str(query)[:500],
                response_text=response,
                embedding=embedding,
                model=model,
                tokens=tokens,
                modality=modality,
            )
            self._index.add(embedding, cache_id)
            self._populations += 1

            # LRU eviction if over limit
            if self._max_entries and self._index.count > self._max_entries:
                evicted = self._store.evict_lru(self._max_entries)
                # Re-sync licznika indeksu (audyt 2026-06-27 should-fix): evict_lru
                # kasuje ze store ale HNSW nie ma delete; bez dekrementu _count dryfował
                # od store → kolejne triggery eviction liczone na stałej liczbie.
                if evicted:
                    self._index._count = max(0, self._index._count - evicted)

            return True

        except Exception as e:
            # Graceful degradation: cache failure → don't crash the caller
            logger.warning("[cacheback] Populate failed: %s", e)
            return False

    def evict_expired(self) -> int:
        """Remove expired entries."""
        return self._store.evict_expired()

    @property
    def stats(self) -> dict:
        """Current cache statistics."""
        total = self._hits + self._misses
        return {
            "hits": self._hits,
            "misses": self._misses,
            "total_lookups": total,
            "hit_rate": self._hits / total if total > 0 else 0.0,
            "entries": self._store.get_total_entries() if self._initialized else 0,
            "populations": self._populations,
            "embedder": type(self._embedder).__name__,
            "modality": self._embedder.modality,
        }

    def save(self) -> None:
        """Persist index to disk."""
        self._index.save()

    def close(self) -> None:
        """Clean shutdown."""
        try:
            self.save()
        except Exception:
            pass
        self._store.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
