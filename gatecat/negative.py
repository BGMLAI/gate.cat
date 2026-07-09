"""Negative cache — blocks known-bad query patterns.

Stores queries that produced hallucinations, refusals, or other bad outputs.
When a similar query is detected, it can be blocked before calling the upstream API.

Usage:
    cache.negative.add("What is the airspeed of an unladen swallow?", reason="hallucination")
    cache.negative.check("airspeed of swallows")  # → match dict or None
    cache.negative.list(limit=50)                  # → list of entries
    cache.negative.remove(entry_id=42)             # → bool
"""

import json
import logging
import os
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

from gatecat.embedders import BaseEmbedder
from gatecat.index import VectorIndex

logger = logging.getLogger(__name__)


def _safe_json(raw) -> dict:
    """Parse metadata JSON with resilience to corruption (audit 2026-06-27 #6/#7).
    Corrupted JSON in the metadata column (DB corruption / manual SQL) must NOT crash
    the public list()/_get_entry() — fall back to {}."""
    if not raw:
        return {}
    try:
        v = json.loads(raw)
        return v if isinstance(v, dict) else {}
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}


NEGATIVE_SCHEMA = """
CREATE TABLE IF NOT EXISTS negative_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    query_text TEXT NOT NULL,
    reason TEXT DEFAULT '',
    category TEXT DEFAULT 'general',
    severity INTEGER DEFAULT 1,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    hit_count INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    metadata TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_neg_expires ON negative_entries(expires_at);
CREATE INDEX IF NOT EXISTS idx_neg_category ON negative_entries(category);
"""

DEFAULT_NEGATIVE_TTL = 30 * 24 * 3600  # 30 days (longer than positive cache)
MAX_FALSE_POSITIVES = 5  # auto-remove after this many false positives


@dataclass
class NegativeEntry:
    id: int
    query_text: str
    reason: str = ""
    category: str = "general"
    severity: int = 1
    created_at: float = 0.0
    expires_at: float = 0.0
    hit_count: int = 0
    false_positives: int = 0
    metadata: dict = field(default_factory=dict)


class NegativeCacheAPI:
    """API for managing the negative (blocklist) cache.

    The negative cache uses a separate SQLite DB and vector index
    from the positive cache, with a lower similarity threshold (0.85 vs 0.92).
    """

    def __init__(
        self,
        cache_dir: str,
        embedder: BaseEmbedder,
        threshold: float = 0.85,
        ttl_seconds: int = DEFAULT_NEGATIVE_TTL,
    ):
        self._cache_dir = cache_dir
        self._embedder = embedder
        self._threshold = threshold
        self._ttl_seconds = ttl_seconds

        neg_dir = os.path.join(cache_dir, "negative")
        self._index = VectorIndex(
            dim=embedder.dim,
            index_path=os.path.join(neg_dir, "neg_index.bin"),
        )
        self._db_path = os.path.join(neg_dir, "negative.db")
        self._conn: Optional[sqlite3.Connection] = None
        self._initialized = False

    def _ensure_db(self):
        if self._conn is not None:
            return
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(NEGATIVE_SCHEMA)

    def _lazy_init(self):
        if self._initialized:
            return
        self._initialized = True
        self._ensure_db()

        # Rebuild index from store
        cursor = self._conn.execute(
            "SELECT id, query_text FROM negative_entries WHERE expires_at > ?",
            (time.time(),),
        )
        rebuilt = 0
        for row in cursor:
            entry_id, query_text = row
            try:
                vec = self._embedder.encode(query_text)
                self._index.add(vec, entry_id)
                rebuilt += 1
            except Exception as exc:
                logger.warning(
                    "[gatecat] Negative cache: failed to embed entry %d: %s",
                    entry_id, exc,
                )
        if rebuilt > 0:
            logger.info("[gatecat] Negative cache: rebuilt %d entries", rebuilt)

    def add(
        self,
        query: str,
        reason: str = "",
        category: str = "general",
        severity: int = 1,
        metadata: Optional[dict] = None,
    ) -> int:
        """Add a query pattern to the negative cache.

        Args:
            query: The query text to block.
            reason: Why this query is blocked (e.g., "hallucination", "refusal").
            category: Category of the bad pattern.
            severity: 1-5 severity level.
            metadata: Additional metadata.

        Returns:
            The entry ID.
        """
        self._lazy_init()

        embedding = self._embedder.encode(query)

        # Skip if already in negative cache
        existing = self._index.search(embedding, k=1, threshold=0.98)
        if existing:
            return existing[0][0]

        now = time.time()
        cursor = self._conn.execute(
            """INSERT INTO negative_entries
               (query_text, reason, category, severity, created_at, expires_at, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                query[:500],
                reason,
                category,
                severity,
                now,
                now + self._ttl_seconds,
                json.dumps(metadata or {}),
            ),
        )
        self._conn.commit()
        entry_id = cursor.lastrowid

        self._index.add(embedding, entry_id)
        logger.debug("[gatecat] Negative cache: added entry %d: %s", entry_id, query[:80])
        return entry_id

    def check(self, query: str) -> Optional[dict]:
        """Check if a query matches the negative cache.

        Args:
            query: The query text to check.

        Returns:
            Dict with match info on HIT, None on MISS.
        """
        self._lazy_init()
        embedding = self._embedder.encode(query)
        return self.check_embedding(embedding)

    def check_embedding(self, embedding: np.ndarray) -> Optional[dict]:
        """Check negative cache using a pre-computed embedding.

        Args:
            embedding: Pre-computed query embedding vector.

        Returns:
            Dict with match info on HIT, None on MISS.
        """
        if not self._initialized:
            self._lazy_init()

        results = self._index.search(embedding, k=1, threshold=self._threshold)
        if not results:
            return None

        entry_id, similarity = results[0]
        entry = self._get_entry(entry_id)
        if not entry:
            return None

        # Auto-remove entries with too many false positives
        if entry.false_positives >= MAX_FALSE_POSITIVES:
            self.remove(entry_id)
            return None

        # Record hit
        self._conn.execute(
            "UPDATE negative_entries SET hit_count = hit_count + 1 WHERE id = ?",
            (entry_id,),
        )
        self._conn.commit()

        return {
            "entry_id": entry.id,
            "query_text": entry.query_text,
            "reason": entry.reason,
            "category": entry.category,
            "severity": entry.severity,
            "similarity": similarity,
            "hit_count": entry.hit_count + 1,
        }

    def list(self, limit: int = 50, category: Optional[str] = None) -> list[NegativeEntry]:
        """List negative cache entries.

        Args:
            limit: Maximum entries to return.
            category: Filter by category (optional).
        """
        self._ensure_db()
        if category:
            rows = self._conn.execute(
                """SELECT id, query_text, reason, category, severity,
                          created_at, expires_at, hit_count, false_positives, metadata
                   FROM negative_entries WHERE expires_at > ? AND category = ?
                   ORDER BY created_at DESC LIMIT ?""",
                (time.time(), category, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                """SELECT id, query_text, reason, category, severity,
                          created_at, expires_at, hit_count, false_positives, metadata
                   FROM negative_entries WHERE expires_at > ?
                   ORDER BY created_at DESC LIMIT ?""",
                (time.time(), limit),
            ).fetchall()

        return [
            NegativeEntry(
                id=r[0], query_text=r[1], reason=r[2], category=r[3],
                severity=r[4], created_at=r[5], expires_at=r[6],
                hit_count=r[7], false_positives=r[8],
                metadata=_safe_json(r[9]),
            )
            for r in rows
        ]

    def remove(self, entry_id: int) -> bool:
        """Remove a negative cache entry.

        Args:
            entry_id: The entry ID to remove.

        Returns:
            True if removed, False if not found.
        """
        self._ensure_db()
        cursor = self._conn.execute(
            "DELETE FROM negative_entries WHERE id = ?", (entry_id,)
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def report_false_positive(self, entry_id: int) -> None:
        """Report a false positive for a negative cache entry."""
        self._ensure_db()
        self._conn.execute(
            "UPDATE negative_entries SET false_positives = false_positives + 1 WHERE id = ?",
            (entry_id,),
        )
        self._conn.commit()

    def _get_entry(self, entry_id: int) -> Optional[NegativeEntry]:
        self._ensure_db()
        row = self._conn.execute(
            """SELECT id, query_text, reason, category, severity,
                      created_at, expires_at, hit_count, false_positives, metadata
               FROM negative_entries WHERE id = ? AND expires_at > ?""",
            (entry_id, time.time()),
        ).fetchone()
        if not row:
            return None
        return NegativeEntry(
            id=row[0], query_text=row[1], reason=row[2], category=row[3],
            severity=row[4], created_at=row[5], expires_at=row[6],
            hit_count=row[7], false_positives=row[8],
            metadata=_safe_json(row[9]),
        )

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None
