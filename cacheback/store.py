"""Cache store — SQLite backend for cached query-response pairs.

Simplified schema vs orchestrator: no domain/framework/source_node fields.
Added modality column for multimodal cache support.
"""

import json
import logging
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

DEFAULT_TTL_SECONDS = 24 * 3600  # 24 hours (conservative vs bgml-cache's 7 days)

# Current schema version — increment when adding migrations
SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS cache_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    query_text TEXT NOT NULL,
    response_text TEXT NOT NULL,
    embedding BLOB NOT NULL,
    model TEXT DEFAULT '',
    tokens INTEGER DEFAULT 0,
    modality TEXT DEFAULT 'text',
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    hit_count INTEGER DEFAULT 0,
    last_hit_at REAL DEFAULT 0.0,
    metadata TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_cache_expires ON cache_entries(expires_at);
CREATE INDEX IF NOT EXISTS idx_cache_modality ON cache_entries(modality);
"""

META_SCHEMA = """
CREATE TABLE IF NOT EXISTS cacheback_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

# Migrations: list of (from_version, to_version, SQL) tuples.
# Add new migrations here when schema changes.
MIGRATIONS: list[tuple[int, int, str]] = [
    # Example for future use:
    # (1, 2, "ALTER TABLE cache_entries ADD COLUMN namespace TEXT DEFAULT ''"),
]


@dataclass
class CacheEntry:
    id: int
    query_text: str
    response_text: str
    model: str = ""
    tokens: int = 0
    modality: str = "text"
    created_at: float = 0.0
    expires_at: float = 0.0
    hit_count: int = 0
    metadata: dict = field(default_factory=dict)


class CacheStore:
    """SQLite-based cache storage with TTL and eviction."""

    def __init__(self, db_path: str, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self._db_path = db_path
        self._ttl_seconds = ttl_seconds
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.RLock()

    def _ensure_db(self):
        if self._conn is not None:
            return
        with self._lock:
            if self._conn is not None:
                return
            self._init_db()

    def _init_db(self):
        os.makedirs(os.path.dirname(self._db_path) or ".", exist_ok=True)
        try:
            self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.executescript(SCHEMA)
            self._conn.executescript(META_SCHEMA)
            self._run_migrations()
        except sqlite3.DatabaseError as exc:
            logger.warning(
                "[cacheback] Corrupt database %s: %s — recreating", self._db_path, exc
            )
            if self._conn:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None
            try:
                os.remove(self._db_path)
            except OSError:
                pass
            self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.executescript(SCHEMA)
            self._conn.executescript(META_SCHEMA)
            self._run_migrations()

    def _get_schema_version(self) -> int:
        """Read current schema version from meta table."""
        try:
            row = self._conn.execute(
                "SELECT value FROM cacheback_meta WHERE key = 'schema_version'"
            ).fetchone()
            return int(row[0]) if row else 0
        except (sqlite3.OperationalError, ValueError):
            return 0

    def _set_schema_version(self, version: int) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO cacheback_meta (key, value) VALUES ('schema_version', ?)",
            (str(version),),
        )
        self._conn.commit()

    def _run_migrations(self) -> None:
        """Run pending schema migrations."""
        current = self._get_schema_version()
        if current >= SCHEMA_VERSION and not MIGRATIONS:
            if current == 0:
                self._set_schema_version(SCHEMA_VERSION)
            return
        for from_ver, to_ver, sql in MIGRATIONS:
            if current < to_ver:
                logger.info("[cacheback] Migrating schema v%d → v%d", from_ver, to_ver)
                self._conn.executescript(sql)
                current = to_ver
        self._set_schema_version(max(current, SCHEMA_VERSION))

    def store(
        self,
        query_text: str,
        response_text: str,
        embedding: np.ndarray,
        model: str = "",
        tokens: int = 0,
        modality: str = "text",
        ttl_seconds: Optional[int] = None,
        metadata: Optional[dict] = None,
    ) -> int:
        self._ensure_db()
        now = time.time()
        ttl = ttl_seconds if ttl_seconds is not None else self._ttl_seconds
        with self._lock:
            cursor = self._conn.execute(
                """INSERT INTO cache_entries
                   (query_text, response_text, embedding, model, tokens, modality,
                    created_at, expires_at, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    query_text[:500],
                    response_text,
                    embedding.tobytes(),
                    model,
                    tokens,
                    modality,
                    now,
                    now + ttl,
                    json.dumps(metadata or {}),
                ),
            )
            self._conn.commit()
            return cursor.lastrowid

    def get(self, cache_id: int) -> Optional[CacheEntry]:
        self._ensure_db()
        row = self._conn.execute(
            """SELECT id, query_text, response_text, model, tokens, modality,
                      created_at, expires_at, hit_count, metadata
               FROM cache_entries WHERE id = ? AND expires_at > ?""",
            (cache_id, time.time()),
        ).fetchone()
        if not row:
            return None
        return CacheEntry(
            id=row[0], query_text=row[1], response_text=row[2],
            model=row[3], tokens=row[4], modality=row[5],
            created_at=row[6], expires_at=row[7], hit_count=row[8],
            metadata=json.loads(row[9]) if row[9] else {},
        )

    def record_hit(self, cache_id: int) -> None:
        self._ensure_db()
        with self._lock:
            self._conn.execute(
                "UPDATE cache_entries SET hit_count = hit_count + 1, last_hit_at = ? WHERE id = ?",
                (time.time(), cache_id),
            )
            self._conn.commit()

    def evict_expired(self) -> int:
        self._ensure_db()
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM cache_entries WHERE expires_at < ?", (time.time(),)
            )
            self._conn.commit()
            return cursor.rowcount

    def evict_lru(self, max_entries: int) -> int:
        self._ensure_db()
        with self._lock:
            total = self._conn.execute(
                "SELECT COUNT(*) FROM cache_entries WHERE expires_at > ?",
                (time.time(),),
            ).fetchone()[0]
            if total <= max_entries:
                return 0
            excess = total - max_entries
            cursor = self._conn.execute(
                """DELETE FROM cache_entries WHERE id IN (
                    SELECT id FROM cache_entries WHERE expires_at > ?
                    ORDER BY last_hit_at ASC, created_at ASC LIMIT ?
                )""",
                (time.time(), excess),
            )
            self._conn.commit()
            return cursor.rowcount

    def get_total_entries(self) -> int:
        self._ensure_db()
        row = self._conn.execute(
            "SELECT COUNT(*) FROM cache_entries WHERE expires_at > ?",
            (time.time(),),
        ).fetchone()
        return row[0] if row else 0

    def get_all_embeddings(self, dim: int) -> list[tuple[int, np.ndarray]]:
        """Get all valid embeddings for index rebuilding."""
        self._ensure_db()
        cursor = self._conn.execute(
            "SELECT id, embedding FROM cache_entries WHERE expires_at > ?",
            (time.time(),),
        )
        results = []
        for row in cursor:
            cache_id, emb_bytes = row
            vec = np.frombuffer(emb_bytes, dtype=np.float32)
            if vec.shape[0] == dim:
                results.append((cache_id, vec))
        return results

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None
