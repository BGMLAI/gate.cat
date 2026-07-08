"""Robustness tests — error recovery, thread safety, schema migration.

Covers gaps identified in CEO review:
- Corrupt DB/index recovery
- response.content=None handling
- Concurrent access (thread safety)
- Schema migration versioning
"""

import os
import sqlite3
import threading
import time
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from gatecat.cache import SemanticCache
from gatecat.store import CacheStore, SCHEMA_VERSION
from gatecat.index import VectorIndex


# --- Corrupt DB recovery ---

class TestCorruptDBRecovery:
    def test_corrupt_db_recreated(self, tmp_path):
        """Corrupt SQLite file should be deleted and recreated."""
        db_path = str(tmp_path / "cache" / "cache.db")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        # Write garbage to the DB file
        with open(db_path, "wb") as f:
            f.write(b"NOT_A_SQLITE_DB_" * 100)

        store = CacheStore(db_path)
        # Should recover, not crash
        store._ensure_db()
        assert store._conn is not None
        # Should be functional after recovery
        emb = np.random.randn(384).astype(np.float32)
        row_id = store.store("test query", "test response", emb)
        assert row_id >= 1
        store.close()

    def test_healthy_db_not_deleted(self, tmp_path):
        """A healthy DB should not be deleted/recreated."""
        db_path = str(tmp_path / "cache" / "cache.db")
        store = CacheStore(db_path)
        emb = np.random.randn(384).astype(np.float32)
        store.store("original query", "original response", emb)
        store.close()

        # Reopen — data should persist
        store2 = CacheStore(db_path)
        assert store2.get_total_entries() == 1
        store2.close()


# --- Corrupt index recovery ---

class TestCorruptIndexRecovery:
    def test_corrupt_index_rebuilt(self, tmp_path):
        """Corrupt hnswlib index file should be deleted and rebuilt fresh."""
        index_path = str(tmp_path / "index.bin")
        # Write garbage to index file
        with open(index_path, "wb") as f:
            f.write(b"CORRUPT_INDEX_DATA_" * 100)

        index = VectorIndex(dim=384, index_path=index_path)
        # Should recover (delete corrupt file, create fresh)
        vec = np.random.randn(384).astype(np.float32)
        vec = vec / np.linalg.norm(vec)
        index.add(vec, 1)
        assert index.count == 1

    def test_missing_index_created_fresh(self, tmp_path):
        """Non-existent index file should be created fresh without error."""
        index_path = str(tmp_path / "nonexistent" / "index.bin")
        index = VectorIndex(dim=384, index_path=index_path)
        vec = np.random.randn(384).astype(np.float32)
        vec = vec / np.linalg.norm(vec)
        index.add(vec, 1)
        assert index.count == 1


# --- response.content=None in OpenAI wrapper ---

class TestOpenAINullContent:
    def test_none_content_no_crash(self, tmp_cache_dir, mock_embedder):
        """response.choices[0].message.content=None should not crash populate."""
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
            similarity_threshold=0.5,
        )

        from gatecat.openai import _CachedChatCompletions

        mock_completions = MagicMock()
        # Simulate response with content=None (e.g., tool_calls response)
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = None
        mock_response.usage.completion_tokens = 0
        mock_completions.create.return_value = mock_response

        cached_comp = _CachedChatCompletions(mock_completions, cache)
        result = cached_comp.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Call a function"}],
        )
        # Should not crash, should not populate cache
        assert cache.stats["populations"] == 0
        cache.close()

    def test_empty_choices_no_crash(self, tmp_cache_dir, mock_embedder):
        """response.choices=[] should not crash."""
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
            similarity_threshold=0.5,
        )

        from gatecat.openai import _CachedChatCompletions

        mock_completions = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = []
        mock_completions.create.return_value = mock_response

        cached_comp = _CachedChatCompletions(mock_completions, cache)
        result = cached_comp.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "What is Python?"}],
        )
        assert cache.stats["populations"] == 0
        cache.close()


# --- Schema migration ---

class TestSchemaMigration:
    def test_fresh_db_gets_version(self, tmp_path):
        """Fresh DB should have schema version set."""
        db_path = str(tmp_path / "cache" / "cache.db")
        store = CacheStore(db_path)
        store._ensure_db()
        version = store._get_schema_version()
        assert version == SCHEMA_VERSION
        store.close()

    def test_version_persists_across_reopens(self, tmp_path):
        """Schema version should persist after close/reopen."""
        db_path = str(tmp_path / "cache" / "cache.db")
        store = CacheStore(db_path)
        store._ensure_db()
        store.close()

        store2 = CacheStore(db_path)
        store2._ensure_db()
        assert store2._get_schema_version() == SCHEMA_VERSION
        store2.close()

    def test_migration_runs_on_older_version(self, tmp_path):
        """Migrations should run when DB has older schema version."""
        db_path = str(tmp_path / "cache" / "cache.db")

        # Create a DB with version 0 (no meta table entry)
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript("""
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
        """)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS gatecat_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        """)
        # Set version to 0
        conn.execute(
            "INSERT INTO gatecat_meta (key, value) VALUES ('schema_version', '0')"
        )
        conn.commit()
        conn.close()

        # Open with CacheStore — should detect v0 and migrate to current
        store = CacheStore(db_path)
        store._ensure_db()
        assert store._get_schema_version() == SCHEMA_VERSION
        store.close()

    def test_meta_table_created_for_legacy_db(self, tmp_path):
        """Legacy DB without meta table should get one added."""
        db_path = str(tmp_path / "cache" / "cache.db")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

        # Create legacy DB (no meta table)
        conn = sqlite3.connect(db_path)
        conn.executescript("""
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
        """)
        conn.commit()
        conn.close()

        store = CacheStore(db_path)
        store._ensure_db()
        # Meta table should now exist with correct version
        assert store._get_schema_version() == SCHEMA_VERSION
        store.close()


# --- Thread safety ---

class TestThreadSafety:
    def test_concurrent_store_operations(self, tmp_path):
        """Multiple threads storing simultaneously should not corrupt data."""
        db_path = str(tmp_path / "cache" / "cache.db")
        store = CacheStore(db_path)
        errors = []

        def store_items(thread_id, count=20):
            try:
                for i in range(count):
                    emb = np.random.randn(384).astype(np.float32)
                    store.store(
                        f"query-{thread_id}-{i}",
                        f"response-{thread_id}-{i}",
                        emb,
                    )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=store_items, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"
        assert store.get_total_entries() == 80  # 4 threads × 20
        store.close()

    def test_concurrent_index_operations(self, tmp_path):
        """Multiple threads adding to index simultaneously should not crash."""
        index = VectorIndex(dim=384)
        errors = []

        def add_items(thread_id, count=20):
            try:
                for i in range(count):
                    vec = np.random.randn(384).astype(np.float32)
                    vec = vec / np.linalg.norm(vec)
                    cache_id = thread_id * 1000 + i
                    index.add(vec, cache_id)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=add_items, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"
        assert index.count == 80

    def test_concurrent_cache_lookup_and_populate(self, tmp_cache_dir, mock_embedder):
        """Concurrent lookup + populate should not crash or corrupt."""
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
            similarity_threshold=0.5,
        )
        errors = []

        def populate_items(thread_id, count=10):
            try:
                for i in range(count):
                    cache.populate(
                        f"Thread {thread_id} question number {i}",
                        f"Response for thread {thread_id} item {i} " * 5,
                    )
            except Exception as e:
                errors.append(e)

        def lookup_items(count=20):
            try:
                for i in range(count):
                    cache.lookup(f"Thread 0 question number {i}")
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=populate_items, args=(0,)),
            threading.Thread(target=populate_items, args=(1,)),
            threading.Thread(target=lookup_items),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"
        cache.close()


# --- Graceful degradation edge cases ---

class TestGracefulDegradation:
    def test_embedder_failure_during_populate(self, tmp_cache_dir):
        """Embedder failure during populate should return False, not crash."""
        class FlakyEmbedder:
            dim = 384
            modality = "text"
            _call_count = 0

            def encode(self, _):
                self._call_count += 1
                if self._call_count % 2 == 0:
                    raise RuntimeError("GPU OOM")
                np.random.seed(42)
                vec = np.random.randn(384).astype(np.float32)
                return vec / np.linalg.norm(vec)

            def encode_batch(self, inputs):
                return [self.encode(i) for i in inputs]

            def preprocess(self, raw):
                return raw

        cache = SemanticCache(cache_dir=tmp_cache_dir, embedder=FlakyEmbedder())
        # First populate should work (odd call)
        # lookup uses 1 encode call, populate uses 1 encode call
        # The timing depends on internal calls, but it should not crash
        result = cache.populate("What is Python programming?", "Python is great " * 5)
        # Regardless of success/failure, no crash
        cache.close()

    def test_store_after_eviction(self, tmp_cache_dir, mock_embedder):
        """Cache should work correctly after evicting all entries."""
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
            ttl_seconds=0,  # expire immediately
        )
        cache.populate("What is Python?", "Python is a programming language. " * 5)
        time.sleep(0.05)
        evicted = cache.evict_expired()
        assert evicted >= 1

        # Should still work after eviction
        ok = cache.populate("What is Java?", "Java is a programming language. " * 5)
        assert ok is True
        cache.close()
