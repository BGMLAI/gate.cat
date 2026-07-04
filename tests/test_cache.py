"""Core semantic cache tests."""

from cacheback.cache import SemanticCache


class TestSemanticCache:
    def test_lookup_miss(self, tmp_cache_dir, mock_embedder):
        cache = SemanticCache(cache_dir=tmp_cache_dir, embedder=mock_embedder)
        result = cache.lookup("What is Python?")
        assert result is None
        assert cache.stats["misses"] == 1

    def test_populate_and_lookup_hit(self, tmp_cache_dir, mock_embedder):
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
            similarity_threshold=0.5,  # low for test reproducibility
        )
        # Populate
        ok = cache.populate("What is Python?", "Python is a programming language." * 2)
        assert ok is True
        assert cache.stats["populations"] == 1

        # Same query should hit
        result = cache.lookup("What is Python?")
        assert result is not None
        assert "Python" in result
        assert cache.stats["hits"] == 1

    def test_populate_skips_short_response(self, tmp_cache_dir, mock_embedder):
        cache = SemanticCache(cache_dir=tmp_cache_dir, embedder=mock_embedder)
        ok = cache.populate("test", "short")
        assert ok is False

    def test_populate_skips_short_query(self, tmp_cache_dir, mock_embedder):
        cache = SemanticCache(cache_dir=tmp_cache_dir, embedder=mock_embedder)
        ok = cache.populate("hi", "This is a long response that should work.")
        assert ok is False

    def test_populate_skips_duplicate(self, tmp_cache_dir, mock_embedder):
        cache = SemanticCache(cache_dir=tmp_cache_dir, embedder=mock_embedder)
        cache.populate("What is Python?", "Python is a programming language." * 2)
        ok = cache.populate("What is Python?", "Different response but same query" * 2)
        assert ok is False  # near-duplicate

    def test_disabled_cache(self, tmp_cache_dir, mock_embedder):
        cache = SemanticCache(cache_dir=tmp_cache_dir, embedder=mock_embedder, enabled=False)
        assert cache.lookup("anything") is None
        assert cache.populate("test query", "test response" * 5) is False

    def test_stats(self, tmp_cache_dir, mock_embedder):
        cache = SemanticCache(cache_dir=tmp_cache_dir, embedder=mock_embedder)
        stats = cache.stats
        assert stats["hits"] == 0
        assert stats["misses"] == 0
        assert stats["embedder"] == "MockEmbedder"
        assert stats["modality"] == "text"

    def test_context_manager(self, tmp_cache_dir, mock_embedder):
        with SemanticCache(cache_dir=tmp_cache_dir, embedder=mock_embedder) as cache:
            cache.lookup("test query here")
        # Should not raise

    def test_evict_expired(self, tmp_cache_dir, mock_embedder):
        import time
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
            ttl_seconds=0,  # expire immediately
        )
        cache.populate("What is Python?", "Python is a programming language." * 2)
        time.sleep(0.05)  # ensure expiry on Windows (low timer resolution)
        evicted = cache.evict_expired()
        assert evicted >= 1

    def test_graceful_degradation_on_embed_failure(self, tmp_cache_dir):
        """Cache should passthrough, not crash, when embedder fails."""
        class FailingEmbedder:
            dim = 384
            modality = "text"
            def encode(self, _):
                raise RuntimeError("Model not found")
            def encode_batch(self, inputs):
                raise RuntimeError("Model not found")
            def preprocess(self, raw):
                return raw

        cache = SemanticCache(cache_dir=tmp_cache_dir, embedder=FailingEmbedder())
        assert cache.lookup("test query here") is None  # no crash
        assert cache.populate("test query", "response" * 10) is False  # no crash
