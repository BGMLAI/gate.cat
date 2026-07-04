"""Negative cache tests."""

from cacheback.negative import NegativeCacheAPI


class TestNegativeCacheAPI:
    def test_add_and_check(self, tmp_cache_dir, mock_embedder):
        neg = NegativeCacheAPI(cache_dir=tmp_cache_dir, embedder=mock_embedder)
        entry_id = neg.add("bad query example here", reason="hallucination")
        assert isinstance(entry_id, int)
        assert entry_id > 0

        # Same query should hit
        result = neg.check("bad query example here")
        assert result is not None
        assert result["reason"] == "hallucination"
        assert result["entry_id"] == entry_id
        neg.close()

    def test_check_miss(self, tmp_cache_dir, mock_embedder):
        neg = NegativeCacheAPI(cache_dir=tmp_cache_dir, embedder=mock_embedder)
        result = neg.check("totally new query here")
        assert result is None
        neg.close()

    def test_add_with_category_and_severity(self, tmp_cache_dir, mock_embedder):
        neg = NegativeCacheAPI(cache_dir=tmp_cache_dir, embedder=mock_embedder)
        neg.add(
            "bad query example here",
            reason="refusal",
            category="safety",
            severity=3,
            metadata={"source": "user_report"},
        )
        entries = neg.list()
        assert len(entries) >= 1
        entry = entries[0]
        assert entry.reason == "refusal"
        assert entry.category == "safety"
        assert entry.severity == 3
        assert entry.metadata.get("source") == "user_report"
        neg.close()

    def test_add_skips_duplicate(self, tmp_cache_dir, mock_embedder):
        neg = NegativeCacheAPI(cache_dir=tmp_cache_dir, embedder=mock_embedder)
        id1 = neg.add("bad query example here", reason="hallucination")
        id2 = neg.add("bad query example here", reason="different reason")
        # Near-duplicate should return existing ID
        assert id1 == id2
        neg.close()

    def test_list_all(self, tmp_cache_dir, mock_embedder):
        neg = NegativeCacheAPI(cache_dir=tmp_cache_dir, embedder=mock_embedder)
        neg.add("bad query one example", reason="r1")
        neg.add("bad query two example", reason="r2", category="safety")
        entries = neg.list()
        assert len(entries) == 2
        neg.close()

    def test_list_by_category(self, tmp_cache_dir, mock_embedder):
        neg = NegativeCacheAPI(cache_dir=tmp_cache_dir, embedder=mock_embedder)
        neg.add("bad query one example", reason="r1", category="general")
        neg.add("bad query two example", reason="r2", category="safety")
        entries = neg.list(category="safety")
        assert len(entries) == 1
        assert entries[0].category == "safety"
        neg.close()

    def test_remove(self, tmp_cache_dir, mock_embedder):
        neg = NegativeCacheAPI(cache_dir=tmp_cache_dir, embedder=mock_embedder)
        entry_id = neg.add("bad query example here", reason="test")
        removed = neg.remove(entry_id)
        assert removed is True
        # Should not find it anymore in the DB
        entries = neg.list()
        assert len(entries) == 0
        neg.close()

    def test_remove_nonexistent(self, tmp_cache_dir, mock_embedder):
        neg = NegativeCacheAPI(cache_dir=tmp_cache_dir, embedder=mock_embedder)
        removed = neg.remove(99999)
        assert removed is False
        neg.close()

    def test_report_false_positive(self, tmp_cache_dir, mock_embedder):
        neg = NegativeCacheAPI(cache_dir=tmp_cache_dir, embedder=mock_embedder)
        entry_id = neg.add("bad query example here", reason="test")
        neg.report_false_positive(entry_id)
        entries = neg.list()
        assert entries[0].false_positives == 1
        neg.close()

    def test_auto_remove_after_max_false_positives(self, tmp_cache_dir, mock_embedder):
        neg = NegativeCacheAPI(cache_dir=tmp_cache_dir, embedder=mock_embedder)
        entry_id = neg.add("bad query example here", reason="test")
        # Report 5 false positives (MAX_FALSE_POSITIVES = 5)
        for _ in range(5):
            neg.report_false_positive(entry_id)
        # check should auto-remove the entry
        result = neg.check("bad query example here")
        assert result is None
        neg.close()

    def test_hit_count_increments(self, tmp_cache_dir, mock_embedder):
        neg = NegativeCacheAPI(cache_dir=tmp_cache_dir, embedder=mock_embedder)
        neg.add("bad query example here", reason="test")
        result1 = neg.check("bad query example here")
        assert result1 is not None
        assert result1["hit_count"] == 1
        result2 = neg.check("bad query example here")
        assert result2["hit_count"] == 2
        neg.close()

    def test_corrupt_metadata_does_not_crash_list(self, tmp_cache_dir, mock_embedder):
        """audyt 2026-06-27 #6/#7: uszkodzony JSON w metadata (korupcja DB / ręczny SQL)
        NIE może crashować publicznego list() przez JSONDecodeError → fallback {}."""
        neg = NegativeCacheAPI(cache_dir=tmp_cache_dir, embedder=mock_embedder)
        entry_id = neg.add("bad query example here", reason="test")
        # wstrzyknij uszkodzony JSON bezpośrednio do kolumny metadata
        neg._conn.execute(
            "UPDATE negative_entries SET metadata = ? WHERE id = ?",
            ("INVALID_JSON{{{", entry_id),
        )
        neg._conn.commit()
        entries = neg.list()  # NIE może rzucić JSONDecodeError
        assert len(entries) == 1
        assert entries[0].metadata == {}  # fallback
        neg.close()


def test_safe_json_helper():
    """Unit: _safe_json odporne na każdy zły wejściowy JSON."""
    from cacheback.negative import _safe_json
    assert _safe_json('{"a": 1}') == {"a": 1}
    assert _safe_json("INVALID{{{") == {}
    assert _safe_json("") == {}
    assert _safe_json(None) == {}
    assert _safe_json("[1,2,3]") == {}   # nie-dict JSON → {}
    assert _safe_json("42") == {}        # skalar → {}
