"""CAS (Cache-Augmented Synthesis) tests -- SynthesisEngine + integration with wrappers."""

from unittest.mock import MagicMock, patch
import pytest

from cacheback.cache import SemanticCache
from cacheback.synthesis import (
    SynthesisEngine,
    SynthesisCandidate,
    SynthesisResult,
    SYNTHESIS_PROMPT,
)
from cacheback.openai import (
    _CachedChatCompletions,
    _CachedResponse,
)
from cacheback.anthropic import (
    _CachedMessages as _AnthropicCachedMessages,
    _CachedMessage as _AnthropicCachedMessage,
)


# --- Mock OpenAI response for synthesis LLM call ---

class MockSynthMessage:
    def __init__(self, content="Synthesized answer about photosynthesis."):
        self.content = content
        self.role = "assistant"


class MockSynthChoice:
    def __init__(self, content="Synthesized answer about photosynthesis."):
        self.index = 0
        self.message = MockSynthMessage(content)
        self.finish_reason = "stop"


class MockSynthUsage:
    def __init__(self):
        self.prompt_tokens = 100
        self.completion_tokens = 50
        self.total_tokens = 150


class MockSynthCompletion:
    def __init__(self, content="Synthesized answer about photosynthesis."):
        self.id = "chatcmpl-synth"
        self.model = "google/gemini-2.0-flash-lite-001"
        self.choices = [MockSynthChoice(content)]
        self.usage = MockSynthUsage()


# --- Mock OpenAI response for upstream calls ---

class MockUpstreamMessage:
    def __init__(self, content="Fresh upstream response about photosynthesis."):
        self.content = content
        self.role = "assistant"


class MockUpstreamChoice:
    def __init__(self, content="Fresh upstream response about photosynthesis."):
        self.index = 0
        self.message = MockUpstreamMessage(content)
        self.finish_reason = "stop"


class MockUpstreamUsage:
    def __init__(self):
        self.prompt_tokens = 50
        self.completion_tokens = 100
        self.total_tokens = 150


class MockUpstreamCompletion:
    def __init__(self, content="Fresh upstream response about photosynthesis."):
        self.id = "chatcmpl-upstream"
        self.model = "gpt-4o"
        self.choices = [MockUpstreamChoice(content)]
        self.usage = MockUpstreamUsage()


# --- SynthesisCandidate helpers ---

def make_candidates(n=3):
    """Create N synthesis candidates."""
    return [
        SynthesisCandidate(
            query=f"What is photosynthesis variant {i}?",
            response=f"Photosynthesis is the process by which plants convert sunlight into energy. Variant {i} detail here.",
            similarity=0.90 - i * 0.02,
            cache_id=100 + i,
        )
        for i in range(n)
    ]


# --- SynthesisEngine unit tests ---

class TestSynthesisEngine:
    def test_init_defaults(self):
        engine = SynthesisEngine()
        assert engine._model == "google/gemini-2.0-flash-lite-001"
        assert engine._max_tokens == 1024
        assert engine._temperature == 0.3
        assert engine._client is None

    def test_init_custom_params(self):
        engine = SynthesisEngine(
            model="local/phi-4-mini",
            base_url="http://localhost:8080/v1",
            api_key="test-key",
            max_tokens=512,
            temperature=0.5,
        )
        assert engine._model == "local/phi-4-mini"
        assert engine._base_url == "http://localhost:8080/v1"
        assert engine._api_key == "test-key"
        assert engine._max_tokens == 512

    def test_build_context_empty(self):
        engine = SynthesisEngine()
        assert engine._build_context([]) == ""

    def test_build_context_single(self):
        engine = SynthesisEngine()
        candidates = make_candidates(1)
        ctx = engine._build_context(candidates)
        assert "Expert Response #1" in ctx
        assert "similarity: 0.90" in ctx
        assert "photosynthesis" in ctx.lower()

    def test_build_context_multiple(self):
        engine = SynthesisEngine()
        candidates = make_candidates(3)
        ctx = engine._build_context(candidates)
        assert "Expert Response #1" in ctx
        assert "Expert Response #2" in ctx
        assert "Expert Response #3" in ctx

    def test_build_context_truncation(self):
        engine = SynthesisEngine()
        long_response = "x" * 5000
        candidates = [
            SynthesisCandidate(
                query="test",
                response=long_response,
                similarity=0.90,
                cache_id=1,
            )
        ]
        ctx = engine._build_context(candidates, max_chars=100)
        assert len(ctx) < 5000
        assert "..." in ctx

    def test_synthesize_empty_candidates(self):
        engine = SynthesisEngine()
        result = engine.synthesize("What is photosynthesis?", [])
        assert result.text == ""
        assert result.source == "miss"

    @patch("cacheback.synthesis.SynthesisEngine._get_client")
    def test_synthesize_success(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = MockSynthCompletion()
        mock_get_client.return_value = mock_client

        engine = SynthesisEngine()
        candidates = make_candidates(3)
        result = engine.synthesize("What is photosynthesis?", candidates)

        assert result.text == "Synthesized answer about photosynthesis."
        assert result.source == "synthesis"
        assert result.candidates_used == 3
        assert result.mean_similarity > 0
        assert result.latency_ms >= 0
        mock_client.chat.completions.create.assert_called_once()

    @patch("cacheback.synthesis.SynthesisEngine._get_client")
    def test_synthesize_llm_failure_returns_miss(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = Exception("API error")
        mock_get_client.return_value = mock_client

        engine = SynthesisEngine()
        candidates = make_candidates(3)
        result = engine.synthesize("What is photosynthesis?", candidates)

        assert result.text == ""
        assert result.source == "miss"

    @patch("cacheback.synthesis.SynthesisEngine._get_client")
    def test_synthesize_empty_response(self, mock_get_client):
        mock_completion = MockSynthCompletion(content="")
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_completion
        mock_get_client.return_value = mock_client

        engine = SynthesisEngine()
        candidates = make_candidates(2)
        result = engine.synthesize("What?", candidates)

        assert result.text == ""
        assert result.source == "synthesis"

    def test_prompt_template_has_placeholders(self):
        assert "{k}" in SYNTHESIS_PROMPT
        assert "{context}" in SYNTHESIS_PROMPT
        assert "{question}" in SYNTHESIS_PROMPT


# --- SynthesisResult tests ---

class TestSynthesisResult:
    def test_defaults(self):
        r = SynthesisResult(text="hello", source="synthesis")
        assert r.latency_ms == 0.0
        assert r.candidates_used == 0
        assert r.mean_similarity == 0.0
        assert r.model == ""
        assert r.tokens == 0


# --- Integration: OpenAI wrapper with synthesis ---

class TestOpenAISynthesisIntegration:
    def test_synthesis_tier_on_miss(self, tmp_cache_dir, mock_embedder):
        """When verbatim miss but synthesis candidates exist, return synthesized."""
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
            similarity_threshold=0.99,  # Very high -- forces verbatim miss
        )

        mock_completions = MagicMock()
        mock_synthesis = MagicMock()

        synth_result = SynthesisResult(
            text="Synthesized: photosynthesis is how plants make food.",
            source="synthesis",
            candidates_used=2,
            mean_similarity=0.85,
        )
        mock_synthesis.synthesize.return_value = synth_result
        mock_synthesis._threshold = 0.80
        mock_synthesis._top_k = 5

        cached_completions = _CachedChatCompletions(mock_completions, cache, mock_synthesis)

        # Patch lookup_for_synthesis to return fake candidates (mock embedder
        # produces random vectors per text, so real lookup wouldn't find matches)
        fake_candidates = [(1, 0.88), (2, 0.85)]
        fake_entry_1 = MagicMock(query_text="What is photosynthesis?", response_text="Plants convert sunlight." * 3)
        fake_entry_2 = MagicMock(query_text="How does photosynthesis work?", response_text="Chlorophyll captures light." * 3)
        cache.lookup_for_synthesis = MagicMock(return_value=fake_candidates)
        cache.get_entry = MagicMock(side_effect=lambda cid: {1: fake_entry_1, 2: fake_entry_2}[cid])

        result = cached_completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Explain photosynthesis to me"}],
        )

        # Should NOT call upstream
        mock_completions.create.assert_not_called()
        # Should be synthesis result
        assert result.cacheback_synthesized is True
        assert result.cacheback_hit is False
        cache.close()

    def test_no_synthesis_when_engine_is_none(self, tmp_cache_dir, mock_embedder):
        """Without synthesis engine, miss goes to upstream."""
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
            similarity_threshold=0.99,
        )

        mock_completions = MagicMock()
        mock_completions.create.return_value = MockUpstreamCompletion()

        # No synthesis engine (default)
        cached_completions = _CachedChatCompletions(mock_completions, cache)
        result = cached_completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Explain photosynthesis to me"}],
        )

        # Should call upstream (no synthesis tier)
        mock_completions.create.assert_called_once()
        assert result.cacheback_hit is False
        assert result.cacheback_synthesized is False
        cache.close()

    def test_synthesis_miss_falls_through_to_upstream(self, tmp_cache_dir, mock_embedder):
        """When synthesis returns empty text, fall through to upstream."""
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
            similarity_threshold=0.99,
        )

        mock_completions = MagicMock()
        mock_completions.create.return_value = MockUpstreamCompletion()

        mock_synthesis = MagicMock()
        mock_synthesis.synthesize.return_value = SynthesisResult(text="", source="miss")
        mock_synthesis._threshold = 0.80
        mock_synthesis._top_k = 5

        cached_completions = _CachedChatCompletions(mock_completions, cache, mock_synthesis)
        result = cached_completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Completely new topic nobody asked about before"}],
        )

        # Should fall through to upstream
        mock_completions.create.assert_called_once()
        cache.close()

    def test_streaming_synthesis(self, tmp_cache_dir, mock_embedder):
        """Streaming with synthesis should replay synthesized text as stream chunks."""
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
            similarity_threshold=0.99,
        )

        mock_completions = MagicMock()
        mock_synthesis = MagicMock()

        synth_result = SynthesisResult(
            text="Streamed synthesis output here.",
            source="synthesis",
            candidates_used=2,
        )
        mock_synthesis.synthesize.return_value = synth_result
        mock_synthesis._threshold = 0.80
        mock_synthesis._top_k = 5

        cached_completions = _CachedChatCompletions(mock_completions, cache, mock_synthesis)

        fake_candidates = [(1, 0.88)]
        fake_entry = MagicMock(query_text="Q", response_text="A" * 30)
        cache.lookup_for_synthesis = MagicMock(return_value=fake_candidates)
        cache.get_entry = MagicMock(return_value=fake_entry)

        stream = cached_completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Explain photosynthesis streaming"}],
            stream=True,
        )
        chunks = list(stream)

        # Should replay as stream: 1 content chunk + 1 stop chunk
        assert len(chunks) == 2
        assert chunks[0].choices[0].delta.content == "Streamed synthesis output here."
        assert chunks[1].choices[0].finish_reason == "stop"
        # Should NOT call upstream
        mock_completions.create.assert_not_called()
        cache.close()

    def test_verbatim_hit_takes_priority_over_synthesis(self, tmp_cache_dir, mock_embedder):
        """Verbatim hit (sim >= threshold) should return directly, not synthesize."""
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
            similarity_threshold=0.5,  # Low threshold to ensure hit
        )
        cache.populate("What is the capital of France?", "Paris is the capital of France." * 3)

        mock_completions = MagicMock()
        mock_synthesis = MagicMock()

        cached_completions = _CachedChatCompletions(mock_completions, cache, mock_synthesis)
        result = cached_completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "What is the capital of France?"}],
        )

        # Should NOT call synthesis
        mock_synthesis.synthesize.assert_not_called()
        # Should NOT call upstream
        mock_completions.create.assert_not_called()
        assert result.cacheback_hit is True
        assert result.cacheback_synthesized is False
        cache.close()


# --- Integration: Anthropic wrapper with synthesis ---

class TestAnthropicSynthesisIntegration:
    def test_synthesis_tier_on_miss(self, tmp_cache_dir, mock_embedder):
        """Anthropic wrapper: synthesis on verbatim miss."""
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
            similarity_threshold=0.99,
        )

        mock_messages = MagicMock()
        mock_synthesis = MagicMock()

        synth_result = SynthesisResult(
            text="Synthesized: photosynthesis is how plants make food.",
            source="synthesis",
            candidates_used=1,
        )
        mock_synthesis.synthesize.return_value = synth_result
        mock_synthesis._threshold = 0.80
        mock_synthesis._top_k = 5

        cached_messages = _AnthropicCachedMessages(mock_messages, cache, mock_synthesis)

        # Patch lookup_for_synthesis to return fake candidates
        fake_candidates = [(1, 0.88)]
        fake_entry = MagicMock(query_text="What is photosynthesis?", response_text="Plants convert sunlight." * 3)
        cache.lookup_for_synthesis = MagicMock(return_value=fake_candidates)
        cache.get_entry = MagicMock(return_value=fake_entry)

        result = cached_messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": "Explain photosynthesis to me"}],
        )

        mock_messages.create.assert_not_called()
        assert result.cacheback_synthesized is True
        assert result.cacheback_hit is False
        cache.close()

    def test_no_synthesis_when_engine_is_none(self, tmp_cache_dir, mock_embedder):
        """Anthropic wrapper: without synthesis engine, miss goes to upstream."""
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
            similarity_threshold=0.99,
        )

        mock_messages = MagicMock()
        mock_response = MagicMock()
        mock_response.content = []
        mock_messages.create.return_value = mock_response

        cached_messages = _AnthropicCachedMessages(mock_messages, cache)
        cached_messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": "Something new entirely"}],
        )

        mock_messages.create.assert_called_once()
        cache.close()


# --- CachedResponse synthesis flag tests ---

class TestCachedResponseSynthesis:
    def test_openai_synthesized_response(self):
        resp = _CachedResponse(
            cached_text="Synthesized text", synthesized=True, model="gpt-4o"
        )
        assert resp.cacheback_synthesized is True
        assert resp.cacheback_hit is False
        assert resp.id == "cache-synthesis"
        assert resp.choices[0].message.content == "Synthesized text"

    def test_openai_verbatim_hit_not_synthesized(self):
        resp = _CachedResponse(
            cached_text="Verbatim cached", cache_hit=True, model="gpt-4o"
        )
        assert resp.cacheback_hit is True
        assert resp.cacheback_synthesized is False
        assert resp.id == "cache-hit"

    def test_anthropic_synthesized_message(self):
        msg = _AnthropicCachedMessage(
            text="Synthesized text", model="claude-sonnet-4-20250514", cache_hit=False, synthesized=True
        )
        assert msg.cacheback_synthesized is True
        assert msg.cacheback_hit is False
        assert msg.id == "cache-synthesis"
        assert msg.content[0].text == "Synthesized text"

    def test_anthropic_verbatim_hit_not_synthesized(self):
        msg = _AnthropicCachedMessage(
            text="Cached text", model="claude-sonnet-4-20250514"
        )
        assert msg.cacheback_hit is True
        assert msg.cacheback_synthesized is False
        assert msg.id == "cache-hit"


# --- SemanticCache.lookup_for_synthesis tests ---

class TestLookupForSynthesis:
    def test_returns_candidates_above_threshold(self, tmp_cache_dir, mock_embedder):
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
            similarity_threshold=0.92,
        )
        cache.populate("What is photosynthesis?", "Plants convert sunlight." * 5)

        # Same query = same embedding = similarity 1.0, well above 0.5
        results = cache.lookup_for_synthesis("What is photosynthesis?", threshold=0.5, top_k=5)
        assert len(results) >= 1
        for cache_id, sim in results:
            assert isinstance(cache_id, int)
            assert sim >= 0.5
        cache.close()

    def test_returns_empty_when_disabled(self, tmp_cache_dir, mock_embedder):
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
            enabled=False,
        )
        results = cache.lookup_for_synthesis("test query")
        assert results == []
        cache.close()

    def test_returns_empty_for_short_query(self, tmp_cache_dir, mock_embedder):
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
        )
        results = cache.lookup_for_synthesis("hi")
        assert results == []
        cache.close()

    def test_get_entry(self, tmp_cache_dir, mock_embedder):
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
        )
        cache.populate("What is Python?", "Python is a programming language." * 3)
        results = cache.lookup_for_synthesis("What is Python?", threshold=0.5)
        assert len(results) >= 1
        entry = cache.get_entry(results[0][0])
        assert entry is not None
        assert "Python" in entry.response_text
        cache.close()
