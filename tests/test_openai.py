"""OpenAI wrapper tests — uses mocked OpenAI client (no real API calls)."""

from unittest.mock import MagicMock
from gatecat.cache import SemanticCache
from gatecat.openai import (
    _CachedChatCompletions,
    _CachedResponse,
    _extract_query,
)


# --- Mock OpenAI response objects ---

class MockUsage:
    def __init__(self, prompt_tokens=10, completion_tokens=20, total_tokens=30):
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.total_tokens = total_tokens


class MockMessage:
    def __init__(self, content="Paris is the capital of France.", role="assistant"):
        self.content = content
        self.role = role


class MockChoice:
    def __init__(self, message=None, finish_reason="stop"):
        self.index = 0
        self.message = message or MockMessage()
        self.finish_reason = finish_reason


class MockCompletion:
    def __init__(self, content="Paris is the capital of France.", model="gpt-4o"):
        self.id = "chatcmpl-test123"
        self.model = model
        self.choices = [MockChoice(message=MockMessage(content))]
        self.usage = MockUsage()


# --- Query extraction ---

class TestExtractQuery:
    def test_extracts_last_user_message(self):
        messages = [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "What is Python?"},
            {"role": "assistant", "content": "Python is a language."},
            {"role": "user", "content": "Tell me more about it."},
        ]
        assert _extract_query(messages) == "Tell me more about it."

    def test_empty_messages(self):
        assert _extract_query([]) == ""

    def test_no_user_message(self):
        messages = [{"role": "system", "content": "System prompt"}]
        assert _extract_query(messages) == ""

    def test_strips_whitespace(self):
        messages = [{"role": "user", "content": "  hello world  "}]
        assert _extract_query(messages) == "hello world"


# --- CachedResponse ---

class TestCachedResponse:
    def test_cache_hit_response(self):
        resp = _CachedResponse(cached_text="Cached answer", cache_hit=True, model="gpt-4o")
        assert resp.gatecat_hit is True
        assert resp._cache_hit is True
        assert resp.id == "cache-hit"
        assert resp.model == "gpt-4o"
        assert resp.choices[0].message.content == "Cached answer"
        assert resp.usage.total_tokens == 0

    def test_cache_miss_response(self):
        original = MockCompletion()
        resp = _CachedResponse(original_response=original)
        assert resp.gatecat_hit is False
        assert resp.id == "chatcmpl-test123"
        assert resp.choices[0].message.content == "Paris is the capital of France."


# --- CachedChatCompletions ---

class TestCachedChatCompletions:
    def test_cache_miss_calls_upstream_and_populates(self, tmp_cache_dir, mock_embedder):
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
            similarity_threshold=0.5,
        )
        mock_completions = MagicMock()
        mock_completions.create.return_value = MockCompletion(content="Test response " * 3)

        cached_completions = _CachedChatCompletions(mock_completions, cache)
        result = cached_completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "What is the capital of France?"}],
        )

        # Should have called upstream
        mock_completions.create.assert_called_once()
        # Response should have cache metadata
        assert result.gatecat_hit is False
        # Cache should be populated
        assert cache.stats["populations"] == 1
        cache.close()

    def test_cache_hit_returns_cached(self, tmp_cache_dir, mock_embedder):
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
            similarity_threshold=0.5,
        )
        # Pre-populate cache
        cache.populate("What is the capital of France?", "Paris is the capital." * 3)

        mock_completions = MagicMock()
        cached_completions = _CachedChatCompletions(mock_completions, cache)
        result = cached_completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "What is the capital of France?"}],
        )

        # Should NOT have called upstream
        mock_completions.create.assert_not_called()
        assert result.gatecat_hit is True
        assert "Paris" in result.choices[0].message.content
        cache.close()

    def test_skips_caching_for_tool_calls(self, tmp_cache_dir, mock_embedder):
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
        )
        mock_completions = MagicMock()
        mock_completions.create.return_value = MockCompletion()

        cached_completions = _CachedChatCompletions(mock_completions, cache)
        cached_completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Use the tool"}],
            tools=[{"type": "function"}],
        )

        mock_completions.create.assert_called_once()
        assert cache.stats["populations"] == 0
        cache.close()

    def test_skips_caching_for_empty_query(self, tmp_cache_dir, mock_embedder):
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
        )
        mock_completions = MagicMock()
        mock_completions.create.return_value = MockCompletion()

        cached_completions = _CachedChatCompletions(mock_completions, cache)
        cached_completions.create(
            model="gpt-4o",
            messages=[{"role": "system", "content": "System only"}],
        )

        mock_completions.create.assert_called_once()
        cache.close()

    def test_streaming_cache_miss(self, tmp_cache_dir, mock_embedder):
        """Streaming miss should yield upstream chunks and cache the result."""
        from gatecat._streaming import _OpenAIStreamChunk, _OpenAIChunkChoice, _OpenAIChunkDelta

        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
            similarity_threshold=0.5,
        )

        # Create mock stream chunks
        mock_stream = [
            _OpenAIStreamChunk(
                choices=[_OpenAIChunkChoice(delta=_OpenAIChunkDelta("Hello world " * 5))],
                model="gpt-4o",
            ),
            _OpenAIStreamChunk(
                choices=[_OpenAIChunkChoice(delta=_OpenAIChunkDelta(), finish_reason="stop")],
                model="gpt-4o",
            ),
        ]
        mock_completions = MagicMock()
        mock_completions.create.return_value = iter(mock_stream)

        cached_completions = _CachedChatCompletions(mock_completions, cache)
        stream = cached_completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "What is Python programming?"}],
            stream=True,
        )
        chunks = list(stream)
        assert len(chunks) == 2
        # Cache populated after stream completion
        assert cache.stats["populations"] == 1
        cache.close()

    def test_streaming_cache_hit(self, tmp_cache_dir, mock_embedder):
        """Streaming hit should replay from cache without calling upstream."""
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
            similarity_threshold=0.5,
        )
        cache.populate("What is Python programming?", "Python is a language." * 5)

        mock_completions = MagicMock()
        cached_completions = _CachedChatCompletions(mock_completions, cache)
        stream = cached_completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "What is Python programming?"}],
            stream=True,
        )
        chunks = list(stream)
        # Replayed: 1 content chunk + 1 stop chunk
        assert len(chunks) == 2
        mock_completions.create.assert_not_called()
        cache.close()
