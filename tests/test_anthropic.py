"""Anthropic wrapper tests — uses mocked Anthropic client (no real API calls)."""

from unittest.mock import MagicMock
from cacheback.cache import SemanticCache
from cacheback.anthropic import (
    _CachedMessages,
    _CachedMessage,
    _extract_query,
)


# --- Mock Anthropic response objects ---

class MockContentBlock:
    def __init__(self, text="Paris is the capital of France."):
        self.type = "text"
        self.text = text


class MockAnthropicUsage:
    def __init__(self, input_tokens=10, output_tokens=20):
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


class MockAnthropicResponse:
    def __init__(self, text="Paris is the capital of France.", model="claude-sonnet"):
        self.id = "msg_test123"
        self.type = "message"
        self.role = "assistant"
        self.content = [MockContentBlock(text)]
        self.model = model
        self.stop_reason = "end_turn"
        self.usage = MockAnthropicUsage()


# --- Query extraction ---

class TestExtractQuery:
    def test_extracts_string_content(self):
        messages = [
            {"role": "user", "content": "What is Python?"},
        ]
        assert _extract_query(messages) == "What is Python?"

    def test_extracts_list_content(self):
        messages = [
            {"role": "user", "content": [
                {"type": "text", "text": "What is the capital?"},
            ]},
        ]
        assert _extract_query(messages) == "What is the capital?"

    def test_extracts_last_user_message(self):
        messages = [
            {"role": "user", "content": "First question"},
            {"role": "assistant", "content": "Answer"},
            {"role": "user", "content": "Second question"},
        ]
        assert _extract_query(messages) == "Second question"

    def test_empty_messages(self):
        assert _extract_query([]) == ""

    def test_no_user_message(self):
        messages = [{"role": "assistant", "content": "Hello"}]
        assert _extract_query(messages) == ""


# --- CachedMessage ---

class TestCachedMessage:
    def test_cache_hit_message(self):
        msg = _CachedMessage(text="Cached response", model="claude-sonnet")
        assert msg.cacheback_hit is True
        assert msg._cache_hit is True
        assert msg.id == "cache-hit"
        assert msg.model == "claude-sonnet"
        assert msg.content[0].text == "Cached response"
        assert msg.stop_reason == "end_turn"
        assert msg.usage.input_tokens == 0


# --- CachedMessages ---

class TestCachedMessages:
    def test_cache_miss_calls_upstream(self, tmp_cache_dir, mock_embedder):
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
            similarity_threshold=0.5,
        )
        mock_messages = MagicMock()
        mock_messages.create.return_value = MockAnthropicResponse(
            text="Test response " * 3
        )

        cached = _CachedMessages(mock_messages, cache)
        cached.create(
            model="claude-sonnet",
            max_tokens=1024,
            messages=[{"role": "user", "content": "What is the capital of France?"}],
        )

        mock_messages.create.assert_called_once()
        assert cache.stats["populations"] == 1
        cache.close()

    def test_cache_hit_returns_cached(self, tmp_cache_dir, mock_embedder):
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
            similarity_threshold=0.5,
        )
        cache.populate("What is the capital of France?", "Paris is the capital." * 3)

        mock_messages = MagicMock()
        cached = _CachedMessages(mock_messages, cache)
        result = cached.create(
            model="claude-sonnet",
            max_tokens=1024,
            messages=[{"role": "user", "content": "What is the capital of France?"}],
        )

        mock_messages.create.assert_not_called()
        assert isinstance(result, _CachedMessage)
        assert result.cacheback_hit is True
        assert "Paris" in result.content[0].text
        cache.close()

    def test_skips_caching_for_tool_use(self, tmp_cache_dir, mock_embedder):
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
        )
        mock_messages = MagicMock()
        mock_messages.create.return_value = MockAnthropicResponse()

        cached = _CachedMessages(mock_messages, cache)
        cached.create(
            model="claude-sonnet",
            max_tokens=1024,
            messages=[{"role": "user", "content": "Use the tool"}],
            tools=[{"name": "calculator"}],
        )

        mock_messages.create.assert_called_once()
        assert cache.stats["populations"] == 0
        cache.close()

    def test_skips_caching_for_empty_query(self, tmp_cache_dir, mock_embedder):
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
        )
        mock_messages = MagicMock()
        mock_messages.create.return_value = MockAnthropicResponse()

        cached = _CachedMessages(mock_messages, cache)
        cached.create(
            model="claude-sonnet",
            max_tokens=1024,
            messages=[{"role": "assistant", "content": "No user msg"}],
        )

        mock_messages.create.assert_called_once()
        cache.close()

    def test_streaming_cache_miss(self, tmp_cache_dir, mock_embedder):
        """Streaming miss should yield upstream events and cache the result."""
        from cacheback._streaming import _AnthropicContentBlock, _AnthropicMessageStop

        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
            similarity_threshold=0.5,
        )

        mock_stream = [
            _AnthropicContentBlock(text="Hello world " * 5),
            _AnthropicMessageStop(),
        ]
        mock_messages = MagicMock()
        mock_messages.create.return_value = iter(mock_stream)

        cached = _CachedMessages(mock_messages, cache)
        stream = cached.create(
            model="claude-sonnet",
            max_tokens=1024,
            messages=[{"role": "user", "content": "What is Python programming?"}],
            stream=True,
        )
        events = list(stream)
        assert len(events) == 2
        assert cache.stats["populations"] == 1
        cache.close()

    def test_streaming_cache_hit(self, tmp_cache_dir, mock_embedder):
        """Streaming hit should replay from cache."""
        cache = SemanticCache(
            cache_dir=tmp_cache_dir,
            embedder=mock_embedder,
            similarity_threshold=0.5,
        )
        cache.populate("What is Python programming?", "Python is a language." * 5)

        mock_messages = MagicMock()
        cached = _CachedMessages(mock_messages, cache)
        stream = cached.create(
            model="claude-sonnet",
            max_tokens=1024,
            messages=[{"role": "user", "content": "What is Python programming?"}],
            stream=True,
        )
        events = list(stream)
        assert len(events) == 2
        mock_messages.create.assert_not_called()
        cache.close()
