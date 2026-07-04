"""StreamBuffer and streaming helper tests."""

import pytest
from cacheback._streaming import (
    StreamBuffer,
    replay_cached_openai_sync,
    replay_cached_anthropic_sync,
    replay_cached_openai_async,
    replay_cached_anthropic_async,
    buffer_and_cache_openai,
    buffer_and_cache_anthropic,
)


# --- Mock chunk objects ---

class MockOpenAIDelta:
    def __init__(self, content=None):
        self.content = content


class MockOpenAIChoice:
    def __init__(self, delta=None, finish_reason=None):
        self.delta = delta or MockOpenAIDelta()
        self.finish_reason = finish_reason


class MockOpenAIChunk:
    def __init__(self, choices=None, model="gpt-4o"):
        self.choices = choices or []
        self.model = model


class MockAnthropicDelta:
    def __init__(self, text=""):
        self.text = text
        self.type = "text_delta"


class MockAnthropicContentBlockDelta:
    def __init__(self, text=""):
        self.type = "content_block_delta"
        self.delta = MockAnthropicDelta(text)


class MockAnthropicMessageStop:
    def __init__(self):
        self.type = "message_stop"


class MockAnthropicMessageModel:
    def __init__(self, model="claude-sonnet"):
        self.model = model


class MockAnthropicMessageStart:
    def __init__(self, model="claude-sonnet"):
        self.type = "message_start"
        self.message = MockAnthropicMessageModel(model)


# --- StreamBuffer tests ---

class TestStreamBuffer:
    def test_feed_openai_chunks(self):
        buf = StreamBuffer()
        chunk1 = MockOpenAIChunk(
            choices=[MockOpenAIChoice(delta=MockOpenAIDelta("Hello"))],
            model="gpt-4o",
        )
        chunk2 = MockOpenAIChunk(
            choices=[MockOpenAIChoice(delta=MockOpenAIDelta(" world"))],
        )
        chunk3 = MockOpenAIChunk(
            choices=[MockOpenAIChoice(
                delta=MockOpenAIDelta(),
                finish_reason="stop",
            )],
        )

        assert buf.feed(chunk1) == "Hello"
        assert buf.feed(chunk2) == " world"
        buf.feed(chunk3)

        assert buf.full_text == "Hello world"
        assert buf.is_complete is True
        assert buf.model == "gpt-4o"

    def test_feed_anthropic_chunks(self):
        buf = StreamBuffer()
        start = MockAnthropicMessageStart(model="claude-sonnet")
        delta = MockAnthropicContentBlockDelta("Hello world")
        stop = MockAnthropicMessageStop()

        buf.feed(start)
        assert buf.feed(delta) == "Hello world"
        buf.feed(stop)

        assert buf.full_text == "Hello world"
        assert buf.is_complete is True
        assert buf.model == "claude-sonnet"

    def test_incomplete_stream(self):
        buf = StreamBuffer()
        chunk = MockOpenAIChunk(
            choices=[MockOpenAIChoice(delta=MockOpenAIDelta("partial"))],
        )
        buf.feed(chunk)
        assert buf.is_complete is False
        assert buf.full_text == "partial"

    def test_empty_buffer(self):
        buf = StreamBuffer()
        assert buf.full_text == ""
        assert buf.is_complete is False
        assert buf.total_tokens == 0

    def test_feed_none_content(self):
        buf = StreamBuffer()
        chunk = MockOpenAIChunk(
            choices=[MockOpenAIChoice(delta=MockOpenAIDelta(None))],
        )
        result = buf.feed(chunk)
        assert result is None
        assert buf.full_text == ""


# --- Replay tests ---

class TestReplayOpenAI:
    def test_replay_sync(self):
        chunks = list(replay_cached_openai_sync("Hello world", model="gpt-4o"))
        assert len(chunks) == 2
        # Content chunk
        assert chunks[0].choices[0].delta.content == "Hello world"
        assert chunks[0].model == "gpt-4o"
        # Stop chunk
        assert chunks[1].choices[0].finish_reason == "stop"

    @pytest.mark.asyncio
    async def test_replay_async(self):
        chunks = []
        async for chunk in replay_cached_openai_async("Hello", model="gpt-4o"):
            chunks.append(chunk)
        assert len(chunks) == 2
        assert chunks[0].choices[0].delta.content == "Hello"


class TestReplayAnthropic:
    def test_replay_sync(self):
        events = list(replay_cached_anthropic_sync("Hello world", model="claude"))
        assert len(events) == 2
        # Content block
        assert events[0].delta.text == "Hello world"
        assert events[0].type == "content_block_delta"
        # Stop
        assert events[1].type == "message_stop"

    @pytest.mark.asyncio
    async def test_replay_async(self):
        events = []
        async for event in replay_cached_anthropic_async("Hello"):
            events.append(event)
        assert len(events) == 2


# --- Buffer-and-cache tests ---

class MockCache:
    """Simple mock cache that records populate calls."""

    def __init__(self):
        self.populated = []

    def populate(self, query, response, model="", tokens=0):
        self.populated.append({
            "query": query,
            "response": response,
            "model": model,
            "tokens": tokens,
        })


class TestBufferAndCacheOpenAI:
    def test_buffers_and_caches_complete_stream(self):
        upstream = [
            MockOpenAIChunk(choices=[MockOpenAIChoice(delta=MockOpenAIDelta("Hello"))], model="gpt-4o"),
            MockOpenAIChunk(choices=[MockOpenAIChoice(delta=MockOpenAIDelta(" world"))]),
            MockOpenAIChunk(choices=[MockOpenAIChoice(delta=MockOpenAIDelta(), finish_reason="stop")]),
        ]
        cache = MockCache()
        chunks = list(buffer_and_cache_openai(upstream, cache, "test query", model="gpt-4o"))

        # All upstream chunks yielded
        assert len(chunks) == 3
        # Cache populated
        assert len(cache.populated) == 1
        assert cache.populated[0]["response"] == "Hello world"
        assert cache.populated[0]["query"] == "test query"

    def test_does_not_cache_incomplete_stream(self):
        upstream = [
            MockOpenAIChunk(choices=[MockOpenAIChoice(delta=MockOpenAIDelta("partial"))]),
            # No finish_reason chunk
        ]
        cache = MockCache()
        list(buffer_and_cache_openai(upstream, cache, "test query"))
        assert len(cache.populated) == 0


class TestBufferAndCacheAnthropic:
    def test_buffers_and_caches_complete_stream(self):
        upstream = [
            MockAnthropicMessageStart(model="claude"),
            MockAnthropicContentBlockDelta("Hello world"),
            MockAnthropicMessageStop(),
        ]
        cache = MockCache()
        events = list(buffer_and_cache_anthropic(upstream, cache, "test query"))

        assert len(events) == 3
        assert len(cache.populated) == 1
        assert cache.populated[0]["response"] == "Hello world"

    def test_does_not_cache_incomplete_stream(self):
        upstream = [
            MockAnthropicContentBlockDelta("partial"),
            # No message_stop
        ]
        cache = MockCache()
        list(buffer_and_cache_anthropic(upstream, cache, "test query"))
        assert len(cache.populated) == 0
