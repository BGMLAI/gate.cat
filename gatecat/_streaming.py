"""Streaming support — buffer-and-replay pattern for cached streams.

CACHE MISS + stream=True:
  Buffer chunks while yielding them through, then cache the complete response.

CACHE HIT + stream=True:
  Replay the cached response as a synthetic stream (single content chunk + stop chunk).
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Generator, AsyncGenerator, Optional

logger = logging.getLogger(__name__)


@dataclass
class StreamBuffer:
    """Accumulates streamed chunks into a complete response."""

    chunks: list[str] = field(default_factory=list)
    model: str = ""
    finish_reason: Optional[str] = None
    prompt_tokens: int = 0
    completion_tokens: int = 0

    def feed(self, chunk: Any) -> Optional[str]:
        """Feed a chunk and extract text content. Returns the text delta or None."""
        # OpenAI format
        if hasattr(chunk, "choices") and chunk.choices:
            choice = chunk.choices[0]
            if hasattr(choice, "delta") and hasattr(choice.delta, "content"):
                text = choice.delta.content
                if text:
                    self.chunks.append(text)
                    return text
            if hasattr(choice, "finish_reason") and choice.finish_reason:
                self.finish_reason = choice.finish_reason
            if not self.model and hasattr(chunk, "model"):
                self.model = chunk.model or ""

        # Anthropic format
        elif hasattr(chunk, "type"):
            if chunk.type == "content_block_delta":
                if hasattr(chunk, "delta") and hasattr(chunk.delta, "text"):
                    text = chunk.delta.text
                    if text:
                        self.chunks.append(text)
                        return text
            elif chunk.type == "message_stop":
                self.finish_reason = "end_turn"
            elif chunk.type == "message_start" and hasattr(chunk, "message"):
                if hasattr(chunk.message, "model"):
                    self.model = chunk.message.model or ""

        return None

    @property
    def full_text(self) -> str:
        return "".join(self.chunks)

    @property
    def is_complete(self) -> bool:
        return self.finish_reason is not None

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


# --- OpenAI streaming helpers ---

class _OpenAIChunkDelta:
    def __init__(self, content: Optional[str] = None, role: Optional[str] = None):
        self.content = content
        self.role = role


class _OpenAIChunkChoice:
    def __init__(self, delta: _OpenAIChunkDelta, finish_reason: Optional[str] = None):
        self.index = 0
        self.delta = delta
        self.finish_reason = finish_reason


class _OpenAIStreamChunk:
    def __init__(self, choices: list[_OpenAIChunkChoice], model: str = ""):
        self.id = "cache-hit"
        self.model = model
        self.choices = choices


def replay_cached_openai_sync(text: str, model: str = "") -> Generator:
    """Replay cached text as a synthetic OpenAI stream (sync)."""
    # Content chunk
    yield _OpenAIStreamChunk(
        choices=[_OpenAIChunkChoice(
            delta=_OpenAIChunkDelta(content=text, role="assistant"),
        )],
        model=model,
    )
    # Stop chunk
    yield _OpenAIStreamChunk(
        choices=[_OpenAIChunkChoice(
            delta=_OpenAIChunkDelta(),
            finish_reason="stop",
        )],
        model=model,
    )


async def replay_cached_openai_async(text: str, model: str = "") -> AsyncGenerator:
    """Replay cached text as a synthetic OpenAI stream (async)."""
    for chunk in replay_cached_openai_sync(text, model):
        yield chunk


# --- Anthropic streaming helpers ---

class _AnthropicDelta:
    def __init__(self, text: str = ""):
        self.type = "text_delta"
        self.text = text


class _AnthropicContentBlock:
    def __init__(self, text: str = ""):
        self.type = "content_block_delta"
        self.delta = _AnthropicDelta(text)


class _AnthropicMessageStop:
    def __init__(self):
        self.type = "message_stop"


def replay_cached_anthropic_sync(text: str, model: str = "") -> Generator:
    """Replay cached text as a synthetic Anthropic stream (sync)."""
    yield _AnthropicContentBlock(text=text)
    yield _AnthropicMessageStop()


async def replay_cached_anthropic_async(text: str, model: str = "") -> AsyncGenerator:
    """Replay cached text as a synthetic Anthropic stream (async)."""
    for event in replay_cached_anthropic_sync(text, model):
        yield event


# --- Wrapper that buffers and caches a stream ---

def buffer_and_cache_openai(
    stream,
    cache: Any,
    query: str,
    model: str = "",
) -> Generator:
    """Wrap an OpenAI stream: yield chunks through while buffering, cache on completion."""
    buf = StreamBuffer()

    for chunk in stream:
        buf.feed(chunk)
        yield chunk

    if buf.is_complete and buf.full_text:
        cache.populate(query, buf.full_text, model=buf.model or model, tokens=buf.completion_tokens)


async def buffer_and_cache_openai_async(
    stream,
    cache: Any,
    query: str,
    model: str = "",
) -> AsyncGenerator:
    """Wrap an async OpenAI stream: yield chunks through while buffering, cache on completion."""
    buf = StreamBuffer()

    async for chunk in stream:
        buf.feed(chunk)
        yield chunk

    if buf.is_complete and buf.full_text:
        cache.populate(query, buf.full_text, model=buf.model or model, tokens=buf.completion_tokens)


def buffer_and_cache_anthropic(
    stream,
    cache: Any,
    query: str,
    model: str = "",
) -> Generator:
    """Wrap an Anthropic stream: yield events through while buffering, cache on completion."""
    buf = StreamBuffer()

    for event in stream:
        buf.feed(event)
        yield event

    if buf.is_complete and buf.full_text:
        cache.populate(query, buf.full_text, model=buf.model or model, tokens=buf.completion_tokens)


async def buffer_and_cache_anthropic_async(
    stream,
    cache: Any,
    query: str,
    model: str = "",
) -> AsyncGenerator:
    """Wrap an async Anthropic stream: yield events through while buffering, cache on completion."""
    buf = StreamBuffer()

    async for event in stream:
        buf.feed(event)
        yield event

    if buf.is_complete and buf.full_text:
        cache.populate(query, buf.full_text, model=buf.model or model, tokens=buf.completion_tokens)
