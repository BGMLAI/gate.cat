"""Anthropic SDK wrapper with transparent semantic caching + streaming.

Usage:
    from gatecat import CachedAnthropic

    client = CachedAnthropic()
    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[{"role": "user", "content": "What is the capital of France?"}],
    )
    print(message._cache_hit)  # True/False

    # Streaming
    with client.messages.stream(...) as stream:
        for text in stream.text_stream:
            print(text, end="")

    # Async
    from gatecat import AsyncCachedAnthropic
    async_client = AsyncCachedAnthropic()
    message = await async_client.messages.create(...)
"""

import logging
from typing import Any, Optional

from gatecat.cache import SemanticCache, DEFAULT_CACHE_DIR
from gatecat._streaming import (
    buffer_and_cache_anthropic,
    buffer_and_cache_anthropic_async,
    replay_cached_anthropic_sync,
    replay_cached_anthropic_async,
)

logger = logging.getLogger(__name__)


# --- Response wrappers ---

class _CachedContent:
    def __init__(self, text: str):
        self.type = "text"
        self.text = text


class _CachedUsage:
    def __init__(self):
        self.input_tokens = 0
        self.output_tokens = 0


class _CachedMessage:
    """Minimal Anthropic Message response for cache hits."""

    def __init__(self, text: str, model: str = "", cache_hit: bool = True, synthesized: bool = False):
        self.id = "cache-synthesis" if synthesized else "cache-hit"
        self.type = "message"
        self.role = "assistant"
        self.content = [_CachedContent(text)]
        self.model = model
        self.stop_reason = "end_turn"
        self.usage = _CachedUsage()
        self.gatecat_hit = cache_hit
        self.gatecat_synthesized = synthesized
        self._cache_hit = cache_hit  # backward compat


# --- Query extraction ---

def _extract_query(messages: list[dict]) -> str:
    """Extract last user message from Anthropic message format."""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            content = msg.get("content", "")
            if isinstance(content, str):
                return content.strip()
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        return block.get("text", "").strip()
            break
    return ""


# --- Sync wrapper ---

class _CachedMessages:
    """Drop-in replacement for anthropic.messages with caching + streaming."""

    def __init__(self, original_messages, cache: SemanticCache, synthesis_engine=None):
        self._original = original_messages
        self._cache = cache
        self._synthesis = synthesis_engine

    def _try_synthesis(self, query: str, model: str) -> _CachedMessage | None:
        """Attempt CAS synthesis from cached candidates. Returns None if not possible."""
        if self._synthesis is None:
            return None
        from gatecat.synthesis import SynthesisCandidate
        candidates_raw = self._cache.lookup_for_synthesis(
            query,
            threshold=self._synthesis._threshold if hasattr(self._synthesis, '_threshold') else 0.80,
            top_k=self._synthesis._top_k if hasattr(self._synthesis, '_top_k') else 5,
        )
        if not candidates_raw:
            return None
        candidates = []
        for cache_id, similarity in candidates_raw:
            entry = self._cache.get_entry(cache_id)
            if entry:
                candidates.append(SynthesisCandidate(
                    query=entry.query_text,
                    response=entry.response_text,
                    similarity=similarity,
                    cache_id=cache_id,
                ))
        if not candidates:
            return None
        result = self._synthesis.synthesize(query, candidates)
        if result.text:
            return _CachedMessage(text=result.text, model=model, cache_hit=False, synthesized=True)
        return None

    def create(self, **kwargs) -> Any:
        messages = kwargs.get("messages", [])
        model = kwargs.get("model", "")
        stream = kwargs.get("stream", False)
        query = _extract_query(messages)

        # Skip caching for tool use or empty queries
        if kwargs.get("tools") or not query:
            return self._original.create(**kwargs)

        cached = self._cache.lookup(query)

        if stream:
            if cached is not None:
                logger.debug("[gatecat] STREAM HIT for: %s", query[:80])
                return replay_cached_anthropic_sync(cached, model=model)
            # Tier 2: Streaming synthesis
            synth = self._try_synthesis(query, model)
            if synth is not None:
                logger.debug("[gatecat] STREAM SYNTHESIS for: %s", query[:80])
                return replay_cached_anthropic_sync(
                    synth.content[0].text, model=model
                )
            upstream = self._original.create(**kwargs)
            return buffer_and_cache_anthropic(upstream, self._cache, query, model=model)

        if cached is not None:
            logger.debug("[gatecat] HIT for: %s", query[:80])
            return _CachedMessage(text=cached, model=model)

        # Tier 2: CAS synthesis (sim >= 0.80 but < 0.92)
        synth = self._try_synthesis(query, model)
        if synth is not None:
            logger.debug("[gatecat] SYNTHESIS for: %s", query[:80])
            return synth

        response = self._original.create(**kwargs)

        # Populate cache
        if response.content:
            text_parts = [b.text for b in response.content if hasattr(b, "text")]
            full_text = " ".join(text_parts)
            if full_text:
                tokens = response.usage.output_tokens if response.usage else 0
                self._cache.populate(query, full_text, model=model, tokens=tokens)

        return response


# --- Async wrapper ---

class _AsyncCachedMessages:
    """Async drop-in replacement for anthropic.messages."""

    def __init__(self, original_messages, cache: SemanticCache, synthesis_engine=None):
        self._original = original_messages
        self._cache = cache
        self._synthesis = synthesis_engine

    def _try_synthesis(self, query: str, model: str) -> _CachedMessage | None:
        """Attempt CAS synthesis (sync -- runs in executor for async callers)."""
        if self._synthesis is None:
            return None
        from gatecat.synthesis import SynthesisCandidate
        candidates_raw = self._cache.lookup_for_synthesis(query)
        if not candidates_raw:
            return None
        candidates = []
        for cache_id, similarity in candidates_raw:
            entry = self._cache.get_entry(cache_id)
            if entry:
                candidates.append(SynthesisCandidate(
                    query=entry.query_text,
                    response=entry.response_text,
                    similarity=similarity,
                    cache_id=cache_id,
                ))
        if not candidates:
            return None
        result = self._synthesis.synthesize(query, candidates)
        if result.text:
            return _CachedMessage(text=result.text, model=model, cache_hit=False, synthesized=True)
        return None

    async def create(self, **kwargs) -> Any:
        messages = kwargs.get("messages", [])
        model = kwargs.get("model", "")
        stream = kwargs.get("stream", False)
        query = _extract_query(messages)

        if kwargs.get("tools") or not query:
            return await self._original.create(**kwargs)

        cached = self._cache.lookup(query)

        if stream:
            if cached is not None:
                logger.debug("[gatecat] ASYNC STREAM HIT for: %s", query[:80])
                return replay_cached_anthropic_async(cached, model=model)
            # Tier 2: Streaming synthesis (run in executor)
            import asyncio
            synth = await asyncio.get_event_loop().run_in_executor(
                None, self._try_synthesis, query, model
            )
            if synth is not None:
                logger.debug("[gatecat] ASYNC STREAM SYNTHESIS for: %s", query[:80])
                return replay_cached_anthropic_async(
                    synth.content[0].text, model=model
                )
            upstream = await self._original.create(**kwargs)
            return buffer_and_cache_anthropic_async(upstream, self._cache, query, model=model)

        if cached is not None:
            logger.debug("[gatecat] ASYNC HIT for: %s", query[:80])
            return _CachedMessage(text=cached, model=model)

        # Tier 2: CAS synthesis
        import asyncio
        synth = await asyncio.get_event_loop().run_in_executor(
            None, self._try_synthesis, query, model
        )
        if synth is not None:
            logger.debug("[gatecat] ASYNC SYNTHESIS for: %s", query[:80])
            return synth

        response = await self._original.create(**kwargs)

        if response.content:
            text_parts = [b.text for b in response.content if hasattr(b, "text")]
            full_text = " ".join(text_parts)
            if full_text:
                tokens = response.usage.output_tokens if response.usage else 0
                self._cache.populate(query, full_text, model=model, tokens=tokens)

        return response


# --- Main classes ---

class CachedAnthropic:
    """Drop-in replacement for anthropic.Anthropic with semantic caching.

    Args:
        cache_dir: Directory for cache data
        similarity_threshold: Similarity threshold for hits (default: 0.92)
        negative_threshold: Similarity threshold for negative cache (default: 0.85)
        cache_max_entries: Max entries before LRU eviction
        cache_ttl: TTL in seconds (default: 24 hours)
        cache_enabled: Enable/disable caching
        on_negative_hit: Policy for negative cache ("raise", "skip", or callable)
        synthesis_mode: CAS mode -- "off" (default), "auto", or "always".
        synthesis_model: Model for CAS synthesis (default: gemini-2.0-flash-lite).
        synthesis_model_base_url: API base URL for synthesis model.
        synthesis_model_api_key: API key for synthesis model.
        synthesis_threshold: Min similarity for synthesis candidates (default: 0.80).
        synthesis_top_k: Number of cached responses to feed synthesizer (default: 5).
        **kwargs: Passed to anthropic.Anthropic()
    """

    def __init__(
        self,
        cache_dir: Optional[str] = None,
        similarity_threshold: float = 0.92,
        negative_threshold: float = 0.85,
        cache_max_entries: int = 100_000,
        cache_ttl: int = 24 * 3600,
        cache_enabled: bool = True,
        on_negative_hit: str = "raise",
        synthesis_mode: str = "off",
        synthesis_model: str = "google/gemini-2.0-flash-lite-001",
        synthesis_model_base_url: Optional[str] = None,
        synthesis_model_api_key: Optional[str] = None,
        synthesis_threshold: float = 0.80,
        synthesis_top_k: int = 5,
        **kwargs,
    ):
        try:
            from anthropic import Anthropic
        except ImportError:
            raise ImportError(
                "anthropic package required. Install with: pip install gate.cat[anthropic]"
            )

        self._client = Anthropic(**kwargs)
        self.cache = SemanticCache(
            cache_dir=cache_dir or DEFAULT_CACHE_DIR,
            similarity_threshold=similarity_threshold,
            negative_threshold=negative_threshold,
            max_entries=cache_max_entries,
            ttl_seconds=cache_ttl,
            enabled=cache_enabled,
            on_negative_hit=on_negative_hit,
        )

        # CAS synthesis engine
        synthesis_engine = None
        if synthesis_mode in ("auto", "always"):
            from gatecat.synthesis import SynthesisEngine
            synthesis_engine = SynthesisEngine(
                model=synthesis_model,
                base_url=synthesis_model_base_url,
                api_key=synthesis_model_api_key,
            )
            synthesis_engine._threshold = synthesis_threshold
            synthesis_engine._top_k = synthesis_top_k

        self.messages = _CachedMessages(self._client.messages, self.cache, synthesis_engine)

    def __getattr__(self, name):
        return getattr(self._client, name)

    def close(self):
        self.cache.close()
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class AsyncCachedAnthropic:
    """Drop-in replacement for anthropic.AsyncAnthropic with semantic caching.

    Same args as CachedAnthropic.
    """

    def __init__(
        self,
        cache_dir: Optional[str] = None,
        similarity_threshold: float = 0.92,
        negative_threshold: float = 0.85,
        cache_max_entries: int = 100_000,
        cache_ttl: int = 24 * 3600,
        cache_enabled: bool = True,
        on_negative_hit: str = "raise",
        synthesis_mode: str = "off",
        synthesis_model: str = "google/gemini-2.0-flash-lite-001",
        synthesis_model_base_url: Optional[str] = None,
        synthesis_model_api_key: Optional[str] = None,
        synthesis_threshold: float = 0.80,
        synthesis_top_k: int = 5,
        **kwargs,
    ):
        try:
            from anthropic import AsyncAnthropic
        except ImportError:
            raise ImportError(
                "anthropic package required. Install with: pip install gate.cat[anthropic]"
            )

        self._client = AsyncAnthropic(**kwargs)
        self.cache = SemanticCache(
            cache_dir=cache_dir or DEFAULT_CACHE_DIR,
            similarity_threshold=similarity_threshold,
            negative_threshold=negative_threshold,
            max_entries=cache_max_entries,
            ttl_seconds=cache_ttl,
            enabled=cache_enabled,
            on_negative_hit=on_negative_hit,
        )

        # CAS synthesis engine
        synthesis_engine = None
        if synthesis_mode in ("auto", "always"):
            from gatecat.synthesis import SynthesisEngine
            synthesis_engine = SynthesisEngine(
                model=synthesis_model,
                base_url=synthesis_model_base_url,
                api_key=synthesis_model_api_key,
            )
            synthesis_engine._threshold = synthesis_threshold
            synthesis_engine._top_k = synthesis_top_k

        self.messages = _AsyncCachedMessages(self._client.messages, self.cache, synthesis_engine)

    def __getattr__(self, name):
        return getattr(self._client, name)

    async def close(self):
        self.cache.close()
        await self._client.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
