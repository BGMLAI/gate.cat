"""OpenAI SDK wrapper with transparent semantic caching + streaming.

Usage:
    from gatecat import CachedOpenAI

    client = CachedOpenAI()
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "What is the capital of France?"}],
    )
    # First call: ~500ms (API call + cache populate)
    # Second call: ~10ms (cache hit)
    print(response.gatecat_hit)  # True/False

    # Streaming works transparently
    stream = client.chat.completions.create(..., stream=True)
    for chunk in stream:
        print(chunk.choices[0].delta.content, end="")

    # Async
    from gatecat import AsyncCachedOpenAI
    async_client = AsyncCachedOpenAI()
    response = await async_client.chat.completions.create(...)
"""

import logging
from typing import Any, Optional

from gatecat.cache import SemanticCache, DEFAULT_CACHE_DIR
from gatecat._streaming import (
    buffer_and_cache_openai,
    buffer_and_cache_openai_async,
    replay_cached_openai_sync,
    replay_cached_openai_async,
)

logger = logging.getLogger(__name__)


# --- Response wrappers ---

class _CachedResponse:
    """Wraps an OpenAI ChatCompletion response with cache metadata."""

    def __init__(
        self,
        original_response=None,
        cached_text: str = "",
        cache_hit: bool = False,
        synthesized: bool = False,
        model: str = "",
    ):
        self.gatecat_hit = cache_hit
        self.gatecat_synthesized = synthesized
        self._cache_hit = cache_hit  # backward compat
        self._original = original_response

        if cache_hit or synthesized:
            self.id = "cache-synthesis" if synthesized else "cache-hit"
            self.model = model
            self.choices = [_CachedChoice(cached_text)]
            self.usage = _CachedUsage(0, 0, 0)
        elif original_response:
            self.id = original_response.id
            self.model = original_response.model
            self.choices = original_response.choices
            self.usage = original_response.usage

    def __getattr__(self, name):
        if self._original and name not in (
            "_original", "gatecat_hit", "_cache_hit", "gatecat_synthesized",
        ):
            return getattr(self._original, name)
        raise AttributeError(f"'{type(self).__name__}' has no attribute '{name}'")


class _CachedChoice:
    def __init__(self, text: str):
        self.index = 0
        self.message = _CachedMessage(text)
        self.finish_reason = "stop"


class _CachedMessage:
    def __init__(self, content: str):
        self.role = "assistant"
        self.content = content


class _CachedUsage:
    def __init__(self, prompt_tokens: int, completion_tokens: int, total_tokens: int):
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.total_tokens = total_tokens


# --- Query extraction ---

def _extract_query(messages: list[dict]) -> str:
    """Extract the last user message as cache key."""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            content = msg.get("content", "")
            if isinstance(content, str):
                return content.strip()
    return ""


# --- Sync wrapper ---

class _CachedChatCompletions:
    """Drop-in replacement for openai.chat.completions with caching + streaming."""

    def __init__(self, original_completions, cache: SemanticCache, synthesis_engine=None):
        self._original = original_completions
        self._cache = cache
        self._synthesis = synthesis_engine

    def _try_synthesis(self, query: str, model: str) -> _CachedResponse | None:
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
            return _CachedResponse(
                cached_text=result.text,
                synthesized=True,
                model=model,
            )
        return None

    def create(self, **kwargs) -> Any:
        messages = kwargs.get("messages", [])
        model = kwargs.get("model", "")
        stream = kwargs.get("stream", False)
        query = _extract_query(messages)

        # Skip caching for tool calls or empty queries
        if kwargs.get("tools") or kwargs.get("functions") or not query:
            return self._original.create(**kwargs)

        # Tier 1: Verbatim cache lookup (sim >= 0.92)
        cached = self._cache.lookup(query)

        if stream:
            if cached is not None:
                logger.debug("[gatecat] STREAM HIT for: %s", query[:80])
                return replay_cached_openai_sync(cached, model=model)
            # Tier 2: Streaming synthesis — synthesize then replay as stream
            synth = self._try_synthesis(query, model)
            if synth is not None:
                logger.debug("[gatecat] STREAM SYNTHESIS for: %s", query[:80])
                return replay_cached_openai_sync(
                    synth.choices[0].message.content, model=model
                )
            # Tier 3: Stream miss — buffer and cache
            upstream = self._original.create(**kwargs)
            return buffer_and_cache_openai(upstream, self._cache, query, model=model)

        # Non-streaming
        if cached is not None:
            logger.debug("[gatecat] HIT for: %s", query[:80])
            return _CachedResponse(cached_text=cached, cache_hit=True, model=model)

        # Tier 2: CAS synthesis (sim >= 0.80 but < 0.92)
        synth = self._try_synthesis(query, model)
        if synth is not None:
            logger.debug("[gatecat] SYNTHESIS for: %s", query[:80])
            return synth

        # Tier 3: Upstream API call (miss)
        response = self._original.create(**kwargs)
        text = None
        if response.choices:
            msg = response.choices[0].message
            if msg and getattr(msg, "content", None):
                text = msg.content
        if text:
            tokens = response.usage.completion_tokens if response.usage else 0
            self._cache.populate(query, text, model=model, tokens=tokens)

        return _CachedResponse(original_response=response)


class _CachedChat:
    def __init__(self, original_chat, cache: SemanticCache, synthesis_engine=None):
        self.completions = _CachedChatCompletions(
            original_chat.completions, cache, synthesis_engine
        )


# --- Async wrapper ---

class _AsyncCachedChatCompletions:
    """Async drop-in replacement for openai.chat.completions."""

    def __init__(self, original_completions, cache: SemanticCache, synthesis_engine=None):
        self._original = original_completions
        self._cache = cache
        self._synthesis = synthesis_engine

    def _try_synthesis(self, query: str, model: str) -> _CachedResponse | None:
        """Attempt CAS synthesis (sync — runs in executor for async callers)."""
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
            return _CachedResponse(
                cached_text=result.text,
                synthesized=True,
                model=model,
            )
        return None

    async def create(self, **kwargs) -> Any:
        messages = kwargs.get("messages", [])
        model = kwargs.get("model", "")
        stream = kwargs.get("stream", False)
        query = _extract_query(messages)

        if kwargs.get("tools") or kwargs.get("functions") or not query:
            return await self._original.create(**kwargs)

        cached = self._cache.lookup(query)

        if stream:
            if cached is not None:
                logger.debug("[gatecat] ASYNC STREAM HIT for: %s", query[:80])
                return replay_cached_openai_async(cached, model=model)
            # Tier 2: Streaming synthesis (run in executor)
            import asyncio
            synth = await asyncio.get_event_loop().run_in_executor(
                None, self._try_synthesis, query, model
            )
            if synth is not None:
                logger.debug("[gatecat] ASYNC STREAM SYNTHESIS for: %s", query[:80])
                return replay_cached_openai_async(
                    synth.choices[0].message.content, model=model
                )
            upstream = await self._original.create(**kwargs)
            return buffer_and_cache_openai_async(upstream, self._cache, query, model=model)

        if cached is not None:
            logger.debug("[gatecat] ASYNC HIT for: %s", query[:80])
            return _CachedResponse(cached_text=cached, cache_hit=True, model=model)

        # Tier 2: CAS synthesis
        import asyncio
        synth = await asyncio.get_event_loop().run_in_executor(
            None, self._try_synthesis, query, model
        )
        if synth is not None:
            logger.debug("[gatecat] ASYNC SYNTHESIS for: %s", query[:80])
            return synth

        response = await self._original.create(**kwargs)
        text = None
        if response.choices:
            msg = response.choices[0].message
            if msg and getattr(msg, "content", None):
                text = msg.content
        if text:
            tokens = response.usage.completion_tokens if response.usage else 0
            self._cache.populate(query, text, model=model, tokens=tokens)

        return _CachedResponse(original_response=response)


class _AsyncCachedChat:
    def __init__(self, original_chat, cache: SemanticCache, synthesis_engine=None):
        self.completions = _AsyncCachedChatCompletions(
            original_chat.completions, cache, synthesis_engine
        )


# --- Main classes ---

class CachedOpenAI:
    """Drop-in replacement for openai.OpenAI with semantic caching.

    Args:
        cache_dir: Directory for cache data (default: ~/.gatecat/)
        similarity_threshold: Similarity threshold for verbatim hits (default: 0.92)
        negative_threshold: Similarity threshold for negative cache (default: 0.85)
        cache_max_entries: Max entries before LRU eviction (default: 100K)
        cache_ttl: TTL in seconds (default: 24 hours)
        cache_enabled: Enable/disable caching (default: True)
        on_negative_hit: Policy for negative cache ("raise", "skip", or callable)
        synthesis_mode: CAS mode — "off" (default), "auto", or "always".
            "auto" = synthesize when verbatim miss but similar candidates exist.
            "always" = always try synthesis before upstream (even on verbatim miss).
        synthesis_model: Model for CAS synthesis (default: gemini-2.0-flash-lite).
        synthesis_model_base_url: API base URL for synthesis model.
        synthesis_model_api_key: API key for synthesis model.
        synthesis_threshold: Min similarity for synthesis candidates (default: 0.80).
        synthesis_top_k: Number of cached responses to feed synthesizer (default: 5).
        **kwargs: Passed to openai.OpenAI()
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
            from openai import OpenAI
        except ImportError:
            raise ImportError(
                "openai package required. Install with: pip install gate.cat[openai]"
            )

        self._client = OpenAI(**kwargs)
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

        self.chat = _CachedChat(self._client.chat, self.cache, synthesis_engine)

    def __getattr__(self, name):
        return getattr(self._client, name)

    def close(self):
        self.cache.close()
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class AsyncCachedOpenAI:
    """Drop-in replacement for openai.AsyncOpenAI with semantic caching.

    Same args as CachedOpenAI.
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
            from openai import AsyncOpenAI
        except ImportError:
            raise ImportError(
                "openai package required. Install with: pip install gate.cat[openai]"
            )

        self._client = AsyncOpenAI(**kwargs)
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

        self.chat = _AsyncCachedChat(self._client.chat, self.cache, synthesis_engine)

    def __getattr__(self, name):
        return getattr(self._client, name)

    async def close(self):
        self.cache.close()
        await self._client.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
