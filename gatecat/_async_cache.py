"""Async wrapper for SemanticCache — runs CPU-bound operations in executor."""

import asyncio
import logging
from typing import Any, Optional

from gatecat.cache import SemanticCache

logger = logging.getLogger(__name__)


class AsyncSemanticCache:
    """Async wrapper for SemanticCache. Runs blocking ops in thread executor.

    Same constructor args as SemanticCache.
    """

    def __init__(self, **kwargs):
        self._cache = SemanticCache(**kwargs)

    async def lookup(self, query: Any) -> Optional[str]:
        """Async cache lookup — runs in executor."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._cache.lookup, query)

    async def populate(self, query: Any, response: str, model: str = "", tokens: int = 0) -> bool:
        """Async cache populate — runs in executor."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._cache.populate, query, response, model, tokens
        )

    async def evict_expired(self) -> int:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._cache.evict_expired)

    @property
    def stats(self) -> dict:
        return self._cache.stats

    @property
    def negative(self):
        return self._cache.negative

    async def close(self):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._cache.close)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
