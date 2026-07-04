"""Cacheback exceptions."""


class CachebackBlocked(Exception):
    """Raised when a query matches the negative cache and on_negative_hit="raise"."""

    def __init__(self, query: str, reason: str = "", similarity: float = 0.0):
        self.query = query
        self.reason = reason
        self.similarity = similarity
        super().__init__(
            f"Query blocked by negative cache (similarity={similarity:.4f}): "
            f"{reason or 'no reason provided'}"
        )


class CachebackError(Exception):
    """Base exception for cacheback internal errors."""
    pass
