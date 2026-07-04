"""Pluggable embedder registry for cacheback.

Supports text (MiniLM), image (CLIP), voice (CLAP/Whisper), and custom embedders.
Each embedder converts modality-specific input into a normalized vector for similarity search.

Usage:
    from cacheback.embedders import get_embedder, register_embedder, BaseEmbedder

    embedder = get_embedder("minilm")  # default text embedder
    vector = embedder.encode("Hello world")  # -> np.ndarray (384-dim)
"""

import abc
import logging
from typing import Any, Optional

import numpy as np

logger = logging.getLogger(__name__)

_registry: dict[str, type["BaseEmbedder"]] = {}
_instances: dict[str, "BaseEmbedder"] = {}


class BaseEmbedder(abc.ABC):
    """Abstract base class for all cacheback embedders.

    Subclasses must define:
        dim: int — output vector dimension
        modality: str — "text", "image", "voice", or custom
        encode(input_data) -> np.ndarray — embed input into normalized vector
    """

    dim: int = 0
    modality: str = "unknown"

    @abc.abstractmethod
    def encode(self, input_data: Any) -> np.ndarray:
        """Encode input into a normalized float32 vector of length self.dim."""
        ...

    def encode_batch(self, inputs: list[Any]) -> list[np.ndarray]:
        """Encode multiple inputs. Override for batch optimization."""
        return [self.encode(inp) for inp in inputs]

    def preprocess(self, raw: Any) -> Any:
        """Optional modality-specific preprocessing. Override if needed."""
        return raw


def register_embedder(name: str, cls: type[BaseEmbedder]) -> None:
    """Register an embedder class by name."""
    _registry[name] = cls
    logger.debug("[cacheback] Registered embedder: %s", name)


def get_embedder(name: str = "minilm", cache_dir: Optional[str] = None) -> BaseEmbedder:
    """Get or create a singleton embedder instance by name.

    Args:
        name: Registered embedder name ("minilm", "clip", "clap", "whisper")
        cache_dir: Directory for model files (passed to embedder constructor)
    """
    key = f"{name}:{cache_dir or 'default'}"
    if key not in _instances:
        if name not in _registry:
            available = list(_registry.keys())
            raise ValueError(
                f"Unknown embedder '{name}'. Available: {available}. "
                f"Register custom embedders with register_embedder()."
            )
        kwargs = {}
        if cache_dir:
            kwargs["cache_dir"] = cache_dir
        _instances[key] = _registry[name](**kwargs)
    return _instances[key]


def list_embedders() -> list[str]:
    """List all registered embedder names."""
    return list(_registry.keys())


def _clear_instances() -> None:
    """Clear cached instances (for testing)."""
    _instances.clear()


# Auto-register built-in embedders
def _register_builtins():
    from cacheback.embedders.minilm import MiniLMEmbedder
    register_embedder("minilm", MiniLMEmbedder)

    # Register optional embedders if their deps are available
    try:
        from cacheback.embedders.clip import CLIPEmbedder
        register_embedder("clip", CLIPEmbedder)
    except ImportError:
        pass

    try:
        from cacheback.embedders.clap import CLAPEmbedder
        register_embedder("clap", CLAPEmbedder)
    except ImportError:
        pass

    try:
        from cacheback.embedders.whisper import WhisperEmbedder
        register_embedder("whisper", WhisperEmbedder)
    except ImportError:
        pass


_register_builtins()
