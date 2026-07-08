"""Test fixtures for gatecat."""


import pytest
import numpy as np


@pytest.fixture
def tmp_cache_dir(tmp_path):
    """Temporary cache directory for tests."""
    return str(tmp_path / "gatecat_test")


class MockEmbedder:
    """Deterministic embedder for testing — no ONNX required."""

    dim = 384
    modality = "text"

    def encode(self, input_data):
        """Hash-based deterministic embedding."""
        text = str(input_data)
        np.random.seed(hash(text) % (2**31))
        vec = np.random.randn(self.dim).astype(np.float32)
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        return vec

    def encode_batch(self, inputs):
        return [self.encode(inp) for inp in inputs]

    def preprocess(self, raw):
        return raw


@pytest.fixture
def mock_embedder():
    """Mock embedder that doesn't require ONNX models."""
    return MockEmbedder()
