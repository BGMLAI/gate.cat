"""MiniLM-L6-v2 text embedder — 384-dim vectors via ONNX Runtime.

Uses ONNX Runtime + HuggingFace tokenizers directly (no torch, no fastembed).
Model downloaded from HuggingFace Hub on first use (~90MB ONNX model).
"""

import logging
import os
import threading
from typing import Any, Optional

import numpy as np

from gatecat.embedders import BaseEmbedder

logger = logging.getLogger(__name__)

DEFAULT_MODEL_REPO = "sentence-transformers/all-MiniLM-L6-v2"
ONNX_FILENAME = "onnx/model.onnx"
_MAX_DOWNLOAD_RETRIES = 3


class MiniLMEmbedder(BaseEmbedder):
    """Text embedder using MiniLM-L6-v2 via ONNX Runtime.

    Thread-safe: model loading is guarded by a lock, and ONNX inference
    is serialized to prevent concurrent access to the session.
    """

    dim = 384
    modality = "text"

    def __init__(
        self,
        model_repo: str = DEFAULT_MODEL_REPO,
        cache_dir: Optional[str] = None,
    ):
        self._model_repo = model_repo
        self._cache_dir = cache_dir or os.path.join(
            os.path.expanduser("~"), ".gatecat", "models"
        )
        self._session = None
        self._tokenizer = None
        self._lock = threading.Lock()

    def _ensure_model(self):
        if self._session is not None:
            return

        with self._lock:
            # Double-check after acquiring lock (another thread may have loaded)
            if self._session is not None:
                return

            import onnxruntime as ort
            from huggingface_hub import hf_hub_download
            from tokenizers import Tokenizer

            os.makedirs(self._cache_dir, exist_ok=True)

            # Download with retry
            model_path = self._download_with_retry(
                hf_hub_download, self._model_repo, ONNX_FILENAME
            )
            tokenizer_path = self._download_with_retry(
                hf_hub_download, self._model_repo, "tokenizer.json"
            )

            sess_opts = ort.SessionOptions()
            sess_opts.inter_op_num_threads = 1
            sess_opts.intra_op_num_threads = 4
            sess_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            session = ort.InferenceSession(
                model_path, sess_options=sess_opts, providers=["CPUExecutionProvider"]
            )

            tokenizer = Tokenizer.from_file(tokenizer_path)
            tokenizer.enable_truncation(max_length=512)
            tokenizer.enable_padding(pad_id=0, pad_token="[PAD]", length=None)

            # Assign both atomically (session last, since it's the guard)
            self._tokenizer = tokenizer
            self._session = session

            logger.info("[gatecat] Loaded %s ONNX (dim=%d)", self._model_repo, self.dim)

    def _download_with_retry(self, download_fn, repo_id: str, filename: str) -> str:
        """Download a file from HuggingFace Hub with retries."""
        import time as _time

        last_err = None
        for attempt in range(_MAX_DOWNLOAD_RETRIES):
            try:
                return download_fn(
                    repo_id=repo_id,
                    filename=filename,
                    cache_dir=self._cache_dir,
                )
            except Exception as e:
                last_err = e
                wait = 2 ** attempt
                logger.warning(
                    "[gatecat] Download %s/%s failed (attempt %d/%d): %s. Retrying in %ds...",
                    repo_id, filename, attempt + 1, _MAX_DOWNLOAD_RETRIES, e, wait,
                )
                _time.sleep(wait)
        raise RuntimeError(
            f"Failed to download {repo_id}/{filename} after {_MAX_DOWNLOAD_RETRIES} attempts"
        ) from last_err

    def _mean_pooling(self, model_output: np.ndarray, attention_mask: np.ndarray) -> np.ndarray:
        mask_expanded = np.expand_dims(attention_mask, axis=-1)
        sum_embeddings = np.sum(model_output * mask_expanded, axis=1)
        sum_mask = np.clip(np.sum(mask_expanded, axis=1), a_min=1e-9, a_max=None)
        return sum_embeddings / sum_mask

    def _normalize(self, vec: np.ndarray) -> np.ndarray:
        vec = vec.astype(np.float32)
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        return vec

    def encode(self, input_data: Any) -> np.ndarray:
        """Encode a single text string into a normalized 384-dim vector."""
        if not isinstance(input_data, str):
            raise TypeError(f"MiniLMEmbedder expects str, got {type(input_data).__name__}")
        return self.encode_batch([input_data])[0]

    def encode_batch(self, inputs: list[Any]) -> list[np.ndarray]:
        """Encode multiple text strings into normalized vectors. Thread-safe."""
        self._ensure_model()

        texts = [str(t) for t in inputs]
        encodings = self._tokenizer.encode_batch(texts)
        input_ids = np.array([e.ids for e in encodings], dtype=np.int64)
        attention_mask = np.array([e.attention_mask for e in encodings], dtype=np.int64)
        token_type_ids = np.zeros_like(input_ids, dtype=np.int64)

        # ONNX Runtime sessions are NOT thread-safe — serialize inference
        with self._lock:
            outputs = self._session.run(None, {
                "input_ids": input_ids,
                "attention_mask": attention_mask,
                "token_type_ids": token_type_ids,
            })

        pooled = self._mean_pooling(outputs[0], attention_mask.astype(np.float32))
        return [self._normalize(vec) for vec in pooled]
