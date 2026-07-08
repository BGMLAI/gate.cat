"""CLIP ViT-B/32 image embedder — 512-dim vectors via ONNX Runtime.

Converts images to semantic vectors for similarity-based caching.
Uses ONNX Runtime + HuggingFace Hub for model download (~150MB).

Requires: pip install gate.cat[image]  (adds Pillow)

Image preprocessing pipeline (matches OpenAI CLIP):
  1. Resize to 224x224 (bicubic, center crop)
  2. Convert to RGB float32 [0, 1]
  3. Normalize with CLIP mean/std
  4. L2-normalize output embedding
"""

import logging
import os
import threading
from typing import Any, Optional

import numpy as np

from gatecat.embedders import BaseEmbedder

logger = logging.getLogger(__name__)

# CLIP ViT-B/32 visual encoder from HuggingFace
# This is the visual (image) half of CLIP, exported to ONNX.
DEFAULT_CLIP_REPO = "Xenova/clip-vit-base-patch32"
ONNX_FILENAME = "onnx/vision_model.onnx"
_MAX_DOWNLOAD_RETRIES = 3

# CLIP normalization constants (ImageNet-derived)
CLIP_MEAN = np.array([0.48145466, 0.4578275, 0.40821073], dtype=np.float32)
CLIP_STD = np.array([0.26862954, 0.26130258, 0.27577711], dtype=np.float32)
CLIP_IMAGE_SIZE = 224


class CLIPEmbedder(BaseEmbedder):
    """Image embedder using CLIP ViT-B/32 via ONNX Runtime.

    Accepts PIL.Image objects or raw bytes (JPEG/PNG).
    Returns normalized 512-dim float32 vectors.

    Thread-safe: model loading is guarded by a lock, and ONNX inference
    is serialized to prevent concurrent access to the session.
    """

    dim = 512
    modality = "image"

    def __init__(
        self,
        model_repo: str = DEFAULT_CLIP_REPO,
        cache_dir: Optional[str] = None,
    ):
        self._model_repo = model_repo
        self._cache_dir = cache_dir or os.path.join(
            os.path.expanduser("~"), ".gatecat", "models"
        )
        self._session = None
        self._lock = threading.Lock()

    def _ensure_model(self):
        if self._session is not None:
            return

        with self._lock:
            if self._session is not None:
                return

            import onnxruntime as ort
            from huggingface_hub import hf_hub_download

            os.makedirs(self._cache_dir, exist_ok=True)

            model_path = self._download_with_retry(
                hf_hub_download, self._model_repo, ONNX_FILENAME
            )

            sess_opts = ort.SessionOptions()
            sess_opts.inter_op_num_threads = 1
            sess_opts.intra_op_num_threads = 4
            sess_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            session = ort.InferenceSession(
                model_path, sess_options=sess_opts, providers=["CPUExecutionProvider"]
            )

            self._session = session
            logger.info("[gatecat] Loaded CLIP %s ONNX (dim=%d)", self._model_repo, self.dim)

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

    def preprocess(self, raw: Any) -> np.ndarray:
        """Convert image input to CLIP-compatible pixel values tensor.

        Accepts:
            - PIL.Image.Image
            - bytes (JPEG/PNG)
            - str (file path)
            - np.ndarray (H, W, 3) uint8

        Returns:
            np.ndarray of shape (1, 3, 224, 224), float32, normalized.
        """
        try:
            from PIL import Image
        except ImportError:
            raise ImportError(
                "Pillow required for image embeddings. "
                "Install with: pip install gate.cat[image]"
            )

        # Convert input to PIL Image
        if isinstance(raw, Image.Image):
            img = raw
        elif isinstance(raw, bytes):
            import io
            img = Image.open(io.BytesIO(raw))
        elif isinstance(raw, str):
            img = Image.open(raw)
        elif isinstance(raw, np.ndarray):
            img = Image.fromarray(raw)
        else:
            raise TypeError(
                f"CLIPEmbedder expects PIL.Image, bytes, str path, or ndarray. "
                f"Got {type(raw).__name__}"
            )

        # Convert to RGB and resize (center crop)
        img = img.convert("RGB")
        img = self._center_crop_resize(img, CLIP_IMAGE_SIZE)

        # To float32 [0, 1] → normalize → CHW → batch
        pixels = np.array(img, dtype=np.float32) / 255.0
        pixels = (pixels - CLIP_MEAN) / CLIP_STD
        pixels = pixels.transpose(2, 0, 1)  # HWC → CHW
        pixels = np.expand_dims(pixels, axis=0)  # → (1, 3, 224, 224)

        return pixels

    def _center_crop_resize(self, img, size: int):
        """Resize with center crop to square, matching CLIP preprocessing."""
        from PIL import Image

        w, h = img.size
        # Resize so shortest side == size
        if w < h:
            new_w = size
            new_h = int(h * size / w)
        else:
            new_h = size
            new_w = int(w * size / h)

        img = img.resize((new_w, new_h), Image.BICUBIC)

        # Center crop to size x size
        left = (new_w - size) // 2
        top = (new_h - size) // 2
        img = img.crop((left, top, left + size, top + size))

        return img

    def _normalize(self, vec: np.ndarray) -> np.ndarray:
        """L2-normalize a vector."""
        vec = vec.astype(np.float32).flatten()
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        return vec

    def encode(self, input_data: Any) -> np.ndarray:
        """Encode an image into a normalized 512-dim vector.

        Args:
            input_data: PIL.Image, bytes, file path str, or np.ndarray (H,W,3).

        Returns:
            np.ndarray of shape (512,), float32, L2-normalized.
        """
        self._ensure_model()

        pixel_values = self.preprocess(input_data)

        # Run ONNX inference (thread-safe)
        with self._lock:
            # The visual model expects "pixel_values" input
            input_name = self._session.get_inputs()[0].name
            outputs = self._session.run(None, {input_name: pixel_values})

        # outputs[0] is the image embedding (pooler_output or last_hidden_state[0])
        # Use the first output, which is typically the pooled image embedding
        embedding = outputs[0]
        if embedding.ndim > 1:
            embedding = embedding[0]  # Remove batch dimension

        return self._normalize(embedding)

    def encode_batch(self, inputs: list[Any]) -> list[np.ndarray]:
        """Encode multiple images. Falls back to sequential (no batch optimization yet)."""
        return [self.encode(inp) for inp in inputs]
