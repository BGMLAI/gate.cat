"""CLAP audio embedder — 512-dim vectors for audio-level matching.

Converts audio to semantic vectors for similarity-based caching.
Uses ONNX Runtime + HuggingFace Hub for model download (~300MB).

Requires: pip install cacheback-ai[voice]  (adds soundfile)

Audio preprocessing pipeline (matches LAION CLAP HTSAT):
  1. Load audio (WAV/FLAC via soundfile, or numpy array)
  2. Resample to 48000 Hz, convert to mono
  3. Pad/truncate to 480000 samples (10 seconds)
  4. Compute 64-bin log mel spectrogram
  5. L2-normalize output embedding

Best for: SFX, alarms, environmental audio, audio fingerprinting.
"Same sound = same response."
"""

import logging
import os
import threading
from typing import Any, Optional

import numpy as np

from cacheback.embedders import BaseEmbedder
from cacheback.embedders._audio import compute_log_mel, load_audio

logger = logging.getLogger(__name__)

# CLAP HTSAT model from HuggingFace (Xenova ONNX export)
DEFAULT_CLAP_REPO = "Xenova/clap-htsat-unfused"
ONNX_FILENAME = "onnx/audio_model.onnx"
_MAX_DOWNLOAD_RETRIES = 3

# CLAP audio config
CLAP_SAMPLE_RATE = 48000
CLAP_DURATION = 10  # seconds
CLAP_N_FFT = 1024
CLAP_HOP_LENGTH = 480
CLAP_N_MELS = 64
CLAP_AUDIO_LENGTH = CLAP_SAMPLE_RATE * CLAP_DURATION  # 480000 samples


class CLAPEmbedder(BaseEmbedder):
    """Audio embedder using CLAP HTSAT via ONNX Runtime.

    Accepts raw audio bytes (WAV/FLAC), file paths, or numpy arrays.
    Returns normalized 512-dim float32 vectors.

    Thread-safe: model loading is guarded by a lock, and ONNX inference
    is serialized to prevent concurrent access to the session.
    """

    dim = 512
    modality = "voice"

    def __init__(
        self,
        model_repo: str = DEFAULT_CLAP_REPO,
        cache_dir: Optional[str] = None,
    ):
        self._model_repo = model_repo
        self._cache_dir = cache_dir or os.path.join(
            os.path.expanduser("~"), ".cacheback", "models"
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
            sess_opts.graph_optimization_level = (
                ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            )
            session = ort.InferenceSession(
                model_path,
                sess_options=sess_opts,
                providers=["CPUExecutionProvider"],
            )

            self._session = session
            logger.info(
                "[cacheback] Loaded CLAP %s ONNX (dim=%d)",
                self._model_repo,
                self.dim,
            )

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
                wait = 2**attempt
                logger.warning(
                    "[cacheback] Download %s/%s failed (attempt %d/%d): %s. Retrying in %ds...",
                    repo_id,
                    filename,
                    attempt + 1,
                    _MAX_DOWNLOAD_RETRIES,
                    e,
                    wait,
                )
                _time.sleep(wait)
        raise RuntimeError(
            f"Failed to download {repo_id}/{filename} after {_MAX_DOWNLOAD_RETRIES} attempts"
        ) from last_err

    def preprocess(self, raw: Any) -> np.ndarray:
        """Convert audio input to CLAP-compatible mel spectrogram tensor.

        Accepts:
            - bytes (WAV/FLAC)
            - str (file path)
            - np.ndarray (mono float32, assumed at 48kHz)

        Returns:
            np.ndarray of shape (1, 1, time_steps, 64), float32.
        """
        audio = load_audio(raw, CLAP_SAMPLE_RATE)

        # Pad or truncate to fixed length (10 seconds)
        if len(audio) > CLAP_AUDIO_LENGTH:
            audio = audio[:CLAP_AUDIO_LENGTH]
        elif len(audio) < CLAP_AUDIO_LENGTH:
            audio = np.pad(audio, (0, CLAP_AUDIO_LENGTH - len(audio)))

        # Compute log mel spectrogram: (time_steps, 64)
        mel = compute_log_mel(
            audio, CLAP_SAMPLE_RATE, CLAP_N_FFT, CLAP_HOP_LENGTH, CLAP_N_MELS
        )

        # CLAP HTSAT expects (batch, channels, time, mels)
        return mel[np.newaxis, np.newaxis, :, :].astype(np.float32)

    def _normalize(self, vec: np.ndarray) -> np.ndarray:
        """L2-normalize a vector."""
        vec = vec.astype(np.float32).flatten()
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        return vec

    def encode(self, input_data: Any) -> np.ndarray:
        """Encode audio into a normalized 512-dim vector.

        Args:
            input_data: bytes (WAV/FLAC), file path str, or np.ndarray.

        Returns:
            np.ndarray of shape (512,), float32, L2-normalized.
        """
        self._ensure_model()

        mel_features = self.preprocess(input_data)

        with self._lock:
            input_name = self._session.get_inputs()[0].name
            outputs = self._session.run(None, {input_name: mel_features})

        embedding = outputs[0]
        if embedding.ndim > 1:
            embedding = embedding[0]

        return self._normalize(embedding)

    def encode_batch(self, inputs: list[Any]) -> list[np.ndarray]:
        """Encode multiple audio inputs. Falls back to sequential."""
        return [self.encode(inp) for inp in inputs]
