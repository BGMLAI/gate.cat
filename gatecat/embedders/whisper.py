"""Whisper + MiniLM compound embedder — voice → text → semantic vector.

Transcribes audio via Whisper tiny (ONNX), then embeds the text with MiniLM.
Best for: voice assistants, dictation — "same meaning = same response."

Uses ONNX Runtime + HuggingFace Hub for model download (~75MB Whisper + ~90MB MiniLM).

Requires: pip install gate.cat[voice]  (adds soundfile)

Pipeline:
  1. Load audio (WAV/FLAC via soundfile, or numpy array)
  2. Resample to 16000 Hz, mono
  3. Compute 80-bin log mel spectrogram (Whisper format)
  4. Whisper encoder → hidden states
  5. Whisper decoder (greedy) → token IDs
  6. Decode tokens → text
  7. MiniLM encode text → 384-dim L2-normalized vector
"""

import logging
import os
import threading
from typing import Any, Optional

import numpy as np

from gatecat.embedders import BaseEmbedder
from gatecat.embedders._audio import (
    load_audio,
    mel_filterbank,
    stft_power,
)

logger = logging.getLogger(__name__)

# Whisper tiny model from HuggingFace (Xenova ONNX export)
DEFAULT_WHISPER_REPO = "Xenova/whisper-tiny"
ENCODER_FILENAME = "onnx/encoder_model.onnx"
DECODER_FILENAME = "onnx/decoder_model_merged.onnx"
_MAX_DOWNLOAD_RETRIES = 3

# Whisper audio config
WHISPER_SAMPLE_RATE = 16000
WHISPER_N_FFT = 400
WHISPER_HOP_LENGTH = 160
WHISPER_N_MELS = 80
WHISPER_CHUNK_SECONDS = 30
WHISPER_N_FRAMES = WHISPER_SAMPLE_RATE * WHISPER_CHUNK_SECONDS // WHISPER_HOP_LENGTH

# Whisper special tokens
_SOT = 50258  # <|startoftranscript|>
_LANG_EN = 50259  # <|en|>
_TRANSCRIBE = 50359  # <|transcribe|>
_NO_TIMESTAMPS = 50363  # <|notimestamps|>
_EOT = 50257  # <|endoftext|>
_MAX_DECODE_TOKENS = 224


def _whisper_log_mel(audio: np.ndarray) -> np.ndarray:
    """Compute Whisper-format 80-bin log mel spectrogram.

    Whisper uses log10 (not ln), clamping, and normalization to [-1, 1].

    Args:
        audio: mono float32 at 16kHz, padded/truncated to 30 seconds.

    Returns:
        np.ndarray of shape (80, 3000), float32.
    """
    power = stft_power(audio, WHISPER_N_FFT, WHISPER_HOP_LENGTH)
    fb = mel_filterbank(WHISPER_SAMPLE_RATE, WHISPER_N_FFT, WHISPER_N_MELS)
    mel_spec = np.dot(power, fb.T)

    # Whisper log10 with clamping and normalization
    mel_spec = np.log10(np.maximum(mel_spec, 1e-10))
    max_val = mel_spec.max()
    mel_spec = np.maximum(mel_spec, max_val - 8.0)
    mel_spec = (mel_spec - (max_val - 4.0)) / 4.0

    # Transpose to (n_mels, n_frames) and pad/truncate to 3000 frames
    mel_spec = mel_spec.T
    if mel_spec.shape[1] > WHISPER_N_FRAMES:
        mel_spec = mel_spec[:, :WHISPER_N_FRAMES]
    elif mel_spec.shape[1] < WHISPER_N_FRAMES:
        pad_width = WHISPER_N_FRAMES - mel_spec.shape[1]
        mel_spec = np.pad(mel_spec, ((0, 0), (0, pad_width)))

    return mel_spec.astype(np.float32)


class WhisperEmbedder(BaseEmbedder):
    """Voice-to-text-to-vector embedder using Whisper + MiniLM pipeline.

    Accepts audio bytes, file paths, or numpy arrays.
    Transcribes via Whisper tiny, then embeds text via MiniLM.
    Returns normalized 384-dim float32 vectors.

    Thread-safe: model loading and inference are lock-guarded.
    """

    dim = 384  # MiniLM output dimension
    modality = "voice"

    def __init__(
        self,
        whisper_repo: str = DEFAULT_WHISPER_REPO,
        cache_dir: Optional[str] = None,
    ):
        self._whisper_repo = whisper_repo
        self._cache_dir = cache_dir or os.path.join(
            os.path.expanduser("~"), ".gatecat", "models"
        )
        self._encoder = None
        self._decoder = None
        self._tokenizer = None
        self._minilm = None
        self._lock = threading.Lock()

    def _ensure_model(self):
        if self._encoder is not None:
            return

        with self._lock:
            if self._encoder is not None:
                return

            import onnxruntime as ort
            from huggingface_hub import hf_hub_download
            from tokenizers import Tokenizer

            os.makedirs(self._cache_dir, exist_ok=True)

            enc_path = self._download_with_retry(
                hf_hub_download, self._whisper_repo, ENCODER_FILENAME
            )
            dec_path = self._download_with_retry(
                hf_hub_download, self._whisper_repo, DECODER_FILENAME
            )
            tok_path = self._download_with_retry(
                hf_hub_download, self._whisper_repo, "tokenizer.json"
            )

            sess_opts = ort.SessionOptions()
            sess_opts.inter_op_num_threads = 1
            sess_opts.intra_op_num_threads = 4
            sess_opts.graph_optimization_level = (
                ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            )

            encoder = ort.InferenceSession(
                enc_path,
                sess_options=sess_opts,
                providers=["CPUExecutionProvider"],
            )
            decoder = ort.InferenceSession(
                dec_path,
                sess_options=sess_opts,
                providers=["CPUExecutionProvider"],
            )
            tokenizer = Tokenizer.from_file(tok_path)

            # Get MiniLM for text embedding (reuses singleton)
            from gatecat.embedders import get_embedder

            minilm = get_embedder("minilm", cache_dir=self._cache_dir)

            self._tokenizer = tokenizer
            self._minilm = minilm
            self._decoder = decoder
            self._encoder = encoder  # assign last — this is the guard variable

            logger.info(
                "[gatecat] Loaded Whisper %s + MiniLM pipeline (dim=%d)",
                self._whisper_repo,
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
                    "[gatecat] Download %s/%s failed (attempt %d/%d): %s. Retrying in %ds...",
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
        """Convert audio input to Whisper-format mel spectrogram.

        Accepts:
            - bytes (WAV/FLAC)
            - str (file path)
            - np.ndarray (mono float32, assumed at 16kHz)

        Returns:
            np.ndarray of shape (1, 80, 3000), float32.
        """
        audio = load_audio(raw, WHISPER_SAMPLE_RATE)

        # Pad/truncate to 30 seconds
        target_len = WHISPER_SAMPLE_RATE * WHISPER_CHUNK_SECONDS
        if len(audio) > target_len:
            audio = audio[:target_len]
        else:
            audio = np.pad(audio, (0, target_len - len(audio)))

        mel = _whisper_log_mel(audio)
        return mel[np.newaxis, :, :].astype(np.float32)  # (1, 80, 3000)

    def _build_decoder_inputs(
        self, input_ids: np.ndarray, encoder_hidden: np.ndarray
    ) -> dict:
        """Build decoder input dict, handling KV-cache and other dynamic inputs."""
        inputs = {}
        for inp in self._decoder.get_inputs():
            name = inp.name
            if name == "input_ids":
                inputs[name] = input_ids
            elif "encoder" in name.lower():
                inputs[name] = encoder_hidden
            elif name == "use_cache_branch":
                inputs[name] = np.array([False])
            else:
                # Past key values or other optional inputs — zero-sized tensors
                shape = []
                for dim in inp.shape:
                    if isinstance(dim, int):
                        shape.append(dim)
                    else:
                        shape.append(0)  # dynamic/string dims → 0 (empty)
                dtype = np.float32
                if "int" in str(inp.type):
                    dtype = np.int64
                inputs[name] = np.zeros(shape, dtype=dtype)
        return inputs

    def _transcribe(self, mel_features: np.ndarray) -> str:
        """Run Whisper encoder + greedy decoder to transcribe audio.

        Args:
            mel_features: (1, 80, 3000) float32 mel spectrogram.

        Returns:
            Transcribed text string.
        """
        with self._lock:
            # Encoder forward pass
            enc_input_name = self._encoder.get_inputs()[0].name
            enc_outputs = self._encoder.run(None, {enc_input_name: mel_features})
            encoder_hidden = enc_outputs[0]

            # Greedy decode
            tokens = [_SOT, _LANG_EN, _TRANSCRIBE, _NO_TIMESTAMPS]

            for _ in range(_MAX_DECODE_TOKENS):
                input_ids = np.array([tokens], dtype=np.int64)
                dec_inputs = self._build_decoder_inputs(input_ids, encoder_hidden)

                dec_outputs = self._decoder.run(None, dec_inputs)
                logits = dec_outputs[0]
                next_token = int(np.argmax(logits[0, -1, :]))

                if next_token == _EOT:
                    break
                tokens.append(next_token)

        # Decode tokens to text — skip the 4 prompt tokens, filter special tokens
        text_tokens = [t for t in tokens[4:] if t < _EOT]
        if not text_tokens:
            return ""

        text = self._tokenizer.decode(text_tokens, skip_special_tokens=True)
        return text.strip()

    def encode(self, input_data: Any) -> np.ndarray:
        """Encode audio: transcribe → embed text → normalized 384-dim vector.

        Args:
            input_data: bytes (WAV/FLAC), file path str, or np.ndarray.

        Returns:
            np.ndarray of shape (384,), float32, L2-normalized.
        """
        self._ensure_model()

        mel_features = self.preprocess(input_data)
        text = self._transcribe(mel_features)

        if not text:
            logger.warning("[gatecat] Whisper returned empty transcription")
            return np.zeros(self.dim, dtype=np.float32)

        return self._minilm.encode(text)

    def transcribe(self, input_data: Any) -> str:
        """Transcribe audio to text (utility method).

        Useful for debugging or when you need the raw text without embedding.
        """
        self._ensure_model()
        mel_features = self.preprocess(input_data)
        return self._transcribe(mel_features)

    def encode_batch(self, inputs: list[Any]) -> list[np.ndarray]:
        """Encode multiple audio inputs. Falls back to sequential."""
        return [self.encode(inp) for inp in inputs]
