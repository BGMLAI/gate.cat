"""Shared audio processing utilities for voice embedders.

Provides mel spectrogram computation, resampling, and audio I/O
using numpy only (no librosa dependency). soundfile loaded lazily.
"""

import numpy as np
from typing import Any


def hz_to_mel(hz: float) -> float:
    """Convert frequency in Hz to Mel scale."""
    return 2595.0 * np.log10(1.0 + hz / 700.0)


def mel_to_hz(mel: float) -> float:
    """Convert Mel scale to frequency in Hz."""
    return 700.0 * (10.0 ** (mel / 2595.0) - 1.0)


def mel_filterbank(sr: int, n_fft: int, n_mels: int) -> np.ndarray:
    """Create triangular mel filterbank matrix.

    Returns:
        np.ndarray of shape (n_mels, n_fft // 2 + 1), float32.
    """
    n_freqs = n_fft // 2 + 1
    low_mel = hz_to_mel(0)
    high_mel = hz_to_mel(sr / 2)
    mel_points = np.linspace(low_mel, high_mel, n_mels + 2)
    hz_points = np.array([mel_to_hz(m) for m in mel_points])
    bin_points = np.floor((n_fft + 1) * hz_points / sr).astype(int)

    fb = np.zeros((n_mels, n_freqs), dtype=np.float32)
    for i in range(n_mels):
        left, center, right = bin_points[i], bin_points[i + 1], bin_points[i + 2]
        for j in range(left, center):
            if center > left:
                fb[i, j] = (j - left) / (center - left)
        for j in range(center, right):
            if right > center:
                fb[i, j] = (right - j) / (right - center)

    return fb


def stft_power(audio: np.ndarray, n_fft: int, hop_length: int) -> np.ndarray:
    """Compute STFT power spectrum using numpy FFT.

    Returns:
        np.ndarray of shape (n_frames, n_fft // 2 + 1), float32.
    """
    pad_length = n_fft // 2
    audio_padded = np.pad(audio, (pad_length, pad_length), mode="reflect")

    n_frames = 1 + (len(audio_padded) - n_fft) // hop_length
    indices = np.arange(n_fft)[None, :] + hop_length * np.arange(n_frames)[:, None]
    frames = audio_padded[indices].astype(np.float32)

    window = np.hanning(n_fft).astype(np.float32)
    fft = np.fft.rfft(frames * window, n=n_fft)
    return (np.abs(fft) ** 2).astype(np.float32)


def compute_log_mel(
    audio: np.ndarray,
    sr: int,
    n_fft: int,
    hop_length: int,
    n_mels: int,
) -> np.ndarray:
    """Compute log mel spectrogram.

    Returns:
        np.ndarray of shape (n_frames, n_mels), float32.
    """
    power = stft_power(audio, n_fft, hop_length)
    fb = mel_filterbank(sr, n_fft, n_mels)
    mel_spec = np.dot(power, fb.T)
    return np.log(np.maximum(mel_spec, 1e-10)).astype(np.float32)


def resample(audio: np.ndarray, orig_sr: int, target_sr: int) -> np.ndarray:
    """Resample audio via linear interpolation."""
    if orig_sr == target_sr:
        return audio
    n_samples = int(len(audio) * target_sr / orig_sr)
    indices = np.linspace(0, len(audio) - 1, n_samples)
    return np.interp(indices, np.arange(len(audio)), audio).astype(np.float32)


def load_audio(raw: Any, target_sr: int) -> np.ndarray:
    """Load audio from bytes, file path, or ndarray as mono float32.

    Args:
        raw: bytes (WAV/FLAC/OGG), file path str, or np.ndarray.
        target_sr: Target sample rate for resampling.

    Returns:
        Mono float32 numpy array at target_sr.

    Raises:
        ImportError: If soundfile is not installed.
        TypeError: If input type is not supported.
    """
    if isinstance(raw, np.ndarray):
        audio = raw.astype(np.float32)
        if audio.ndim > 1:
            audio = np.mean(audio, axis=-1)
        return audio

    # Type check BEFORE importing soundfile so TypeError is raised
    # even when soundfile is not installed
    if not isinstance(raw, (bytes, str)):
        raise TypeError(
            f"Expected bytes, str path, or ndarray. Got {type(raw).__name__}"
        )

    try:
        import soundfile as sf
    except ImportError:
        raise ImportError(
            "soundfile required for audio embeddings. "
            "Install with: pip install cacheback-ai[voice]"
        )

    if isinstance(raw, bytes):
        import io
        audio, sr = sf.read(io.BytesIO(raw), dtype="float32")
    else:
        audio, sr = sf.read(raw, dtype="float32")

    if audio.ndim > 1:
        audio = np.mean(audio, axis=-1)

    return resample(audio, sr, target_sr)
