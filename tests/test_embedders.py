"""Embedder registry and base embedder tests."""

import io
import struct
import wave

import numpy as np
import pytest
from gatecat.embedders import (
    BaseEmbedder,
    register_embedder,
    get_embedder,
    list_embedders,
    _registry,
    _clear_instances,
)


class DummyEmbedder(BaseEmbedder):
    """Minimal test embedder."""

    dim = 64
    modality = "test"

    def __init__(self, cache_dir=None):
        self.cache_dir = cache_dir

    def encode(self, input_data):
        np.random.seed(hash(str(input_data)) % (2**31))
        vec = np.random.randn(self.dim).astype(np.float32)
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        return vec


class TestBaseEmbedder:
    def test_encode_returns_normalized_vector(self):
        emb = DummyEmbedder()
        vec = emb.encode("hello world")
        assert vec.shape == (64,)
        assert vec.dtype == np.float32
        assert abs(np.linalg.norm(vec) - 1.0) < 1e-5

    def test_encode_batch_default(self):
        emb = DummyEmbedder()
        vecs = emb.encode_batch(["hello", "world"])
        assert len(vecs) == 2
        for v in vecs:
            assert v.shape == (64,)

    def test_preprocess_passthrough(self):
        emb = DummyEmbedder()
        assert emb.preprocess("raw input") == "raw input"

    def test_deterministic_encoding(self):
        emb = DummyEmbedder()
        v1 = emb.encode("hello")
        v2 = emb.encode("hello")
        np.testing.assert_array_equal(v1, v2)

    def test_different_inputs_different_vectors(self):
        emb = DummyEmbedder()
        v1 = emb.encode("hello")
        v2 = emb.encode("goodbye")
        assert not np.allclose(v1, v2)


class TestEmbedderRegistry:
    def setup_method(self):
        """Save registry state before each test."""
        self._saved = dict(_registry)

    def teardown_method(self):
        """Restore registry and clear instances after each test."""
        _registry.clear()
        _registry.update(self._saved)
        _clear_instances()

    def test_register_custom_embedder(self):
        register_embedder("test-embedder", DummyEmbedder)
        assert "test-embedder" in list_embedders()

    def test_get_custom_embedder(self):
        register_embedder("test-embedder", DummyEmbedder)
        emb = get_embedder("test-embedder")
        assert isinstance(emb, DummyEmbedder)
        assert emb.dim == 64
        assert emb.modality == "test"

    def test_get_embedder_singleton(self):
        register_embedder("test-embedder", DummyEmbedder)
        emb1 = get_embedder("test-embedder")
        emb2 = get_embedder("test-embedder")
        assert emb1 is emb2

    def test_get_unknown_embedder_raises(self):
        with pytest.raises(ValueError, match="Unknown embedder"):
            get_embedder("nonexistent-embedder-xyz")

    def test_list_embedders_includes_minilm(self):
        names = list_embedders()
        assert "minilm" in names

    def test_builtin_registration(self):
        # minilm should always be registered
        assert "minilm" in _registry
        # clip/clap/whisper may or may not be depending on imports
        # Just verify minilm exists as the base case

    def test_clear_instances(self):
        register_embedder("test-embedder", DummyEmbedder)
        emb1 = get_embedder("test-embedder")
        _clear_instances()
        emb2 = get_embedder("test-embedder")
        assert emb1 is not emb2

    def test_embedder_with_cache_dir(self):
        register_embedder("test-embedder", DummyEmbedder)
        emb1 = get_embedder("test-embedder", cache_dir="/tmp/a")
        emb2 = get_embedder("test-embedder", cache_dir="/tmp/b")
        # Different cache_dirs should create different instances
        assert emb1 is not emb2


# --- CLIP Embedder tests (structure + preprocessing, no ONNX model needed) ---

class TestCLIPEmbedder:
    """Tests for CLIPEmbedder that don't require the actual ONNX model."""

    @pytest.fixture(autouse=True)
    def _require_pillow(self):
        pytest.importorskip("PIL")

    def test_clip_class_attributes(self):
        from gatecat.embedders.clip import CLIPEmbedder
        emb = CLIPEmbedder()
        assert emb.dim == 512
        assert emb.modality == "image"

    def test_clip_registered(self):
        """CLIP should be registered if Pillow is available."""
        try:
            import PIL  # noqa: F401
            assert "clip" in list_embedders()
        except ImportError:
            pytest.skip("Pillow not installed")

    def test_preprocess_pil_image(self):
        """Preprocess should accept PIL Image and return normalized tensor."""
        try:
            from PIL import Image
        except ImportError:
            pytest.skip("Pillow not installed")
        from gatecat.embedders.clip import CLIPEmbedder

        emb = CLIPEmbedder()
        # Create a test image (red 100x100)
        img = Image.new("RGB", (100, 100), color=(255, 0, 0))
        result = emb.preprocess(img)
        assert isinstance(result, np.ndarray)
        assert result.shape == (1, 3, 224, 224)
        assert result.dtype == np.float32

    def test_preprocess_bytes(self):
        """Preprocess should accept JPEG/PNG bytes."""
        try:
            from PIL import Image
        except ImportError:
            pytest.skip("Pillow not installed")
        import io
        from gatecat.embedders.clip import CLIPEmbedder

        emb = CLIPEmbedder()
        # Create JPEG bytes
        img = Image.new("RGB", (50, 50), color=(0, 255, 0))
        buf = io.BytesIO()
        img.save(buf, format="JPEG")
        result = emb.preprocess(buf.getvalue())
        assert result.shape == (1, 3, 224, 224)

    def test_preprocess_ndarray(self):
        """Preprocess should accept numpy array (H, W, 3)."""
        try:
            from PIL import Image  # noqa: F401
        except ImportError:
            pytest.skip("Pillow not installed")
        from gatecat.embedders.clip import CLIPEmbedder

        emb = CLIPEmbedder()
        arr = np.zeros((80, 120, 3), dtype=np.uint8)
        result = emb.preprocess(arr)
        assert result.shape == (1, 3, 224, 224)

    def test_preprocess_non_square(self):
        """Preprocess should handle non-square images via center crop."""
        try:
            from PIL import Image
        except ImportError:
            pytest.skip("Pillow not installed")
        from gatecat.embedders.clip import CLIPEmbedder

        emb = CLIPEmbedder()
        # Wide image
        img = Image.new("RGB", (640, 480), color=(128, 128, 128))
        result = emb.preprocess(img)
        assert result.shape == (1, 3, 224, 224)

        # Tall image
        img = Image.new("RGB", (480, 640), color=(128, 128, 128))
        result = emb.preprocess(img)
        assert result.shape == (1, 3, 224, 224)

    def test_preprocess_invalid_type_raises(self):
        """Preprocess should raise TypeError for unsupported input."""
        from gatecat.embedders.clip import CLIPEmbedder
        emb = CLIPEmbedder()
        with pytest.raises(TypeError, match="CLIPEmbedder expects"):
            emb.preprocess(12345)

    def test_preprocess_rgba_converted_to_rgb(self):
        """RGBA images should be converted to RGB."""
        try:
            from PIL import Image
        except ImportError:
            pytest.skip("Pillow not installed")
        from gatecat.embedders.clip import CLIPEmbedder

        emb = CLIPEmbedder()
        img = Image.new("RGBA", (100, 100), color=(255, 0, 0, 128))
        result = emb.preprocess(img)
        assert result.shape == (1, 3, 224, 224)  # 3 channels, not 4

    def test_normalization_constants(self):
        """Verify CLIP normalization constants are reasonable."""
        from gatecat.embedders.clip import CLIP_MEAN, CLIP_STD
        assert CLIP_MEAN.shape == (3,)
        assert CLIP_STD.shape == (3,)
        assert all(0.0 < m < 1.0 for m in CLIP_MEAN)
        assert all(0.0 < s < 1.0 for s in CLIP_STD)

    def test_center_crop_resize(self):
        """Center crop should produce exact square output."""
        try:
            from PIL import Image
        except ImportError:
            pytest.skip("Pillow not installed")
        from gatecat.embedders.clip import CLIPEmbedder

        emb = CLIPEmbedder()
        img = Image.new("RGB", (800, 600))
        cropped = emb._center_crop_resize(img, 224)
        assert cropped.size == (224, 224)


# --- Helper: generate WAV bytes for audio tests ---

def _make_wav_bytes(duration: float = 1.0, sr: int = 16000, freq: float = 440.0) -> bytes:
    """Create WAV bytes with a simple sine wave."""
    n_samples = int(sr * duration)
    t = np.linspace(0, duration, n_samples, endpoint=False)
    samples = (np.sin(2 * np.pi * freq * t) * 32767).astype(np.int16)
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sr)
        wf.writeframes(samples.tobytes())
    return buf.getvalue()


# --- Audio utilities tests (pure numpy, no ONNX model needed) ---

class TestAudioUtils:
    """Tests for shared audio processing utilities."""

    def test_mel_filterbank_shape_whisper(self):
        from gatecat.embedders._audio import mel_filterbank
        fb = mel_filterbank(sr=16000, n_fft=400, n_mels=80)
        assert fb.shape == (80, 201)
        assert fb.dtype == np.float32

    def test_mel_filterbank_shape_clap(self):
        from gatecat.embedders._audio import mel_filterbank
        fb = mel_filterbank(sr=48000, n_fft=1024, n_mels=64)
        assert fb.shape == (64, 513)
        assert fb.dtype == np.float32

    def test_mel_filterbank_non_negative(self):
        from gatecat.embedders._audio import mel_filterbank
        fb = mel_filterbank(sr=48000, n_fft=1024, n_mels=64)
        assert np.all(fb >= 0)
        # With enough FFT resolution, each filter should have non-zero bins
        assert np.all(fb.sum(axis=1) > 0)

    def test_mel_filterbank_low_res_valid(self):
        """Low-res FFT (Whisper: 80 mels, 201 bins) may have sparse low filters."""
        from gatecat.embedders._audio import mel_filterbank
        fb = mel_filterbank(sr=16000, n_fft=400, n_mels=80)
        assert np.all(fb >= 0)
        # Most filters should be non-zero (some low-freq ones may be empty)
        active = np.sum(fb.sum(axis=1) > 0)
        assert active >= 70  # at least 70 of 80 filters active

    def test_resample_upsample(self):
        from gatecat.embedders._audio import resample
        audio = np.sin(np.linspace(0, 2 * np.pi, 16000, endpoint=False)).astype(np.float32)
        resampled = resample(audio, 16000, 48000)
        assert len(resampled) == 48000
        assert resampled.dtype == np.float32

    def test_resample_downsample(self):
        from gatecat.embedders._audio import resample
        audio = np.random.randn(48000).astype(np.float32)
        resampled = resample(audio, 48000, 16000)
        assert len(resampled) == 16000

    def test_resample_identity(self):
        from gatecat.embedders._audio import resample
        audio = np.random.randn(16000).astype(np.float32)
        result = resample(audio, 16000, 16000)
        np.testing.assert_array_equal(result, audio)

    def test_stft_power_shape(self):
        from gatecat.embedders._audio import stft_power
        audio = np.random.randn(16000).astype(np.float32)
        power = stft_power(audio, n_fft=400, hop_length=160)
        assert power.shape[1] == 201  # n_fft // 2 + 1
        assert np.all(power >= 0)  # power is non-negative

    def test_compute_log_mel_shape(self):
        from gatecat.embedders._audio import compute_log_mel
        audio = np.random.randn(16000).astype(np.float32)
        mel = compute_log_mel(audio, sr=16000, n_fft=400, hop_length=160, n_mels=80)
        assert mel.shape[1] == 80
        assert mel.dtype == np.float32

    def test_load_audio_ndarray(self):
        from gatecat.embedders._audio import load_audio
        audio = np.random.randn(16000).astype(np.float32)
        result = load_audio(audio, target_sr=16000)
        np.testing.assert_array_equal(result, audio)

    def test_load_audio_stereo_to_mono(self):
        from gatecat.embedders._audio import load_audio
        stereo = np.random.randn(16000, 2).astype(np.float32)
        result = load_audio(stereo, target_sr=16000)
        assert result.ndim == 1
        assert len(result) == 16000

    def test_load_audio_invalid_type(self):
        from gatecat.embedders._audio import load_audio
        with pytest.raises(TypeError, match="Expected bytes"):
            load_audio(12345, target_sr=16000)

    def test_load_audio_wav_bytes(self):
        """Load WAV bytes via soundfile."""
        try:
            import soundfile  # noqa: F401
        except ImportError:
            pytest.skip("soundfile not installed")
        from gatecat.embedders._audio import load_audio
        wav = _make_wav_bytes(duration=0.5, sr=16000)
        result = load_audio(wav, target_sr=16000)
        assert result.ndim == 1
        assert result.dtype == np.float32
        assert abs(len(result) - 8000) < 100  # ~0.5s at 16kHz


# --- CLAP Embedder tests (structure + preprocessing, no ONNX model needed) ---

class TestCLAPEmbedder:
    """Tests for CLAPEmbedder that don't require the actual ONNX model."""

    def test_clap_class_attributes(self):
        from gatecat.embedders.clap import CLAPEmbedder
        emb = CLAPEmbedder()
        assert emb.dim == 512
        assert emb.modality == "voice"

    def test_clap_registered(self):
        """CLAP should always be registered (only numpy at import time)."""
        assert "clap" in list_embedders()

    def test_preprocess_ndarray(self):
        """Preprocess should accept numpy array and return mel spectrogram tensor."""
        from gatecat.embedders.clap import CLAPEmbedder, CLAP_N_MELS
        emb = CLAPEmbedder()
        audio = np.random.randn(48000).astype(np.float32)  # 1s at 48kHz
        result = emb.preprocess(audio)
        assert isinstance(result, np.ndarray)
        assert result.ndim == 4  # (1, 1, time_steps, n_mels)
        assert result.shape[0] == 1
        assert result.shape[1] == 1
        assert result.shape[3] == CLAP_N_MELS
        assert result.dtype == np.float32

    def test_preprocess_short_audio_padded(self):
        """Short audio should be zero-padded to 10 seconds."""
        from gatecat.embedders.clap import CLAPEmbedder, CLAP_AUDIO_LENGTH
        emb = CLAPEmbedder()
        audio = np.random.randn(4800).astype(np.float32)  # 0.1s
        result = emb.preprocess(audio)
        assert result.ndim == 4

    def test_preprocess_long_audio_truncated(self):
        """Long audio should be truncated to 10 seconds."""
        from gatecat.embedders.clap import CLAPEmbedder
        emb = CLAPEmbedder()
        audio = np.random.randn(960000).astype(np.float32)  # 20s at 48kHz
        result = emb.preprocess(audio)
        assert result.ndim == 4

    def test_preprocess_wav_bytes(self):
        """Preprocess should accept WAV bytes."""
        try:
            import soundfile  # noqa: F401
        except ImportError:
            pytest.skip("soundfile not installed")
        from gatecat.embedders.clap import CLAPEmbedder
        emb = CLAPEmbedder()
        wav = _make_wav_bytes(duration=1.0, sr=48000)
        result = emb.preprocess(wav)
        assert result.ndim == 4
        assert result.shape[3] == 64

    def test_preprocess_invalid_type_raises(self):
        from gatecat.embedders.clap import CLAPEmbedder
        emb = CLAPEmbedder()
        with pytest.raises(TypeError, match="Expected bytes"):
            emb.preprocess(12345)

    def test_clap_constants(self):
        from gatecat.embedders.clap import (
            CLAP_SAMPLE_RATE, CLAP_DURATION, CLAP_N_MELS, CLAP_AUDIO_LENGTH,
        )
        assert CLAP_SAMPLE_RATE == 48000
        assert CLAP_DURATION == 10
        assert CLAP_N_MELS == 64
        assert CLAP_AUDIO_LENGTH == 480000


# --- Whisper Embedder tests (structure + preprocessing, no ONNX model needed) ---

class TestWhisperEmbedder:
    """Tests for WhisperEmbedder that don't require the actual ONNX model."""

    def test_whisper_class_attributes(self):
        from gatecat.embedders.whisper import WhisperEmbedder
        emb = WhisperEmbedder()
        assert emb.dim == 384
        assert emb.modality == "voice"

    def test_whisper_registered(self):
        """Whisper should always be registered (only numpy at import time)."""
        assert "whisper" in list_embedders()

    def test_preprocess_ndarray(self):
        """Preprocess should accept numpy array and return Whisper mel tensor."""
        from gatecat.embedders.whisper import WhisperEmbedder, WHISPER_N_FRAMES, WHISPER_N_MELS
        emb = WhisperEmbedder()
        audio = np.random.randn(16000).astype(np.float32)  # 1s at 16kHz
        result = emb.preprocess(audio)
        assert isinstance(result, np.ndarray)
        assert result.shape == (1, WHISPER_N_MELS, WHISPER_N_FRAMES)
        assert result.dtype == np.float32

    def test_preprocess_short_audio_padded(self):
        """Short audio should be zero-padded to 30 seconds."""
        from gatecat.embedders.whisper import WhisperEmbedder
        emb = WhisperEmbedder()
        audio = np.random.randn(1600).astype(np.float32)  # 0.1s
        result = emb.preprocess(audio)
        assert result.shape == (1, 80, 3000)

    def test_preprocess_long_audio_truncated(self):
        """Long audio should be truncated to 30 seconds."""
        from gatecat.embedders.whisper import WhisperEmbedder
        emb = WhisperEmbedder()
        audio = np.random.randn(640000).astype(np.float32)  # 40s at 16kHz
        result = emb.preprocess(audio)
        assert result.shape == (1, 80, 3000)

    def test_preprocess_wav_bytes(self):
        """Preprocess should accept WAV bytes."""
        try:
            import soundfile  # noqa: F401
        except ImportError:
            pytest.skip("soundfile not installed")
        from gatecat.embedders.whisper import WhisperEmbedder
        emb = WhisperEmbedder()
        wav = _make_wav_bytes(duration=1.0, sr=16000)
        result = emb.preprocess(wav)
        assert result.shape == (1, 80, 3000)

    def test_preprocess_invalid_type_raises(self):
        from gatecat.embedders.whisper import WhisperEmbedder
        emb = WhisperEmbedder()
        with pytest.raises(TypeError, match="Expected bytes"):
            emb.preprocess(12345)

    def test_whisper_log_mel_output_range(self):
        """Whisper mel spectrogram should be normalized to roughly [-1, 1]."""
        from gatecat.embedders.whisper import _whisper_log_mel, WHISPER_SAMPLE_RATE, WHISPER_CHUNK_SECONDS
        audio = np.random.randn(WHISPER_SAMPLE_RATE * WHISPER_CHUNK_SECONDS).astype(np.float32) * 0.1
        mel = _whisper_log_mel(audio)
        assert mel.shape == (80, 3000)
        assert mel.dtype == np.float32
        # Whisper normalization: values should be in roughly [-1, 1] range
        assert mel.max() <= 1.0 + 1e-5
        assert mel.min() >= -2.5  # can go below -1 for very quiet audio

    def test_whisper_special_tokens(self):
        from gatecat.embedders.whisper import _SOT, _EOT, _LANG_EN, _TRANSCRIBE, _NO_TIMESTAMPS
        assert _SOT == 50258
        assert _EOT == 50257
        assert _LANG_EN == 50259
        assert _TRANSCRIBE == 50359
        assert _NO_TIMESTAMPS == 50363
