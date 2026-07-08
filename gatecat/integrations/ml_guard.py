"""ml_guard - the OPTIONAL ML escalation layer for input_guard (INGRESS).

The regex floor in input_guard is fast, offline, zero-dep, and fail-closed. It
catches ~55% of real prompt-injections at <1% FPR. This module adds a light
LEARNED head on top to catch the long-tail paraphrases a phrase regex cannot:
a 384-dim MiniLM embedding (the ONNX model gatecat already ships for cache) fed
into a tiny logistic-regression head (a single 384-float weight vector + bias,
trained offline on public injection corpora).

  measured on a HELD-OUT test split (Lakera/gandalf + deepset + jackhhao):
    regex-only  recall 54.6%  FPR 0.81%
    regex + ML  recall 88.3%  FPR 5.17%   (this layer, threshold 0.559)

Design guarantees:
  * OPTIONAL. If onnxruntime / the ONNX model / the .npz head is unavailable,
    predict() returns None and input_guard silently stays regex-only. Installing
    the ML extra is opt-in (`pip install gate-cat[ml]`); the core never pulls it.
  * SKLEARN-FREE at runtime. The head is a dot product + sigmoid over the model's
    coefficients loaded from a .npz - we do not import sklearn to score.
  * ADDITIVE / fail-open-toward-regex. A model error never downgrades the regex
    verdict; on any exception predict() returns None and the floor stands.
  * LAZY. The embedder + head load on first use, not import, so `import
    gatecat` stays light (see gotcha: lazy ML deps).
"""
from __future__ import annotations

import math
import os
import threading
from pathlib import Path

_MODEL_PATH = Path(__file__).with_name("models") / "injection_lr.npz"
# ML escalation is OPT-IN. The regex floor is the always-on free tier with a
# clean-benign contract (<1% FPR); the ML head lifts recall to ~88% but at a
# higher FPR (~5%), so a user turns it on deliberately (the paid/paranoid tier).
# Off by default keeps the core's benign contract and import weight unchanged.
_ENABLE_ENV = "GATECAT_ENABLE_ML_GUARD"
_DISABLE_ENV = "GATECAT_DISABLE_ML_GUARD"

_lock = threading.Lock()
_state = {"loaded": False, "coef": None, "intercept": 0.0, "threshold": 1.0,
          "embedder": None, "ok": False}


def _model_is_cached(embedder) -> bool:
    """True iff the MiniLM ONNX weights are ALREADY in the local HF cache, with
    NO network fetch. Uses hf_hub_download(local_files_only=True), which raises
    if the file is not cached. This lets ml_guard decide availability instantly
    instead of triggering the embedder's blocking download-with-retry path."""
    try:
        from huggingface_hub import hf_hub_download
        repo = getattr(embedder, "_model_repo", None)
        cache_dir = getattr(embedder, "_cache_dir", None)
        if not repo:
            return False
        # the two files the embedder needs; both must be cached
        for fn in ("onnx/model.onnx", "tokenizer.json"):
            hf_hub_download(repo_id=repo, filename=fn, cache_dir=cache_dir,
                            local_files_only=True)
        return True
    except Exception:
        return False


def _load() -> bool:
    """Load the MiniLM embedder + LR head once. Returns True if the ML layer is
    usable. Never raises - a failure just leaves the layer disabled."""
    if _state["loaded"]:
        return _state["ok"]
    with _lock:
        if _state["loaded"]:
            return _state["ok"]
        _state["loaded"] = True
        # opt-in: disabled unless explicitly enabled, and a kill-switch wins.
        if os.environ.get(_DISABLE_ENV):
            return False
        if not os.environ.get(_ENABLE_ENV):
            return False
        try:
            import numpy as np  # noqa: F401
            if not _MODEL_PATH.exists():
                return False
            data = np.load(_MODEL_PATH)   # allow_pickle=False (numpy default): no RCE
            _state["coef"] = data["coef"].astype("float32")
            _state["intercept"] = float(data["intercept"])
            _state["threshold"] = float(data["threshold"])
            # reuse gatecat's ONNX MiniLM (torch-free); import lazily
            from gatecat.embedders.minilm import MiniLMEmbedder
            emb = MiniLMEmbedder()
            # FAIL-FAST: the MiniLM weights download lazily on first encode with
            # exponential-backoff retries. If they are NOT already in the local
            # cache, warming here would hang scan() for minutes then fall back
            # anyway. So verify the model is cached WITHOUT a network fetch; if
            # not present, the ML layer reports unavailable and input_guard stays
            # on the regex floor (opt-in ML degrades cleanly, never blocks/hangs).
            if not _model_is_cached(emb):
                return False
            _state["embedder"] = emb
            _state["ok"] = True
        except Exception:
            _state["ok"] = False
        return _state["ok"]


def available() -> bool:
    """True if the ML escalation layer can run (deps + model present)."""
    return _load()


def score(text: str) -> "float | None":
    """Return P(injection) in [0,1] for the text, or None if the ML layer is
    unavailable or errored. Pure dot-product + sigmoid over the MiniLM embedding
    - no sklearn at runtime."""
    if not _load():
        return None
    try:
        import numpy as np
        vec = _state["embedder"].encode(text)  # normalized 384-dim float32
        z = float(np.dot(_state["coef"], vec)) + _state["intercept"]
        return 1.0 / (1.0 + math.exp(-z))
    except Exception:
        return None


def predict(text: str) -> "tuple[bool, float] | None":
    """Return (is_injection, probability) using the trained threshold, or None if
    the ML layer is unavailable. input_guard uses this to ESCALATE content the
    regex floor called clean; it never downgrades a regex hit."""
    p = score(text)
    if p is None:
        return None
    return (p >= _state["threshold"], p)


def threshold() -> float:
    _load()
    return _state["threshold"]
