"""truthgate — disagreement-gate: knows WHEN a small model is guessing, before it answers.

Mechanism (measured, BGML Study A, N=4800): the spread of N samples from the model at
temperature > 0 predicts whether the model is wrong — AUC 0.77-0.90 for 7-30B models.
Self-confidence of a single answer is DEAD (AUC 0.50); we use the SPREAD
(an external signal), not the confidence of one generation.

HONEST LIMITATION (do not hide from the customer):
  The gate catches HESITATION, not LYING. A hallucination where the model is wrong
  CONFIDENTLY (the same N samples, the same wrong answer — zero spread) is UNCATCHABLE
  by spread. Gate = "uncertainty flag → human review", NOT a "guarantee of
  zero hallucinations". Measured: confident-wrong AUC drops to ~0.71 on frontier.

Model-agnostic: works on ANY model via the `sample_fn` callback. Zero
dependency on the BGML fleet/orchestrator — you inject your Ollama / vLLM /
llama.cpp / OpenAI-compatible base_url and the gate does the rest.

Usage (minimal):
    from gatecat.gate import Gate

    def sample(prompt: str) -> str:
        # call YOUR model once at temp>0, return the text
        return my_llm(prompt, temperature=0.7)

    gate = Gate(sample_fn=sample, n_samples=5)
    verdict = gate.check("Who wrote Hamlet?")
    if verdict.uncertain:
        # the model doesn't know — reach for cache/web, escalate to a human, or abstain
        ...
    print(verdict.disagreement, verdict.samples)
"""
from __future__ import annotations

import os
import statistics
from dataclasses import dataclass, field
from typing import Callable, Sequence

# Default spread threshold above which "the model doesn't know" (gate-on).
# Measured (Study A): the gate discriminates errors from ~0.81 AUC at this threshold.
DEFAULT_DISAGREEMENT_ON = float(os.environ.get("TRUTHGATE_DISAGREEMENT_ON", "0.30"))
# Default number of probe samples. Study A: majority@8 gave full AUC; N=5 is a
# signal/cost compromise (the gate costs 5-10× tokens — a deliberate on-prem cost).
DEFAULT_N_SAMPLES = int(os.environ.get("TRUTHGATE_N_SAMPLES", "5"))


def disagreement_from_scores(scores: Sequence[float]) -> float:
    """Spread of N scalar scores -> [0,1]. High = disagreement = 'the model doesn't know'.

    Consistent with BGML router_three_branch.disagreement: normalized range (hi-lo)/hi.
    Scale-invariant. <2 values = no signal = 0.0 (treat as confident).
    """
    vals = [float(s) for s in scores if isinstance(s, (int, float))]
    if len(vals) < 2:
        return 0.0
    lo, hi = min(vals), max(vals)
    if hi <= 0:
        return 0.0
    return max(0.0, min(1.0, (hi - lo) / hi))


def _normalize(text: str) -> str:
    import re
    t = (text or "").strip().lower()
    t = re.sub(r"[^\w\s]", " ", t)
    return re.sub(r"\s+", " ", t).strip()


def disagreement_from_samples(samples: Sequence[str], embedder=None) -> float:
    """Spread of N TEXT samples -> [0,1]. Two methods:

    - embedder provided: 1 - mean pairwise cosine-sim of embeddings (semantic spread).
      Samples saying the same thing in different words = low spread (model confident on content).
    - without an embedder (fallback): fraction of UNIQUE normalized samples
      (lexical). Cheaper, coarser — good when answers are short/factoid.
    """
    clean = [s for s in samples if s and s.strip()]
    if len(clean) < 2:
        return 0.0

    if embedder is not None:
        try:
            import numpy as np
            vecs = np.array([embedder.embed(s) for s in clean], dtype=np.float32)
            # L2-normalize -> cosine = dot
            norms = np.linalg.norm(vecs, axis=1, keepdims=True)
            norms[norms == 0] = 1.0
            vecs = vecs / norms
            n = len(vecs)
            sims = []
            for i in range(n):
                for j in range(i + 1, n):
                    sims.append(float(np.dot(vecs[i], vecs[j])))
            mean_sim = statistics.mean(sims) if sims else 1.0
            return max(0.0, min(1.0, 1.0 - mean_sim))
        except Exception:
            pass  # fall back to lexical

    # lexical fallback: how many unique answers (after normalization)
    uniq = {_normalize(s) for s in clean}
    return (len(uniq) - 1) / (len(clean) - 1) if len(clean) > 1 else 0.0


@dataclass
class GateVerdict:
    """Gate result for a single query."""
    disagreement: float                 # [0,1] spread of samples
    uncertain: bool                     # disagreement >= threshold => "the model doesn't know"
    samples: list[str] = field(default_factory=list)
    threshold: float = DEFAULT_DISAGREEMENT_ON
    method: str = "samples"             # "samples" (text) | "scores" (scalars)
    n: int = 0

    def to_dict(self) -> dict:
        return {
            "disagreement": round(self.disagreement, 4),
            "uncertain": self.uncertain,
            "threshold": self.threshold,
            "method": self.method,
            "n_samples": self.n,
            "samples": self.samples,
        }


class Gate:
    """Disagreement-gate on ANY model.

    Args:
        sample_fn: callback(prompt:str) -> str. Call YOUR model ONCE at temp>0.
                   The gate calls it n_samples times. Required, unless you use
                   check_scores()/check_samples() directly.
        n_samples: how many probe samples (default 5).
        threshold: spread threshold for "the model doesn't know" (default 0.30).
        embedder: optional embedder (e.g. gatecat get_embedder("minilm")) for
                  semantic spread. Without it -> lexical fallback.
    """

    def __init__(
        self,
        sample_fn: Callable[[str], str] | None = None,
        *,
        n_samples: int = DEFAULT_N_SAMPLES,
        threshold: float = DEFAULT_DISAGREEMENT_ON,
        embedder=None,
    ):
        self.sample_fn = sample_fn
        self.n_samples = max(2, int(n_samples))
        self.threshold = float(threshold)
        self._embedder = embedder

    # --- main API: give a question, the gate collects the samples itself ---
    def check(self, prompt: str) -> GateVerdict:
        """Collect n_samples from the model (sample_fn) and evaluate the spread."""
        if self.sample_fn is None:
            raise ValueError(
                "Gate.check() requires sample_fn. Either pass a callback to the constructor, "
                "or use check_samples(samples) / check_scores(scores)."
            )
        samples = []
        for _ in range(self.n_samples):
            try:
                samples.append(str(self.sample_fn(prompt)))
            except Exception:
                pass  # a single failed sample does not break the gate
        # FAIL-CLOSED (audit 2026-06-27 #4): when ALL samples failed (model
        # unavailable/crash/auth), an empty set → disagreement=0.0 → uncertain=False
        # would report a BROKEN model as "confident". No signal = treat as uncertain.
        if not samples:
            return GateVerdict(
                disagreement=1.0, uncertain=True, samples=[],
                threshold=self.threshold, method="samples", n=0,
            )
        return self.check_samples(samples)

    def check_samples(self, samples: Sequence[str]) -> GateVerdict:
        """Evaluate the spread of already-collected text samples.

        FAIL-CLOSED (audit 2026-06-27 should-fix): rejects None/empty BEFORE str()
        (otherwise None→'None' would pose as a confident answer → disagreement=0.0). <2 real
        samples = no spread signal → uncertain=True (not a false "confident")."""
        valid = [str(s) for s in samples if s is not None and str(s).strip()]
        if len(valid) < 2:
            return GateVerdict(
                disagreement=1.0, uncertain=True, samples=valid,
                threshold=self.threshold, method="samples", n=len(valid),
            )
        dis = disagreement_from_samples(valid, embedder=self._embedder)
        return GateVerdict(
            disagreement=dis,
            uncertain=dis >= self.threshold,
            samples=valid,
            threshold=self.threshold,
            method="samples",
            n=len(valid),
        )

    def check_scores(self, scores: Sequence[float]) -> GateVerdict:
        """Evaluate the spread of scalar scores (when you already have sample scores, not text)."""
        dis = disagreement_from_scores(scores)
        return GateVerdict(
            disagreement=dis,
            uncertain=dis >= self.threshold,
            samples=[],
            threshold=self.threshold,
            method="scores",
            n=len(list(scores)),
        )

    # --- helper for the auto-embedder from gatecat ---
    def with_minilm(self) -> "Gate":
        """Enable semantic spread via gatecat MiniLM (ONNX, CPU, ~90MB).

        If loading the embedder fails (no onnxruntime/network/disk), the gate still
        runs on the lexical fallback — but we WARN (audit 2026-06-27 should-fix:
        silently swallowing it hid the degradation from a user who EXPLICITLY asked for semantics)."""
        if self._embedder is None:
            try:
                from gatecat.embedders import get_embedder
                self._embedder = get_embedder("minilm")
            except Exception as e:
                import warnings
                warnings.warn(
                    f"with_minilm(): failed to load the MiniLM embedder "
                    f"({type(e).__name__}: {e}); the gate is using the lexical fallback.",
                    stacklevel=2,
                )
        return self
