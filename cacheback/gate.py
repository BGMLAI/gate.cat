"""truthgate — disagreement-gate: wie KIEDY mały model zgaduje, zanim odpowie.

Mechanizm (zmierzony, BGML Badanie A, N=4800): rozrzut N próbek z modelu przy
temperaturze > 0 przewiduje czy model się myli — AUC 0.77-0.90 dla modeli 7-30B.
Self-confidence pojedynczej odpowiedzi jest MARTWA (AUC 0.50); używamy ROZRZUTU
(zewnętrzny sygnał), nie pewności jednej generacji.

UCZCIWE OGRANICZENIE (nie ukrywać przed klientem):
  Gate łapie WAHANIE, nie KŁAMSTWO. Halucynacja, gdy model myli się PEWNIE
  (te same N próbek, ta sama zła odpowiedź — zerowy rozrzut), jest NIEŁAPALNA
  rozrzutem. Gate = "uncertainty flag → human review", NIE "gwarancja
  zero-halucynacji". Mierzone: confident-wrong AUC spada ~0.71 na frontier.

Model-agnostic: działa na DOWOLNYM modelu przez callback `sample_fn`. Zero
zależności od floty/orchestratora BGML — wstrzykujesz swój Ollama / vLLM /
llama.cpp / OpenAI-compatible base_url i gate robi resztę.

Użycie (minimalne):
    from cacheback.gate import Gate

    def sample(prompt: str) -> str:
        # zawołaj SWÓJ model raz przy temp>0, zwróć tekst
        return my_llm(prompt, temperature=0.7)

    gate = Gate(sample_fn=sample, n_samples=5)
    verdict = gate.check("Who wrote Hamlet?")
    if verdict.uncertain:
        # model nie wie — sięgnij do cache/web, eskaluj do człowieka, albo abstain
        ...
    print(verdict.disagreement, verdict.samples)
"""
from __future__ import annotations

import os
import statistics
from dataclasses import dataclass, field
from typing import Callable, Sequence

# Domyślny próg rozrzutu, powyżej którego "model nie wie" (gate-on).
# Zmierzone (Badanie A): gate dyskryminuje błąd od ~0.81 AUC przy tym progu.
DEFAULT_DISAGREEMENT_ON = float(os.environ.get("TRUTHGATE_DISAGREEMENT_ON", "0.30"))
# Domyślna liczba próbek probe. Badanie A: majority@8 dawał pełny AUC; N=5 to
# kompromis sygnał/koszt (gate to 5-10× tokenów — to świadomy koszt on-prem).
DEFAULT_N_SAMPLES = int(os.environ.get("TRUTHGATE_N_SAMPLES", "5"))


def disagreement_from_scores(scores: Sequence[float]) -> float:
    """Rozrzut N skalarnych score'ów -> [0,1]. Wysoki = niezgoda = 'model nie wie'.

    Zgodne z BGML router_three_branch.disagreement: znormalizowany range (hi-lo)/hi.
    Odporne na skalę. <2 wartości = brak sygnału = 0.0 (traktuj jak pewny).
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
    """Rozrzut N TEKSTOWYCH próbek -> [0,1]. Dwie metody:

    - embedder podany: 1 - średnia parowa cosine-sim embeddingów (semantyczny rozrzut).
      Próbki mówiące to samo różnymi słowami = niski rozrzut (model pewny treści).
    - bez embeddera (fallback): odsetek UNIKALNYCH znormalizowanych próbek
      (lexical). Tańsze, grubsze — dobre gdy odpowiedzi są krótkie/faktoidalne.
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
            pass  # spadnij na lexical

    # lexical fallback: ile unikalnych odpowiedzi (po normalizacji)
    uniq = {_normalize(s) for s in clean}
    return (len(uniq) - 1) / (len(clean) - 1) if len(clean) > 1 else 0.0


@dataclass
class GateVerdict:
    """Wynik gate dla jednego zapytania."""
    disagreement: float                 # [0,1] rozrzut próbek
    uncertain: bool                     # disagreement >= próg => "model nie wie"
    samples: list[str] = field(default_factory=list)
    threshold: float = DEFAULT_DISAGREEMENT_ON
    method: str = "samples"             # "samples" (tekst) | "scores" (skalary)
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
    """Disagreement-gate na DOWOLNYM modelu.

    Args:
        sample_fn: callback(prompt:str) -> str. Wołaj SWÓJ model RAZ przy temp>0.
                   Gate woła go n_samples razy. Wymagane, chyba że używasz
                   check_scores()/check_samples() bezpośrednio.
        n_samples: ile próbek probe (default 5).
        threshold: próg rozrzutu dla "model nie wie" (default 0.30).
        embedder: opcjonalny embedder (np. cacheback get_embedder("minilm")) do
                  semantycznego rozrzutu. Bez niego -> lexical fallback.
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

    # --- główne API: daj pytanie, gate sam zbierze próbki ---
    def check(self, prompt: str) -> GateVerdict:
        """Zbierz n_samples z modelu (sample_fn) i oceń rozrzut."""
        if self.sample_fn is None:
            raise ValueError(
                "Gate.check() wymaga sample_fn. Albo podaj callback w konstruktorze, "
                "albo użyj check_samples(samples) / check_scores(scores)."
            )
        samples = []
        for _ in range(self.n_samples):
            try:
                samples.append(str(self.sample_fn(prompt)))
            except Exception:
                pass  # pojedyncza nieudana próbka nie psuje gate
        # FAIL-CLOSED (audyt 2026-06-27 #4): gdy WSZYSTKIE próbki padły (model
        # niedostępny/crash/auth), pusty zbiór → disagreement=0.0 → uncertain=False
        # raportowałby ZEPSUTY model jako "pewny". Brak sygnału = traktuj jak niepewny.
        if not samples:
            return GateVerdict(
                disagreement=1.0, uncertain=True, samples=[],
                threshold=self.threshold, method="samples", n=0,
            )
        return self.check_samples(samples)

    def check_samples(self, samples: Sequence[str]) -> GateVerdict:
        """Oceń rozrzut już-zebranych próbek tekstowych.

        FAIL-CLOSED (audyt 2026-06-27 should-fix): odrzuca None/puste PRZED str()
        (inaczej None→'None' udawał pewną odpowiedź → disagreement=0.0). <2 realnych
        próbek = brak sygnału rozrzutu → uncertain=True (nie fałszywe "pewny")."""
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
        """Oceń rozrzut skalarnych score'ów (gdy masz już oceny próbek, nie tekst)."""
        dis = disagreement_from_scores(scores)
        return GateVerdict(
            disagreement=dis,
            uncertain=dis >= self.threshold,
            samples=[],
            threshold=self.threshold,
            method="scores",
            n=len(list(scores)),
        )

    # --- pomocnicze do auto-embeddera z cacheback ---
    def with_minilm(self) -> "Gate":
        """Włącz semantyczny rozrzut przez cacheback MiniLM (ONNX, CPU, ~90MB).

        Jeśli załadowanie embeddera padnie (brak onnxruntime/sieci/dysku), gate dalej
        działa na lexical fallback — ale OSTRZEGAMY (audyt 2026-06-27 should-fix:
        ciche połknięcie ukrywało degradację przed userem który JAWNIE poprosił o semantykę)."""
        if self._embedder is None:
            try:
                from cacheback.embedders import get_embedder
                self._embedder = get_embedder("minilm")
            except Exception as e:
                import warnings
                warnings.warn(
                    f"with_minilm(): nie udało się załadować embeddera MiniLM "
                    f"({type(e).__name__}: {e}); gate używa lexical fallback.",
                    stacklevel=2,
                )
        return self
