"""stagnation — stagnation-by-state: pilnuje KORYTA, nie rzeki.

ARCHITEKTURA (Aksjomat 1 / teoria τ, user-designed REJESTR 2026-06-26):
  "Koryto pilnuje rzeki, STAGNACJA pilnuje koryta."

Dwie role, NIE mylić:
  - GatedLoop (cacheback.agent): pilnuje RZEKI — przerywa runaway agenta gdy model
    zgaduje w pętli (rozrzut próbek). Sygnał = WAHANIE rzeki.
  - StagnationMonitor (TU): pilnuje KORYTA — wykrywa gdy koryto ODRZUCA odpowiedź
    za odpowiedzią bez postępu. Sygnał = brak-postępu-mimo-odrzuceń = KORYTO ZGNIŁO
    (baza stale/zła odrzuca DOBRE odpowiedzi), nie rzeka się myli.

PO CO (zmierzone, REJESTR 2026-06-27): koryto-lookup SAMO bywa confident-wrong —
zepsuta/nieaktualna baza wprowadza własny błąd (koryto-stale: Casablanca zamiast
Rabat → odrzuca poprawną odpowiedź modelu = bad-block). Sam licznik rozrzutu tego
NIE złapie (koryto jest deterministyczne, zero rozrzutu). Stagnation-by-state to
OBIEKTYWNY licznik: seria odrzuceń przez koryto bez akceptacji = sygnał "to koryto
zgniło". Wtedy eskaluj do web-rozjemcy (rozsądzi KTO ma rację) zamiast ślepo ufać
korytu.

Lekki, bez zależności. Trzyma stan (okno ostatnich werdyktów) i mówi KIEDY przestać
ufać korytu i sięgnąć po arbitra.

Użycie:
    from cacheback.stagnation import StagnationMonitor

    mon = StagnationMonitor(window=5, refute_ratio=0.8)
    for q, ans in stream:
        kv = koryto.verify(q, ans)
        st = mon.observe(kv)            # podaj werdykt koryta
        if st.koryto_suspect:
            # koryto odrzuca za dużo bez akceptacji → może samo zgniło
            # → NIE blokuj na korycie, eskaluj do web-rozjemcy
            ...
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class StagnationState:
    """Migawka stanu monitora po obserwacji jednego werdyktu."""
    koryto_suspect: bool          # czy koryto wygląda na zgniłe (za dużo odrzuceń bez postępu)
    refute_streak: int            # ile odrzuceń Z RZĘDU (twardych/miękkich łącznie)
    soft_refute_streak: int       # ile MIĘKKICH odrzuceń (lookup, needs_arbiter) z rzędu — to one sygnalizują stale
    window_refute_ratio: float    # odsetek odrzuceń w oknie
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "koryto_suspect": self.koryto_suspect,
            "refute_streak": self.refute_streak,
            "soft_refute_streak": self.soft_refute_streak,
            "window_refute_ratio": round(self.window_refute_ratio, 3),
            "reason": self.reason,
        }


class StagnationMonitor:
    """Licznik stanu koryta: wykrywa "koryto zgniło" przez serię odrzuceń bez postępu.

    Sygnał celowo skupia się na MIĘKKICH odrzuceniach (lookup, needs_arbiter=True),
    bo to one bywają stale. TWARDE odrzucenia (exec/calc) to prawdziwy confident-wrong
    rzeki — ich seria NIE jest podejrzana wobec koryta (interpreter się nie myli).

    Args:
        window: rozmiar okna ostatnich werdyktów (default 5).
        refute_ratio: odsetek odrzuceń w oknie powyżej którego koryto jest podejrzane (default 0.8).
        soft_streak_trigger: ile MIĘKKICH odrzuceń z rzędu = od razu podejrzane (default 3).
                             Miękkie = lookup/needs_arbiter (potencjalnie stale baza).
    """

    def __init__(self, *, window: int = 5, refute_ratio: float = 0.8,
                 soft_streak_trigger: int = 3):
        self.window = max(2, int(window))
        self.refute_ratio = float(refute_ratio)
        self.soft_streak_trigger = max(1, int(soft_streak_trigger))
        self._recent: deque = deque(maxlen=self.window)
        self._refute_streak = 0
        self._soft_refute_streak = 0

    def observe(self, verdict: Any) -> StagnationState:
        """Podaj KorytoVerdict (lub dict-like z .verdict/.hard/.needs_arbiter).
        Zwraca StagnationState mówiący czy koryto jest podejrzane."""
        v = self._verdict_str(verdict)
        is_refute = (v == "refute")
        is_soft = is_refute and self._is_soft(verdict)

        # okno trzyma (verdict, is_soft) — by window-ratio rozróżniał twarde od miękkich
        self._recent.append((v, is_soft))

        if is_refute:
            self._refute_streak += 1
        else:
            self._refute_streak = 0
        if is_soft:
            self._soft_refute_streak += 1
        else:
            self._soft_refute_streak = 0

        refutes = sum(1 for vv, _ in self._recent if vv == "refute")
        soft_refutes = sum(1 for vv, sf in self._recent if vv == "refute" and sf)
        ratio = refutes / len(self._recent) if self._recent else 0.0

        # PODEJRZANE gdy:
        #  (a) seria MIĘKKICH odrzuceń (lookup/needs_arbiter) >= próg — stale baza?
        #  (b) okno pełne, wysoki odsetek odrzuceń, I są w nim MIĘKKIE odrzucenia.
        # KLUCZ: czysto TWARDE odrzucenia (exec/calc) NIGDY nie czynią koryta podejrzanym —
        # interpreter się nie myli, to prawdziwy confident-wrong rzeki (nie zgnite koryto).
        suspect = False
        reason = ""
        if self._soft_refute_streak >= self.soft_streak_trigger:
            suspect = True
            reason = (f"{self._soft_refute_streak} miękkich odrzuceń z rzędu (lookup/needs_arbiter) "
                      f"→ koryto może być stale; eskaluj do web-rozjemcy")
        elif (len(self._recent) >= self.window and ratio >= self.refute_ratio
              and soft_refutes > 0):
            suspect = True
            reason = (f"odsetek odrzuceń {ratio:.0%} w oknie {self.window} ≥ {self.refute_ratio:.0%} "
                      f"({soft_refutes} miękkich) → brak postępu mimo odrzuceń; sprawdź czy koryto nie zgniło")

        return StagnationState(
            koryto_suspect=suspect,
            refute_streak=self._refute_streak,
            soft_refute_streak=self._soft_refute_streak,
            window_refute_ratio=ratio,
            reason=reason,
        )

    def reset(self) -> None:
        self._recent.clear()
        self._refute_streak = 0
        self._soft_refute_streak = 0

    # --- adaptery na różne kształty werdyktu ---
    @staticmethod
    def _verdict_str(verdict: Any) -> str:
        if hasattr(verdict, "verdict"):
            return str(verdict.verdict)
        if isinstance(verdict, dict):
            return str(verdict.get("verdict", "unknown"))
        return str(verdict)

    @staticmethod
    def _is_soft(verdict: Any) -> bool:
        """Miękkie odrzucenie = lookup/needs_arbiter (potencjalnie stale), NIE exec/calc (twarde)."""
        if hasattr(verdict, "needs_arbiter"):
            # twarde (exec/calc) ma hard=True; miękkie (lookup) ma needs_arbiter=True
            hard = bool(getattr(verdict, "hard", False))
            return bool(getattr(verdict, "needs_arbiter", False)) or not hard
        if isinstance(verdict, dict):
            hard = bool(verdict.get("hard", False))
            return bool(verdict.get("needs_arbiter", False)) or not hard
        return True  # nieznany kształt → traktuj jako miękki (ostrożniej)
