"""bidirectional — BidirectionalGate: bramka dwukierunkowa (DOSTAWCA + STRAŻNIK) na wspólnym silniku.

Council 10-głosów (2026-06-28) TOP-3: ten sam silnik prawdy (koryto), ale OSOBNE INTERFEJSY.
Powód: błąd dostawcy (stary cache) NIE może skazić strażnika; strażnik może ZAWETOWAĆ akcję
opartą na błędnym HARD od dostawcy. Izolacja blast-radius.

  Provider.provide_truth(op, args)   — kierunek 1: dostarcza agentowi zweryfikowany fakt (read-only).
  Guardian.veto(action, ...)         — kierunek 2: wetuje akcję ZANIM się wykona (fail-closed).

Disagreement-gate (uncertainty, SOFT) żyje osobno w gate.py — to inny mechanizm.
Tu: bramka AKCJI/PRAWDY (dwukierunkowa pętla agenta).

Rdzeń 100% stdlib + koryto + veto + provider (wszystko stdlib). Zero API/model w runtime.
"""
from __future__ import annotations

from typing import Optional

from cacheback.koryto import Koryto
from cacheback.veto import VetoGate, ActionPolicy, VetoDecision
from cacheback.provider import (
    provide_truth as _provide_truth,
    provide_hint as _provide_hint,
    verify_proof as _verify_proof,
    Verified, Hint,
)


class Provider:
    """Kierunek 1 — DOSTAWCA prawdy. Read-only, czyste funkcje (mutuje ⇒ Actor nie Oracle).
    Daje agentowi Verified (HARD, exec/calc) lub Hint (SOFT, cache). NIGDY nie wykonuje akcji."""

    def __init__(self, koryto: Optional[Koryto] = None):
        # współdzielony silnik z Guardianem (council TOP-3) — ale Provider go tylko CZYTA
        self.koryto = koryto or Koryto(enable_exec=True, enable_calc=True)

    def provide_truth(self, op: str, args: str) -> Optional[Verified]:
        """Zwróć Verified (HARD) lub None. Tylko exec/calc — dowód z wykonania."""
        return _provide_truth(op, args)

    def provide_hint(self, value: str, sim: float, source: str = "lookup") -> Hint:
        """Zwróć Hint (SOFT) — z cache/lookup. NIGDY HARD (nawet sim=1.0)."""
        return _provide_hint(value, sim, source)

    @staticmethod
    def verify_proof(verified: Verified) -> bool:
        """Agent odtwarza dowód niezależnie (nie ufa bramce ślepo)."""
        return _verify_proof(verified)


class Guardian:
    """Kierunek 2 — STRAŻNIK. Wetuje akcję ZANIM się wykona. Fail-closed.
    Opakowuje istniejący VetoGate (NIE zastępuje) — separacja interfejsu od dostawcy."""

    def __init__(self, veto_gate: Optional[VetoGate] = None,
                 koryto: Optional[Koryto] = None):
        self._veto = veto_gate or VetoGate(koryto=koryto)

    def veto(self, action: str, args=(), kwargs=None) -> VetoDecision:
        """Oceń akcję. allowed=False ⇒ NIE wykonuj. Fail-closed na każdym wyjątku."""
        return self._veto.evaluate(action, tuple(args), dict(kwargs or {}))


class BidirectionalGate:
    """Jeden silnik koryto, dwa interfejsy (council TOP-3). Pełna pętla:
      1. provider.provide_truth() — bramka DAJE prawdę agentowi (wejście decyzji)
      2. agent rozumuje na pewnych danych
      3. guardian.veto() — bramka SPRAWDZA akcję (wyjście, fail-closed)

    Wspólny Koryto = prawda jedna; osobne Provider/Guardian = blast-radius izolowany.
    """

    def __init__(self, policy: Optional[ActionPolicy] = None,
                 koryto: Optional[Koryto] = None):
        self.koryto = koryto or Koryto(enable_exec=True, enable_calc=True)
        self.provider = Provider(koryto=self.koryto)
        self.guardian = Guardian(
            veto_gate=VetoGate(policy=policy, koryto=self.koryto))

    # wygodne skróty
    def provide_truth(self, op: str, args: str) -> Optional[Verified]:
        return self.provider.provide_truth(op, args)

    def veto(self, action: str, args=(), kwargs=None) -> VetoDecision:
        return self.guardian.veto(action, args, kwargs)
