"""gatecat.veto — action-veto: zatrzymaj agenta ZANIM zrobi nieodwracalną akcję.

Problem (z realnych issues frameworków agentowych): agent z dostępem do narzędzi
wykonuje akcję, której nie powinien — i jest ona NIEODWRACALNA. Zmierzone w dziczy:
duplicate payments / trades (crewAI #5802, 65 komentarzy), agent zniszczył konto AWS
deployując Terraform w zły cel ($106k straty, autogen #7770), brak tool-call
authorization (crewAI #5888, 66 komentarzy). To NIE jest problem kosztu tokenów —
to problem KONTROLI nad akcją zanim dotknie świata.

GatedLoop (gatecat.agent) pilnuje RZEKI: model się waha (rozrzut) → pauza pętli.
Veto pilnuje AKCJI: zanim funkcja-narzędzie się wykona, akcja musi przepłynąć przez
deterministyczne KORYTO (policy + niezależny check). Confident-wrong na poziomie
AKCJI jest niełapalny rozrzutem (model jest PEWNY że trzeba zapłacić/zdeployować) —
łapie go dopiero policy + interpreter, nie uncertainty-signal.

Trzy mury (fail-closed — błąd któregokolwiek = VETO, nie przepuszczenie):
  1. POLICY — deterministyczne reguły: deny / próg kwoty / wymaga-człowieka.
  2. KORYTO — gdy akcja ma sprawdzalny atom, interpreter weryfikuje NIEZALEŻNIE
              od modelu (gatecat.koryto, recall 1.0, 0% false-pass w proxy).
  3. HUMAN  — gdy policy żąda człowieka i brak zatwierdzenia → akcja zablokowana.

UCZCIWOŚĆ (granica, nie udawajmy):
  - Veto blokuje akcje pasujące do reguł / sprzeczne z deterministycznym checkiem.
    To DETEKCJA+BLOKADA znanych wzorców, NIE gwarancja że każda zła akcja jest złapana.
  - Veto musi być pewne tylko co BLOKUJE (znane wzorce, sprzeczność z interpreterem),
    nigdy co PRZEPUSZCZA. Dlatego fail-closed: wątpliwość → veto.
  - Policy jest tak dobra jak jej reguły. Pusta policy bez koryto = przepuszcza wszystko
    (uczciwie zgłaszane przez `VetoGate(strict=True)` które wymaga ≥1 muru).

Użycie:
    from gatecat.veto import before_action, ActionPolicy, ActionVetoed

    policy = ActionPolicy(
        deny=[r"terraform.*(destroy|apply).*prod", r"drop\\s+table"],
        require_human=[r"charge_card", r"send_wire"],
        max_amount=100.0,
    )

    @before_action(policy, human_approve=lambda call: ask_user(call),
                   amount_of=lambda **k: k.get("amount"))
    def charge_card(*, customer, amount):
        return payment_api.charge(customer, amount)

    try:
        charge_card(customer="acme", amount=5000)
    except ActionVetoed as e:
        log.warning("akcja zablokowana: %s", e.reason)   # nieodwracalne nie stało się faktem
"""
from __future__ import annotations

import functools
import inspect
import math
import re
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional, Sequence

from gatecat.exceptions import ActionVetoed
from gatecat.koryto import Koryto, KorytoVerdict


@dataclass
class VetoDecision:
    """Wynik bramki veto dla jednej próby akcji (do audytu)."""
    allowed: bool
    mur: str                       # "policy-deny" | "policy-amount" | "koryto" | "human" | "allow"
    reason: str = ""
    verdict: Optional[KorytoVerdict] = None

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "mur": self.mur,
            "reason": self.reason,
            "koryto": self.verdict.to_dict() if self.verdict else None,
        }


# ActionVetoed żyje w gatecat.exceptions (0.4.1): JEDNA klasa dla silnika i dla
# warstwy integrations, więc `except gatecat.ActionVetoed` łapie veto z każdej
# warstwy. Import na górze pliku re-eksportuje ją stąd — `from gatecat.veto
# import ActionVetoed` działa jak dawniej, konstrukcja z VetoDecision też.


@dataclass
class ActionPolicy:
    """Deklaratywne koryto akcji: co WOLNO, co wymaga człowieka, co jest zakazane.

    Reguły to wzorce regex dopasowywane do reprezentacji wywołania (`fn(args, kwargs)`).
    Kolejność priorytetów: deny (twardy zakaz) > próg kwoty > wymaga-człowieka.

    Args:
        deny:          wzorce akcji ZAKAZANYCH bezwarunkowo (veto natychmiast).
        require_human: wzorce wymagające zatwierdzenia człowieka (veto bez approve).
        max_amount:    próg kwoty — akcja z `amount > max_amount` wymaga człowieka.
    """
    deny: Sequence[str] = field(default_factory=tuple)
    require_human: Sequence[str] = field(default_factory=tuple)
    max_amount: Optional[float] = None

    # ReDoS-guard (audyt 2026-06-27 should-fix): catastrophic backtracking skaluje
    # z DŁUGOŚCIĄ dopasowywanego tekstu. Wzorce pochodzą od operatora (nie z ruchu),
    # ale długi call_repr (duże argumenty) mógłby zawiesić zły wzorzec. Przycinamy
    # wejście do bezpiecznej długości — dopasowanie nazwy/akcji nie potrzebuje więcej.
    _MAX_MATCH_LEN = 4096

    def classify(self, call_repr: str, amount: Optional[float]) -> VetoDecision:
        """Zwróć decyzję policy. Fail-closed: zły regex → traktuj jako dopasowanie (veto)."""
        call_repr = call_repr[:self._MAX_MATCH_LEN]
        for pat in self.deny:
            try:
                hit = re.search(pat, call_repr, re.I)
            except re.error:
                return VetoDecision(False, "policy-deny",
                                    f"invalid deny pattern /{pat}/ - fail-closed veto")
            if hit:
                return VetoDecision(False, "policy-deny",
                                    f"action matches denied pattern /{pat}/")
        if self.max_amount is not None and amount is not None:
            try:
                amt_f = float(amount)
            except (TypeError, ValueError):
                return VetoDecision(False, "policy-amount",
                                    f"amount {amount!r} not comparable to cap - fail-closed veto")
            # NaN/inf omijają porównanie '>' (IEEE 754: nan > x zawsze False) → fail-closed.
            # Bez tego charge(amount=float('nan')) przechodziłby ponad cap. (audyt 2026-06-27 #1)
            if math.isnan(amt_f) or math.isinf(amt_f):
                return VetoDecision(False, "policy-amount",
                                    f"amount {amount!r} is not a finite number - fail-closed veto")
            over = amt_f > float(self.max_amount)
            if over:
                return VetoDecision(False, "policy-amount",
                                    f"amount {amount} > cap {self.max_amount} - requires human approval")
        for pat in self.require_human:
            try:
                hit = re.search(pat, call_repr, re.I)
            except re.error:
                return VetoDecision(False, "human",
                                    f"invalid require_human pattern /{pat}/ - fail-closed veto")
            if hit:
                return VetoDecision(False, "human",
                                    f"/{pat}/ requires human approval")
        return VetoDecision(True, "allow", "policy: allowed")


class VetoGate:
    """Bramka action-veto: ocenia próbę akcji przez trzy mury, ZANIM się wykona.

    Args:
        policy:        ActionPolicy (deny/próg/human). None = brak reguł policy.
        koryto:        Koryto do niezależnego checku (domyślnie nowy z exec+calc).
        human_approve: Callable[[call_repr], bool] pytany gdy policy żąda człowieka.
                       Brak → każde wymaga-człowieka kończy się veto (fail-closed).
        amount_of:     Callable(*args, **kwargs) → Optional[float] wyłuskujący kwotę.
        exec_check:    Callable(*args, **kwargs) → Optional[Sequence[str]] zwracający
                       statementy do uruchomienia przez koryto (gdy akcja ma sprawdzalny atom).
        strict:        gdy True wymaga ≥1 aktywnego muru (policy z regułami / exec_check),
                       inaczej rzuca ValueError przy konstrukcji (pusta bramka przepuszcza wszystko).
    """

    def __init__(
        self,
        policy: Optional[ActionPolicy] = None,
        *,
        koryto: Optional[Koryto] = None,
        human_approve: Optional[Callable[[str], bool]] = None,
        amount_of: Optional[Callable[..., Optional[float]]] = None,
        exec_check: Optional[Callable[..., Optional[Sequence[str]]]] = None,
        strict: bool = False,
    ):
        self.policy = policy
        self.koryto = koryto or Koryto(enable_exec=True, enable_calc=True)
        self.human_approve = human_approve
        self.amount_of = amount_of
        self.exec_check = exec_check
        has_rules = bool(policy and (policy.deny or policy.require_human or policy.max_amount is not None))
        if strict and not (has_rules or exec_check):
            raise ValueError(
                "VetoGate(strict=True): an empty gate would allow everything - "
                "provide a policy with rules or an exec_check"
            )

    def evaluate(self, call_repr: str, args: tuple, kwargs: dict,
                 fn: Optional[Callable] = None) -> VetoDecision:
        """Oceń akcję. Zwraca VetoDecision (allowed True/False). Nie wykonuje akcji.

        `fn` (opcjonalne): funkcja-narzędzie — pozwala związać argumenty POZYCYJNE
        z nazwami parametrów. Bez tego `charge(5000)` (LLM-y często generują
        pozycyjnie) omijał próg max_amount, bo kwota była brana tylko z
        kwargs['amount'] (workflow review 2026-07-02, P1 fail-open)."""
        amount = None
        if self.amount_of is not None:
            try:
                amount = self.amount_of(*args, **kwargs)
            except Exception as e:
                return VetoDecision(False, "policy-amount",
                                    f"amount_of raised {e!r} - fail-closed veto")
        else:
            bound = dict(kwargs)
            if fn is not None and args:
                try:
                    bound = dict(inspect.signature(fn).bind_partial(*args, **kwargs).arguments)
                except (TypeError, ValueError):
                    pass  # nie da się związać — zostają same kwargs
            if "amount" in bound:
                amount = bound["amount"]

        # MUR 1: policy (deny / próg)
        if self.policy is not None:
            dec = self.policy.classify(call_repr, amount)
            if not dec.allowed and dec.mur in ("policy-deny", "policy-amount"):
                return dec
            policy_wants_human = (not dec.allowed and dec.mur == "human")
        else:
            policy_wants_human = False

        # MUR 2: koryto (niezależny check gdy akcja ma sprawdzalny atom)
        if self.exec_check is not None:
            try:
                stmts = self.exec_check(*args, **kwargs)
            except Exception as e:
                return VetoDecision(False, "koryto",
                                    f"exec_check raised {e!r} - fail-closed veto")
            if stmts:
                expected = kwargs.get("expect")
                try:
                    v = self.koryto.verify(call_repr, str(expected if expected is not None else ""),
                                            exec_stmts=list(stmts))
                except Exception as e:
                    return VetoDecision(False, "koryto",
                                        f"koryto.verify raised {e!r} - fail-closed veto", None)
                if v.caught:
                    return VetoDecision(False, "koryto",
                                        f"interpreter says {v.truth!r}, agent claimed {expected!r}", v)

        # MUR 3: human-in-the-loop
        if policy_wants_human:
            approved = False
            if self.human_approve is not None:
                try:
                    approved = bool(self.human_approve(call_repr))
                except Exception as e:
                    return VetoDecision(False, "human",
                                        f"human_approve raised {e!r} - fail-closed veto")
            if not approved:
                return VetoDecision(False, "human",
                                    "requires human approval - no approval given, veto")

        return VetoDecision(True, "allow", "all walls passed")


def before_action(
    policy: Optional[ActionPolicy] = None,
    *,
    koryto: Optional[Koryto] = None,
    human_approve: Optional[Callable[[str], bool]] = None,
    amount_of: Optional[Callable[..., Optional[float]]] = None,
    exec_check: Optional[Callable[..., Optional[Sequence[str]]]] = None,
    strict: bool = False,
    on_veto: Optional[Callable[[VetoDecision], Any]] = None,
):
    """Dekorator veto-gate na funkcji-narzędziu agenta. Sprawdza ZANIM funkcja się wykona.

    Działa na funkcjach sync i async. Gdy akcja zawetowana:
      - jeśli `on_veto` podane → wywołane z VetoDecision, jego wynik zwrócony zamiast akcji;
      - inaczej → rzucony ActionVetoed (akcja NIE wykonana).

    Patrz VetoGate po opis murów i argumentów.
    """
    gate = VetoGate(policy, koryto=koryto, human_approve=human_approve,
                    amount_of=amount_of, exec_check=exec_check, strict=strict)

    def deco(fn: Callable):
        call_name = getattr(fn, "__name__", "action")

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def awrapped(*args, **kwargs):
                call_repr = f"{call_name}(args={args!r}, kwargs={kwargs!r})"
                dec = gate.evaluate(call_repr, args, kwargs, fn=fn)
                if not dec.allowed:
                    if on_veto is not None:
                        return on_veto(dec)
                    raise ActionVetoed(dec)
                return await fn(*args, **kwargs)
            awrapped.veto_gate = gate
            return awrapped

        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            call_repr = f"{call_name}(args={args!r}, kwargs={kwargs!r})"
            dec = gate.evaluate(call_repr, args, kwargs, fn=fn)
            if not dec.allowed:
                if on_veto is not None:
                    return on_veto(dec)
                raise ActionVetoed(dec)
            return fn(*args, **kwargs)
        wrapped.veto_gate = gate
        return wrapped

    return deco
