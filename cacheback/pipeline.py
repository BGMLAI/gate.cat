"""cacheback.pipeline — uniwersalny pipeline prawdy i compliance (SLM i LLM).

Składa klocki SDK w JEDNO wejście. Kolejność celowa (koszt + komplementarność):

  1. KORYTO   (cacheback.koryto)  — deterministyczna weryfikacja atomu
               (exec/calc/lookup). Łapie confident-wrong: rzeka wylewa z koryta,
               a rozrzut tego nie widzi (model myli się PEWNIE). $0, bez modelu.
  2. STAGNACJA (cacheback.stagnation) — pilnuje KORYTA: seria miękkich odrzuceń
               bez postępu = koryto zgniło (stale baza), nie rzeka się myli.
  3. ARBITER  (opcjonalny callback) — rozsądza miękkie rozbieżności (lookup może
               być stale — NIGDY nie blokujemy twardo na samym lookupie).
  4. GATE     (cacheback.gate) — rozrzut N próbek rzeki. Dopiero gdy koryto nie
               zna atomu (gate kosztuje N wywołań modelu; koryto-first = taniej).
               Łapie WAHANIE, nie kłamstwo.
  5. VETO     (cacheback.veto) — compliance na AKCJACH: policy deny / próg kwoty /
               human-in-the-loop / niezależny exec-check, ZANIM akcja dotknie świata.

Model-agnostic: SLM na telefonie i frontier LLM wchodzą tym samym `sample_fn`
(callback prompt→str). Zero zależności od floty/orchestratora.

UCZCIWOŚĆ WERDYKTU (nie udajemy więcej niż mierzymy):
  confirmed — koryto zna atom i odpowiedź się zgadza (hard=czy exec/calc).
  refuted   — koryto zna atom i odpowiedź jest błędna; twarde od razu, miękkie
              dopiero po potwierdzeniu arbitrem (koryto-stale to realny koszt).
  uncertain — sygnał "nie ufaj": miękka rozbieżność bez arbitra, albo rozrzut
              rzeki ponad progiem. Eskaluj / abstain, nie publikuj.
  unchecked — poza zasięgiem koryta i bez alarmu gate. NIE znaczy "prawda" —
              znaczy "nie mieliśmy czym rozstrzygnąć". To jest granica, jawnie.

PRECEDENS WERDYKTÓW (kontrakt — hierarchia rozstrzygania sprzeczności):
  1. exec/calc (twarde koryto)  — rozstrzyga ZAWSZE; gate nie jest nawet pytany.
  2. lookup    (miękkie koryto) — rozbieżność idzie do arbitra; bez arbitra →
     uncertain (chyba że lookup_hard_block=True — wtedy refuted od razu).
  3. gate      — TYLKO gdy koryto nie zna atomu (verdict "unknown").
  4. veto      — oś ortogonalna (akcje, nie odpowiedzi); zawsze fail-closed.
  Sprzeczność koryto-vs-gate jest niemożliwa z konstrukcji: gate nie startuje,
  gdy koryto się wypowiedziało.

CZYTANIE WYNIKU:
  report.reliable — True TYLKO dla confirmed (miałeś dowód). Do systemów
                    krytycznych filtruj po reliable, nie po trusted.
  report.trusted  — confirmed LUB unchecked (wolno publikować, ale unchecked
                    to świadoma publikacja BEZ dowodu — nie myl z prawdą).
  report.stages   — pełny ślad decyzji (observability: kto się wypowiedział,
                    z czym, dlaczego werdykt jest taki a nie inny).

Użycie (minimalne):
    from cacheback import TruthPipeline, ActionPolicy

    pipe = TruthPipeline(
        sample_fn=my_llm,                     # SLM albo LLM — jeden callback
        fact_base={"capital of france": "Paris"},
        policy=ActionPolicy(deny=[r"terraform.*prod"]),
    )

    r = pipe.evaluate("Evaluate: 6 / 2 * 3", answer="1")
    print(r.verdict, r.truth)                 # refuted 9

    @pipe.guard()
    def deploy(target): ...
    deploy(target="terraform apply prod")     # ActionVetoed ZANIM się wykona
"""
from __future__ import annotations

import functools
import inspect
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Sequence

from cacheback.gate import Gate, GateVerdict
from cacheback.koryto import FactBase, Koryto, KorytoVerdict, atoms_match
from cacheback.stagnation import StagnationMonitor, StagnationState
from cacheback.veto import ActionPolicy, ActionVetoed, VetoDecision, VetoGate

VERDICT_CONFIRMED = "confirmed"
VERDICT_REFUTED = "refuted"
VERDICT_UNCERTAIN = "uncertain"
VERDICT_UNCHECKED = "unchecked"


@dataclass
class TruthReport:
    """Wynik pipeline'u dla jednej pary (pytanie, odpowiedź) — do audytu.

    `stages` to uporządkowany ślad KAŻDEGO etapu który się wypowiedział
    (koryto/stagnacja/arbiter/gate) — kompletny materiał dowodowy decyzji.
    """
    verdict: str                               # confirmed | refuted | uncertain | unchecked
    question: str
    answer: str
    truth: Optional[str] = None                # atom prawdy (gdy koryto zna)
    hard: bool = False                         # True = dowód fizycznie niezależny (exec/calc)
    channel: str = "none"                      # exec | calc | lookup | gate | none
    koryto: Optional[KorytoVerdict] = None
    gate: Optional[GateVerdict] = None
    stagnation: Optional[StagnationState] = None
    arbiter: Optional[str] = None              # "koryto-potwierdzone" | "model-mial-racje" | None
    stages: list[dict] = field(default_factory=list)
    ts: float = field(default_factory=time.time)

    @property
    def caught(self) -> bool:
        """Czy pipeline złapał błąd modelu (refuted)."""
        return self.verdict == VERDICT_REFUTED

    @property
    def trusted(self) -> bool:
        """Czy odpowiedź wolno publikować bez eskalacji (confirmed/unchecked).

        UWAGA: unchecked = publikacja BEZ dowodu (świadoma). Do systemów
        krytycznych używaj `reliable`, nie `trusted`.
        """
        return self.verdict in (VERDICT_CONFIRMED, VERDICT_UNCHECKED)

    @property
    def reliable(self) -> bool:
        """True TYLKO gdy odpowiedź ma dowód (confirmed). Filtr dla systemów
        krytycznych — unchecked/uncertain nigdy nie przechodzi."""
        return self.verdict == VERDICT_CONFIRMED

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "question": self.question,
            "answer": self.answer,
            "truth": self.truth,
            "hard": self.hard,
            "channel": self.channel,
            "arbiter": self.arbiter,
            "stages": self.stages,
            "ts": self.ts,
        }


class TruthPipeline:
    """Uniwersalny pipeline prawdy i compliance: koryto → arbiter → gate + veto.

    Args:
        sample_fn:  callback(prompt) -> str. Wołaj SWÓJ model raz przy temp>0
                    (SLM lokalny / flota / OpenAI-compatible / cokolwiek).
                    Bez niego etap gate jest pominięty (koryto dalej działa).
        koryto:     gotowe Koryto. Domyślnie exec+calc (+lookup gdy fact_base).
        fact_base:  dict | FactBase | callable(question)->Optional[str] dla kanału
                    lookup (ignorowane gdy podałeś własne `koryto`).
        policy:     ActionPolicy dla bramki veto na akcjach (guard()).
        arbiter_fn: callback(question, answer, KorytoVerdict) -> Optional[bool].
                    Rozsądza MIĘKKIE odrzucenia: True = koryto ma rację (refute
                    stoi), False = model miał rację (koryto stale), None = brak
                    werdyktu. Wyjątek arbitra NIE blokuje (fail-safe → uncertain).
        lookup_hard_block: domyślnie False — lookup jest sygnałem miękkim, bo
                    baza może być stale/niepełna (realny koszt: fałszywe blokady).
                    Ustaw True TYLKO gdy Twoja baza jest aktualna w momencie
                    zapytania i akceptujesz to ryzyko: rozbieżność lookup →
                    refuted od razu, bez arbitra.
        n_samples/threshold/embedder: konfiguracja gate (jak cacheback.gate.Gate).
        stagnation: czy pilnować koryta StagnationMonitorem (default True).
        human_approve/amount_of/exec_check: przekazywane do VetoGate (guard()).
                    Bramka jest STRICT: pusta ActionPolicy() bez reguł → ValueError
                    przy konstrukcji (pusta bramka przepuszczałaby wszystko).
                    UWAGA (jawna granica): pipeline z SAMYM exec_check weryfikuje
                    tylko akcje, dla których exec_check zwróci statementy — akcje
                    bez sprawdzalnego atomu przechodzą. Chcesz twardych zakazów →
                    dodaj policy z deny/max_amount.
        on_event:   callback(dict) na KAŻDE zdarzenie audytowe (evaluate/veto).
                    Wyjątki połykane — telemetria nie może psuć decyzji.
        audit_max:  ile ostatnich zdarzeń trzymać w pamięci (default 1000).
    """

    def __init__(
        self,
        *,
        sample_fn: Optional[Callable[[str], str]] = None,
        koryto: Optional[Koryto] = None,
        fact_base: "dict | FactBase | Callable[[str], Optional[str]] | None" = None,
        policy: Optional[ActionPolicy] = None,
        arbiter_fn: Optional[Callable[[str, str, KorytoVerdict], Optional[bool]]] = None,
        lookup_hard_block: bool = False,
        n_samples: int = 5,
        threshold: float = 0.30,
        embedder=None,
        stagnation: bool = True,
        human_approve: Optional[Callable[[str], bool]] = None,
        amount_of: Optional[Callable[..., Optional[float]]] = None,
        exec_check: Optional[Callable[..., Optional[Sequence[str]]]] = None,
        on_event: Optional[Callable[[dict], Any]] = None,
        audit_max: int = 1000,
    ):
        if koryto is None:
            if callable(fact_base) and not isinstance(fact_base, FactBase):
                fact_base = FactBase(lookup_fn=fact_base)
            koryto = Koryto(fact_base)
        self.koryto = koryto
        self.sample_fn = sample_fn
        self.gate = (
            Gate(sample_fn=sample_fn, n_samples=n_samples,
                 threshold=threshold, embedder=embedder)
            if sample_fn is not None else None
        )
        self.arbiter_fn = arbiter_fn
        self.lookup_hard_block = bool(lookup_hard_block)
        self.monitor = StagnationMonitor() if stagnation else None
        self.policy = policy
        # strict=True: pusta ActionPolicy() bez żadnej reguły NIE przechodzi
        # konstrukcji — bez tego guard() wyglądał na uzbrojony, a przepuszczał
        # wszystko (workflow review 2026-07-02, fail-closed P1/P2)
        self._veto = VetoGate(
            policy, koryto=self.koryto, human_approve=human_approve,
            amount_of=amount_of, exec_check=exec_check, strict=True,
        ) if (policy is not None or exec_check is not None) else None
        self.on_event = on_event
        self.audit: deque[dict] = deque(maxlen=max(1, int(audit_max)))
        self._lock = threading.Lock()  # audit/stagnacja — pipeline bywa współdzielony między wątkami
        self._last_stagnation: Optional[StagnationState] = None
        self._koryto_suspect_events = 0  # historia zgnilizny koryta (nie tylko ostatni stan)

    # ------------------------------------------------------------------
    # audyt
    # ------------------------------------------------------------------
    def _emit(self, kind: str, payload: dict) -> None:
        event = {"ts": time.time(), "kind": kind, **payload}
        with self._lock:
            self.audit.append(event)
        if self.on_event is not None:
            try:
                self.on_event(event)
            except Exception:
                pass  # telemetria nie może psuć decyzji

    def compliance_report(self) -> dict:
        """Zbiorczy raport audytowy: ile werdyktów którego typu, ile wet.

        To jest ślad EGZEKWOWANIA (policy enforcement + audit trail), nie
        certyfikat zgodności — regulacje wymagają procesu wokół, nie tylko logów.
        """
        counts: dict[str, int] = {}
        vetoes = allowed_actions = 0
        with self._lock:  # snapshot — iteracja deque podczas append = RuntimeError
            events = list(self.audit)
            last_st = self._last_stagnation
            suspect_events = self._koryto_suspect_events
        for e in events:
            if e["kind"] == "evaluate":
                counts[e["verdict"]] = counts.get(e["verdict"], 0) + 1
            elif e["kind"] == "action":
                if e["allowed"]:
                    allowed_actions += 1
                else:
                    vetoes += 1
        return {
            "evaluations": counts,
            "actions_allowed": allowed_actions,
            "actions_vetoed": vetoes,
            "koryto_suspect": bool(last_st and last_st.koryto_suspect),
            # historia: ile razy koryto BYŁO podejrzane w retencjonowanym okresie —
            # sam ostatni stan ukrywał zgniliznę wyczyszczoną późniejszymi confirmami
            "koryto_suspect_events": suspect_events,
            "events_retained": len(events),
        }

    # ------------------------------------------------------------------
    # oś PRAWDY: evaluate / ask
    # ------------------------------------------------------------------
    def evaluate(
        self,
        question: str,
        answer: str,
        *,
        exec_stmts: Optional[Sequence[str]] = None,
        exec_js: Optional[str] = None,
        aliases: Sequence[str] = (),
    ) -> TruthReport:
        """Zweryfikuj odpowiedź (dowolnego modelu) względem koryta, arbitra i gate.

        answer=None (awaria backendu / brak odpowiedzi) → uncertain od razu:
        brak odpowiedzi to NIE confident-wrong, refute byłby przekłamaniem.
        Falsy odpowiedzi (0, 0.0, False) są normalnie weryfikowane."""
        question = "" if question is None else str(question)
        stages: list[dict] = []

        if answer is None:
            report = TruthReport(
                verdict=VERDICT_UNCERTAIN, question=question, answer="",
                stages=[{"stage": "input", "no_answer": True}],
            )
            return self._finish(report)
        answer = str(answer)

        # 1. KORYTO — deterministyczne, $0, bez wołania modelu
        kv = self.koryto.verify(question, answer, exec_stmts=exec_stmts,
                                exec_js=exec_js, aliases=aliases)
        stages.append({"stage": "koryto", **kv.to_dict()})

        # 2. STAGNACJA — obserwuj każdy werdykt koryta (pilnuje koryta, nie rzeki)
        st = None
        if self.monitor is not None:
            with self._lock:  # monitor mutuje okno — przeplot dwóch evaluate przekłamuje streaki
                st = self.monitor.observe(kv)
                self._last_stagnation = st
                if st.koryto_suspect:
                    self._koryto_suspect_events += 1
        if st is not None:
            stages.append({"stage": "stagnation", **st.to_dict()})

        report = TruthReport(
            verdict=VERDICT_UNCHECKED, question=question, answer=answer,
            koryto=kv, stagnation=st, stages=stages,
        )

        if kv.verdict == "confirm":
            report.verdict = VERDICT_CONFIRMED
            report.truth, report.hard, report.channel = kv.truth, kv.hard, kv.channel
            return self._finish(report)

        if kv.verdict == "refute":
            report.truth, report.channel = kv.truth, kv.channel
            if kv.hard:
                # exec/calc: fizycznie niezależne od modelu — blokuj od razu
                report.verdict, report.hard = VERDICT_REFUTED, True
                return self._finish(report)
            if self.lookup_hard_block:
                # jawny opt-in usera: "moja baza jest aktualna" → blokuj od razu
                report.verdict = VERDICT_REFUTED
                stages.append({"stage": "lookup_hard_block", "applied": True})
                return self._finish(report)
            # miękkie (lookup może być stale) → arbiter; NIGDY twarda blokada solo
            arb = None
            if self.arbiter_fn is not None:
                try:
                    arb = self.arbiter_fn(question, answer, kv)
                except Exception as e:
                    arb = None
                    stages.append({"stage": "arbiter", "error": repr(e)})
            if arb is not None:
                stages.append({"stage": "arbiter", "koryto_right": bool(arb)})
                if arb:
                    report.verdict = VERDICT_REFUTED
                    report.arbiter = "koryto-potwierdzone"
                else:
                    # model miał rację, koryto stale — NIE karz odpowiedzi
                    report.verdict = VERDICT_CONFIRMED
                    report.arbiter = "model-mial-racje"
                    report.truth = None
                return self._finish(report)
            report.verdict = VERDICT_UNCERTAIN
            return self._finish(report)

        # kv.verdict == "unknown" → koryto nie zna atomu; pytamy rzekę o rozrzut
        if self.gate is not None:
            gv = self.gate.check(question)
            report.gate = gv
            stages.append({"stage": "gate", **gv.to_dict()})
            if gv.uncertain:
                report.verdict, report.channel = VERDICT_UNCERTAIN, "gate"
                return self._finish(report)
            # model spójny, ale czy spójny NA OCENIANĄ odpowiedź? Spójne 5× "Kraków"
            # przy answer="Warszawa" to silny sygnał błędu — zmierzony rozrzutem,
            # nie wolno go zignorować (workflow review 2026-07-02, P2)
            if gv.samples and not any(
                atoms_match(answer, s) or atoms_match(s, answer) for s in gv.samples
            ):
                stages.append({"stage": "gate_answer_check",
                               "answer_agrees_with_samples": False})
                report.verdict, report.channel = VERDICT_UNCERTAIN, "gate"
                return self._finish(report)

        report.verdict = VERDICT_UNCHECKED  # jawna granica: nie mieliśmy czym rozstrzygnąć
        return self._finish(report)

    def ask(self, question: str, **verify_kw) -> TruthReport:
        """Wygeneruj odpowiedź modelem (sample_fn) i od razu ją zweryfikuj.

        Przy `refuted` z twardego koryta poprawna wartość jest w `report.truth` —
        wołający może skorygować odpowiedź zamiast ją publikować.
        """
        if self.sample_fn is None:
            raise ValueError("ask() wymaga sample_fn (model do odpytania)")
        raw = self.sample_fn(question)
        # None ≠ odpowiedź "None" — gate.check_samples filtruje ten sam przypadek
        # PRZED str() (padnięty backend udawałby pewną odpowiedź); evaluate(None)
        # zwraca uncertain z jawnym stage no_answer
        answer = raw if raw is None else str(raw)
        return self.evaluate(question, answer, **verify_kw)

    def _finish(self, report: TruthReport) -> TruthReport:
        self._emit("evaluate", {
            "verdict": report.verdict, "channel": report.channel,
            "hard": report.hard, "question": report.question[:500],
            "answer": report.answer[:500], "truth": report.truth,
            "arbiter": report.arbiter,
            # audyt musi odróżniać "unchecked bez gate" od "unchecked po spójnym
            # gate" (wydano N wywołań modelu i zebrano dowód spójności)
            "gate_ran": report.gate is not None,
            "gate_disagreement": (round(report.gate.disagreement, 4)
                                  if report.gate is not None else None),
            "koryto_suspect": bool(report.stagnation
                                   and report.stagnation.koryto_suspect),
        })
        return report

    # ------------------------------------------------------------------
    # oś COMPLIANCE: guard / check_action
    # ------------------------------------------------------------------
    def check_action(self, call_repr: str, args: tuple = (), kwargs: Optional[dict] = None,
                     fn: Optional[Callable] = None) -> VetoDecision:
        """Oceń akcję bramką veto BEZ wykonywania. Każda decyzja idzie do audytu.

        `fn` (opcjonalne): funkcja-narzędzie — pozwala bramce związać argumenty
        pozycyjne z nazwami (próg kwoty działa też dla `charge(5000)`)."""
        if self._veto is None:
            raise ValueError(
                "check_action() wymaga policy lub exec_check w konstruktorze — "
                "pusta bramka przepuszczałaby wszystko (fail-closed by design)"
            )
        dec = self._veto.evaluate(call_repr, args, dict(kwargs or {}), fn=fn)
        self._emit("action", {
            "allowed": dec.allowed, "mur": dec.mur,
            "reason": dec.reason, "call": call_repr[:500],
        })
        return dec

    def guard(self, on_veto: Optional[Callable[[VetoDecision], Any]] = None):
        """Dekorator compliance na funkcji-narzędziu: veto ZANIM akcja się wykona.

        Jak cacheback.veto.before_action, ale ze wspólną policy/koryto pipeline'u
        i pełnym śladem audytowym (KAŻDA decyzja — allow i veto — logowana).
        """
        if self._veto is None:
            raise ValueError(
                "guard() wymaga policy lub exec_check w konstruktorze — "
                "pusta bramka przepuszczałaby wszystko (fail-closed by design)"
            )

        def deco(fn: Callable):
            call_name = getattr(fn, "__name__", "action")

            if inspect.iscoroutinefunction(fn):
                @functools.wraps(fn)
                async def awrapped(*args, **kwargs):
                    call_repr = f"{call_name}(args={args!r}, kwargs={kwargs!r})"
                    dec = self.check_action(call_repr, args, kwargs, fn=fn)
                    if not dec.allowed:
                        if on_veto is not None:
                            res = on_veto(dec)
                            # async on_veto bez await = handler nigdy nie działa,
                            # caller dostaje truthy coroutine (cichy misfire)
                            return await res if inspect.isawaitable(res) else res
                        raise ActionVetoed(dec)
                    return await fn(*args, **kwargs)
                awrapped.veto_gate = self._veto
                return awrapped

            @functools.wraps(fn)
            def wrapped(*args, **kwargs):
                call_repr = f"{call_name}(args={args!r}, kwargs={kwargs!r})"
                dec = self.check_action(call_repr, args, kwargs, fn=fn)
                if not dec.allowed:
                    if on_veto is not None:
                        return on_veto(dec)
                    raise ActionVetoed(dec)
                return fn(*args, **kwargs)
            wrapped.veto_gate = self._veto
            return wrapped

        return deco
