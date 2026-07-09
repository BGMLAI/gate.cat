"""gatecat.pipeline — universal truth and compliance pipeline (SLM and LLM).

Assembles the SDK building blocks into ONE entry point. The order is deliberate
(cost + complementarity):

  1. KORYTO   (gatecat.koryto)  — deterministic verification of an atom
               (exec/calc/lookup). Catches confident-wrong: the river overflows
               its bed, and sample dispersion does not see it (the model is
               CONFIDENTLY wrong). $0, no model.
  2. STAGNACJA (gatecat.stagnation) — watches the KORYTO: a run of soft rejections
               with no progress = the koryto has gone stale (stale base), it is
               not the river that is wrong.
  3. ARBITER  (optional callback) — adjudicates soft discrepancies (a lookup may
               be stale — we NEVER hard-block on a lookup alone).
  4. GATE     (gatecat.gate) — dispersion of N samples of the river. Only when the
               koryto does not know the atom (gate costs N model calls; koryto-first
               = cheaper). Catches HESITATION, not a lie.
  5. VETO     (gatecat.veto) — compliance on ACTIONS: policy deny / amount threshold /
               human-in-the-loop / independent exec-check, BEFORE the action touches
               the world.

Model-agnostic: an SLM on a phone and a frontier LLM enter through the same
`sample_fn` (prompt→str callback). Zero dependency on the fleet/orchestrator.

VERDICT HONESTY (we do not claim more than we measure):
  confirmed — koryto knows the atom and the answer agrees (hard=whether exec/calc).
  refuted   — koryto knows the atom and the answer is wrong; hard immediately, soft
              only after an arbiter confirms it (a stale koryto is a real cost).
  uncertain — a "do not trust" signal: a soft discrepancy without an arbiter, or the
              river's dispersion above threshold. Escalate / abstain, do not publish.
  unchecked — beyond the koryto's reach and with no gate alarm. Does NOT mean "true" —
              it means "we had nothing to decide it with". This is a limit, made explicit.

VERDICT PRECEDENCE (contract — hierarchy for resolving contradictions):
  1. exec/calc (hard koryto)   — decides ALWAYS; the gate is not even asked.
  2. lookup    (soft koryto)   — a discrepancy goes to the arbiter; without an arbiter →
     uncertain (unless lookup_hard_block=True — then refuted immediately).
  3. gate      — ONLY when the koryto does not know the atom (verdict "unknown").
  4. veto      — an orthogonal axis (actions, not answers); always fail-closed.
  A koryto-vs-gate contradiction is impossible by construction: the gate does not
  start once the koryto has spoken.

READING THE RESULT:
  report.reliable — True ONLY for confirmed (you had proof). For critical systems
                    filter by reliable, not by trusted.
  report.trusted  — confirmed OR unchecked (may be published, but unchecked is a
                    deliberate publication WITHOUT proof — do not confuse it with truth).
  report.stages   — the full decision trail (observability: who spoke up, with what,
                    why the verdict is this and not another).

Usage (minimal):
    from gatecat import TruthPipeline, ActionPolicy

    pipe = TruthPipeline(
        sample_fn=my_llm,                     # SLM albo LLM — jeden callback
        fact_base={"capital of france": "Paris"},
        policy=ActionPolicy(deny=[r"terraform.*prod"]),
    )

    r = pipe.evaluate("Evaluate: 6 / 2 * 3", answer="1")
    print(r.verdict, r.truth)                 # refuted 9

    @pipe.guard()
    def deploy(target): ...
    deploy(target="terraform apply prod")     # ActionVetoed BEFORE it runs
"""
from __future__ import annotations

import functools
import inspect
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Sequence

from gatecat.gate import Gate, GateVerdict
from gatecat.koryto import FactBase, Koryto, KorytoVerdict, atoms_match
from gatecat.stagnation import StagnationMonitor, StagnationState
from gatecat.veto import ActionPolicy, ActionVetoed, VetoDecision, VetoGate

VERDICT_CONFIRMED = "confirmed"
VERDICT_REFUTED = "refuted"
VERDICT_UNCERTAIN = "uncertain"
VERDICT_UNCHECKED = "unchecked"


@dataclass
class TruthReport:
    """Pipeline result for a single (question, answer) pair — for auditing.

    `stages` is an ordered trail of EVERY stage that spoke up
    (koryto/stagnation/arbiter/gate) — the complete evidentiary record of the decision.
    """
    verdict: str                               # confirmed | refuted | uncertain | unchecked
    question: str
    answer: str
    truth: Optional[str] = None                # the truth atom (when the koryto knows it)
    hard: bool = False                         # True = physically independent proof (exec/calc)
    channel: str = "none"                      # exec | calc | lookup | gate | none
    koryto: Optional[KorytoVerdict] = None
    gate: Optional[GateVerdict] = None
    stagnation: Optional[StagnationState] = None
    arbiter: Optional[str] = None              # "koryto-potwierdzone" | "model-mial-racje" | None
    stages: list[dict] = field(default_factory=list)
    ts: float = field(default_factory=time.time)

    @property
    def caught(self) -> bool:
        """Whether the pipeline caught a model error (refuted)."""
        return self.verdict == VERDICT_REFUTED

    @property
    def trusted(self) -> bool:
        """Whether the answer may be published without escalation (confirmed/unchecked).

        NOTE: unchecked = publication WITHOUT proof (deliberate). For critical
        systems use `reliable`, not `trusted`.
        """
        return self.verdict in (VERDICT_CONFIRMED, VERDICT_UNCHECKED)

    @property
    def reliable(self) -> bool:
        """True ONLY when the answer has proof (confirmed). Filter for critical
        systems — unchecked/uncertain never passes."""
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
    """Universal truth and compliance pipeline: koryto → arbiter → gate + veto.

    Args:
        sample_fn:  callback(prompt) -> str. Call YOUR model once at temp>0
                    (local SLM / fleet / OpenAI-compatible / anything).
                    Without it the gate stage is skipped (koryto still works).
        koryto:     a ready-made Koryto. Defaults to exec+calc (+lookup when fact_base).
        fact_base:  dict | FactBase | callable(question)->Optional[str] for the
                    lookup channel (ignored when you pass your own `koryto`).
        policy:     ActionPolicy for the veto gate on actions (guard()).
        arbiter_fn: callback(question, answer, KorytoVerdict) -> Optional[bool].
                    Adjudicates SOFT rejections: True = the koryto is right (the refute
                    stands), False = the model was right (koryto stale), None = no
                    verdict. An arbiter exception does NOT block (fail-safe → uncertain).
        lookup_hard_block: defaults to False — a lookup is a soft signal, because the
                    base may be stale/incomplete (real cost: false blocks).
                    Set True ONLY when your base is current at query time and you
                    accept that risk: a lookup discrepancy →
                    refuted immediately, without the arbiter.
        n_samples/threshold/embedder: gate configuration (as in gatecat.gate.Gate).
        stagnation: whether to watch the koryto with StagnationMonitor (default True).
        human_approve/amount_of/exec_check: passed through to VetoGate (guard()).
                    The gate is STRICT: an empty ActionPolicy() with no rules → ValueError
                    at construction (an empty gate would let everything through).
                    NOTE (explicit limit): a pipeline with ONLY exec_check verifies
                    only actions for which exec_check returns statements — actions
                    without a checkable atom pass. If you want hard prohibitions →
                    add a policy with deny/max_amount.
        on_event:   callback(dict) on EVERY audit event (evaluate/veto).
                    Exceptions are swallowed — telemetry must not break decisions.
        audit_max:  how many recent events to keep in memory (default 1000).
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
        # strict=True: an empty ActionPolicy() with no rules does NOT pass
        # construction — without this guard() looked armed while it let
        # everything through (workflow review 2026-07-02, fail-closed P1/P2)
        self._veto = VetoGate(
            policy, koryto=self.koryto, human_approve=human_approve,
            amount_of=amount_of, exec_check=exec_check, strict=True,
        ) if (policy is not None or exec_check is not None) else None
        self.on_event = on_event
        self.audit: deque[dict] = deque(maxlen=max(1, int(audit_max)))
        self._lock = threading.Lock()  # audit/stagnation — the pipeline may be shared across threads
        self._last_stagnation: Optional[StagnationState] = None
        self._koryto_suspect_events = 0  # history of koryto rot (not just the last state)

    # ------------------------------------------------------------------
    # audit
    # ------------------------------------------------------------------
    def _emit(self, kind: str, payload: dict) -> None:
        event = {"ts": time.time(), "kind": kind, **payload}
        with self._lock:
            self.audit.append(event)
        if self.on_event is not None:
            try:
                self.on_event(event)
            except Exception:
                pass  # telemetry must not break decisions

    def compliance_report(self) -> dict:
        """Aggregate audit report: how many verdicts of each type, how many vetoes.

        This is an ENFORCEMENT trail (policy enforcement + audit trail), not a
        compliance certificate — regulations require a process around it, not just logs.
        """
        counts: dict[str, int] = {}
        vetoes = allowed_actions = 0
        with self._lock:  # snapshot — iterating the deque during an append = RuntimeError
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
            # history: how many times the koryto WAS suspect in the retained window —
            # the last state alone hid rot that was cleared by later confirms
            "koryto_suspect_events": suspect_events,
            "events_retained": len(events),
        }

    # ------------------------------------------------------------------
    # the TRUTH axis: evaluate / ask
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
        """Verify an answer (from any model) against the koryto, the arbiter and the gate.

        answer=None (backend failure / no answer) → uncertain immediately:
        no answer is NOT confident-wrong, a refute would be a distortion.
        Falsy answers (0, 0.0, False) are verified normally."""
        question = "" if question is None else str(question)
        stages: list[dict] = []

        if answer is None:
            report = TruthReport(
                verdict=VERDICT_UNCERTAIN, question=question, answer="",
                stages=[{"stage": "input", "no_answer": True}],
            )
            return self._finish(report)
        answer = str(answer)

        # 1. KORYTO — deterministic, $0, no model call
        kv = self.koryto.verify(question, answer, exec_stmts=exec_stmts,
                                exec_js=exec_js, aliases=aliases)
        stages.append({"stage": "koryto", **kv.to_dict()})

        # 2. STAGNACJA — observe every koryto verdict (watches the koryto, not the river)
        st = None
        if self.monitor is not None:
            with self._lock:  # the monitor mutates the window — interleaving two evaluate calls corrupts the streaks
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
                # exec/calc: physically independent of the model — block immediately
                report.verdict, report.hard = VERDICT_REFUTED, True
                return self._finish(report)
            if self.lookup_hard_block:
                # explicit user opt-in: "my base is current" → block immediately
                report.verdict = VERDICT_REFUTED
                stages.append({"stage": "lookup_hard_block", "applied": True})
                return self._finish(report)
            # soft (a lookup may be stale) → arbiter; NEVER a hard block on its own
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
                    # the model was right, koryto stale — do NOT penalize the answer
                    report.verdict = VERDICT_CONFIRMED
                    report.arbiter = "model-mial-racje"
                    report.truth = None
                return self._finish(report)
            report.verdict = VERDICT_UNCERTAIN
            return self._finish(report)

        # kv.verdict == "unknown" → the koryto does not know the atom; we ask the river for its dispersion
        if self.gate is not None:
            gv = self.gate.check(question)
            report.gate = gv
            stages.append({"stage": "gate", **gv.to_dict()})
            if gv.uncertain:
                report.verdict, report.channel = VERDICT_UNCERTAIN, "gate"
                return self._finish(report)
            # the model is consistent, but consistent ON THE EVALUATED answer? A consistent 5x "Kraków"
            # with answer="Warszawa" is a strong error signal — measured by dispersion,
            # it must not be ignored (workflow review 2026-07-02, P2)
            if gv.samples and not any(
                atoms_match(answer, s) or atoms_match(s, answer) for s in gv.samples
            ):
                stages.append({"stage": "gate_answer_check",
                               "answer_agrees_with_samples": False})
                report.verdict, report.channel = VERDICT_UNCERTAIN, "gate"
                return self._finish(report)

        report.verdict = VERDICT_UNCHECKED  # explicit limit: we had nothing to decide it with
        return self._finish(report)

    def ask(self, question: str, **verify_kw) -> TruthReport:
        """Generate an answer with the model (sample_fn) and verify it right away.

        On `refuted` from the hard koryto the correct value is in `report.truth` —
        the caller can correct the answer instead of publishing it.
        """
        if self.sample_fn is None:
            raise ValueError("ask() requires sample_fn (a model to query)")
        raw = self.sample_fn(question)
        # None != the answer "None" — gate.check_samples filters the same case
        # BEFORE str() (a crashed backend would fake a confident answer); evaluate(None)
        # returns uncertain with an explicit no_answer stage
        answer = raw if raw is None else str(raw)
        return self.evaluate(question, answer, **verify_kw)

    def _finish(self, report: TruthReport) -> TruthReport:
        self._emit("evaluate", {
            "verdict": report.verdict, "channel": report.channel,
            "hard": report.hard, "question": report.question[:500],
            "answer": report.answer[:500], "truth": report.truth,
            "arbiter": report.arbiter,
            # the audit must distinguish "unchecked without a gate" from "unchecked after a
            # consistent gate" (N model calls were spent and consistency evidence gathered)
            "gate_ran": report.gate is not None,
            "gate_disagreement": (round(report.gate.disagreement, 4)
                                  if report.gate is not None else None),
            "koryto_suspect": bool(report.stagnation
                                   and report.stagnation.koryto_suspect),
        })
        return report

    # ------------------------------------------------------------------
    # the COMPLIANCE axis: guard / check_action
    # ------------------------------------------------------------------
    def check_action(self, call_repr: str, args: tuple = (), kwargs: Optional[dict] = None,
                     fn: Optional[Callable] = None) -> VetoDecision:
        """Evaluate an action with the veto gate WITHOUT executing it. Every decision goes to the audit.

        `fn` (optional): the tool function — lets the gate bind positional
        arguments to names (the amount threshold also works for `charge(5000)`)."""
        if self._veto is None:
            raise ValueError(
                "check_action() requires policy or exec_check in the constructor — "
                "an empty gate would let everything through (fail-closed by design)"
            )
        dec = self._veto.evaluate(call_repr, args, dict(kwargs or {}), fn=fn)
        self._emit("action", {
            "allowed": dec.allowed, "mur": dec.mur,
            "reason": dec.reason, "call": call_repr[:500],
        })
        return dec

    def guard(self, on_veto: Optional[Callable[[VetoDecision], Any]] = None):
        """Compliance decorator on a tool function: veto BEFORE the action runs.

        Like gatecat.veto.before_action, but with the pipeline's shared policy/koryto
        and a full audit trail (EVERY decision — allow and veto — is logged).
        """
        if self._veto is None:
            raise ValueError(
                "guard() requires policy or exec_check in the constructor — "
                "an empty gate would let everything through (fail-closed by design)"
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
                            # async on_veto without await = the handler never runs,
                            # the caller gets a truthy coroutine (a silent misfire)
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
