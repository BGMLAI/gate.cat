"""truthgate.agent — gate dla pętli agenta: zatrzymaj runaway ZANIM przepali budżet.

Problem (z życia): agent wpada w pętlę / przepala budżet, bo model jest PEWNY
(nie gadatliwy) — hard `max_steps` / `thinking_budget` łapie to PO fakcie i tnie
też dobre długie rozumowanie. Realny przypadek: cache-write spiral, $305 w 24h.

TruthGate gatuje na ZMIERZONEJ niepewności: probe N tanich próbek następnego
kroku → jeśli model nie zgadza się ze sobą (rozrzut) = zgaduje = pauza/eskalacja/
abstain. Zatrzymuje TYLKO kroki które realnie zgadują, nie drogie-ale-poprawne.

UCZCIWOŚĆ: gate łapie WAHANIE, nie KŁAMSTWO. Confident-wrong (pewny błąd) jest
niełapalny rozrzutem — to uncertainty-signal, nie correctness-guarantee.

Użycie:
    from cacheback.agent import GatedLoop

    def step(state) -> StepResult:        # jeden krok agenta
        ...                               # zwraca StepResult(output, done, prompt)

    def sample(prompt) -> str:            # model agenta przy temp>0
        return agent_llm(prompt, temperature=0.7)

    loop = GatedLoop(step_fn=step, sample_fn=sample,
                     max_uncertain_steps=3, max_steps=50)
    result = loop.run(initial_state)
    print(result.stopped_reason)          # "done" | "runaway_guessing" | "max_steps"
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from cacheback.gate import Gate


@dataclass
class StepResult:
    """Zwracane przez step_fn agenta."""
    output: Any                    # wynik kroku (stan, obserwacja, cokolwiek)
    done: bool = False             # czy agent skończył zadanie
    prompt: str | None = None      # prompt który gate probe'uje na NASTĘPNY krok
    cost: float = 0.0              # opcjonalny koszt kroku (tokeny/$ — do budżetu)


@dataclass
class LoopResult:
    stopped_reason: str            # "done" | "runaway_guessing" | "max_steps" | "budget"
    steps: int
    uncertain_steps: int           # ile kroków oflagowano jako niepewne
    consecutive_uncertain: int     # najdłuższa seria niepewnych z rzędu
    total_cost: float
    final_output: Any = None
    trace: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "stopped_reason": self.stopped_reason,
            "steps": self.steps,
            "uncertain_steps": self.uncertain_steps,
            "consecutive_uncertain": self.consecutive_uncertain,
            "total_cost": round(self.total_cost, 4),
        }


class GatedLoop:
    """Owija pętlę agenta. Przerywa gdy agent zgaduje (N niepewnych kroków z rzędu).

    Args:
        step_fn(state) -> StepResult : jeden krok agenta.
        sample_fn(prompt) -> str     : model agenta przy temp>0 (gate probe).
        max_uncertain_steps : ile niepewnych KROKÓW Z RZĘDU = runaway → stop (default 3).
        max_steps           : twardy backstop (default 50).
        max_cost            : opcjonalny limit kosztu (None = bez limitu).
        on_uncertain        : opcjonalny callback(step_idx, verdict, state) — np. eskalacja
                              do silniejszego modelu / człowieka. Zwróć True by KONTYNUOWAĆ
                              (np. po eskalacji), False/None by liczyć jako niepewny krok.
        n_samples, threshold: konfiguracja gate.
        embedder            : opcjonalny embedder (semantyczny rozrzut).
    """

    def __init__(
        self,
        *,
        step_fn: Callable[[Any], StepResult],
        sample_fn: Callable[[str], str],
        max_uncertain_steps: int = 3,
        max_steps: int = 50,
        max_cost: float | None = None,
        on_uncertain: Callable[[int, Any, Any], bool] | None = None,
        n_samples: int = 5,
        threshold: float = 0.30,
        embedder=None,
    ):
        self.step_fn = step_fn
        self.gate = Gate(sample_fn=sample_fn, n_samples=n_samples,
                         threshold=threshold, embedder=embedder)
        self.max_uncertain_steps = max(1, int(max_uncertain_steps))
        self.max_steps = max(1, int(max_steps))
        self.max_cost = max_cost
        self.on_uncertain = on_uncertain

    def run(self, state: Any) -> LoopResult:
        steps = 0
        uncertain_total = 0
        consecutive = 0
        max_consecutive = 0
        total_cost = 0.0
        trace: list[dict] = []
        last_output = None

        while steps < self.max_steps:
            steps += 1
            result = self.step_fn(state)
            last_output = result.output
            total_cost += float(result.cost or 0.0)
            state = result.output

            entry = {"step": steps, "cost": result.cost, "done": result.done}

            if result.done:
                entry["uncertain"] = False
                trace.append(entry)
                return LoopResult("done", steps, uncertain_total, max_consecutive,
                                  total_cost, last_output, trace)

            # gate probe na NASTĘPNY krok (jeśli agent dał prompt)
            if result.prompt:
                verdict = self.gate.check(result.prompt)
                entry["uncertain"] = verdict.uncertain
                entry["disagreement"] = round(verdict.disagreement, 3)
                if verdict.uncertain:
                    uncertain_total += 1
                    # eskalacja: callback może "naprawić" krok i pozwolić kontynuować.
                    # FAIL-SAFE (audyt 2026-06-27 #5): wyjątek w callbacku NIE może
                    # crashować pętli — degraduj do rescued=False (niepewny krok liczony).
                    if self.on_uncertain:
                        try:
                            rescued = bool(self.on_uncertain(steps, verdict, state))
                        except Exception:
                            rescued = False
                    else:
                        rescued = False
                    entry["rescued"] = rescued
                    if rescued:
                        consecutive = 0
                    else:
                        consecutive += 1
                        max_consecutive = max(max_consecutive, consecutive)
                else:
                    consecutive = 0
            else:
                entry["uncertain"] = None  # brak promptu = brak gate dla tego kroku

            trace.append(entry)

            # RUNAWAY: N niepewnych kroków z rzędu = agent zgaduje w pętli → stop
            if consecutive >= self.max_uncertain_steps:
                return LoopResult("runaway_guessing", steps, uncertain_total,
                                  max_consecutive, total_cost, last_output, trace)

            # budżet
            if self.max_cost is not None and total_cost >= self.max_cost:
                return LoopResult("budget", steps, uncertain_total,
                                  max_consecutive, total_cost, last_output, trace)

        return LoopResult("max_steps", steps, uncertain_total, max_consecutive,
                          total_cost, last_output, trace)
