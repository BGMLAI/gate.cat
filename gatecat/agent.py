"""truthgate.agent — gate for the agent loop: stop a runaway BEFORE it burns the budget.

Real-world problem: an agent falls into a loop / burns the budget because the model
is CONFIDENT (not verbose) — a hard `max_steps` / `thinking_budget` catches this AFTER
the fact and also cuts off good long reasoning. Real case: a cache-write spiral, $305 in 24h.

TruthGate gates on MEASURED uncertainty: probe N cheap samples of the next
step → if the model disagrees with itself (spread) = it's guessing = pause/escalate/
abstain. It stops ONLY the steps that are genuinely guessing, not expensive-but-correct ones.

HONESTY: the gate catches HESITATION, not LYING. Confident-wrong (a confident error) is
not catchable by spread — this is an uncertainty signal, not a correctness guarantee.

Usage:
    from gatecat.agent import GatedLoop

    def step(state) -> StepResult:        # one agent step
        ...                               # returns StepResult(output, done, prompt)

    def sample(prompt) -> str:            # agent model at temp>0
        return agent_llm(prompt, temperature=0.7)

    loop = GatedLoop(step_fn=step, sample_fn=sample,
                     max_uncertain_steps=3, max_steps=50)
    result = loop.run(initial_state)
    print(result.stopped_reason)          # "done" | "runaway_guessing" | "max_steps"
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from gatecat.gate import Gate


@dataclass
class StepResult:
    """Returned by the agent's step_fn."""
    output: Any                    # result of the step (state, observation, whatever)
    done: bool = False             # whether the agent finished the task
    prompt: str | None = None      # prompt the gate probes for the NEXT step
    cost: float = 0.0              # optional cost of the step (tokens/$ — for the budget)


@dataclass
class LoopResult:
    stopped_reason: str            # "done" | "runaway_guessing" | "max_steps" | "budget"
    steps: int
    uncertain_steps: int           # how many steps were flagged as uncertain
    consecutive_uncertain: int     # longest run of consecutive uncertain steps
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
    """Wraps the agent loop. Aborts when the agent is guessing (N consecutive uncertain steps).

    Args:
        step_fn(state) -> StepResult : one agent step.
        sample_fn(prompt) -> str     : agent model at temp>0 (gate probe).
        max_uncertain_steps : how many CONSECUTIVE uncertain STEPS = runaway → stop (default 3).
        max_steps           : hard backstop (default 50).
        max_cost            : optional cost limit (None = no limit).
        on_uncertain        : optional callback(step_idx, verdict, state) — e.g. escalation
                              to a stronger model / a human. Return True to CONTINUE
                              (e.g. after escalation), False/None to count it as an uncertain step.
        n_samples, threshold: gate configuration.
        embedder            : optional embedder (semantic spread).
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

            # gate probe for the NEXT step (if the agent provided a prompt)
            if result.prompt:
                verdict = self.gate.check(result.prompt)
                entry["uncertain"] = verdict.uncertain
                entry["disagreement"] = round(verdict.disagreement, 3)
                if verdict.uncertain:
                    uncertain_total += 1
                    # escalation: the callback may "fix" the step and allow continuing.
                    # FAIL-SAFE (audit 2026-06-27 #5): an exception in the callback MUST NOT
                    # crash the loop — degrade to rescued=False (the uncertain step is counted).
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
                entry["uncertain"] = None  # no prompt = no gate for this step

            trace.append(entry)

            # RUNAWAY: N consecutive uncertain steps = agent is guessing in a loop → stop
            if consecutive >= self.max_uncertain_steps:
                return LoopResult("runaway_guessing", steps, uncertain_total,
                                  max_consecutive, total_cost, last_output, trace)

            # budget
            if self.max_cost is not None and total_cost >= self.max_cost:
                return LoopResult("budget", steps, uncertain_total,
                                  max_consecutive, total_cost, last_output, trace)

        return LoopResult("max_steps", steps, uncertain_total, max_consecutive,
                          total_cost, last_output, trace)
