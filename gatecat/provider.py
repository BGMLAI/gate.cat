"""provider — PROVIDER of truth (direction 1 of the bidirectional gate).

Council of 10 votes (2026-06-28): the gate not only EVALUATES the agent's output (the veto.py guard),
but also PROVIDES the agent with verified data FOR its decisions. One koryto engine, two interfaces.

KEY PRINCIPLES (unanimous verdict of the council — without them = a confident-wrong generator):
  1. [HARD] = EXCLUSIVELY exec/calc (proof from EXECUTION). Cache/lookup = SOFT (Hint) ALWAYS,
     even at sim=1.0 — because similarity ≠ proof of execution (Kimi: "sim:0.99 = a hallucination in disguise").
  2. Origin label as a TYPE, not metadata: Verified<value, proof_ref> | Hint<value, sim>.
     No proof_ref ⇒ automatically SOFT. The code is FORCED to be honest.
  3. proof_ref is REPLAYABLE by the agent (replay_command + hash), not a pointer to the gate.
     The agent can CHECK the gate, does not trust blindly (a certificate without an audit = circular trust).
  4. provide_truth = pure/read-only/sandbox (if it mutates ⇒ Actor, not Oracle).

Core is 100% stdlib (hashlib, dataclasses) + koryto (also stdlib). Zero API/model at runtime.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional

from gatecat.koryto import koryto_calc, koryto_exec_python


# ======================================================================
# ORIGIN TYPES — Verified (HARD) vs Hint (SOFT). Disjoint classes.
# ======================================================================

@dataclass(frozen=True)
class ProofRef:
    """Replayable proof of execution. The agent can REPRODUCE it independently of the gate."""
    method: str                  # "exec" | "calc"
    replay_command: str          # command the agent can run itself (e.g. python -c "...")
    input_hash: str              # sha256 of the input
    output_hash: str             # sha256 of the result
    statements: tuple = ()       # raw statements (for replay)

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "replay_command": self.replay_command,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
        }


@dataclass(frozen=True)
class Verified:
    """HARD fact — truth from EXECUTION. Carries a replayable proof_ref."""
    value: str
    proof_ref: ProofRef
    kind: str = "HARD"

    def label(self) -> str:
        return f"[HARD_{self.proof_ref.method.upper()}: {self.value} | proof={self.proof_ref.output_hash[:8]}]"


@dataclass(frozen=True)
class Hint:
    """SOFT hint — from retrieval/cache. NEVER a proof. The agent MUST verify."""
    value: str
    sim: float
    source: str = "lookup"
    kind: str = "SOFT"

    def label(self) -> str:
        return f"[RETRIEVED_{self.source}: {self.value} | sim={self.sim:.2f} — unverified]"


def _sha(s: str) -> str:
    return hashlib.sha256(str(s).encode("utf-8")).hexdigest()


def _clean_exec_output(out: Optional[str]) -> Optional[str]:
    """Context-guard appends '\\r\\nNone' (the last print returns None). We take the 1st line."""
    if not out:
        return None
    first = out.replace("\r\n", "\n").split("\n", 1)[0].strip()
    return first or None


# ======================================================================
# PROVIDER — provide_truth(op, args). Pure function, read-only.
# ======================================================================

def provide_truth(op: str, args: str) -> Optional[object]:
    """Provide the agent with a VERIFIED fact. Returns Verified (HARD) | None.

    op:
      "calc" — args = a pure arithmetic expression ("17*23"). Result from the interpreter.
      "exec" — args = a JSON list of Python statements. Result from execution in the sandbox.

    Only exec/calc yield Verified (proof from execution). Cache/lookup → provide_hint (SOFT).
    Returns None when op is unsupported / cannot be executed (safe absence of a fact).
    """
    op = (op or "").strip().lower()

    if op == "calc":
        expr = (args or "").strip()
        truth = koryto_calc(expr)
        if truth is None:
            return None  # not a pure expression — no HARD fact
        replay = f'python -c "print({expr})"'
        return Verified(
            value=str(truth),
            proof_ref=ProofRef(
                method="calc",
                replay_command=replay,
                input_hash=_sha(expr),
                output_hash=_sha(truth),
                statements=(expr,),
            ),
        )

    if op == "exec":
        try:
            stmts = json.loads(args) if isinstance(args, str) else args
            stmts = [str(s) for s in stmts]
        except (json.JSONDecodeError, TypeError, ValueError):
            return None
        raw = koryto_exec_python(stmts)
        truth = _clean_exec_output(raw)
        if truth is None:
            return None
        replay = "python -c " + json.dumps("; ".join(stmts))
        return Verified(
            value=truth,
            proof_ref=ProofRef(
                method="exec",
                replay_command=replay,
                input_hash=_sha("\n".join(stmts)),
                output_hash=_sha(truth),
                statements=tuple(stmts),
            ),
        )

    return None  # unsupported op


def provide_hint(value: str, sim: float, source: str = "lookup") -> Hint:
    """Provide a SOFT hint from cache/lookup. NEVER HARD (sim=similarity).
    Council unanimously: even sim=1.0 stays a Hint."""
    return Hint(value=str(value), sim=float(sim), source=source)


# ======================================================================
# proof_ref VERIFICATION by the agent (TOP-2: the agent checks the gate, does not trust blindly)
# ======================================================================

def verify_proof(verified: Verified) -> bool:
    """The agent REPRODUCES the proof independently: re-executes and checks output_hash.
    Returns True when the replay yields THE SAME result. This eliminates 'a HARD label on a made-up value'.
    """
    pr = verified.proof_ref
    try:
        if pr.method == "calc":
            again = koryto_calc(pr.statements[0])
        elif pr.method == "exec":
            again = _clean_exec_output(koryto_exec_python(list(pr.statements)))
        else:
            return False
        return again is not None and _sha(again) == pr.output_hash
    except Exception:
        return False  # cannot reproduce → do NOT trust (fail-closed)
