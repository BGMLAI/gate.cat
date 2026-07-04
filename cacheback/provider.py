"""provider — DOSTAWCA prawdy (kierunek 1 bramki dwukierunkowej).

Council 10-głosów (2026-06-28): bramka nie tylko OCENIA output agenta (strażnik veto.py),
ale DOSTARCZA agentowi zweryfikowane dane DO decyzji. Jeden silnik koryto, dwa interfejsy.

KLUCZOWE ZASADY (jednomyślny werdykt rady — bez nich = generator confident-wrong):
  1. [HARD] = WYŁĄCZNIE exec/calc (dowód z WYKONANIA). Cache/lookup = SOFT (Hint) ZAWSZE,
     nawet sim=1.0 — bo podobieństwo ≠ dowód wykonania (Kimi: "sim:0.99 = halucynacja w przebraniu").
  2. Etykieta pochodzenia jako TYP, nie metadana: Verified<value, proof_ref> | Hint<value, sim>.
     Brak proof_ref ⇒ automatycznie SOFT. Kod ZMUSZONY do szczerości.
  3. proof_ref REPLAYABLE przez agenta (replay_command + hash), nie pointer do bramki.
     Agent może SPRAWDZIĆ bramkę, nie ufa ślepo (certyfikat bez audytu = circular trust).
  4. provide_truth = czyste/read-only/sandbox (mutuje ⇒ Actor nie Oracle).

Rdzeń 100% stdlib (hashlib, dataclasses) + koryto (też stdlib). Zero API/model w runtime.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional

from cacheback.koryto import koryto_calc, koryto_exec_python


# ======================================================================
# TYPY pochodzenia — Verified (HARD) vs Hint (SOFT). Rozłączne klasy.
# ======================================================================

@dataclass(frozen=True)
class ProofRef:
    """Replayable dowód wykonania. Agent może go ODTWORZYĆ niezależnie od bramki."""
    method: str                  # "exec" | "calc"
    replay_command: str          # komenda którą agent może uruchomić sam (np. python -c "...")
    input_hash: str              # sha256 wejścia
    output_hash: str             # sha256 wyniku
    statements: tuple = ()       # surowe statementy (do replay)

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "replay_command": self.replay_command,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
        }


@dataclass(frozen=True)
class Verified:
    """HARD fakt — prawda z WYKONANIA. Niesie replayable proof_ref."""
    value: str
    proof_ref: ProofRef
    kind: str = "HARD"

    def label(self) -> str:
        return f"[HARD_{self.proof_ref.method.upper()}: {self.value} | proof={self.proof_ref.output_hash[:8]}]"


@dataclass(frozen=True)
class Hint:
    """SOFT podpowiedź — z retrievalu/cache. NIGDY nie jest dowodem. Agent MUSI zweryfikować."""
    value: str
    sim: float
    source: str = "lookup"
    kind: str = "SOFT"

    def label(self) -> str:
        return f"[RETRIEVED_{self.source}: {self.value} | sim={self.sim:.2f} — niezweryfikowane]"


def _sha(s: str) -> str:
    return hashlib.sha256(str(s).encode("utf-8")).hexdigest()


def _clean_exec_output(out: Optional[str]) -> Optional[str]:
    """Context-guard dokleja '\\r\\nNone' (ostatni print zwraca None). Bierzemy 1. linię."""
    if not out:
        return None
    first = out.replace("\r\n", "\n").split("\n", 1)[0].strip()
    return first or None


# ======================================================================
# DOSTAWCA — provide_truth(op, args). Czysta funkcja, read-only.
# ======================================================================

def provide_truth(op: str, args: str) -> Optional[object]:
    """Dostarcz agentowi ZWERYFIKOWANY fakt. Zwraca Verified (HARD) | None.

    op:
      "calc" — args = czyste wyrażenie arytmetyczne ("17*23"). Wynik z interpretera.
      "exec" — args = JSON-lista statementów Python. Wynik z wykonania w sandboxie.

    Tylko exec/calc dają Verified (dowód z wykonania). Cache/lookup → provide_hint (SOFT).
    Zwraca None gdy op nieobsługiwane / nie da się wykonać (bezpieczny brak faktu).
    """
    op = (op or "").strip().lower()

    if op == "calc":
        expr = (args or "").strip()
        truth = koryto_calc(expr)
        if truth is None:
            return None  # nie czyste wyrażenie — brak HARD-faktu
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

    return None  # nieobsługiwane op


def provide_hint(value: str, sim: float, source: str = "lookup") -> Hint:
    """Dostarcz SOFT podpowiedź z cache/lookup. NIGDY nie jest HARD (sim=podobieństwo).
    Council jednomyślnie: nawet sim=1.0 zostaje Hint."""
    return Hint(value=str(value), sim=float(sim), source=source)


# ======================================================================
# WERYFIKACJA proof_ref przez agenta (TOP-2: agent sprawdza bramkę, nie ufa ślepo)
# ======================================================================

def verify_proof(verified: Verified) -> bool:
    """Agent ODTWARZA dowód niezależnie: re-wykonuje i sprawdza output_hash.
    Zwraca True gdy replay daje TEN SAM wynik. To eliminuje 'HARD-etykieta na zmyślonej wartości'.
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
        return False  # nie da się odtworzyć → NIE ufaj (fail-closed)
