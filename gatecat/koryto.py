"""koryto — deterministic atom verifier: catches confident-wrong where the
disagreement-gate is blind (zero spread, model confident + wrong).

THEORY (Axiom 1 / τ, BGML): the RIVER (model, probabilistic) must flow through
the CHANNEL (deterministic source of truth: interpreter / calculator / fact base).
confident-wrong = the river overflows its channel. The gate measures the river's
HESITATION; the channel measures AGREEMENT with a source physically independent of
the model weights — which is why it sees what the gate cannot.

MEASURED (TRUTH_REGISTRY 2026-06-26/27, qwen-2.5-7b, N>=40/domain):
  - exec-channel (code): recall 1.0 on confident-wrong, $0, model-independent.
    NOT a tautology — the interpreter EXECUTES, gold never enters exec.
  - calc-channel (explicit expressions): 13/13 correct, 29% coverage of math
    (the rest is NL->expression = the choice of operation belongs to the river).
  - lookup-channel (fact base): recall 0.65-1.0, BUT with two real costs:
    (a) incompleteness -> false-neg (an atom outside the base passes through),
    (b) CHANNEL-STALE -> a broken/outdated base introduces its OWN confident-wrong.
    So lookup returns confidence + a 'may-be-stale' flag; it NEVER blocks
    hard on lookup alone without a control layer (web-arbiter).

BOUNDARY (honest, the same across all domains): the channel catches an EXECUTION /
FACT-VERIFICATION error (a quantified atom), NOT an error in the CHOICE of
operation/concept — unless you encode that choice in a deterministic rule. It scales
by growing the fact base, not by magic.

Zero dependency on the fleet/orchestrator. Pluggable fact-base (dict / callback).

Usage (minimal):
    from gatecat.koryto import Koryto

    koryto = Koryto()  # exec+calc built in; lookup empty until you supply a base
    v = koryto.verify("In Python, fns=[lambda: i for i in range(3)]; [g() for g in fns]?",
                      answer="[0, 1, 2]")
    if v.verdict == "refute":
        print("confident-wrong:", v.truth, "via", v.channel)  # [2, 2, 2] via exec
"""
from __future__ import annotations

import ast
import operator
import os
import re
import subprocess
import sys
import unicodedata
from dataclasses import dataclass, field
from typing import Callable, Optional, Sequence


# ======================================================================
# atom normalization / comparison
# ======================================================================

_STOP = {"the", "a", "an", "of", "and", "to", "in", "is", "was", "by"}


def _norm(s: str) -> str:
    s = (s or "").strip().lower()
    # diacritics → base form: 'Brasília' must match the atom 'Brasilia' (benchmark 50q
    # 2026-07-02: a correct answer with a diacritic yielded soft-refute → uncertain)
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = re.sub(r"[^\w\s.+-]", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def atoms_match(answer: str, truth: str, aliases: Sequence[str] = ()) -> bool:
    """Whether the model's answer contains the truth atom (or an alias). WORD-BOUNDARY
    ONLY — a bare substring gave confirmed for '19' vs truth '9'
    and 'comparison' vs 'Paris' (workflow review 2026-07-02, P1). An empty atom
    does not match; answer=0/False are real answers (falsy != missing)."""
    if answer is None or not str(answer).strip():
        return False
    na = _norm(str(answer))
    for cand in [truth, *(aliases or [])]:
        nc = _norm(str(cand))
        if len(nc) < 1 or nc in _STOP:
            continue
        if re.search(rf"(?<!\w){re.escape(nc)}(?!\w)", na):
            return True
    return False


# ======================================================================
# CHANNEL 1: exec (interpreter) — hard channel, recall 1.0 on executable code
# ======================================================================

def koryto_exec_python(stmts: Sequence[str], timeout: float = 5.0) -> Optional[str]:
    """exec with a context-guard IN A SEALED SANDBOX: separate statements reconstruct the
    question's context, the last one is the expression to display. The context-guard is
    ESSENTIAL (REGISTRY 2026-06-26: a naive 'a=257 is b' as a single block → True via the
    peephole optimizer = rubber-stamp).

    SANDBOX (workflow exec-hardening, 26 attacks): AST allow-list + clean env (no secrets)
    + builtins-firewall + Job Object/rlimit. Gate on the user's INPUT (every statement), the
    harness context-guard is trusted. Code that fails the gate → None (safe absence of a verdict).
    Returns stdout or None (when not executed/rejected)."""
    if not stmts:
        return None
    try:
        from gatecat.koryto_sandbox import run_context_guard
        r = run_context_guard(stmts, timeout=timeout)
        return r.stdout or None if r.ok else None
    except Exception:
        return None


def koryto_exec_node(code: str, timeout: float = 10.0) -> Optional[str]:
    """exec for JavaScript (Node). Returns stdout or None (when node is missing/disabled/errors).

    🔒 SECURITY (audit 2026-06-27 #10): Node-exec is NOT sandboxed like Python
    (gotcha exec-hardening #4: a JS regex-deny is INDEFENSIBLE — `'req'+'uire'`,
    constructor.constructor, fromCharCode bypass any deny-list). Therefore:
      - DISABLED BY DEFAULT. Requires an explicit `GATECAT_KORYTO_EXEC_NODE_UNSAFE=1`
        (the name says UNSAFE deliberately — the operator sees they are taking responsibility).
      - Even when enabled: clean env (no process secrets) instead of the full os.environ.
    Full JS isolation = deploy-level (container/vm), out of reach for plain pip.
    Without opt-in it returns None (safe absence of a verdict, NOT execution).
    """
    if os.environ.get("GATECAT_KORYTO_EXEC_NODE_UNSAFE", "0").strip() not in ("1", "true", "True"):
        return None
    import shutil
    node = shutil.which("node")
    if not node or not code:
        return None
    try:
        from gatecat.koryto_sandbox import _clean_env
        env = _clean_env()
    except Exception:
        env = {"PATH": os.environ.get("PATH", "")}
    try:
        r = subprocess.run([node, "-e", code], capture_output=True, text=True,
                           timeout=timeout, env=env)
        out = (r.stdout or "").strip()
        return out or None
    except Exception:
        return None


# ======================================================================
# CHANNEL 2: calc (calculator) — explicit arithmetic expressions, independent of gold
# ======================================================================

_CALC_OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.Div: operator.truediv, ast.Pow: operator.pow, ast.Mod: operator.mod,
    ast.FloorDiv: operator.floordiv, ast.USub: operator.neg, ast.UAdd: operator.pos,
}


def _calc_eval(node):
    if isinstance(node, ast.Expression):
        return _calc_eval(node.body)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float)):
            return node.value
        raise ValueError("non-numeric")
    if isinstance(node, ast.BinOp) and type(node.op) in _CALC_OPS:
        return _CALC_OPS[type(node.op)](_calc_eval(node.left), _calc_eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _CALC_OPS:
        return _CALC_OPS[type(node.op)](_calc_eval(node.operand))
    raise ValueError("unsupported")


def koryto_calc(question: str) -> Optional[str]:
    """Compute an EXPLICIT expression from the question text (NOT from gold → not a tautology).
    Handles 'Evaluate: 6 / 2 * 3', '(2+3) squared', '2 ^ 3 ^ 2'. Returns None when the
    question is a word problem (NL→expression) — the choice of operation belongs to the river."""
    q = question or ""
    m = re.search(r"(?:evaluate|order of operations|compute|oblicz)[^:]*:\s*(.+)$", q, re.IGNORECASE)
    raw = m.group(1) if m else (q if re.fullmatch(r"[\s\d.+\-*/^()²]+(squared)?\.?", q.strip(), re.I) else None)
    if not raw:
        return None
    raw = re.sub(r"\(that is\b.*$", "", raw, flags=re.IGNORECASE).strip().rstrip(".")
    raw = raw.replace("×", "*").replace("÷", "/").replace("^", "**").replace("²", "**2")
    raw = re.sub(r"\)\s*squared", r")**2", raw, flags=re.I)
    raw = re.sub(r"([0-9.])\s*squared", r"(\1)**2", raw, flags=re.I)
    raw = raw.replace("squared", "**2")
    raw = re.sub(r"[^0-9.+\-*/() ]", "", raw)
    if not raw.strip() or not re.search(r"\d", raw):
        return None
    try:
        v = _calc_eval(ast.parse(raw, mode="eval"))
        if isinstance(v, float) and v.is_integer():
            v = int(v)
        return str(v)
    except Exception:
        return None


# ======================================================================
# CHANNEL 3: lookup (fact base) — soft channel, MAY BE STALE
# ======================================================================

class FactBase:
    """Independent fact base: question→key (substring, longest = most specific).
    The real weaknesses of lookup are a FEATURE, not a bug: incompleteness (miss), a
    different format, staleness. That is why lookup is NEVER a hard arbiter on its own —
    it returns an atom + a signal that it needs confirmation (web-arbiter)."""

    def __init__(self, facts: Optional[dict[str, str]] = None,
                 lookup_fn: Optional[Callable[[str], Optional[str]]] = None):
        self.facts = {(_norm(k)): v for k, v in (facts or {}).items()}
        self.lookup_fn = lookup_fn

    def lookup(self, question: str) -> Optional[str]:
        if self.lookup_fn is not None:
            try:
                v = self.lookup_fn(question)
                if v is not None:
                    return v
            except Exception:
                pass
        if not self.facts:
            return None
        nq = _norm(question)
        best_key = None
        for key in self.facts:
            if key and key in nq:
                if best_key is None or len(key) > len(best_key):
                    best_key = key
        return self.facts.get(best_key) if best_key else None


# ======================================================================
# VERDICT + ROUTER
# ======================================================================

@dataclass
class KorytoVerdict:
    """Result of verifying a single answer through the channel.

    verdict:
      "confirm"  — the channel knows the truth and the model's answer agrees with it.
      "refute"   — the channel knows the truth and the model's answer is WRONG (confident-wrong caught).
      "unknown"  — the channel has no atom (out of reach / NL→expression / not in the base). Pass through.
    """
    verdict: str                       # confirm | refute | unknown
    channel: str                       # exec | calc | lookup | none
    truth: Optional[str] = None        # truth atom from the channel (when known)
    answer: str = ""
    hard: bool = False                 # True for exec/calc (physically independent); False for lookup (may be stale)
    needs_arbiter: bool = False        # True when the verdict comes from the soft channel → confirm with the web-arbiter before blocking
    note: str = ""

    @property
    def caught(self) -> bool:
        return self.verdict == "refute"

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "channel": self.channel,
            "truth": self.truth,
            "hard": self.hard,
            "needs_arbiter": self.needs_arbiter,
            "note": self.note,
        }


class Koryto:
    """Deterministic atom verifier. Composes the exec → calc → lookup channels.

    The hard channels (exec, calc) work on the question's structure, physically independent
    of the model — they yield verdict.hard=True (can block immediately). The soft channel (lookup)
    may be stale → verdict.needs_arbiter=True (confirm before blocking).

    Args:
        fact_base: FactBase | dict | None. Base for the lookup channel.
        enable_exec: whether to run the interpreter (default True; disable in a sandbox without subprocess).
        enable_calc: whether to compute explicit expressions (default True).
    """

    def __init__(
        self,
        fact_base: "FactBase | dict | None" = None,
        *,
        enable_exec: bool = True,
        enable_calc: bool = True,
    ):
        if isinstance(fact_base, dict):
            fact_base = FactBase(fact_base)
        self.fact_base: Optional[FactBase] = fact_base
        self.enable_exec = enable_exec and (os.environ.get("KORYTO_DISABLE_EXEC") != "1")
        self.enable_calc = enable_calc

    def verify(
        self,
        question: str,
        answer: str,
        *,
        exec_stmts: Optional[Sequence[str]] = None,
        exec_js: Optional[str] = None,
        aliases: Sequence[str] = (),
    ) -> KorytoVerdict:
        """Verify the model's answer against the deterministic channel.

        exec_stmts / exec_js: explicit execution (when the question is executable and you know
        the statements). Without them the exec-channel only tries if the question looks like pure
        code — but reliable execution requires the supplied statements (context-guard).
        """
        # NOT `answer or ""` — 0/0.0/False are correct answers (workflow P1)
        answer = "" if answer is None else str(answer)

        # --- CHANNEL 1: exec (hard) ---
        if self.enable_exec:
            truth = None
            if exec_js is not None:
                truth = koryto_exec_node(exec_js)
                ch = "exec"
            elif exec_stmts:
                truth = koryto_exec_python(exec_stmts)
                ch = "exec"
            if truth is not None:
                ok = atoms_match(answer, truth, aliases)
                return KorytoVerdict(
                    verdict=("confirm" if ok else "refute"),
                    channel="exec", truth=truth, answer=answer, hard=True,
                    note="interpreter executed — physically independent of the model",
                )

        # --- CHANNEL 2: calc (hard) ---
        if self.enable_calc:
            truth = koryto_calc(question)
            if truth is not None:
                ok = atoms_match(answer, truth, aliases)
                return KorytoVerdict(
                    verdict=("confirm" if ok else "refute"),
                    channel="calc", truth=truth, answer=answer, hard=True,
                    note="calculator computed the explicit expression from the question text",
                )

        # --- CHANNEL 3: lookup (soft, MAY BE STALE) ---
        if self.fact_base is not None:
            truth = self.fact_base.lookup(question)
            if truth is not None:
                ok = atoms_match(answer, truth, aliases)
                return KorytoVerdict(
                    verdict=("confirm" if ok else "refute"),
                    channel="lookup", truth=truth, answer=answer, hard=False,
                    needs_arbiter=(not ok),   # discrepancy from the soft channel → confirm before blocking
                    note="fact base (may be incomplete/outdated — confirm with an arbiter on any discrepancy)",
                )

        # --- no atom: out of the channel's reach (honest false-neg) ---
        return KorytoVerdict(verdict="unknown", channel="none", answer=answer,
                             note="channel does not know the atom — pass through (atom outside reach/base)")
