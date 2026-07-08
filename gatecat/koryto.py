"""koryto — deterministyczny weryfikator atomu: łapie confident-wrong tam, gdzie
disagreement-gate jest ślepy (rozrzut zero, model pewny + błędny).

TEORIA (Aksjomat 1 / τ, BGML): RZEKA (model, probabilistyczne) musi płynąć
KORYTEM (deterministyczne źródło prawdy: interpreter / kalkulator / baza faktów).
confident-wrong = rzeka wylewa z koryta. Gate mierzy WAHANIE rzeki; koryto mierzy
ZGODNOŚĆ ze źródłem fizycznie niezależnym od wag modelu — dlatego widzi to, czego
gate nie widzi.

ZMIERZONE (REJESTR_PRAWD 2026-06-26/27, qwen-2.5-7b, N≥40/domena):
  - exec-koryto (kod): recall 1.0 na confident-wrong, $0, model-niezależny.
    NIE tautologia — interpreter WYKONUJE, gold nie wchodzi do exec.
  - calc-koryto (jawne wyrażenia): 13/13 poprawnych, pokrycie 29% mathu
    (reszta to NL→wyrażenie = wybór operacji należy do rzeki).
  - lookup-koryto (baza faktów): recall 0.65-1.0, ALE z dwoma realnymi kosztami:
    (a) niekompletność → false-neg (atom spoza bazy przechodzi),
    (b) KORYTO-STALE → zepsuta/nieaktualna baza wprowadza WŁASNY confident-wrong.
    Dlatego lookup zwraca confidence + flagę 'może-być-stale'; NIGDY nie blokuje
    twardo na samym lookupie bez warstwy kontroli (web-rozjemca).

GRANICA (uczciwa, ta sama we wszystkich domenach): koryto łapie błąd WYKONANIA /
WERYFIKACJI-FAKTU (atom skwantyfikowany), NIE błąd WYBORU operacji/konceptu —
chyba że ten wybór zamkniesz w deterministycznej regule. Skaluje przez rozrost
bazy faktów, nie magię.

Zero zależności od floty/orchestratora. Pluggable fact-base (dict / callback).

Użycie (minimalne):
    from gatecat.koryto import Koryto

    koryto = Koryto()  # exec+calc wbudowane; lookup pusty dopóki nie podasz bazy
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
# normalizacja / porównanie atomów
# ======================================================================

_STOP = {"the", "a", "an", "of", "and", "to", "in", "is", "was", "by"}


def _norm(s: str) -> str:
    s = (s or "").strip().lower()
    # diakrytyki → baza: 'Brasília' musi matchować atom 'Brasilia' (benchmark 50q
    # 2026-07-02: poprawna odpowiedź z diakrytykiem dawała soft-refute → uncertain)
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = re.sub(r"[^\w\s.+-]", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def atoms_match(answer: str, truth: str, aliases: Sequence[str] = ()) -> bool:
    """Czy odpowiedź modelu zawiera atom prawdy (lub alias). WYŁĄCZNIE
    word-boundary — goły substring dawał confirmed dla '19' vs truth '9'
    i 'comparison' vs 'Paris' (workflow review 2026-07-02, P1). Pusty atom
    nie matchuje; answer=0/False to realne odpowiedzi (falsy ≠ brak)."""
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
# KANAŁ 1: exec (interpreter) — twarde koryto, recall 1.0 na wykonywalnym kodzie
# ======================================================================

def koryto_exec_python(stmts: Sequence[str], timeout: float = 5.0) -> Optional[str]:
    """exec z context-guard W SZCZELNYM SANDBOXIE: osobne statementy odtwarzają kontekst
    pytania, ostatni to wyrażenie do wyświetlenia. Context-guard KONIECZNY (REJESTR
    2026-06-26: naiwny 'a=257 is b' jako jeden blok → True przez peephole = rubber-stamp).

    SANDBOX (workflow exec-hardening, 26 ataków): allow-list AST + clean env (bez sekretów)
    + builtins-firewall + Job Object/rlimit. Gate na WEJŚCIU usera (każdy statement), harness
    context-guard zaufany. Kod który nie przejdzie gate → None (bezpieczny brak werdyktu).
    Zwraca stdout lub None (gdy nie wykonano/odrzucono)."""
    if not stmts:
        return None
    try:
        from gatecat.koryto_sandbox import run_context_guard
        r = run_context_guard(stmts, timeout=timeout)
        return r.stdout or None if r.ok else None
    except Exception:
        return None


def koryto_exec_node(code: str, timeout: float = 10.0) -> Optional[str]:
    """exec dla JavaScript (Node). Zwraca stdout lub None (gdy node brak/wyłączony/błąd).

    🔒 BEZPIECZEŃSTWO (audyt 2026-06-27 #10): Node-exec NIE jest sandboxowany jak Python
    (gotcha exec-hardening #4: JS regex-deny NIE DO OBRONIENIA — `'req'+'uire'`,
    constructor.constructor, fromCharCode obchodzą każdą deny-listę). Dlatego:
      - DOMYŚLNIE WYŁĄCZONY. Wymaga jawnego `GATECAT_KORYTO_EXEC_NODE_UNSAFE=1`
        (nazwa z UNSAFE celowo — operator widzi że bierze odpowiedzialność).
      - Nawet włączony: clean env (bez sekretów procesu) zamiast pełnego os.environ.
    Pełna izolacja JS = deploy-level (kontener/vm), poza zasięgiem czystego pip.
    Bez opt-in zwraca None (bezpieczny brak werdyktu, NIE wykonanie).
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
# KANAŁ 2: calc (kalkulator) — jawne wyrażenia arytmetyczne, niezależnie od gold
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
    """Policz JAWNE wyrażenie z treści pytania (NIE z gold → nie tautologia).
    Obsługuje 'Evaluate: 6 / 2 * 3', '(2+3) squared', '2 ^ 3 ^ 2'. Zwraca None gdy
    pytanie to zadanie słowne (NL→wyrażenie) — wybór operacji należy do rzeki."""
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
# KANAŁ 3: lookup (baza faktów) — miękkie koryto, MOŻE BYĆ STALE
# ======================================================================

class FactBase:
    """Niezależna baza faktów: pytanie→klucz (substring, najdłuższy = najspecyficzniejszy).
    Realne wady lookupu są CECHĄ, nie bugiem: niekompletność (miss), inny format,
    nieaktualność (stale). Dlatego lookup NIGDY nie jest twardym arbitrem sam —
    zwraca atom + sygnał, że wymaga potwierdzenia (web-rozjemca)."""

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
# WERDYKT + ROUTER
# ======================================================================

@dataclass
class KorytoVerdict:
    """Wynik weryfikacji jednej odpowiedzi przez koryto.

    verdict:
      "confirm"  — koryto zna prawdę i odpowiedź modelu się z nią zgadza.
      "refute"   — koryto zna prawdę i odpowiedź modelu jest BŁĘDNA (confident-wrong złapany).
      "unknown"  — koryto nie ma atomu (poza zasięgiem / NL→wyrażenie / brak w bazie). Przepuść.
    """
    verdict: str                       # confirm | refute | unknown
    channel: str                       # exec | calc | lookup | none
    truth: Optional[str] = None        # atom prawdy z koryta (gdy znany)
    answer: str = ""
    hard: bool = False                 # True dla exec/calc (fizycznie niezależne); False dla lookup (może być stale)
    needs_arbiter: bool = False        # True gdy verdict z miękkiego koryta → potwierdź web-rozjemcą zanim zablokujesz
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
    """Deterministyczny weryfikator atomu. Składa kanały exec → calc → lookup.

    Kanały twarde (exec, calc) działają na strukturze pytania, fizycznie niezależnie
    od modelu — dają verdict.hard=True (można blokować od razu). Kanał miękki (lookup)
    może być stale → verdict.needs_arbiter=True (potwierdź zanim zablokujesz).

    Args:
        fact_base: FactBase | dict | None. Baza dla kanału lookup.
        enable_exec: czy uruchamiać interpreter (domyślnie True; wyłącz w sandboxie bez subprocess).
        enable_calc: czy liczyć jawne wyrażenia (domyślnie True).
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
        """Zweryfikuj odpowiedź modelu względem deterministycznego koryta.

        exec_stmts / exec_js: jawne wykonanie (gdy pytanie jest wykonywalne i znasz
        statementy). Bez nich exec-kanał próbuje tylko jeśli pytanie wygląda na czysty kod
        — ale pewne wykonanie wymaga podanych statementów (context-guard).
        """
        # NIE `answer or ""` — 0/0.0/False to poprawne odpowiedzi (workflow P1)
        answer = "" if answer is None else str(answer)

        # --- KANAŁ 1: exec (twardy) ---
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
                    note="interpreter wykonał — fizycznie niezależne od modelu",
                )

        # --- KANAŁ 2: calc (twardy) ---
        if self.enable_calc:
            truth = koryto_calc(question)
            if truth is not None:
                ok = atoms_match(answer, truth, aliases)
                return KorytoVerdict(
                    verdict=("confirm" if ok else "refute"),
                    channel="calc", truth=truth, answer=answer, hard=True,
                    note="kalkulator policzył jawne wyrażenie z treści pytania",
                )

        # --- KANAŁ 3: lookup (miękki, MOŻE BYĆ STALE) ---
        if self.fact_base is not None:
            truth = self.fact_base.lookup(question)
            if truth is not None:
                ok = atoms_match(answer, truth, aliases)
                return KorytoVerdict(
                    verdict=("confirm" if ok else "refute"),
                    channel="lookup", truth=truth, answer=answer, hard=False,
                    needs_arbiter=(not ok),   # rozbieżność z miękkiego koryta → potwierdź zanim zablokujesz
                    note="baza faktów (może być niekompletna/nieaktualna — potwierdź arbitrem przy rozbieżności)",
                )

        # --- brak atomu: poza zasięgiem koryta (uczciwy false-neg) ---
        return KorytoVerdict(verdict="unknown", channel="none", answer=answer,
                             note="koryto nie zna atomu — przepuść (atom spoza zasięgu/bazy)")
