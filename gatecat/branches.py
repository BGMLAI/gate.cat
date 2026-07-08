"""truthgate — gałęzie naprawy: web + tools (3. i 4. stopień kaskady).

Pełna kaskada produktu (mechanizm /goal, council 6/6):
    SLM(pewny → stop) → cache(sim≥0.92) → WEB(snippet ma odp) → TOOLS(calc/lookup) → abstain

Gdy gate mówi "model nie wie" a cache nie naprawił, sięgamy po świeże/policzalne
źródło ZANIM pozwolimy modelowi zgadywać. Każda gałąź jest lekka, samodzielna,
bez zależności od floty BGML.

UCZCIWE OGRANICZENIE (Badanie C, zmierzone):
  Web naprawia 75-77% GDY snippet ma odpowiedź (W_hit), ale web-SZUM psuje
  base-correct 57-68% — 2-3× mocniej niż zły cache. Dlatego web wstrzykuje się
  TYLKO po progu jakości snippetu (snippet_score ≥ próg). Ślepe wstrzykiwanie
  web = trucizna. To samo dla tools: zła obserwacja gorsza niż brak.

Web: domyślnie Brave Search API (klucz BRAVE_API_KEY / param). Pluggable —
podaj własny search_fn(query)->list[dict] dla innego dostawcy.
Tools: lekkie wbudowane (calc bezpieczny przez ast, lookup-callback). Pluggable.
"""
from __future__ import annotations

import ast
import operator
import os
import re
from dataclasses import dataclass
from typing import Any, Callable, Sequence

# --- próg jakości snippetu web (Badanie C: poniżej = W_noise = trucizna) ---
# Dla retrieval_score od dostawcy: 0.55 (zmierzone Badanie C).
WEB_SNIPPET_MIN = float(os.environ.get("TRUTHGATE_WEB_SNIPPET_MIN", "0.55"))
# Token-overlap to grubszy proxy (gdy dostawca nie daje retrieval_score) —
# inna skala, niższy próg. "co najmniej 1/4 słów pytania w snippecie".
WEB_OVERLAP_MIN = float(os.environ.get("TRUTHGATE_WEB_OVERLAP_MIN", "0.25"))


# ======================================================================
# WEB (gałąź 3)
# ======================================================================

def _token_overlap(query: str, text: str) -> float:
    """Proxy snippet_has_gold: token-overlap query<->snippet (0..1)."""
    qt = set(re.findall(r"\w{3,}", (query or "").lower()))
    if not qt:
        return 0.0
    tt = set(re.findall(r"\w{3,}", (text or "").lower()))
    return round(len(qt & tt) / max(1, len(qt)), 4)


def best_web_snippet_score(results: Sequence[dict], query: str) -> tuple[float, bool]:
    """Najwyższy score snippetu (proxy snippet_has_gold). Zwraca (score, used_retrieval_score).
    Używa retrieval_score jeśli dostawca go daje (próg 0.55), inaczej token-overlap (próg 0.25)."""
    best = 0.0
    used_rs = False
    for r in results or []:
        s = r.get("retrieval_score")
        if isinstance(s, (int, float)):
            used_rs = True
        else:
            text = " ".join(str(r.get(k) or "") for k in ("title", "snippet", "description", "url"))
            s = _token_overlap(query, text)
        if isinstance(s, (int, float)) and s > best:
            best = float(s)
    return best, used_rs


def brave_search(query: str, *, api_key: str | None = None, count: int = 5) -> list[dict]:
    """Brave Search API → lista {title, snippet, url}. Pusta lista przy błędzie."""
    import httpx
    key = api_key or os.environ.get("BRAVE_API_KEY", "")
    if not key:
        return []
    try:
        r = httpx.get(
            "https://api.search.brave.com/res/v1/web/search",
            params={"q": query, "count": count},
            headers={"X-Subscription-Token": key, "Accept": "application/json"},
            timeout=15.0,
        )
        data = r.json().get("web", {}).get("results", []) or []
        return [{"title": d.get("title", ""), "snippet": d.get("description", ""),
                 "url": d.get("url", "")} for d in data]
    except Exception:
        return []


@dataclass
class WebResult:
    used: bool                 # czy snippet przeszedł próg i nadaje się do wstrzyknięcia
    score: float               # najlepszy snippet_score
    context: str               # sklejony kontekst do wstrzyknięcia (pusty gdy used=False)
    results: list[dict]


class WebBranch:
    """3. gałąź: świeży kontekst z web, TYLKO gdy snippet ma odpowiedź (próg jakości)."""

    def __init__(self, search_fn: Callable[[str], list[dict]] | None = None,
                 *, api_key: str | None = None, threshold: float | None = None, top_k: int = 3):
        self.search_fn = search_fn or (lambda q: brave_search(q, api_key=api_key))
        self.threshold = threshold  # None = auto (0.55 retrieval_score / 0.25 overlap)
        self.top_k = top_k

    def fetch(self, query: str) -> WebResult:
        results = self.search_fn(query) or []
        score, used_rs = best_web_snippet_score(results, query)
        thr = self.threshold if self.threshold is not None else (WEB_SNIPPET_MIN if used_rs else WEB_OVERLAP_MIN)
        if score < thr:
            # W_noise: poniżej progu = trucizna, NIE wstrzykuj
            return WebResult(used=False, score=score, context="", results=results)
        snippets = []
        for r in results[: self.top_k]:
            t = (r.get("title") or "").strip()
            s = (r.get("snippet") or "").strip()
            if s:
                snippets.append(f"- {t}: {s}" if t else f"- {s}")
        context = "\n".join(snippets)
        return WebResult(used=bool(context), score=score, context=context, results=results)


# ======================================================================
# TOOLS (gałąź 4)
# ======================================================================

_SAFE_OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.Div: operator.truediv, ast.Pow: operator.pow, ast.Mod: operator.mod,
    ast.FloorDiv: operator.floordiv, ast.USub: operator.neg, ast.UAdd: operator.pos,
}


def _safe_eval(node):
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float)):
            return node.value
        raise ValueError("non-numeric constant")
    if isinstance(node, ast.BinOp) and type(node.op) in _SAFE_OPS:
        return _SAFE_OPS[type(node.op)](_safe_eval(node.left), _safe_eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _SAFE_OPS:
        return _SAFE_OPS[type(node.op)](_safe_eval(node.operand))
    raise ValueError("unsupported expression")


def _extract_expr(text: str) -> str:
    """Wyłuskaj wyrażenie arytmetyczne ze zdania ('ile to 12 * 7?' -> '12 * 7').
    Gdy całe wejście to już czyste wyrażenie (np. '2*(3+4)') — zwróć je w całości."""
    t = (text or "").replace("×", "*").replace("÷", "/")
    # czyste wyrażenie (tylko cyfry/operatory/nawiasy/spacje) → użyj wprost (zachowuje nawiasy)
    if re.fullmatch(r"[\d.+\-*/%()\s]+", t.strip()) and re.search(r"\d", t):
        return t.strip()
    # inaczej wyłuskaj ze zdania: ciąg z operatorem między liczbami (z opcjonalnymi nawiasami)
    matches = re.findall(r"[\d.(]+(?:\s*[+\-*/%()]\s*[\d.()]+)+", t)
    if matches:
        return max(matches, key=len)
    return t


def calculate(expr: str) -> str:
    """Bezpieczny kalkulator (ast, bez eval). Liczby + - * / ** % //.
    Akceptuje też zdanie ('ile to 12*7?') — wyłuskuje wyrażenie."""
    try:
        raw = _extract_expr(expr)
        cleaned = re.sub(r"[^0-9+\-*/.()%\s]", "", raw).strip()
        if not cleaned or not re.search(r"\d", cleaned):
            return "calc: brak wyrażenia"
        tree = ast.parse(cleaned, mode="eval")
        return str(_safe_eval(tree.body))
    except Exception as e:
        return f"calc error: {e}"


@dataclass
class Tool:
    name: str
    description: str
    run: Callable[[str], str]


# wbudowane, samodzielne narzędzia (bez floty)
BUILTIN_TOOLS = [
    Tool(name="calculate",
         description="Policz wyrażenie arytmetyczne. Wejście: '2*(3+4)'. Użyj do liczb.",
         run=calculate),
]


def looks_like_math(query: str) -> bool:
    """Heurystyka: czy zapytanie to obliczenie (kieruj do calc)."""
    q = (query or "").lower()
    if re.search(r"\d\s*[\+\-\*/×÷]\s*\d", q):
        return True
    return bool(re.search(r"\b(oblicz|policz|ile to|sum of|product of|calculate|what is)\b", q)
                and re.search(r"\d", q))


class ToolBranch:
    """4. gałąź: deterministyczne narzędzia (calc, lookup-callback) gdy pasują."""

    def __init__(self, tools: Sequence[Tool] | None = None):
        self.tools = {t.name: t for t in (tools or BUILTIN_TOOLS)}

    def maybe_run(self, query: str) -> tuple[str, str] | None:
        """Zwraca (tool_name, observation) jeśli któreś narzędzie pasuje, inaczej None."""
        if "calculate" in self.tools and looks_like_math(query):
            return ("calculate", self.tools["calculate"].run(query))
        return None

    def add(self, name: str, description: str, run: Callable[[str], str]) -> "ToolBranch":
        self.tools[name] = Tool(name=name, description=description, run=run)
        return self
