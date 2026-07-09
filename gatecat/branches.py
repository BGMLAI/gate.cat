"""truthgate — repair branches: web + tools (3rd and 4th stage of the cascade).

Full product cascade (/goal mechanism, council 6/6):
    SLM(confident → stop) → cache(sim≥0.92) → WEB(snippet has answer) → TOOLS(calc/lookup) → abstain

When the gate says "model does not know" and cache did not repair, we reach for a
fresh/computable source BEFORE we let the model guess. Each branch is lightweight,
self-contained, with no dependency on the BGML fleet.

HONEST LIMITATION (Study C, measured):
  Web repairs 75-77% WHEN the snippet has the answer (W_hit), but web NOISE damages
  base-correct 57-68% — 2-3× more strongly than bad cache. That is why web is injected
  ONLY above the snippet quality threshold (snippet_score ≥ threshold). Blind web
  injection = poison. The same for tools: a bad observation is worse than none.

Web: Brave Search API by default (BRAVE_API_KEY key / param). Pluggable —
supply your own search_fn(query)->list[dict] for a different provider.
Tools: lightweight built-ins (calc safe via ast, lookup-callback). Pluggable.
"""
from __future__ import annotations

import ast
import operator
import os
import re
from dataclasses import dataclass
from typing import Any, Callable, Sequence

# --- web snippet quality threshold (Study C: below = W_noise = poison) ---
# For retrieval_score from the provider: 0.55 (measured in Study C).
WEB_SNIPPET_MIN = float(os.environ.get("TRUTHGATE_WEB_SNIPPET_MIN", "0.55"))
# Token-overlap is a coarser proxy (when the provider gives no retrieval_score) —
# different scale, lower threshold. "at least 1/4 of the question words in the snippet".
WEB_OVERLAP_MIN = float(os.environ.get("TRUTHGATE_WEB_OVERLAP_MIN", "0.25"))


# ======================================================================
# WEB (branch 3)
# ======================================================================

def _token_overlap(query: str, text: str) -> float:
    """Proxy snippet_has_gold: token-overlap query<->snippet (0..1)."""
    qt = set(re.findall(r"\w{3,}", (query or "").lower()))
    if not qt:
        return 0.0
    tt = set(re.findall(r"\w{3,}", (text or "").lower()))
    return round(len(qt & tt) / max(1, len(qt)), 4)


def best_web_snippet_score(results: Sequence[dict], query: str) -> tuple[float, bool]:
    """Highest snippet score (proxy for snippet_has_gold). Returns (score, used_retrieval_score).
    Uses retrieval_score if the provider gives it (threshold 0.55), otherwise token-overlap (threshold 0.25)."""
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
    """Brave Search API → list of {title, snippet, url}. Empty list on error."""
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
    used: bool                 # whether the snippet passed the threshold and is fit for injection
    score: float               # best snippet_score
    context: str               # concatenated context for injection (empty when used=False)
    results: list[dict]


class WebBranch:
    """3rd branch: fresh context from the web, ONLY when the snippet has the answer (quality threshold)."""

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
            # W_noise: below threshold = poison, do NOT inject
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
# TOOLS (branch 4)
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
    """Extract an arithmetic expression from a sentence ('ile to 12 * 7?' -> '12 * 7').
    When the whole input is already a clean expression (e.g. '2*(3+4)') — return it in full."""
    t = (text or "").replace("×", "*").replace("÷", "/")
    # clean expression (only digits/operators/parens/spaces) → use directly (preserves parens)
    if re.fullmatch(r"[\d.+\-*/%()\s]+", t.strip()) and re.search(r"\d", t):
        return t.strip()
    # otherwise extract from the sentence: a run with an operator between numbers (with optional parens)
    matches = re.findall(r"[\d.(]+(?:\s*[+\-*/%()]\s*[\d.()]+)+", t)
    if matches:
        return max(matches, key=len)
    return t


def calculate(expr: str) -> str:
    """Safe calculator (ast, no eval). Numbers + - * / ** % //.
    Also accepts a sentence ('ile to 12*7?') — extracts the expression."""
    try:
        raw = _extract_expr(expr)
        cleaned = re.sub(r"[^0-9+\-*/.()%\s]", "", raw).strip()
        if not cleaned or not re.search(r"\d", cleaned):
            return "calc: no expression"
        tree = ast.parse(cleaned, mode="eval")
        return str(_safe_eval(tree.body))
    except Exception as e:
        return f"calc error: {e}"


@dataclass
class Tool:
    name: str
    description: str
    run: Callable[[str], str]


# built-in, self-contained tools (no fleet)
BUILTIN_TOOLS = [
    Tool(name="calculate",
         description="Compute an arithmetic expression. Input: '2*(3+4)'. Use for numbers.",
         run=calculate),
]


def looks_like_math(query: str) -> bool:
    """Heuristic: is the query a calculation (route to calc)."""
    q = (query or "").lower()
    if re.search(r"\d\s*[\+\-\*/×÷]\s*\d", q):
        return True
    return bool(re.search(r"\b(oblicz|policz|ile to|sum of|product of|calculate|what is)\b", q)
                and re.search(r"\d", q))


class ToolBranch:
    """4th branch: deterministic tools (calc, lookup-callback) when they match."""

    def __init__(self, tools: Sequence[Tool] | None = None):
        self.tools = {t.name: t for t in (tools or BUILTIN_TOOLS)}

    def maybe_run(self, query: str) -> tuple[str, str] | None:
        """Returns (tool_name, observation) if some tool matches, otherwise None."""
        if "calculate" in self.tools and looks_like_math(query):
            return ("calculate", self.tools["calculate"].run(query))
        return None

    def add(self, name: str, description: str, run: Callable[[str], str]) -> "ToolBranch":
        self.tools[name] = Tool(name=name, description=description, run=run)
        return self
