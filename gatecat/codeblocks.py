"""codeblocks — extracting code blocks from a question/answer (for koryto-exec).

WHY: koryto-exec needs executable code. In the study, statements were placed manually
in the dataset; in a real proxy the client sends a question like "what does this code
return: ```python ...```". This parser extracts the blocks so that koryto can execute
them and compare against what the model claims.

SECURITY NOTE: this extracts code FROM INTERNET TRAFFIC. The parser itself executes
nothing — it only returns text. Execution goes through a SEALED sandbox (separate module).
Auto-extracted code is executed ONLY when the operator deliberately enables unsafe-exec.

Returns CodeBlock(lang, code, source) — source="question"|"answer".
"""
from __future__ import annotations

import re
from dataclasses import dataclass


# languages we can execute (the rest are ignored)
_KNOWN_LANGS = {
    "python": "python", "py": "python", "python3": "python",
    "javascript": "js", "js": "js", "node": "js", "nodejs": "js",
}


@dataclass
class CodeBlock:
    lang: str          # normalized: "python" | "js"
    code: str
    source: str = ""   # "question" | "answer" | ""


# ```lang\n...\n```  (fence with an optional language)
_FENCE_RE = re.compile(r"```([a-zA-Z0-9_+-]*)\n(.*?)```", re.DOTALL)


def extract_code_blocks(text: str, source: str = "") -> list[CodeBlock]:
    """Extract fenced code blocks in known languages. Unknown language → skipped.
    No fence but the whole thing looks like code → we do NOT guess (too risky); return []."""
    if not text:
        return []
    blocks: list[CodeBlock] = []
    for m in _FENCE_RE.finditer(text):
        lang_raw = (m.group(1) or "").strip().lower()
        code = m.group(2).strip("\n")
        if not code.strip():
            continue
        lang = _KNOWN_LANGS.get(lang_raw)
        if lang is None:
            # fence without a language: guess Python if it looks like Python, otherwise skip
            if lang_raw == "" and _looks_like_python(code):
                lang = "python"
            else:
                continue
        blocks.append(CodeBlock(lang=lang, code=code, source=source))
    return blocks


def _looks_like_python(code: str) -> bool:
    """Conservative heuristic: typical Python constructs. Only for a fence-without-language."""
    signals = (r"\bprint\s*\(", r"\bdef\s+\w+\s*\(", r"\bimport\s+\w+",
               r"\blambda\b", r"\bfor\s+\w+\s+in\b", r"==|!=|\bis\b")
    hits = sum(1 for s in signals if re.search(s, code))
    return hits >= 2


def to_exec_statements(code: str) -> list[str]:
    """Turn a Python block into (exec_stmts) for Koryto.verify with a context-guard:
    all lines except the last EXPRESSION as setup, the last expression to evaluate.

    Strategy (consistent with koryto_exec_python): if the last non-empty line is an
    expression (not an assignment/def/return/print) → that one is the 'final', the rest is setup.
    Otherwise the whole code is setup, and final = None (nothing to evaluate → exec returns stdout
    from print if there was one, but verify needs an expression; we return the whole thing as one setup
    + empty final → koryto_exec_python will cope when the last element is a print).
    """
    lines = [l for l in code.splitlines()]
    # find the last non-empty, non-comment line
    idx = None
    for i in range(len(lines) - 1, -1, -1):
        s = lines[i].strip()
        if s and not s.startswith("#"):
            idx = i
            break
    if idx is None:
        return []
    last = lines[idx].strip()
    # print(X) at the end → unpack X (eval(print(...)) would give None) — check BEFORE is_expression
    pm0 = re.match(r"print\s*\((.*)\)\s*$", last)
    if pm0 and pm0.group(1).strip():
        setup = [l for l in lines[:idx] if l.strip()]
        return setup + [pm0.group(1).strip()]
    # is the last line a pure EXPRESSION (candidate for eval)?
    is_expr = _is_expression(last)
    if is_expr:
        setup = [l for l in lines[:idx] if l.strip()]
        return setup + [last]
    # the last line is a statement (def/assign/...) with no extractable expression →
    # return the whole thing as setup (verify gets the last stmt and evals it; when that fails,
    # koryto_exec_python returns None = unknown — a safe lack of verdict, not an error).
    return [l for l in lines if l.strip()]


def _is_expression(line: str) -> bool:
    """Is the line an expression (candidate for eval), not a statement."""
    s = line.strip()
    if not s:
        return False
    # statements: assignment (=, but not ==), def/class/import/return/for/while/if/with/print(=
    if re.match(r"^(def |class |import |from |return |for |while |if |elif |else|with |try|except|finally|raise |assert |del |global |nonlocal |pass|break|continue|@)", s):
        return False
    # assignment: = that is not ==, !=, <=, >=
    if re.search(r"(?<![=!<>])=(?!=)", s):
        return False
    return True
