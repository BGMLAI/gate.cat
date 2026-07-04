"""codeblocks — wyłuskiwanie bloków kodu z pytania/odpowiedzi (dla koryto-exec).

PO CO: koryto-exec potrzebuje wykonywalnego kodu. W badaniu statementy były ręcznie
w datasecie; w realnym proxy klient wysyła pytanie typu "co zwraca ten kod: ```python
...```". Ten parser wyłuskuje bloki, by koryto mogło je wykonać i porównać z tym co
model twierdzi.

UWAGA BEZPIECZEŃSTWA: to wyłuskuje kod Z RUCHU INTERNETOWEGO. Sam parser nic nie
wykonuje — tylko zwraca tekst. Wykonanie idzie przez SZCZELNY sandbox (osobny moduł).
Auto-wyłuskany kod jest wykonywany TYLKO gdy operator świadomie włączy unsafe-exec.

Zwraca CodeBlock(lang, code, source) — source="question"|"answer".
"""
from __future__ import annotations

import re
from dataclasses import dataclass


# języki które umiemy wykonać (reszta ignorowana)
_KNOWN_LANGS = {
    "python": "python", "py": "python", "python3": "python",
    "javascript": "js", "js": "js", "node": "js", "nodejs": "js",
}


@dataclass
class CodeBlock:
    lang: str          # znormalizowany: "python" | "js"
    code: str
    source: str = ""   # "question" | "answer" | ""


# ```lang\n...\n```  (fence z opcjonalnym językiem)
_FENCE_RE = re.compile(r"```([a-zA-Z0-9_+-]*)\n(.*?)```", re.DOTALL)


def extract_code_blocks(text: str, source: str = "") -> list[CodeBlock]:
    """Wyłuskaj fenced code blocks ze znanych języków. Nieznany język → pominięty.
    Bez fence ale całość wygląda na kod → NIE zgadujemy (zbyt ryzykowne); zwracamy []."""
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
            # fence bez języka: zgadnij Python jeśli wygląda na Python, inaczej pomiń
            if lang_raw == "" and _looks_like_python(code):
                lang = "python"
            else:
                continue
        blocks.append(CodeBlock(lang=lang, code=code, source=source))
    return blocks


def _looks_like_python(code: str) -> bool:
    """Konserwatywna heurystyka: typowe konstrukcje Pythona. Tylko dla fence-bez-języka."""
    signals = (r"\bprint\s*\(", r"\bdef\s+\w+\s*\(", r"\bimport\s+\w+",
               r"\blambda\b", r"\bfor\s+\w+\s+in\b", r"==|!=|\bis\b")
    hits = sum(1 for s in signals if re.search(s, code))
    return hits >= 2


def to_exec_statements(code: str) -> list[str]:
    """Z bloku Python zrób (exec_stmts) dla Koryto.verify z context-guard:
    wszystkie linie poza ostatnim WYRAŻENIEM jako setup, ostatnie wyrażenie do oceny.

    Strategia (zgodna z koryto_exec_python): jeśli ostatnia niepusta linia jest
    wyrażeniem (nie przypisaniem/def/return/print) → to ona jest 'final', reszta setup.
    Inaczej cały kod to setup, a final = None (brak czego oceniać → exec zwróci stdout
    z print jeśli był, ale verify potrzebuje wyrażenia; zwracamy całość jako jeden setup
    + pusty final → koryto_exec_python sobie poradzi gdy ostatni element to print).
    """
    lines = [l for l in code.splitlines()]
    # znajdź ostatnią niepustą, nie-komentarzową linię
    idx = None
    for i in range(len(lines) - 1, -1, -1):
        s = lines[i].strip()
        if s and not s.startswith("#"):
            idx = i
            break
    if idx is None:
        return []
    last = lines[idx].strip()
    # print(X) na końcu → rozpakuj X (eval(print(...)) dałby None) — sprawdź PRZED is_expression
    pm0 = re.match(r"print\s*\((.*)\)\s*$", last)
    if pm0 and pm0.group(1).strip():
        setup = [l for l in lines[:idx] if l.strip()]
        return setup + [pm0.group(1).strip()]
    # czy ostatnia linia to czyste WYRAŻENIE (kandydat do eval)?
    is_expr = _is_expression(last)
    if is_expr:
        setup = [l for l in lines[:idx] if l.strip()]
        return setup + [last]
    # ostatnia linia to statement (def/assign/...) bez wyłuskiwalnego wyrażenia →
    # zwróć całość jako setup (verify dostanie ostatni stmt i eval go; gdy się nie uda,
    # koryto_exec_python zwróci None = unknown — bezpieczny brak werdyktu, nie błąd).
    return [l for l in lines if l.strip()]


def _is_expression(line: str) -> bool:
    """Czy linia to wyrażenie (kandydat do eval), nie statement."""
    s = line.strip()
    if not s:
        return False
    # statementy: przypisanie (=, ale nie ==), def/class/import/return/for/while/if/with/print(=
    if re.match(r"^(def |class |import |from |return |for |while |if |elif |else|with |try|except|finally|raise |assert |del |global |nonlocal |pass|break|continue|@)", s):
        return False
    # przypisanie: = które nie jest ==, !=, <=, >=
    if re.search(r"(?<![=!<>])=(?!=)", s):
        return False
    return True
