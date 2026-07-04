"""Testy wyłuskiwania bloków kodu (dla koryto-exec z ruchu)."""
from cacheback.codeblocks import extract_code_blocks, to_exec_statements, CodeBlock


# ---- extract_code_blocks ----

def test_python_fence():
    text = "Co zwraca ten kod?\n```python\nx = 1 + 1\nx\n```"
    blocks = extract_code_blocks(text, source="question")
    assert len(blocks) == 1
    assert blocks[0].lang == "python"
    assert blocks[0].source == "question"
    assert "1 + 1" in blocks[0].code


def test_js_fence():
    blocks = extract_code_blocks("```js\nconsole.log([]==![])\n```")
    assert len(blocks) == 1
    assert blocks[0].lang == "js"


def test_lang_aliases():
    assert extract_code_blocks("```py\nprint(1)\n```")[0].lang == "python"
    assert extract_code_blocks("```node\nconsole.log(1)\n```")[0].lang == "js"


def test_unknown_lang_skipped():
    assert extract_code_blocks("```rust\nfn main(){}\n```") == []
    assert extract_code_blocks("```bash\nrm -rf /\n```") == []   # NIE wykonujemy basha


def test_fence_no_lang_python_heuristic():
    """Fence bez języka, ale wygląda na Python → wyłuskany."""
    code = "```\ndef f(x):\n    return x\nfor i in range(3):\n    print(i)\n```"
    blocks = extract_code_blocks(code)
    assert len(blocks) == 1 and blocks[0].lang == "python"


def test_fence_no_lang_ambiguous_skipped():
    """Fence bez języka, niejednoznaczny (proza/dane) → pominięty (nie zgadujemy)."""
    assert extract_code_blocks("```\nLorem ipsum dolor sit\n```") == []


def test_multiple_blocks():
    text = "```python\na=1\na\n```\ni drugi\n```python\nb=2\nb\n```"
    blocks = extract_code_blocks(text)
    assert len(blocks) == 2


def test_empty_and_none():
    assert extract_code_blocks("") == []
    assert extract_code_blocks(None) == []
    assert extract_code_blocks("zwykły tekst bez kodu") == []


# ---- to_exec_statements ----

def test_stmts_last_line_expression():
    """Ostatnia linia to wyrażenie → setup + final."""
    stmts = to_exec_statements("fns=[lambda: i for i in range(3)]\n[g() for g in fns]")
    assert stmts == ["fns=[lambda: i for i in range(3)]", "[g() for g in fns]"]


def test_stmts_print_unwrapped():
    """Ostatnia linia to print(X) → wyłuskaj X jako wyrażenie do oceny."""
    stmts = to_exec_statements("x = 2 + 3\nprint(x * 2)")
    assert stmts[-1] == "x * 2"
    assert "x = 2 + 3" in stmts


def test_stmts_assignment_only():
    """Sam setup bez końcowego wyrażenia → zwróć całość (verify dostanie ostatni stmt)."""
    stmts = to_exec_statements("a = 1\nb = 2")
    assert stmts == ["a = 1", "b = 2"]


def test_stmts_skips_comments():
    stmts = to_exec_statements("x = 5\n# komentarz\nx + 1")
    assert stmts[-1] == "x + 1"


def test_stmts_empty():
    assert to_exec_statements("") == []
    assert to_exec_statements("# tylko komentarz") == []
