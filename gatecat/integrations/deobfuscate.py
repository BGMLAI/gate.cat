"""De-obfuscation normalizer (Layer 1).

Adversarial actors hide a dangerous command behind cheap shell tricks so the
literal never matches a deny-regex: they split a word with empty quotes
(``a"z"`` -> ``az``), stash the verb in a variable (``H=helm; $H uninstall``),
build it with ``$(printf ...)`` / ``$(command -v X)``, ANSI-C-quote the bytes
(``$'\\x44ROP'`` -> ``DROP``), base64-encode it, alias it, or concat PowerShell
strings (``('Remove'+'-Item')``). None of these change what actually runs - they
only change the *spelling* the gate sees.

:func:`deobfuscate` takes the raw action and returns a small list of *variants*:
the original ALWAYS first, then carefully normalized spellings that peel one
obfuscation layer at a time. The caller (``guard.check_action``) runs EACH
variant through the same policy walls and takes the strictest verdict - so a
normalizer can only ADD a catch on an obfuscated input, never remove one.

Design contract (why this is fail-safe):
  * Pure function, no I/O, no ``eval``/``exec``, no subprocess. It only pattern-
    matches and substitutes LITERALS. It never *runs* anything (a ``$(printf)``
    is decoded from its literal argument, not by executing printf).
  * Every step is bounded (input length caps, iteration caps) so a crafted
    input cannot make it loop or backtrack forever - a normalizer that hangs
    would be a DoS of the guard itself.
  * A step that cannot confidently decode does nothing (returns the text
    unchanged for that layer). Worst case is "failed to add a catch", never
    "opened a bypass": the original variant is always evaluated on its own.
  * The result is DENY-MATCHING FODDER, not a runnable command. Joining a split
    token or substituting a var may produce text that would not run verbatim;
    that is fine - we only need the dangerous verb+resource to become visible to
    the regex walls.

ASCII only in any print/log path (cp1252 consoles). Comments explain jargon in
plain terms where a non-programmer maintainer would trip.
"""

from __future__ import annotations

import base64 as _b64
import re

# ---- global safety caps -------------------------------------------------
# Do not normalize absurdly long inputs (a giant paste is not a hand-crafted
# obfuscation and running the substitution passes over it wastes time). The
# raw action still hits the walls unchanged via the always-present original.
_MAX_INPUT = 4096
# Cap on how many distinct variants we hand back (keeps the caller's extra
# evaluate() passes bounded regardless of how many layers stack).
_MAX_VARIANTS = 24


def _cap(variants: "list[str]") -> "list[str]":
    """De-dupe preserving order and cap the count. The original (index 0) is
    always kept."""
    seen: set[str] = set()
    out: list[str] = []
    for v in variants:
        if v is None:
            continue
        v = v[:_MAX_INPUT]
        if v in seen:
            continue
        seen.add(v)
        out.append(v)
        if len(out) >= _MAX_VARIANTS:
            break
    return out


# ==========================================================================
# Step 1: ANSI-C quoting  $'...\xNN...\NNN...'  ->  decoded literal
# ==========================================================================
# Bash ``$'...'`` interprets backslash escapes: ``$'\x44ROP'`` is the bytes
# ``DROP``. An attacker uses it to spell ``DROP``/``rm``/``dd`` so the literal
# letters never appear. We decode the WELL-KNOWN escapes to their character and
# leave the quotes off (the decoded text is what the shell would run).
_ANSI_C = re.compile(r"\$'((?:\\.|[^'\\])*)'")

# Recognized escapes inside $'...'. Anything else is left as-is (conservative).
_ANSI_ESCAPES = {
    "\\n": "\n", "\\t": "\t", "\\r": "\r", "\\\\": "\\",
    "\\'": "'", '\\"': '"', "\\a": "\a", "\\b": "\b",
    "\\f": "\f", "\\v": "\v", "\\e": "\x1b", "\\0": "\x00",
}
_ANSI_HEX = re.compile(r"\\x([0-9A-Fa-f]{1,2})")
_ANSI_OCT = re.compile(r"\\([0-7]{1,3})")
_ANSI_UNI = re.compile(r"\\u([0-9A-Fa-f]{1,4})|\\U([0-9A-Fa-f]{1,8})")


def _decode_ansi_c_body(body: str) -> str:
    def _hex(m: "re.Match") -> str:
        try:
            return chr(int(m.group(1), 16))
        except ValueError:
            return m.group(0)

    def _oct(m: "re.Match") -> str:
        try:
            return chr(int(m.group(1), 8))
        except ValueError:
            return m.group(0)

    def _uni(m: "re.Match") -> str:
        g = m.group(1) or m.group(2)
        try:
            return chr(int(g, 16))
        except (ValueError, OverflowError):
            return m.group(0)

    s = _ANSI_HEX.sub(_hex, body)
    s = _ANSI_UNI.sub(_uni, s)
    s = _ANSI_OCT.sub(_oct, s)
    for esc, rep in _ANSI_ESCAPES.items():
        s = s.replace(esc, rep)
    return s


def _step_ansi_c(action: str) -> str:
    if "$'" not in action:
        return action
    def _repl(m: "re.Match") -> str:
        return _decode_ansi_c_body(m.group(1))
    return _ANSI_C.sub(_repl, action)


# ==========================================================================
# Step 2: token-splitting quotes  a"z" / o''f= / --"force"  ->  az / of= / --force
# ==========================================================================
# The shell glues adjacent quoted/unquoted fragments with NO space:
# ``a"z"`` is the single word ``az``; ``o''f=`` is ``of=``. An attacker uses
# it to break up ``dd``/``of=``/``yes`` etc.
#
# We work on BALANCED quote pairs (open quote ... matching close quote of the
# same kind). A pair is a WORD-SPLITTER - and only then are its two quotes
# removed - when ALL of:
#   * the content between the quotes contains NO whitespace, AND
#   * the pair is fused to a bare word with no space on at least one side
#     (a word char touches the open quote on the left, OR touches the close
#     quote on the right).
# A real quoted argument (``"s3 rb"``, ``"$DATABASE_URL"``, a value with a
# space, or a standalone token surrounded by spaces) is NEVER stripped, so we
# can only glue split words, never unbalance a legitimately quoted string.
# ``left`` char is treated as fused only when it is an actual word char and NOT
# ``=`` (so ``VAR="value"`` keeps its quotes - it is a normal quoted assignment,
# handled by the var step instead).
_LEFT_FUSE = re.compile(r"[A-Za-z0-9_./:+-]")   # a word char to the LEFT (no '=')
_RIGHT_FUSE = re.compile(r"[A-Za-z0-9_./:+=-]")  # a word char to the RIGHT ('=' ok: o'f'= )
# A standalone quoted token that is a plain shell "word" (a command name, flag,
# path, or URL - no spaces, no shell metacharacters). ``"docker"``/``'DELETE'``/
# ``"/usr/sbin/rabbitmqctl"`` mean exactly the same as the bare word to the
# shell, so stripping the quotes only reveals the verb to the walls - it can
# never merge two separate arguments (they are still space-separated).
_BARE_WORD = re.compile(r"^[A-Za-z0-9_./:@=+-]+$")


def _step_unsplit_quotes(action: str) -> str:
    if "'" not in action and '"' not in action:
        return action
    out: list[str] = []
    i = 0
    n = len(action)
    while i < n:
        ch = action[i]
        if ch in "'\"":
            # find the matching close quote of the same kind
            k = action.find(ch, i + 1)
            if k == -1:
                # unbalanced quote: keep the rest verbatim (never guess)
                out.append(action[i:])
                break
            content = action[i + 1:k]
            prev_c = action[i - 1] if i > 0 else ""
            next_c = action[k + 1] if k + 1 < n else ""
            left_fused = bool(_LEFT_FUSE.match(prev_c or ""))
            right_fused = bool(_RIGHT_FUSE.match(next_c or ""))
            no_space = (" " not in content) and ("\t" not in content)
            if no_space and (left_fused or right_fused):
                # word-splitter: drop the two quotes, keep the content fused
                out.append(content)
                i = k + 1
                continue
            # standalone quoted plain word (space/edge on both sides): a quoted
            # command name/flag/path/url. Strip the quotes - equivalent to the
            # shell, and it uncovers the verb. Never done for content with spaces
            # or shell metacharacters (those stay a real quoted string).
            if no_space and not left_fused and not right_fused and _BARE_WORD.match(content):
                out.append(content)
                i = k + 1
                continue
            # real quoted string: keep quotes + content verbatim
            out.append(action[i:k + 1])
            i = k + 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


# ==========================================================================
# Step 3: leading variable assignments  VAR=value; ... $VAR / ${VAR} / ${VAR:-d}
# ==========================================================================
# ``H=helm; N=prod; $H uninstall ... -n $N`` stashes the verb in a variable so
# the literal ``helm`` is not adjacent to ``uninstall``. We parse the leading
# ``NAME=value`` assignments (separated by ``;`` or whitespace, possibly several)
# and substitute their expansions later in the SAME line. Values are limited to
# simple constants (no command substitution here - step 4 handles $(...)).
_ASSIGN = re.compile(
    r"""^\s*
        (?:(?:export|env)\s+)?          # optional leading export/env
        (?P<name>[A-Za-z_][A-Za-z0-9_]*)=
        (?P<val>
            \$'(?:\\.|[^'\\])*'         # $'ANSI-C quoted' (may contain spaces)
          | '(?:[^'])*'                 # 'single quoted' (may contain spaces)
          | "(?:[^"\\]|\\.)*"           # "double quoted" (may contain spaces)
          | [^\s;|&]*                   # bare word (no spaces/operators)
        )
        \s*(?:;|\s)\s*                  # terminator: ; or whitespace
    """,
    re.VERBOSE,
)


def _unquote(v: str) -> str:
    # $'...' -> ANSI-C decoded content
    if v.startswith("$'") and v.endswith("'") and len(v) >= 3:
        return _decode_ansi_c_body(v[2:-1])
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        return v[1:-1]
    return v


def _parse_leading_assignments(action: str) -> "tuple[dict[str, str], str]":
    """Peel leading NAME=value assignments off the front. Returns (env, rest).
    Bounded to a small number of assignments."""
    env: dict[str, str] = {}
    rest = action
    for _ in range(12):  # cap: no shell prefixes 12 vars in a real attack line
        m = _ASSIGN.match(rest)
        if not m:
            break
        name = m.group("name")
        val = _unquote(m.group("val"))
        # only accept simple constant values (no nested $() / backticks here)
        if "$(" in val or "`" in val:
            break
        env[name] = val
        rest = rest[m.end():]
    return env, rest


# $VAR, ${VAR}, ${VAR:-default}, ${VAR:+word}, ${VAR:=default}
_VARREF = re.compile(
    r"\$(?:\{(?P<br>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?::(?P<op>[-+=])(?P<word>[^}]*))?\}"
    r"|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))"
)


def _substitute_vars(text: str, env: "dict[str, str]") -> str:
    def _repl(m: "re.Match") -> str:
        name = m.group("br") or m.group("plain")
        if name is None:
            return m.group(0)
        set_ = name in env
        val = env.get(name, "")
        op = m.group("op")
        if op is None:
            # bare $VAR / ${VAR}: substitute if known, else leave literal
            return val if set_ else m.group(0)
        word = m.group("word") or ""
        if op == "-":            # ${VAR:-word}: VAR if set(&non-empty) else word
            return val if (set_ and val != "") else word
        if op == "=":            # ${VAR:=word}: same value semantics for us
            return val if (set_ and val != "") else word
        if op == "+":            # ${VAR:+word}: word if set(&non-empty) else ""
            return word if (set_ and val != "") else ""
        return m.group(0)
    # a bounded few passes: a ${VAR:+word} expansion can itself contain another
    # $VAR (``${DISK:+mkfs -F "$DISK"}`` -> ``mkfs -F "$DISK"`` -> resolve $DISK).
    for _ in range(4):
        new = _VARREF.sub(_repl, text)
        if new == text:
            break
        text = new
    return text


def _step_var_indirection(action: str) -> str:
    env, rest = _parse_leading_assignments(action)
    if not env:
        return action
    # substitute in the remainder; keep it bounded (single pass is enough for the
    # flat VAR=value forms in scope - no recursive expansion of a var into a var).
    return _substitute_vars(rest, env)


# ==========================================================================
# Step 4: literal command substitution  $(printf ...) / $(command -v X) / $(which X)
# ==========================================================================
# ``$(printf 'gclo%s' 'ud')`` builds ``gcloud`` at runtime; ``$(command -v git)``
# and ``$(which git)`` resolve to the path of ``git`` (we substitute the bare
# tool name, which is what matters to the walls). We ONLY handle these literal,
# side-effect-free forms - we never execute anything.
_CMDSUB = re.compile(r"\$\(\s*([^()]*?)\s*\)")
_PRINTF = re.compile(r"^printf\s+(.*)$", re.DOTALL)
_COMMAND_V = re.compile(r"^command\s+-v\s+(\S+)$")
_WHICH = re.compile(r"^(?:which|type\s+-P)\s+(\S+)$")


def _printf_literal(argstr: str) -> "str | None":
    """Reduce a printf arg list to its literal output for the SIMPLE cases:
    a single format string, or a ``%s`` format with string args substituted in
    order. Returns None if it is not a simple, decodable form."""
    # tokenize the args honoring single/double quotes (no shell exec)
    toks = _split_shell_words(argstr)
    if not toks:
        return None
    fmt = toks[0]
    args = toks[1:]
    # decode ANSI-C-ish escapes that printf interprets in the FORMAT string
    fmt = _decode_printf_escapes(fmt)
    if "%" not in fmt:
        # plain format string, no conversions: literal is the format itself
        # (ignore any stray extra args)
        return fmt
    # only handle %s (and %%). Replace each %s with the next arg in order.
    out: list[str] = []
    ai = 0
    i = 0
    while i < len(fmt):
        c = fmt[i]
        if c == "%" and i + 1 < len(fmt):
            nxt = fmt[i + 1]
            if nxt == "%":
                out.append("%")
                i += 2
                continue
            if nxt == "s":
                out.append(args[ai] if ai < len(args) else "")
                ai += 1
                i += 2
                continue
            # any other conversion (%d, %x, width specs) -> too complex, bail
            return None
        out.append(c)
        i += 1
    return "".join(out)


def _decode_printf_escapes(s: str) -> str:
    # printf interprets \xNN, \NNN(octal), \n\t etc. in the format string.
    s = _ANSI_HEX.sub(lambda m: chr(int(m.group(1), 16)) if m.group(1) else m.group(0), s)
    s = _ANSI_OCT.sub(lambda m: chr(int(m.group(1), 8)), s)
    for esc, rep in _ANSI_ESCAPES.items():
        s = s.replace(esc, rep)
    return s


def _split_shell_words(s: str) -> "list[str]":
    """Minimal shell-word splitter honoring '...' and "..." (no expansion, no
    exec). Adjacent quoted fragments glue (``'produc''tion'`` -> ``production``)."""
    words: list[str] = []
    cur: list[str] = []
    i = 0
    n = len(s)
    in_word = False
    while i < n:
        c = s[i]
        if c.isspace():
            if in_word:
                words.append("".join(cur))
                cur = []
                in_word = False
            i += 1
            continue
        in_word = True
        if c in "'\"":
            q = c
            i += 1
            buf: list[str] = []
            while i < n and s[i] != q:
                if q == '"' and s[i] == "\\" and i + 1 < n:
                    buf.append(s[i + 1])
                    i += 2
                    continue
                buf.append(s[i])
                i += 1
            i += 1  # skip closing quote (if unbalanced, we just stop at EOS)
            cur.append("".join(buf))
            continue
        cur.append(c)
        i += 1
    if in_word:
        words.append("".join(cur))
    return words


def _reduce_cmdsub(inner: str) -> "str | None":
    inner = inner.strip()
    m = _PRINTF.match(inner)
    if m:
        return _printf_literal(m.group(1))
    m = _COMMAND_V.match(inner)
    if m:
        return m.group(1)
    m = _WHICH.match(inner)
    if m:
        return m.group(1)
    return None


def _step_cmdsub(action: str) -> str:
    if "$(" not in action:
        return action
    # iterate a few times so a substitution nested one level (rare) resolves
    text = action
    for _ in range(4):
        changed = False

        def _repl(m: "re.Match") -> str:
            nonlocal changed
            red = _reduce_cmdsub(m.group(1))
            if red is None:
                return m.group(0)
            changed = True
            return red

        new = _CMDSUB.sub(_repl, text)
        if not changed or new == text:
            text = new
            break
        text = new
    return text


# ==========================================================================
# Step 5: alias name=target; ... name ...  ->  substitute target for name
# ==========================================================================
# ``alias q=cryptsetup; q luksErase ...`` renames the dangerous tool. We read
# ``alias NAME=TARGET`` definitions and replace a STANDALONE later use of NAME
# with TARGET (word-boundary, so we don't rewrite substrings).
_ALIAS_DEF = re.compile(
    r"\balias\s+([A-Za-z_][A-Za-z0-9_]*)="
    r"('(?:[^']*)'|\"(?:[^\"\\]|\\.)*\"|[^\s;|&]+)"
)


def _step_alias(action: str) -> str:
    if "alias " not in action:
        return action
    defs: dict[str, str] = {}
    for m in _ALIAS_DEF.finditer(action):
        name = m.group(1)
        target = _unquote(m.group(2))
        if target and "$(" not in target and "`" not in target:
            defs[name] = target
    if not defs:
        return action
    text = action
    for name, target in defs.items():
        # replace standalone `name` used as a command word; keep it conservative:
        # bounded by non-word chars, and NOT inside the alias definition itself
        # (that gets removed below anyway). Regex-escape the name.
        text = re.sub(rf"(?<![\w.-]){re.escape(name)}(?![\w.=-])", target, text)
    return text


# ==========================================================================
# Step 6: base64 decode  echo 'B64' | base64 -d  ->  decoded plaintext
# ==========================================================================
# ``echo 'RFJP...' | base64 -d | mysql`` hides ``DROP DATABASE ...`` inside a
# base64 blob. We decode the LITERAL base64 argument (only when it is a quoted or
# bare literal being fed to ``base64 -d``/``--decode``) and expose the plaintext,
# so the DB/rm/etc. verb becomes visible. We never decode a $VAR or a file.
_ECHO_B64 = re.compile(
    r"(?:echo|printf)\s+(?:-[A-Za-z]+\s+)*"
    r"(?P<q>['\"]?)(?P<data>[A-Za-z0-9+/=\s]+?)(?P=q)"
    r"\s*\|\s*base64\s+(?:-d\b|--decode\b|-D\b)"
)


def _step_base64(action: str) -> str:
    if "base64" not in action:
        return action
    def _repl(m: "re.Match") -> str:
        raw = m.group("data").strip()
        compact = re.sub(r"\s+", "", raw)
        if len(compact) < 8 or len(compact) % 4 != 0:
            return m.group(0)
        try:
            dec = _b64.b64decode(compact, validate=True)
        except Exception:
            return m.group(0)
        try:
            txt = dec.decode("utf-8", "strict")
        except UnicodeDecodeError:
            return m.group(0)
        if not txt.isprintable() and not any(c in txt for c in "\n\t "):
            return m.group(0)
        # replace the whole "echo B64 | base64 -d" with the decoded plaintext, so
        # a following "| mysql" still trails it and the verb is visible.
        return " " + txt + " "
    return _ECHO_B64.sub(_repl, action)


# ==========================================================================
# Step 7: PowerShell string concat + gcm alias
# ==========================================================================
# ``('Remove'+'-Item')`` builds the cmdlet name ``Remove-Item`` at runtime;
# ``gcm`` is the alias for ``Get-Command``. We join adjacent quoted string
# literals separated by ``+`` inside parentheses.
_PS_CONCAT = re.compile(
    r"\(\s*((?:'[^']*'|\"[^\"]*\")(?:\s*\+\s*(?:'[^']*'|\"[^\"]*\"))+)\s*\)"
)


def _step_powershell(action: str) -> str:
    text = action
    if "+" in text and ("'" in text or '"' in text):
        def _repl(m: "re.Match") -> str:
            parts = re.findall(r"'([^']*)'|\"([^\"]*)\"", m.group(1))
            joined = "".join(a or b for a, b in parts)
            return joined
        text = _PS_CONCAT.sub(_repl, text)
    return text


# ==========================================================================
# public entry point
# ==========================================================================
# Two step orders, because obfuscations nest in either direction:
#   order A peels VARIABLES/ALIAS/CMDSUB first (so a var whose value is an
#           ANSI-C literal - ``M=$'\\x44ROP...'`` - is substituted whole, its
#           value decoded by _unquote), THEN the byte-level tricks.
#   order B peels the byte-level tricks first (ANSI-C, split-quotes) so a
#           STANDALONE ``$'DROP\\x20SCHEMA'`` or ``d''d`` is decoded before the
#           command is read.
# Every produced form is a variant; the caller takes the strictest verdict, so
# running both orders can only ADD catches.
# _step_powershell runs BEFORE _step_unsplit_quotes: the string-concat cmdlet
# build ``('Remove'+'-Item')`` needs its quotes intact to be recognized (once
# unsplit strips them it becomes ``Remove+-Item`` and the concat is lost).
def _step_strip_word_backslash(action: str) -> str:
    """Bare-word backslash escapes: unquoted ``d\\d``, ``r\\b``, ``p\\ush``,
    ``des\\troy`` are the shell words ``dd``, ``rb``, ``push``, ``destroy`` (an
    unquoted ``\\X`` is just ``X`` to the shell). Strip a backslash that is
    OUTSIDE quotes and immediately precedes an ALPHANUMERIC, revealing the real
    verb to the walls. Quoted content and ``\\<newline>`` continuations are left
    intact. Variant-only: the original is always evaluated too, so this can only
    ADD a catch on an obfuscated token, never mangle a legitimate command into a
    false block."""
    if "\\" not in action:
        return action
    out: list[str] = []
    i, n = 0, len(action)
    quote: "str | None" = None
    changed = False
    while i < n:
        c = action[i]
        if quote:
            out.append(c)
            if c == quote:
                quote = None
            i += 1
            continue
        if c in "'\"":
            quote = c
            out.append(c)
            i += 1
            continue
        if c == "\\" and i + 1 < n and action[i + 1].isalnum():
            out.append(action[i + 1])
            changed = True
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out) if changed else action


_ORDER_A = (
    _step_var_indirection, _step_alias, _step_cmdsub,
    _step_ansi_c, _step_powershell, _step_unsplit_quotes,
    _step_strip_word_backslash, _step_base64,
)
_ORDER_B = (
    _step_ansi_c, _step_powershell, _step_unsplit_quotes, _step_strip_word_backslash,
    _step_var_indirection, _step_cmdsub, _step_alias, _step_base64,
)


def _run_pipeline(action: str, steps) -> "list[str]":
    """Apply *steps* in order, appending every intermediate that changed."""
    out: list[str] = []
    cur = action
    for step in steps:
        try:
            nxt = step(cur)
        except Exception:
            nxt = cur
        if nxt != cur:
            out.append(nxt)
            cur = nxt
    return out


def deobfuscate(action: str) -> "list[str]":
    """Return de-obfuscation variants of *action* (original ALWAYS first).

    Fail-safe: any step that raises is skipped; the original is always present,
    so a normalizer bug can only fail to add a catch, never remove one. Pure /
    bounded / no exec - see module docstring.
    """
    if not action:
        return [action]
    variants: list[str] = [action]
    if len(action) > _MAX_INPUT:
        return variants  # too big to normalize; raw variant still evaluated

    for order in (_ORDER_A, _ORDER_B):
        produced = _run_pipeline(action, order)
        variants.extend(produced)
        # one extra full pass over each order's fully-reduced form catches a
        # layer only visible after an earlier peel (bounded: single re-pass).
        if produced:
            reduced = produced[-1]
            repass = _run_pipeline(reduced, order)
            if repass:
                variants.append(repass[-1])

    return _cap(variants)
