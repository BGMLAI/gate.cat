"""Phase-1 action classifier: target-anchored delete veto (replaces grep-on-text).

Why this module exists
----------------------
The regex deny-list (``policies.RM_RF``) measured a 92.1% false-block rate on
14,717 real agent commands (dogfood, 2026-07-04): it fired on ``rm -rf dist.new``
and every other regenerable build/temp path. Two independent councils + an
adversarial red-team converged on the same root cause and fix:

  ROOT CAUSE  the wall greps TEXT but the product sells action-veto. A text
              matcher cannot tell ``rm -rf dist`` (regenerable) from
              ``rm -rf ~/backup`` (irreplaceable), and is trivially bypassed by
              ``sudo rm``, ``/bin/rm``, ``xargs rm``, ``find -delete``, heredoc,
              ``$()`` and ``bash -c``.

  FIX         classify the TARGET, not the command shape. A deletion is BLOCKED
              when its resolved target lands under a PROTECTED root (home, /root,
              /etc, /opt, prod DB, backups, remote hosts, paid infra) REGARDLESS
              of the verb or wrapper. A deletion is ALLOWED only on positive
              proof of containment-in-a-regenerable-location (build/temp/cache).
              Anything the analyzer genuinely CANNOT SEE - a remote ssh target,
              an opaque ``$()``/``| sh`` target, an unresolved ``$VAR`` - is
              WARN (unchecked): logged and surfaced, but not hard-blocked.
              Three states, not two: block / warn / allow.

  D-narrow    when the harness passes the real ``env`` (the hook resolves it
              from ``os.environ``), ``$VAR`` in a target is resolved BY VALUE
              first, turning most "unresolved $VAR" WARNs into a real block/allow
              on the resolved path. Only a var absent from env stays a WARN.

Honest line (mechanical, not marketing): the gate is certain only about what it
BLOCKS. Every ALLOW here is a proof that the target is a disposable artifact
strictly inside the working tree or a temp root; every doubt is a BLOCK.

Design constraints
------------------
- stdlib only (``shlex`` for word-splitting a single segment, ``posixpath`` /
  ``ntpath`` for containment). NO bashlex/tree-sitter dependency.
- ``shlex`` is a *word splitter*, NOT a shell parser. This module NEVER trusts
  it to understand shell structure. Segment splitting, opacity detection and
  wrapper-unwrapping are done explicitly BEFORE any per-word logic, and any
  construct shlex cannot faithfully represent is treated as opaque -> BLOCK.
- ASCII-safe reasons (D1): rendered on cp1252 consoles / hook stderr.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from dataclasses import dataclass, field
from typing import Optional, Sequence

# --------------------------------------------------------------------------
# Verdict
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class DeleteVerdict:
    """Outcome of analyzing a command for irreversible-deletion risk.

    Three states (via ``level``):
      "block" -> a proven-dangerous target (protected root / declared asset).
                 The command must NOT run.
      "warn"  -> UNCHECKED: the analyzer genuinely cannot see the target
                 (remote ssh filesystem, an opaque $()/pipe-to-shell). Not
                 proven dangerous, not proven safe. The harness surfaces a
                 warning and logs it, but does NOT hard-block - hard-blocking
                 what you cannot classify both breaks the "unmatched != safe"
                 promise from the other side AND trains autopilot-approval.
      "allow" -> a proven-disposable target (build/temp/cache); safe to run.

    ``blocked`` stays True only for "block" (back-compat: callers that map a
    verdict to block/allow keep working; a "warn" is not a hard block).
    """

    level: str  # "block" | "warn" | "allow"
    reason: str
    matched: str = ""

    @property
    def blocked(self) -> bool:
        return self.level == "block"

    @property
    def is_warn(self) -> bool:
        return self.level == "warn"


def _block(reason: str, matched: str = "") -> DeleteVerdict:
    return DeleteVerdict("block", reason, matched)


def _warn(reason: str, matched: str = "") -> DeleteVerdict:
    return DeleteVerdict("warn", reason, matched)


_ALLOW = DeleteVerdict("allow", "proven-disposable target", "")


# --------------------------------------------------------------------------
# Configuration (protect-list + regenerable proof)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class DeletePolicy:
    """Where deletion is allowed vs. always blocked.

    A target is ALLOWED only if it is strictly contained in one of
    ``regenerable_roots`` (the working tree, plus temp roots) AND its basename
    (or a path component) matches a regenerable-artifact pattern OR it sits
    under a temp root. Everything else - absolute paths outside those roots,
    anything under a protected root, remote targets - is BLOCKED.

    protected_roots wins over regenerable_roots: a target under both (e.g. a
    temp dir nested in $HOME) is blocked. Containment is decided on a
    normalized (``..``-collapsed) path, never on substrings.
    """

    # Absolute roots under which deletion is always blocked. Matched by path
    # containment on the normalized target. '~' expands to the caller's home.
    protected_roots: tuple[str, ...] = (
        "/", "/etc", "/root", "/opt", "/var", "/srv", "/usr", "/boot",
        "/home", "/data", "/mnt", "/media", "/lib", "/bin", "/sbin",
    )
    # Regenerable artifact basenames / path components (fnmatch-style, anchored).
    regenerable_names: tuple[str, ...] = (
        "dist", "dist2", "build", "out", "coverage", "node_modules",
        ".pnpm-store", ".cache", "__pycache__", ".pytest_cache", ".mypy_cache",
        ".next", ".astro", ".turbo", ".venv", "venv", "target", ".tox",
        ".npm-cache", "_npx", ".ruff_cache", ".gradle", ".parcel-cache",
    )
    # A path whose basename matches a TOOL-OWNED regenerable name is disposable
    # ANYWHERE (not only in-tree): these dirs are reconstructed verbatim by their
    # tool (npm install / pytest / a compiler) and their name == their content, so
    # deleting one loses nothing wherever it lives. (Distinct from suffix/marker
    # rules, which still require in-tree/temp.)
    # NOT here (under-block fix, re-review 2026-07-06): `.cache` and `.gradle`.
    # Their name is a CONVENTION, not a content guarantee - `~/.cache` holds
    # arbitrary XDG cache (HF tokens, gated model weights) and `~/.gradle` holds
    # gradle.properties credentials, neither regenerable. They stay in
    # `regenerable_names`, so an IN-TREE `./.cache`/`./.gradle` still ALLOWs via
    # rule 2; only the out-of-tree/home deletion now falls through to the
    # protected-root block.
    cache_names_anywhere: tuple[str, ...] = (
        "node_modules", ".pnpm-store", ".npm-cache", "__pycache__",
        ".pytest_cache", ".mypy_cache", ".ruff_cache", ".turbo",
        ".parcel-cache", "_npx",
    )
    # Regenerable suffix families (e.g. dist.new, functions.new, dist.broken).
    regenerable_suffixes: tuple[str, ...] = (
        ".new", ".broken", ".old", ".bak.tmp", ".tmp",
    )
    # Substrings that mark a directory as staging/scratch (component-anchored).
    regenerable_markers: tuple[str, ...] = (
        "-staging", "staging", "scratchpad", "scratch",
    )
    # Path COMPONENTS that mark the whole subtree as temp/scratch anywhere it
    # appears (e.g. .../AppData/Local/Temp/... on Windows, .../tmp/...). A target
    # with any of these as a path component is disposable regardless of root -
    # matched as an exact component, not a substring (so `mytemp` != `temp`).
    temp_components: tuple[str, ...] = (
        "temp", "tmp", "scratchpad", ".tmp",
    )
    # Absolute temp roots: any target strictly under these is regenerable.
    # Includes common per-OS/per-drive temp dirs seen in real agent traffic
    # (Git-Bash maps Windows drives to /c, /d, ...; agents scratch under /d/tmp).
    temp_roots: tuple[str, ...] = (
        "/tmp", "/var/tmp", "/d/tmp", "/c/tmp", "/e/tmp",
    )
    # Extra caller-declared assets that must be blocked regardless of location
    # (paid-infra ids, prod DB files, remote hosts). Matched as substrings on
    # the RAW command - these are operator-declared, high-confidence.
    protected_assets: tuple[str, ...] = ()


DEFAULT_DELETE_POLICY = DeletePolicy()


# --------------------------------------------------------------------------
# Opacity: constructs a static analyzer cannot resolve -> fail-closed BLOCK
# --------------------------------------------------------------------------

# LINE-level opacity: an executor that pulls a payload from ELSEWHERE on the
# line (a different segment, stdin, a heredoc body). These join segments, so
# they must be checked on the whole line, not per-segment - e.g.
# `printf 'rm -rf /root' | bash` hides rm in one segment and bash in another.
_OPAQUE_LINE: tuple[tuple[str, str], ...] = (
    (r"\|\s*(sh|bash|zsh|dash|ash|pwsh|powershell)\b", "pipe into a shell"),
    (r"<<-?\s*['\"]?\w+", "heredoc - body may be executed by a shell"),
    (r"\beval\s", "eval - executes a runtime-built string"),
    # xargs is opaque ONLY when it builds a DELETE command; `... | xargs kill`
    # is not our concern. `xargs rm/rmdir/shred/unlink` (with optional flags) is.
    (r"\bxargs\b(\s+-\S+)*\s+(rm|rmdir|shred|unlink|truncate)\b",
     "xargs building a delete command from stdin"),
    (r"(^|[;&|]\s*)(source|\.)\s+\S", "sourcing an external script"),
)

# SEGMENT-level opacity: the target of THIS delete is computed at runtime, so
# only the segment that actually deletes needs to be opaque-free. A `$(date)`
# in a sibling segment does not make `rm -rf dist.new` unprovable (this was the
# single biggest over-block: 68 false blocks fixed by scoping opacity per
# segment instead of per line).
_OPAQUE_SEGMENT: tuple[tuple[str, str], ...] = (
    (r"\$\(", "command substitution $(...) in the delete target"),
    (r"`", "backtick command substitution in the delete target"),
)

# Wrappers whose FIRST inner argument is itself a command string / remote body:
# their payload must be recursed into, and if we cannot, blocked.
_DASH_C_WRAPPERS = ("sh", "bash", "zsh", "dash", "ash", "pwsh", "powershell", "cmd", "env")


def _has_command_flag(verb: str, argv: "tuple[str, ...]") -> bool:
    """True if argv carries the 'run this string' flag for `verb`. POSIX shells
    use `-c`; PowerShell uses `-Command` (or any unambiguous prefix down to `-c`,
    e.g. `-Co`, `-Command`) and Windows `cmd` uses `/c` or `/k`. Matching only
    the literal `-c` let `powershell -Command "Remove-Item -Recurse"` and
    `cmd /c "del /s"` wrap a delete past the analyzer (council round-3)."""
    if verb in ("powershell", "pwsh"):
        return any(re.fullmatch(r"[-/]c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?", t.lower())
                   for t in argv)
    if verb == "cmd":
        return any(t.lower() in ("/c", "/k", "-c", "-k") for t in argv)
    return "-c" in argv
# non-shell interpreters whose `-c`/`-e` argument is SOURCE, not a shell command.
_NONSHELL_INTERP_VERB = re.compile(r"^(?:python\d?|ruby|node|perl|php|Rscript)$", re.IGNORECASE)
_REMOTE_WRAPPERS = ("ssh", "sshpass", "scp", "rsync", "docker", "kubectl")
# Prefixes that shift argv0 off the real verb (POSIX-legal, must be stripped).
_PREFIX_WRAPPERS = ("sudo", "doas", "nice", "ionice", "time", "command", "env",
                    "nohup", "stdbuf", "setsid")

# Max command length we will tokenize. Real shell commands are well under this;
# anything larger is a padding/DoS shape (a multi-MB comment crafted to make the
# superlinear tokenizer hang). Over this, a delete-intent command fails CLOSED.
_MAX_ACTION_LEN = 64 * 1024

# The heredoc-stripping regexes below use `(?P<body>.*?)\n\s*(?P=tag)` under
# DOTALL. On a large UNTERMINATED heredoc (`rm -rf ~ ; cat <<EOF` + tens of KB
# with no closing tag) the lazy body + backreference backtracks catastrophically
# (~30-100s at 50KB — under the 64KB _MAX_ACTION_LEN cap, so the earlier guard
# does not catch it). A hung analyzer past the hook timeout = the hook is killed
# = fail-OPEN on a real `rm -rf ~`. So before any heredoc strip we bound the
# input the heredoc regexes may scan; over the bound with delete intent = BLOCK
# (fail-closed, never allow), no delete intent = defer to the other walls.
_HEREDOC_STRIP_MAX = 16 * 1024

# Deletion / destruction verbs beyond `rm` that a target-anchored gate must see.
# (argv0 basename, lowercased). rm handled separately (needs recursive/force).
_DELETE_VERBS = ("rmdir", "unlink", "shred", "truncate")

# Windows-native delete verbs. gate.cat is dogfooded on Windows, where an agent
# emits PowerShell `Remove-Item -Recurse -Force <path>` / `del /s /q <path>` /
# `rd /s /q <path>` far more often than POSIX `rm`. These NEVER matched _rm_ nor
# _DELETE_VERBS, so before this they resolved to ALLOW against C:/Windows, the
# whole home, backups - the verb-agnostic promise broke on the exact OS we ship
# on (E2E audit 2026-07-05, CRITICAL false-allow). Verb basename may carry a
# `.exe`/`.ps1` suffix or a `Microsoft.PowerShell...\Remove-Item` module prefix,
# both stripped by the basename+suffix normalization in _win_verb.
_WIN_DELETE_VERBS = ("remove-item", "ri", "erase", "del", "rd", "rmdir")

# cmd flags use a leading slash (/s /q /f); PowerShell uses -Recurse/-Force/etc.
# Neither is a delete OPERAND, so _win_operands drops both forms. A bare `rd`
# without /s is still a directory delete; we classify its target regardless of
# recursion (unlike POSIX rm, a Windows delete of a protected root is dangerous
# even non-recursively for `del`, and `rd` refuses only non-empty dirs).
_WIN_FLAG = re.compile(r"^/[a-zA-Z]|^-[a-zA-Z]")


def _win_verb(verb_raw: str) -> str:
    """Normalize a Windows verb token: strip a module path prefix
    (``Microsoft.PowerShell.Management\\Remove-Item``) and an ``.exe``/``.ps1``
    suffix, lowercase. Returns '' if it is not a recognized Windows delete verb."""
    base = posixpath.basename(_to_posix(verb_raw)).lstrip("\\")
    base = re.sub(r"\.(exe|ps1|cmd|bat)$", "", base, flags=re.IGNORECASE).lower()
    return base if base in _WIN_DELETE_VERBS else ""


def _win_operands(args: Sequence[str]) -> list[str]:
    """Delete operands for a Windows verb: drop /flags (cmd) and -Flags
    (PowerShell), keep every positional path. ``-Path``/``-LiteralPath`` are
    dropped as flags but the PATH value that follows is a plain token and is
    kept. This over-includes rather than under-includes: a stray kept arg risks
    a false BLOCK (safe), never the false ALLOW this fix exists to close."""
    out: list[str] = []
    for tok in args:
        if _WIN_FLAG.match(tok) or tok == "--":
            continue
        # Windows paths use backslash separators (`.\node_modules`,
        # `sub\dir`). _normalize/_basename_regenerable reason in posix form, so a
        # lone backslash would leave `.\node_modules` un-normalized and fail the
        # disposable-name check (false BLOCK). Convert separators to '/' here;
        # a UNC/`C:\` absolute path normalizes the same way. We do NOT touch a
        # backslash that is a shell escape (those were already consumed by
        # shlex before we see the token), so this only rewrites real separators.
        out.append(tok.replace("\\", "/"))
    return out


# --------------------------------------------------------------------------
# Segment splitting (explicit, NOT via shlex - shlex eats operators/newlines)
# --------------------------------------------------------------------------

# Split a command line into top-level segments on &&, ||, ;, |, and newlines,
# while respecting single/double quotes so an operator inside a quoted string
# does not split. This is a small state machine, not a shell parser: its only
# job is to find UNQUOTED top-level separators. Anything subtler (nested $(),
# heredocs) is already caught by the opacity check, which runs first.
def split_segments(line: str) -> list[str]:
    segs: list[str] = []
    cur: list[str] = []
    i, n = 0, len(line)
    quote: Optional[str] = None
    while i < n:
        ch = line[i]
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            cur.append(ch)
            i += 1
            continue
        if ch == "\\" and i + 1 < n:  # escaped char - keep both, never a sep
            cur.append(ch)
            cur.append(line[i + 1])
            i += 2
            continue
        # unquoted `#` at a word boundary starts a shell comment: drop the rest
        # of THIS segment up to the next newline. This keeps a crafted multi-MB
        # trailing comment (`rm -rf ~ # AAAA...`) from ever reaching the O(n^2)
        # tokenizer, and matches shell semantics (the comment is not executed).
        # A `#` mid-token (a path like `foo#1`, a fragment) is NOT a comment, so
        # we require the previous emitted char to be whitespace or the segment
        # start.
        if ch == "#" and (not cur or cur[-1].isspace()):
            j = line.find("\n", i)
            if j == -1:
                break            # comment runs to end of line -> segment done
            i = j                # jump to the newline; the loop handles it as a sep
            continue
        # two-char operators
        if line[i:i + 2] in ("&&", "||"):
            segs.append("".join(cur)); cur = []
            i += 2
            continue
        if ch in (";", "|", "\n", "&"):
            segs.append("".join(cur)); cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    if quote is not None:
        # unbalanced quote - the whole line is unparseable -> caller blocks
        raise ValueError("unbalanced quote")
    segs.append("".join(cur))
    return [s.strip() for s in segs if s.strip()]


# --------------------------------------------------------------------------
# Path containment
# --------------------------------------------------------------------------

_WIN_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")


def _to_posix(p: str) -> str:
    """Normalize a path to forward-slash form for containment checks. Windows
    drive paths (C:\\...) and MSYS (/c/...) both map into a comparable space."""
    p = p.replace("\\", "/")
    m = _WIN_DRIVE.match(p.replace("/", "\\"))
    if _WIN_DRIVE.match(p) or (len(p) >= 2 and p[1] == ":"):
        # C:/Users/... -> /c/Users/... (matches MSYS + our protected roots)
        p = "/" + p[0].lower() + p[2:]
    return p


def _normalize(target: str, home: str, cwd: str) -> Optional[str]:
    """Resolve a target to a normalized absolute posix path, or None if it
    cannot be resolved with certainty (unexpanded var, glob, etc.)."""
    t = target.strip().strip('"').strip("'")
    if not t:
        return None
    # tilde -> home
    if t == "~" or t.startswith("~/"):
        t = home.rstrip("/") + t[1:]
    t = _to_posix(t)
    home_p = _to_posix(home)
    cwd_p = _to_posix(cwd)
    if not posixpath.isabs(t):
        t = posixpath.join(cwd_p, t)
    # collapse .. and . AFTER joining to cwd (so ../.. escapes are resolved)
    t = posixpath.normpath(t)
    return t


def _under(target: str, root: str) -> bool:
    """True if normalized ``target`` == root or is strictly inside it.

    Note: ``root == "/"`` matches ONLY the target ``/`` itself, never "any
    absolute path" - otherwise every path would count as under every protected
    root. Deleting ``/`` is caught by the exact-match; deleting ``/foo`` is
    judged by whether ``/foo`` (or an ancestor) is a *named* protected root."""
    root = posixpath.normpath(_to_posix(root))
    if target == root:
        return True
    if root == "/":
        return False  # only literal "/" is "under /"; children judged by their own root
    return target.startswith(root + "/")


def _basename_regenerable(target: str, policy: DeletePolicy) -> bool:
    """Regenerability is decided by the target's OWN basename, not by an
    ancestor. ``dist`` and ``dist.new`` are disposable; ``dist/prod-data`` is
    NOT - a real data dir living inside a build dir must not inherit the
    parent's disposability (red-team bypass 'rm -rf dist/prod-data')."""
    base = posixpath.basename(target)
    if base in policy.regenerable_names:
        return True
    if any(base.endswith(sfx) for sfx in policy.regenerable_suffixes):
        return True
    if any(mark in base for mark in policy.regenerable_markers):
        return True
    return False


# --------------------------------------------------------------------------
# Per-target classification
# --------------------------------------------------------------------------

# a token that is a flag, not a path
_FLAG = re.compile(r"^-")
# a token containing shell metacharacters we cannot resolve statically
_UNRESOLVABLE = re.compile(r"[$*?{}\[\]~]")


def _classify_target(raw_token: str, home: str, cwd: str,
                     policy: DeletePolicy) -> DeleteVerdict:
    """Decide one delete operand. Default-BLOCK; ALLOW only on proof."""
    # end-of-options marker and flags are not targets
    if raw_token == "--":
        return _ALLOW  # skip; not a path
    # unexpanded var / glob / brace / tilde-not-at-start: cannot prove -> BLOCK
    stripped = raw_token.strip('"').strip("'")
    if _UNRESOLVABLE.search(stripped) and not (stripped == "~" or stripped.startswith("~/")):
        return _block(
            f"target {stripped!r} contains an unresolved shell metachar "
            "(var/glob/brace) - cannot prove disposable, fail-closed",
            stripped,
        )
    norm = _normalize(raw_token, home, cwd)
    if norm is None:
        return _warn(f"target {raw_token!r} unresolvable (opaque) - unchecked", raw_token)

    cwd_p = posixpath.normpath(_to_posix(cwd))
    home_p = posixpath.normpath(_to_posix(home))

    # 0) CACHE dirs are regenerable ANYWHERE (a package/build cache is
    #    reconstructible wherever it lives - even under $HOME). Basename-anchored
    #    so `~/.npm-cache` allows but `~/laptop-backup` does not.
    if posixpath.basename(norm) in policy.cache_names_anywhere:
        return _ALLOW

    # 1) TEMP roots: anything strictly inside /tmp or /var/tmp is disposable.
    #    (strictly inside, not the root itself - `rm -rf /tmp` is too broad.)
    for tr in policy.temp_roots:
        tr_n = posixpath.normpath(_to_posix(tr))
        if norm != tr_n and _under(norm, tr_n):
            return _ALLOW

    # 1b) TEMP components: a target strictly under a temp/scratch path component
    #     (e.g. .../AppData/Local/Temp/... on Windows) is disposable. But a bare
    #     `tmp`/`temp` component must NOT override the protected-root/home block
    #     for an out-of-tree absolute path (under-block fix, re-review 2026-07-06):
    #     `rm -rf ~/tmp/wallet.dat`, `/root/tmp/secrets`, `.../Documents/temp/x`
    #     hold real, non-regenerable work. So require the SAME containment proof
    #     as the in-tree rule: the temp component's subtree must be either
    #       (a) a RECOGNISED SYSTEM temp path (the OS temp dir - `.../AppData/
    #           Local/Temp/...` or a declared temp_root), OR
    #       (b) strictly inside the working tree (cwd).
    #     A user-made `~/tmp` outside cwd is NOT a system temp and falls through
    #     to the protected-root block.
    comps = [c.lower() for c in norm.split("/") if c]
    for i, comp in enumerate(comps):
        if comp in policy.temp_components and i < len(comps) - 1:
            # (a) OS temp dir: ONLY the genuine ordered Windows chain
            #     `appdata/local/temp` (the three components consecutively, ending
            #     at this `temp`). A user-made `~/local/temp` or `/root/local/temp`
            #     is NOT the OS temp dir and must fall through to the protected-root
            #     block. (Re-review 2026-07-06: the earlier `"local" in window`
            #     heuristic was vacuous - the preceding `local` alone satisfied it -
            #     so `.../local/temp/...` under ANY root wrongly ALLOWed. Require
            #     the full ordered appdata/local/temp.)
            is_system_temp = (
                comp == "temp" and i >= 2
                and comps[i - 2] == "appdata" and comps[i - 1] == "local"
            )
            # (b) in-tree scratch: under cwd (the working tree's own tmp/scratch).
            in_tree = (norm != cwd_p and _under(norm, cwd_p))
            if is_system_temp or in_tree:
                return _ALLOW  # proven disposable temp subtree
            # otherwise: a bare tmp/temp component outside cwd & the OS temp dir.
            # Do NOT allow here - let the protected-root block (rule 3) decide.
            break

    # 2) IN-TREE regenerable artifact: target lives strictly inside the working
    #    tree AND is a proven build/temp/cache artifact. This is the ONLY way a
    #    path under a protected root (e.g. cwd nested in $HOME) can be allowed -
    #    it must be a named disposable artifact, never plain source.
    #    We require the target to be a *strict descendant* of cwd (not cwd
    #    itself - `rm -rf .` at cwd root is not provably disposable).
    if norm != cwd_p and _under(norm, cwd_p) and _basename_regenerable(norm, policy):
        return _ALLOW

    # 3) PROTECTED roots (incl. home): block. Checked AFTER the two allow-proofs
    #    so an in-tree build dir under $HOME still passes, but ~/laptop-backup,
    #    /root/x, /opt/x, a bare home dir, etc. are blocked.
    for root in (*policy.protected_roots, home_p):
        if _under(norm, root):
            return _block(
                f"deletes {norm!r} under protected root {root!r} - requires a human",
                norm,
            )

    # 4) Anything else absolute/out-of-tree we could not prove disposable.
    if norm != cwd_p and _under(norm, cwd_p):
        return _block(
            f"deletes {norm!r} inside the tree but not a known regenerable "
            "artifact (build/temp/cache) - fail-closed",
            norm,
        )
    return _block(
        f"deletes {norm!r} outside the working tree and temp roots - "
        "cannot prove disposable, fail-closed",
        norm,
    )


# --------------------------------------------------------------------------
# rm flag detection (recursive)
# --------------------------------------------------------------------------

_RM_RECURSIVE = re.compile(r"^-(?:-recursive$|[a-zA-Z]*[rR][a-zA-Z]*$)")


def _is_recursive_rm(tokens: Sequence[str]) -> bool:
    for tok in tokens[1:]:
        if tok == "--":
            break
        if _RM_RECURSIVE.match(tok):
            return True
    return False


# --------------------------------------------------------------------------
# Top-level entry: analyze one command line
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# Remote-body extraction: ssh host "<body>" / ssh host 'cmd' <<EOF ... EOF
# --------------------------------------------------------------------------

# `ssh [opts] host "<body>"` or `ssh [opts] host '<body>'`: the last quoted
# argument is a command string executed on the remote. We extract it and
# recurse, so a remote `rm -rf dist.new` (after `cd /var/www/site`) is judged
# by the SAME rules - a remote build-dir delete allows, a remote ~/backup or
# /root delete blocks. Depth-limited; if we cannot extract, fail-closed.
# `ssh` as a COMMAND (start of line/segment or after an operator), not as a
# path fragment - `\bssh\b` wrongly matched `rm -rf ~/.ssh` and treated it as a
# remote exec. Require ssh to be an argv0-position token.
_SSH_HOST = re.compile(r"(?:^|[;&|]|\bsudo\s+|\btimeout\s+\S+\s+)\s*(?:ssh|sshpass)\b",
                       re.IGNORECASE)


# A heredoc feeds a SHELL (its body is shell commands we analyze) vs a FILE/pager
# (inert data) vs a NON-SHELL interpreter (its body is Python/Ruby/... source,
# NOT shell commands). Only a SHELL heredoc is delete-relevant to this shell
# analyzer: `bash <<EOF\n rm -rf x \nEOF` really deletes. A `python3 <<EOF\n
# del sys.modules[m] \nEOF` does NOT - `del`/`rm` there are Python tokens, not
# shell verbs, and analyzing them as shell produced false blocks on real agent
# traffic (Nemotron corpus: `del sys.modules[...]` misread as a Windows `del`).
# A genuine `shutil.rmtree(...)` inside python is caught by the RUNTIME_DELETE
# regex wall separately, not here. So non-shell interpreter heredocs are treated
# as DATA (body stripped) exactly like a file sink.
_HEREDOC_SHELL_EXECUTORS = re.compile(
    r"\b(?:ssh|sshpass|bash|sh|zsh|dash|ash|pwsh|powershell)\b",
    re.IGNORECASE,
)
# non-shell interpreters: body is source in THAT language, not shell commands.
_HEREDOC_NONSHELL_INTERP = re.compile(
    r"\b(?:python\d?|perl|ruby|node|php|Rscript|osascript|awk)\b",
    re.IGNORECASE,
)
# kept for callers that only ask "is this an executor at all" (shell or interp):
_HEREDOC_EXECUTORS = re.compile(
    _HEREDOC_SHELL_EXECUTORS.pattern + "|" + _HEREDOC_NONSHELL_INTERP.pattern,
    re.IGNORECASE,
)
# things that consume a heredoc as DATA (write-to-file / pager / read-into-var)
_HEREDOC_DATA_SINKS = re.compile(
    r"\b(?:cat|tee|dd|read|sponge|less|more)\b|[>|]\s*\S", re.IGNORECASE,
)


def _heredoc_is_executed(action: str) -> bool:
    """Does the heredoc body get EXECUTED (fed to a shell/interpreter) or is it
    DATA (written to a file, read into a var)? Look at the command preceding the
    first ``<<TAG``. Default to executed (fail-closed) only when the preamble
    names a shell/interpreter; a pure data sink (cat>/tee) is treated as data."""
    m = re.search(r"^(.*?)<<-?\s*['\"]?\w+", action, re.DOTALL)
    preamble = m.group(1) if m else action
    # only look at the last logical command before the heredoc
    tail = re.split(r"[;&|\n]", preamble)[-1]
    # a non-shell interpreter (python/ruby/...) runs its body as source in THAT
    # language, not as shell commands -> not shell-executed (body is inert to us)
    if _HEREDOC_NONSHELL_INTERP.search(tail):
        return False
    if _HEREDOC_SHELL_EXECUTORS.search(tail):
        return True
    if _HEREDOC_DATA_SINKS.search(tail):
        return False
    # ambiguous preamble -> fail-closed treat as executed
    return True


def _strip_data_heredocs(action: str) -> str:
    """Replace the body of any DATA heredoc (written to a file/var, not executed)
    with a placeholder, so literals inside a written document/script are never
    analyzed as commands. Executed heredocs (bash<<EOF) are left untouched."""
    if "<<" not in action:
        return action

    def repl(m: "re.Match") -> str:
        preamble = m.group("pre")
        tag = m.group("tag")
        # is THIS heredoc's preamble a shell/interpreter executor, or a data
        # sink? An EXECUTED heredoc (shell OR non-shell interpreter) is kept
        # intact: a shell body may hold real `rm`, and a python/ruby body may
        # hold a real `shutil.rmtree` that the RUNTIME_DELETE regex wall must
        # still see. Only a DATA heredoc (written to a file) has its body
        # stripped. The shell-vs-python distinction is handled later, inside the
        # delete-analyzer's own segment logic, not here - so we never blind the
        # runtime-delete wall.
        last_cmd = re.split(r"[;&|\n]", preamble)[-1]
        if _HEREDOC_EXECUTORS.search(last_cmd) and not _HEREDOC_DATA_SINKS.search(last_cmd):
            return m.group(0)  # executed (shell or interpreter) -> keep intact
        # data heredoc -> keep the opening line, drop the body
        return f"{preamble}<<{tag}\n__HEREDOC_DATA__\n{tag}"

    # match: <preamble up to <<TAG> \n <body> \n TAG
    # (wrapped in try/except like the sibling strip helpers: a regex issue must
    # degrade to "return input unchanged", never raise/hang — the length cap in
    # analyze_delete already bounds catastrophic backtracking.)
    try:
        pat = re.compile(
            r"(?P<pre>[^\n]*?)<<-?\s*['\"]?(?P<tag>\w+)['\"]?\s*\n(?P<body>.*?)\n\s*(?P=tag)\s*(?=\n|$)",
            re.DOTALL,
        )
        return pat.sub(repl, action)
    except Exception:
        return action


# Python/Ruby/... runtime deletes worth keeping when we reduce an interpreter
# heredoc body: these are the ONLY tokens in interpreter source that mean a real
# file deletion. Everything else in the body (SQL-looking comments, the word
# `terraform`, a `del x` on a dict) is source, not a shell/SQL/IaC action.
_RUNTIME_DELETE_MARKERS = re.compile(
    r"shutil\.rmtree\s*\(|os\.remove\s*\(|os\.unlink\s*\(|"
    r"\.unlink\s*\(|os\.rmdir\s*\(|pathlib[^\n]*unlink|Path[^\n]*unlink|"
    # runtime SHELL-OUT lines must survive the reduction too, so the walls see a
    # `subprocess.run(['rm','-rf',...])` / `os.system("rm -rf ...")` inside a
    # heredoc (Codex round-4). Keeping a benign subprocess line is harmless - the
    # RUNTIME_DELETE wall only fires on an rm/-rf shell-out.
    r"subprocess\.\w+\s*\(|os\.system\s*\(|os\.popen\s*\(",
    re.IGNORECASE,
)


def reduce_nonshell_heredocs(action: str) -> str:
    """For the regex WALLS: replace a non-shell interpreter heredoc body with
    only the lines that carry a real runtime-delete (shutil.rmtree/os.remove/
    unlink); drop the rest. This kills false blocks from SQL-looking comments or
    the words rm/terraform/DELETE inside Python source (Nemotron corpus:
    `# delete from exif` matched the SQL DELETE wall) while keeping a genuine
    `shutil.rmtree(...)` visible to RUNTIME_DELETE. Best-effort."""
    if "<<" not in action:
        return action

    def repl(m: "re.Match") -> str:
        preamble = m.group("pre")
        tag = m.group("tag")
        body = m.group("body")
        last_cmd = re.split(r"[;&|\n]", preamble)[-1]
        if (_HEREDOC_NONSHELL_INTERP.search(last_cmd)
                and not _HEREDOC_SHELL_EXECUTORS.search(last_cmd)
                and not _HEREDOC_DATA_SINKS.search(last_cmd)):
            kept = [ln for ln in body.splitlines() if _RUNTIME_DELETE_MARKERS.search(ln)]
            new_body = "\n".join(kept) if kept else "__INTERP_SOURCE__"
            return f"{preamble}<<{tag}\n{new_body}\n{tag}"
        return m.group(0)

    try:
        pat = re.compile(
            r"(?P<pre>[^\n]*?)<<-?\s*['\"]?(?P<tag>\w+)['\"]?\s*\n(?P<body>.*?)\n\s*(?P=tag)\s*(?=\n|$)",
            re.DOTALL,
        )
        return pat.sub(repl, action)
    except Exception:
        return action


def _strip_nonshell_dashc(action: str) -> str:
    """Blank the quoted argument of an inline non-shell `-c`/`-e` interpreter call
    (``python -c "<source>"``, ``ruby -e '<source>'``, ``node -e "..."``). The
    argument is source in that language, not shell; keeping it lets its quotes
    break segment splitting and its tokens (del/truncate/rm as method names) fire
    the shell analyzer. Runtime deletes inside it are still caught by the
    RUNTIME_DELETE regex wall on the raw action. Best-effort."""
    if not re.search(r"-[ce]\b", action):
        return action

    def repl(m: "re.Match") -> str:
        return m.group("pre") + m.group("q") + "__INTERP_SOURCE__" + m.group("q")

    try:
        # <interp> ... -c/-e <quote> <body> <quote>  (body may span newlines)
        pat = re.compile(
            r"(?P<pre>\b(?:python\d?|ruby|node|perl|php|Rscript)\b[^\n]*?\s-[ce]\s+)"
            r"(?P<q>['\"])(?P<body>(?:\\.|(?!(?P=q)).)*)(?P=q)",
            re.IGNORECASE | re.DOTALL,
        )
        return pat.sub(repl, action)
    except Exception:
        return action


def _strip_nonshell_interp_heredocs(action: str) -> str:
    """Blank the body of a NON-SHELL interpreter heredoc (``python3<<EOF ... EOF``,
    ``ruby<<EOF``, ...) so the shell delete-analyzer never reads Python/Ruby
    ``del``/``rm`` tokens as shell verbs. Shell heredocs (bash<<EOF) and data
    heredocs are untouched here. Best-effort; on any regex issue return input."""
    if "<<" not in action:
        return action

    def repl(m: "re.Match") -> str:
        preamble = m.group("pre")
        tag = m.group("tag")
        last_cmd = re.split(r"[;&|\n]", preamble)[-1]
        # non-shell interpreter AND not a shell/data preamble -> body is source
        if (_HEREDOC_NONSHELL_INTERP.search(last_cmd)
                and not _HEREDOC_SHELL_EXECUTORS.search(last_cmd)
                and not _HEREDOC_DATA_SINKS.search(last_cmd)):
            return f"{preamble}<<{tag}\n__INTERP_SOURCE__\n{tag}"
        return m.group(0)

    try:
        pat = re.compile(
            r"(?P<pre>[^\n]*?)<<-?\s*['\"]?(?P<tag>\w+)['\"]?\s*\n(?P<body>.*?)\n\s*(?P=tag)\s*(?=\n|$)",
            re.DOTALL,
        )
        return pat.sub(repl, action)
    except Exception:
        return action


def _extract_heredoc_body(action: str) -> Optional[str]:
    """Return the body of a `<<TAG ... TAG` heredoc if present, else None.

    Only returns a body when the heredoc is EXECUTED (fed to a shell); a data
    heredoc (cat>file) returns None so its literal content is never analyzed as
    a command."""
    if not _heredoc_is_executed(action):
        return None
    m = re.search(r"<<-?\s*(['\"]?)(\w+)\1\s*\n(.*?)\n\s*\2\s*$",
                  action, re.DOTALL | re.MULTILINE)
    if m:
        return m.group(3)
    # heredoc without a trailing newline before EOF, or EOF at end
    m = re.search(r"<<-?\s*(['\"]?)(\w+)\1\s*\n(.*)", action, re.DOTALL)
    if m:
        body = m.group(3)
        # strip a trailing EOF tag line if present
        body = re.sub(r"\n\s*" + re.escape(m.group(2)) + r"\s*$", "", body)
        return body
    return None


def _extract_ssh_body(action: str) -> Optional[str]:
    """Return the remote command string from `ssh [opts] host "<body>"`.

    We find the ssh token, then take the LAST single/double-quoted run on the
    line as the remote body (ssh's command argument). Returns None if there is
    no quoted remote body (e.g. bare `ssh host` interactive, or body is in a
    heredoc handled separately)."""
    if not _SSH_HOST.search(action):
        return None
    # last quoted span on the line
    spans = list(re.finditer(r"'([^']*)'|\"([^\"]*)\"", action, re.DOTALL))
    if not spans:
        return None
    last = spans[-1]
    body = last.group(1) if last.group(1) is not None else last.group(2)
    # ignore a trivial wrapper like 'bash -s' (real body is in a heredoc)
    if body.strip() in ("bash -s", "bash", "sh -s", "sh", "bash -l"):
        return None
    return body


_ASSIGN = re.compile(
    r"""(?:^|[;&|\n]|\bexport\s+)[ \t]*(\w+)=("([^"]*)"|'([^']*)'|(\S+))""",
    re.MULTILINE,
)


def _collect_assignments(action: str, base_env: Optional[dict] = None) -> dict[str, str]:
    """Collect ``VAR=value`` assignments from the command line so a later
    ``rm -rf $VAR`` resolves. ``base_env`` (the harness env, D-narrow) seeds the
    resolution so an RHS like ``OUT="$LOCALAPPDATA/build"`` resolves transitively
    against the real env - not a guess, the actual value the shell would use.

    An RHS with a command substitution ``$(...)`` stays unresolved (opaque ->
    the delete target fail-closes to WARN)."""
    out: dict[str, str] = dict(base_env) if base_env else {}
    for m in _ASSIGN.finditer(action):
        name = m.group(1)
        val = m.group(3) if m.group(3) is not None else \
            (m.group(4) if m.group(4) is not None else m.group(5))
        if val is None:
            continue
        if "`" in val or "$(" in val:
            continue  # command substitution - genuinely opaque, leave unresolved
        if "$" in val:
            # resolve transitively against already-known vars + base env
            resolved = _expand_vars(val, out)
            if "$" in resolved:
                continue  # still references an unknown var -> leave unresolved
            val = resolved
        out[name] = val
    return out


_VAR_REF = re.compile(r"\$\{(\w+)\}|\$(\w+)")


def _expand_vars(text: str, env: dict[str, str]) -> str:
    """Substitute ``$VAR`` / ``${VAR}`` using ``env``; unknown vars stay literal
    (so an unresolved ``$X`` keeps its ``$`` and fail-closes the target check)."""
    def repl(m: "re.Match") -> str:
        name = m.group(1) or m.group(2)
        return env.get(name, m.group(0))
    return _VAR_REF.sub(repl, text)


def _track_cd(segments: Sequence[str], start_cwd: str) -> str:
    """Walk segments, applying any `cd <dir>` to compute the effective cwd for
    later segments. Best-effort: an unresolvable cd (var/glob) leaves cwd as-is
    but the later delete-target check will fail-closed on its own."""
    cwd = start_cwd
    for seg in segments:
        toks = seg.strip().split()
        if len(toks) >= 2 and toks[0] == "cd":
            target = toks[1].strip('"').strip("'")
            if _UNRESOLVABLE.search(target) and not target.startswith("~"):
                continue  # can't resolve - keep old cwd, delete-check blocks later
            nc = _normalize(target, start_cwd, cwd)
            if nc:
                cwd = nc
    return cwd


def analyze_delete(action: str, *, home: str, cwd: str,
                   policy: DeletePolicy = DEFAULT_DELETE_POLICY,
                   env: Optional[dict] = None,
                   _depth: int = 0) -> Optional[DeleteVerdict]:
    """Classify a shell command for irreversible-deletion risk.

    ``env`` (D-narrow): the REAL environment the command runs in, supplied by
    the harness (the Claude Code hook resolves it from ``os.environ``). When
    given, ``$VAR`` in a delete target is resolved BY VALUE against this env -
    not guessed by name - so ``rm -rf $LOCALAPPDATA/scratch`` classifies the
    resolved absolute path against the protect-list. A var absent from ``env``
    stays unresolved and fail-closes. This is reading data the shell already
    has one step earlier, not weakening fail-closed.

    Returns:
        DeleteVerdict(blocked=True/False) if the command is delete-relevant,
        or ``None`` if this command has no deletion semantics at all (so the
        caller falls through to the other policy walls unchanged).

    Semantics:
        - protected-asset substring present -> BLOCK.
        - ssh/heredoc remote body -> recurse into it with the SAME rules
          (remote cwd tracked from `cd` in the body); unresolvable -> BLOCK.
        - opaque construct ($()/backtick in a delete segment, | sh, eval,
          xargs) touching a delete verb -> BLOCK.
        - rm -r / rmdir / unlink / shred / truncate on a target that is not
          provably disposable -> BLOCK.
        - all delete targets proven disposable -> ALLOW (blocked=False).
    """
    if not action or not action.strip():
        return None
    if _depth > 3:  # runaway recursion guard -> fail-closed if delete-relevant
        return _warn("recursion depth exceeded - unchecked", action[:40]) \
            if _has_delete_intent(action.lower()) else None

    # DoS / fail-open guard (E2E audit 2026-07-05, HIGH). analyze_delete's
    # tokenization is superlinear on a single giant token (a multi-MB trailing
    # `# AAAA...` comment stays one token and shlex scans it O(n^2): ~12s at 1MB,
    # ~400s at 2MB). A crafted `rm -rf ~ # <megabytes>` would hang past the hook
    # timeout, the killed hook emits no block, and the delete proceeds = fail
    # OPEN. Cap the input: anything over the limit is UNPROVABLE by definition,
    # so if it carries delete intent we BLOCK (fail-CLOSED, never allow); with no
    # delete intent we defer (None) - a huge benign non-delete command is the
    # other walls' problem, not a delete to analyze.
    if len(action) > _MAX_ACTION_LEN:
        if _has_delete_intent(action[:_MAX_ACTION_LEN].lower()) or _has_delete_intent(action.lower()):
            return _block(
                f"command exceeds {_MAX_ACTION_LEN} bytes and carries delete "
                "intent - too large to prove safe, fail-closed", action[:60],
            )
        return None

    # ReDoS guard for the heredoc-stripping regexes (B1, council 2026-07-06). A
    # large unterminated heredoc makes the DOTALL lazy-body + backreference below
    # backtrack catastrophically (~30-100s at 50KB), the hook is killed, and the
    # delete proceeds = fail-OPEN. Bound the input those regexes may scan: over
    # the bound WITH a `<<` heredoc marker, fail CLOSED (block if delete intent,
    # else defer). A normal command is far under 16KB; only a padding/DoS shape
    # trips this.
    if len(action) > _HEREDOC_STRIP_MAX and "<<" in action:
        if _has_delete_intent(action.lower()):
            return _block(
                f"oversized heredoc ({len(action)} bytes) with delete intent - "
                "too large to strip safely, fail-closed", action[:60],
            )
        return None

    # Strip DATA heredoc bodies (cat>file<<EOF ... EOF) BEFORE any analysis:
    # their content is a document/script being WRITTEN, not commands being run,
    # so a literal `rm`/`destroy`/protected-asset name inside must never be read
    # as an action (44 false blocks: writing REJESTR.md / a stripe script).
    # Executed shell heredocs (bash<<EOF) are left intact for the remote-body path.
    action = _strip_data_heredocs(action)
    # ALSO strip NON-SHELL interpreter heredoc bodies (python3<<EOF ... EOF) for
    # THIS shell delete-analyzer only: their body is Python/Ruby/... source, where
    # `del x` / `rm` are language tokens, not shell verbs. Reading them as shell
    # produced false blocks on real agent traffic (Nemotron: `del sys.modules[m]`
    # misread as a Windows `del`). A genuine `shutil.rmtree(...)` is still caught
    # upstream by the RUNTIME_DELETE regex wall, which runs on the UN-stripped
    # action in guard.check_action - so this narrows the shell analyzer without
    # blinding the runtime-delete wall.
    action = _strip_nonshell_interp_heredocs(action)
    # ALSO blank the argument of an inline non-shell `-c`/`-e` (python -c "...",
    # ruby -e "...", node -e "..."): it is SOURCE, not shell. Its quotes/newlines
    # would also break segment splitting ("unbalanced quote" -> fail-closed WARN
    # on a benign `python -c "df.truncate(...)"`; Nemotron corpus). A real
    # `shutil.rmtree(...)` is still seen by the RUNTIME_DELETE regex wall on the
    # raw action in guard, so blanking it here narrows the shell analyzer only.
    action = _strip_nonshell_dashc(action)

    low = action.lower()
    line_delete_intent = _has_delete_intent(low)

    # declared protected assets: block on raw-substring, highest confidence.
    # A declared asset (paid-infra id, prod host, backup root) is high-value by
    # definition - any destructive-capable verb OR a paid-infra destroy near it
    # blocks. (`vastai destroy <id>` has no rm-style verb but IS irreversible.)
    # Host-only assets (a bare IP/hostname) are NOT enough on their own: a
    # deploy `ssh prod "rm -rf dist.new"` names the host but only deletes a
    # build dir. Require the asset to co-occur with a paid-infra destroy OR a
    # backup/home path, not merely a remote rm of a proven artifact.
    for asset in policy.protected_assets:
        if asset and asset.lower() in low:
            if _asset_is_target(low, asset.lower()):
                return _block(
                    f"touches declared protected asset {asset!r} with a "
                    "destructive verb - requires a human",
                    asset,
                )

    # REMOTE body: ssh "<body>" or ssh 'bash -s' <<EOF ... EOF. Recurse into the
    # remote command with the SAME rules, tracking `cd` inside the body for the
    # remote cwd. A remote rm of a build dir allows; remote ~/backup blocks.
    remote_body = _extract_heredoc_body(action) or _extract_ssh_body(action)
    is_remote = bool(_SSH_HOST.search(action)) or ("<<" in action and remote_body)
    if is_remote and remote_body and _has_delete_intent(remote_body.lower()):
        # unknown remote cwd: start from "/" so only absolute or cd-resolved
        # targets are judged; a bare `rm -rf dist.new` with no `cd` cannot be
        # proven in-tree -> will fail-closed. With `cd /var/www/site` it can.
        try:
            body_segs = split_segments(remote_body)
        except ValueError:
            return _warn("remote body unparseable (unchecked) - review before running", remote_body[:50])
        remote_cwd = _track_cd(body_segs, "/__remote_unknown__")
        sub = analyze_delete(remote_body, home="/__remote_home__",
                             cwd=remote_cwd, policy=policy, _depth=_depth + 1)
        if sub is not None:
            return sub
        # remote body had no resolvable delete -> treat as handled (allow)
        return _ALLOW
    if is_remote and _has_delete_intent(low) and not remote_body:
        return _warn("remote exec (ssh) with delete intent - remote filesystem unchecked", action[:50])

    # LINE-level opacity: if the line has delete intent AND an executor that pulls
    # its payload from elsewhere (| sh, heredoc, eval, xargs), the real target may
    # be runtime-built (`printf 'rm -rf /root' | bash` spans two segments).
    # B2 fix (council 2026-07-06): do NOT short-circuit the whole line to WARN
    # here. A benign opaque token in a SIBLING segment (`rm -rf ~ ; cat <<EOF ...`)
    # must never downgrade a RESOLVABLE protected-root delete in another segment.
    # So we only REMEMBER that an opaque construct is present, run the segment
    # analysis first (a hard BLOCK from any segment wins below), and fall back to
    # the line-level WARN only when no segment produced a block or a proven-safe
    # delete — i.e. the delete really is hidden behind the opaque construct.
    line_opaque_why: Optional[str] = None
    if line_delete_intent:
        for pat, why in _OPAQUE_LINE:
            if re.search(pat, action):
                line_opaque_why = why
                break

    # split into segments (fail-closed on unbalanced quotes)
    try:
        segments = split_segments(action)
    except ValueError as exc:
        if _has_delete_intent(low):
            return _warn(f"unparseable command ({exc}) with delete intent - unchecked", action[:60])
        return None

    # track cd across segments so `cd build && rm -rf out` resolves `out`
    # relative to the post-cd cwd. Collect in-line VAR=value assignments so
    # `OUT=/tmp/x; rm -rf $OUT` resolves statically.
    effective_cwd = cwd
    # D-narrow: real env from the harness is the base; in-line VAR= assignments
    # override it (a later `OUT=/x` on the line wins over the ambient $OUT).
    # in-line assignments resolved against the real env (transitive), then env
    # itself as the base for any $VAR not assigned on the line.
    assignments = _collect_assignments(action, base_env=env)
    saw_delete = False
    saw_opaque_warn: Optional[DeleteVerdict] = None
    for seg in segments:
        seg_low = seg.lower()
        # apply a leading `cd` in this segment to the running cwd (env-expanded)
        _toks = seg.strip().split()
        if len(_toks) >= 2 and _toks[0] == "cd":
            _t = _expand_vars(_toks[1].strip('"').strip("'"), assignments) if assignments \
                else _toks[1].strip('"').strip("'")
            if not (_UNRESOLVABLE.search(_t) and not _t.startswith("~")):
                _nc = _normalize(_t, cwd, effective_cwd)
                if _nc:
                    effective_cwd = _nc
        seg_has_delete = _has_delete_intent(seg_low)
        # segment-level opacity: only the deleting segment must be free of a
        # runtime-computed target ($()/backtick). A sibling segment's $(date)
        # is irrelevant to whether THIS rm's target is provable.
        # NOTE (under-block fix, re-review 2026-07-06): an opaque delete segment
        # must NOT early-return WARN - that skips the REST of the line, letting a
        # hard-block destruction in a LATER segment (`rm -rf $(x) && dd if=... of=
        # /dev/sda`) pass. Remember the warn and keep scanning; a later block wins.
        if seg_has_delete:
            _opaque_here = False
            for pat, why in _OPAQUE_SEGMENT:
                if re.search(pat, seg):
                    if saw_opaque_warn is None:
                        saw_opaque_warn = _warn(
                            f"opaque construct in a delete segment ({why}) - unchecked",
                            seg[:60])
                    _opaque_here = True
                    break
            if _opaque_here:
                continue  # this segment's target is hidden; later segments still checked
        # tokenize the segment (word-splitter only; opacity already handled).
        # Windows delete verbs carry backslash path separators (`.\node_modules`,
        # `C:\Windows`) that posix shlex would EAT as escapes (turning
        # `C:\Windows` into `C:Windows` and `.\build\out.tmp` into `.buildout.tmp`
        # - both mis-classify the target). For a segment naming a Windows delete
        # verb we tokenize with posix=False (backslashes preserved) and strip
        # surrounding quotes ourselves; everything else stays posix.
        win_seg = _has_win_delete_intent(seg_low)
        try:
            tokens = shlex.split(seg, comments=False, posix=not win_seg)
            if win_seg:
                tokens = [_strip_quotes(t) for t in tokens]
        except ValueError:
            if seg_has_delete:
                return _block("segment not tokenizable with delete intent - "
                              "fail-closed", seg[:60])
            continue
        if not tokens:
            continue
        # expand in-line-assigned vars in each token (static, same-line only)
        if assignments:
            tokens = [_expand_vars(t, assignments) for t in tokens]
        verdict = _analyze_segment(tokens, seg_low, home, effective_cwd, policy)
        if verdict is not None:
            if verdict.blocked:
                return verdict  # a resolvable protected-root delete wins over any opaque token
            saw_delete = True  # this segment was a proven-safe delete

    # No segment hard-blocked. A per-segment opaque delete (target hidden) surfaces
    # as WARN (unchecked) - the deleting segment's real target could not be proven.
    if saw_opaque_warn is not None:
        return saw_opaque_warn

    # If the line carried an opaque delete construct and no segment resolved to a
    # proven-safe delete, the real target is hidden -> WARN (unchecked), preserving
    # the original line-opacity intent for shapes like `printf 'rm -rf /root'|bash`.
    # If a segment WAS a proven-safe delete, the opaque token was a benign sibling.
    if line_opaque_why is not None and not saw_delete:
        return _warn(f"opaque construct with delete intent ({line_opaque_why}) - unchecked", action[:60])

    if saw_delete:
        return _ALLOW
    return None  # no deletion semantics -> other walls decide


def _analyze_segment(tokens: list[str], seg_low: str, home: str, cwd: str,
                     policy: DeletePolicy) -> Optional[DeleteVerdict]:
    """Analyze one already-split segment. Returns a verdict if delete-relevant,
    else None."""
    # unwrap prefix wrappers (sudo/env/nice/VAR=val ...) to reach the real verb
    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        base = posixpath.basename(_to_posix(tok)).lstrip("\\")
        if "=" in tok and re.match(r"^\w+=", tok):  # FOO=bar env-assignment prefix
            idx += 1
            continue
        if base in _PREFIX_WRAPPERS:
            idx += 1
            continue
        break
    if idx >= len(tokens):
        return None
    argv = tokens[idx:]
    verb_raw = argv[0]
    verb = posixpath.basename(_to_posix(verb_raw)).lstrip("\\").lower()

    # remote / opaque exec wrappers: if they carry delete intent we cannot
    # resolve the remote target -> BLOCK; else not our concern.
    if verb in _REMOTE_WRAPPERS:
        if _has_delete_intent(seg_low):
            # UNDER-BLOCK FIX (re-review 2026-07-06): a wrapper used only as a
            # PREFIX around a LOCAL, resolvable delete (`kubectl exec pod -- rm
            # -rf ~`, `docker exec c rm -rf /root`) must not be waved through as a
            # generic remote-warn - the inner `rm -rf ~` target IS resolvable and
            # lands under a protected root. Unwrap past the wrapper (and a `--`
            # separator if present) and re-analyze the inner command with the
            # normal target-anchored path; a resolvable protected-root target then
            # BLOCKs. If unwrapping yields no local delete verb, fall back to the
            # remote-unchecked warn.
            inner = argv[1:]
            _delete_verbs_all = (*_DELETE_VERBS, "rm")
            if "--" in inner:
                inner = inner[inner.index("--") + 1:]
            else:
                # skip the wrapper's own sub-args up to the first delete verb
                for j, tk in enumerate(inner):
                    if posixpath.basename(_to_posix(tk)).lstrip("\\").lower() in _delete_verbs_all:
                        inner = inner[j:]
                        break
            if inner:
                inner_verb = posixpath.basename(_to_posix(inner[0])).lstrip("\\").lower()
                if inner_verb in _delete_verbs_all or _win_verb(inner[0]):
                    inner_seg_low = " ".join(inner).lower()
                    v = _analyze_segment(inner, inner_seg_low, home, cwd, policy)
                    if v is not None and v.blocked:
                        return v  # resolvable protected-root delete inside the wrapper
            return _warn(f"remote/opaque exec ({verb}) carrying delete intent - remote unchecked", verb)
        return None
    if verb in _DASH_C_WRAPPERS and _has_command_flag(verb, argv):
        if _has_delete_intent(seg_low):
            return _block(f"{verb} -c/-Command '<string>' with delete intent - "
                          "inner command unresolvable, fail-closed", verb)
        return None

    # python -c / ruby -e / node -e / perl -e: the argument is SOURCE in that
    # language, not shell. `df.truncate(...)` (pandas), `del d[k]` (Python) are
    # NOT shell delete verbs; analyzing them as shell false-warned on real agent
    # traffic (Nemotron: `python -c "df.truncate(...)"`). A genuine
    # `shutil.rmtree(...)` is caught by the RUNTIME_DELETE regex wall, which runs
    # on the raw action in guard - so we defer (None) here, never fail-open.
    if _NONSHELL_INTERP_VERB.match(verb) and re.search(r"(?:^|\s)-[ce]\b", seg_low):
        return None

    # find ... -delete / -exec rm : destructive, target is a search root -> BLOCK
    if verb == "find" and re.search(r"-delete\b|-exec\s+rm\b|-exec\s+shred\b", seg_low):
        return _block("find -delete/-exec rm - deletes matched files, "
                      "target set unresolvable, fail-closed", "find")

    # git clean -fdx / -fd : removes untracked+ignored files, unbounded -> BLOCK
    if verb == "git" and re.search(r"\bclean\b", seg_low) and re.search(r"-\w*f", seg_low):
        return _block("git clean -f - removes untracked/ignored files "
                      "irreversibly, fail-closed", "git clean")

    # rm: needs recursive (dogfood scope: RM_RF is recursive-delete). Non-recursive
    # rm of single files is out of the RM_RF class - leave to other walls.
    if verb == "rm":
        if not _is_recursive_rm(argv):
            return None
        targets = _operands(argv[1:])
        if not targets:
            return _block("rm recursive with no explicit target - fail-closed", "rm")
        for t in targets:
            v = _classify_target(t, home, cwd, policy)
            if v.blocked:
                return v
        return _ALLOW

    # rmdir/unlink/shred/truncate: destructive, classify targets
    if verb in _DELETE_VERBS and verb != "rmdir":
        targets = _operands(argv[1:])
        if not targets:
            return _block(f"{verb} with no explicit target - fail-closed", verb)
        for t in targets:
            v = _classify_target(t, home, cwd, policy)
            if v.blocked:
                return v
        return _ALLOW

    # Windows-native delete verbs (Remove-Item / del / rd / rmdir / erase).
    # Same target-anchored logic as rm, but with Windows flag conventions
    # (/s /q for cmd, -Recurse -Force for PowerShell). `rmdir` is shared with
    # the POSIX branch above via the guard `!= "rmdir"`, so it lands here where
    # both flag styles are stripped. A Windows delete of a protected root is
    # dangerous regardless of a recurse flag (`del` needs none; `rd /s` and
    # `Remove-Item -Recurse` are the recursive forms), so - unlike POSIX rm -
    # we classify the target unconditionally rather than gating on recursion.
    win = _win_verb(verb_raw)
    if win or verb == "rmdir":
        targets = _win_operands(argv[1:])
        if not targets:
            return _block(f"{verb} with no explicit target - fail-closed", verb)
        for t in targets:
            v = _classify_target(t, home, cwd, policy)
            if v.blocked:
                return v
        return _ALLOW

    return None  # not a deletion verb


# a redirection operator token (2>, >, >>, &>, 2>&1, <, etc.)
_REDIR = re.compile(r"^\d*[<>]|^&>|>&\d*$")


def _operands(args: Sequence[str]) -> list[str]:
    """Delete operands only: drop flags, ``--``, and redirections with their
    targets (``2>/dev/null`` etc. are NOT paths being deleted)."""
    out: list[str] = []
    skip_next = False
    for tok in args:
        if skip_next:
            skip_next = False
            continue
        if tok == "--" or _FLAG.match(tok):
            continue
        if _REDIR.match(tok):
            # `2>` alone -> its target is the next token; `2>/dev/null` -> inline
            if re.fullmatch(r"\d*[<>]+&?\d*", tok):
                skip_next = True
            continue
        out.append(tok)
    return out


# a segment "could delete" if it names any delete verb (used to scope opacity
# and remote-wrapper blocking so we do not block benign `echo $(date)`).
_DELETE_INTENT = re.compile(
    r"\brm\b|\brmdir\b|\bunlink\b|\bshred\b|\btruncate\b|"
    r"-delete\b|-exec\s+rm\b|\bgit\s+clean\b|"
    r"remove-item\b|\brd\b|\bdel\b",
    re.IGNORECASE,
)


def _has_delete_intent(text_low: str) -> bool:
    return bool(_DELETE_INTENT.search(text_low))


# Windows delete verbs only - used to pick posix=False tokenization so backslash
# path separators survive. Word-boundary anchored to the verb position (start of
# segment or after a wrapper) to avoid firing on e.g. the word "model" (which
# contains "del"): require the verb as a standalone token.
_WIN_DELETE_INTENT = re.compile(
    r"(?:^|[\s;&|])(?:remove-item|ri|erase|del|rd|rmdir)(?:\s|$)",
    re.IGNORECASE,
)


def _has_win_delete_intent(text_low: str) -> bool:
    return bool(_WIN_DELETE_INTENT.search(text_low))


def _strip_quotes(tok: str) -> str:
    """Strip a single layer of matching surrounding quotes (posix=False leaves
    them on). Only touches a fully-wrapped token; inner quotes are left as-is."""
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in ("'", '"'):
        return tok[1:-1]
    return tok


# paid-infra / cloud destroy verbs that are IRREVERSIBLE (not merely a service
# stop/restart). `stop`/`reload`/`restart` are deliberately EXCLUDED: stopping a
# service or reloading nginx is reversible and was the single biggest new
# false-block source (a deploy `ssh prod "systemctl reload nginx"` names a
# declared host but destroys nothing). Only genuinely-destructive verbs here.
_DESTROY_INTENT = re.compile(
    r"\bdestroy\b|\bterminate\b|\bdelete-\w+\b|\bdrop\s+(table|database|schema)\b",
    re.IGNORECASE,
)


def _has_destroy_intent(text_low: str) -> bool:
    return bool(_DESTROY_INTENT.search(text_low))


# Does the command actually delete/destroy a declared asset, vs merely NAME it
# (e.g. ssh to that host to run a benign command)? An asset block requires the
# asset to co-occur with a file-delete verb OR a destroy verb - not just the
# host appearing as an ssh target.
def _asset_is_target(action_low: str, asset_low: str) -> bool:
    if _has_destroy_intent(action_low):
        return True
    # a file-delete verb applied near the asset (e.g. rm -rf ~/laptop-backup)
    if _has_delete_intent(action_low) and _looks_like_path_asset(asset_low):
        return True
    return False


def _looks_like_path_asset(asset_low: str) -> bool:
    """A path-like asset (laptop-backup, /opt/x) vs a host-like asset (an IP or
    bare hostname). A file-delete only matters for path-like assets; a host-like
    asset matters only under a destroy verb (handled above)."""
    return "/" in asset_low or "-" in asset_low and not re.match(r"^[\d.]+$", asset_low)
