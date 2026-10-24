#!/usr/bin/env python3
"""gate.cat retro-scan — measure the irreversible actions your agents ALREADY took.

WHY THIS FILE EXISTS
--------------------
Nobody buys protection against a risk they have not measured. Every argument for
a policy gate that starts with *our* numbers is marketing; the only argument that
survives a security review starts with *your* numbers. So this tool is run BY YOU,
ON YOUR MACHINE, before anyone sells you anything. It reads the agent session
transcripts already sitting on your disk, extracts every command your agents
actually executed, classifies the irreversible ones, and writes one HTML file.

It is deliberately boring on purpose, because a security buyer will audit it:

  ZERO third-party dependencies   Python 3.11+ standard library only — no HTTP
                                  client, no jinja2, no rich, nothing to install.
                                  `python3 gatecat_retroscan.py` works on a
                                  locked-down box with no package index access.
  ZERO network calls              There is no networking import in this file, and
                                  nothing that could make one. Run
                                      python3 gatecat_retroscan.py --verify-offline
                                  to print the exact grep that proves it. That grep
                                  must return NOTHING — not even this comment, which
                                  is why the forbidden module names are assembled from
                                  fragments at the bottom of the file rather than
                                  written out here. One hit = do not run this tool.
  READ-ONLY                       The only writes are the output paths you name on
                                  the command line (--out, --json). Transcripts are
                                  opened read-only, streamed line by line, never
                                  modified, never moved, never deleted.
  REDACT BEFORE REPORT            Every captured command passes through `redact()`
                                  before it can reach the report, the JSON, or your
                                  terminal. Nothing else in this file is allowed to
                                  touch raw command text on an output path.

WHAT IT MEASURES
----------------
A command counts as EXECUTED only when the transcript contains a matching, non-error,
non-denied tool result. A tool call with no result, an error result, or a permission
denial is "proposed, not executed" and is reported in a separate bucket. That single
distinction is the credibility of the whole report: an inflated headline number is
worth less than no number at all.

WHAT IT DOES NOT CLAIM
----------------------
A command landing in an irreversible class is NOT proof that harm occurred. It is
proof that the class was REACHABLE — that nothing in the loop was positioned to stop
it. And the scan is certain only about what it found: an unparsed session is unknown,
not clean.

Author: gate.cat  ·  Apache-2.0  ·  stdlib-only, offline, read-only.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import html
import json
import os
import posixpath
import re
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Optional, Sequence

TOOL_NAME = "gatecat_retroscan"
TOOL_VERSION = "1.0.0"
SCHEMA_VERSION = 1

# A single transcript line larger than this is treated as corrupt rather than
# loaded — a 500 MB JSONL must never become a 500 MB string.
MAX_LINE_BYTES = 8 * 1024 * 1024
# Defensive ceiling on shell-fragment expansion (nested `$()` bombs).
MAX_UNITS_PER_COMMAND = 256
# Rows rendered per class in the HTML. The full set always goes to --json.
MAX_ROWS_PER_CLASS = 200


# ===========================================================================
# 1. REDACTION
# ---------------------------------------------------------------------------
# This runs FIRST, on every captured command, before classification and long
# before rendering. It is the single most likely reason a prospect refuses to
# run the tool, so it is the first thing in the file and the most tested thing
# in the suite. Order matters: specific credential shapes are consumed before
# the generic `key=value` sweep, so a recognised token is labelled by kind
# instead of flattened into a nameless "credential".
# ===========================================================================

def _marker(kind: str) -> str:
    """Redaction placeholder. Guillemets make a survivor obvious in a diff."""
    return f"«REDACTED:{kind}»"


# (kind, compiled pattern, replacement builder)
_REDACTORS: list[tuple[str, re.Pattern[str], Callable[[re.Match[str], str], str]]] = []


def _add(kind: str, pattern: str, flags: int = 0, keep: int = 0) -> None:
    """Register a redactor. `keep` = number of leading groups preserved verbatim."""
    rx = re.compile(pattern, flags)

    def _sub(m: re.Match[str], k: str = kind, n: int = keep) -> str:
        prefix = "".join(m.group(i) or "" for i in range(1, n + 1))
        return prefix + _marker(k)

    _REDACTORS.append((kind, rx, _sub))


# PEM private key blocks first — they span lines and would otherwise be chewed
# up by narrower patterns.
_add("private-key",
     r"-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----")
_add("private-key", r"-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*\Z")
# basic-auth inside a URL: https://user:pass@host  ->  https://«REDACTED:basic-auth»@host
_add("basic-auth", r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*://)([^/\s:@]+:[^/\s@]+)(?=@)",
     0, keep=1)
# Vendor tokens, most specific first.
_add("stripe-key", r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b")
_add("anthropic-key", r"\bsk-ant-[A-Za-z0-9_\-]{12,}\b")
_add("openai-key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{16,}\b")
_add("github-token", r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")
_add("github-token", r"\bgh[porsu]_[A-Za-z0-9]{16,}\b")
_add("aws-access-key", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{12,20}\b")
_add("slack-token", r"\bxox[baprse]-[A-Za-z0-9\-]{10,}\b")
_add("google-api-key", r"\bAIza[0-9A-Za-z_\-]{30,}\b")
_add("bearer-token", r"\b(Bearer\s+)[A-Za-z0-9._\-~+/]{12,}={0,2}", re.IGNORECASE, keep=1)
_add("jwt", r"\beyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\b")
# Generic assignments — also catches URL query strings (`?token=...&x=1`) because
# the bare-value alternative stops at `&`. The `(?!«)` guard stops this from
# re-redacting a marker a more specific rule already produced.
_add("credential",
     r"(?P<k>\b(?:password|passwd|pwd|token|api[_\-]?key|apikey|secret|"
     r"access[_\-]?token|auth[_\-]?token|refresh[_\-]?token|client[_\-]?secret|"
     r"private[_\-]?key|session[_\-]?key)\b\s*[:=]\s*)"
     r"(?!«)(?:\"[^\"\n]{1,512}\"|'[^'\n]{1,512}'|[^\s&;|,\"'<>)]{1,512})",
     re.IGNORECASE, keep=1)
# Space-separated forms the `key=value` rule cannot see:
#   aws configure set aws_secret_access_key wJalrXUt...
#   deploy --token s3cr3t   /   psql --password hunter2
_add("credential",
     r"(?P<k>\b(?:aws_secret_access_key|aws_access_key_id|aws_session_token)\s+)"
     r"(?!«)\S{8,}", re.IGNORECASE, keep=1)
_add("credential",
     r"(?P<k>(?:^|\s)--?(?:password|passwd|token|api[_\-]?key|secret|"
     r"client[_\-]?secret|auth[_\-]?token|with-token)\s+)"
     r"(?!«|-)(?:\"[^\"\n]{1,512}\"|'[^'\n]{1,512}'|\S{4,})",
     re.IGNORECASE, keep=1)


def redact(text: str) -> str:
    """Return `text` with every recognised secret replaced by a kind-labelled marker.

    Idempotent: running it twice produces the same string, which is what makes the
    final `--redact-check` pass meaningful (a second pass that changes anything is
    a bug report, not a no-op).
    """
    if not text:
        return text
    for _kind, rx, sub in _REDACTORS:
        text = rx.sub(sub, text)
    return text


def residual_secrets(text: str) -> list[str]:
    """Kinds of secret still detectable in `text`. Should always be empty on output."""
    found: list[str] = []
    for kind, rx, _sub in _REDACTORS:
        if rx.search(text):
            found.append(kind)
    return sorted(set(found))


# ===========================================================================
# 2. SHELL NORMALISATION
# ---------------------------------------------------------------------------
# The two false positives that discredit a scan like this are:
#
#   (a) WRITING ABOUT a command is not RUNNING it.  `cat > README.md <<'EOF'`
#       followed by a paragraph containing `rm -rf /` is documentation.
#   (b) SEARCHING FOR a command is not RUNNING it.  `grep -r 'rm -rf' .` is
#       an audit, and flagging it would mean this tool flags itself.
#
# Both are killed structurally rather than by blacklist: heredoc bodies and
# comments are removed before anything is matched, command substitutions are
# lifted out and judged on their own, and each pipeline stage is judged by its
# executable head. Nothing here is a shell parser — it is a conservative
# splitter that fails toward "do not flag".
# ===========================================================================

_HEREDOC_RE = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def strip_comments(text: str) -> str:
    """Drop `# ...` to end of line when the `#` starts a word outside quotes.

    A commented-out command was not run. `foo#bar`, `$#` and `#` inside a quoted
    string are left alone.
    """
    out_lines: list[str] = []
    for line in text.splitlines():
        buf: list[str] = []
        quote: Optional[str] = None
        i = 0
        while i < len(line):
            ch = line[i]
            if quote:
                if ch == "\\" and quote == '"':
                    buf.append(ch)
                    i += 1
                    if i < len(line):
                        buf.append(line[i])
                        i += 1
                    continue
                if ch == quote:
                    quote = None
                buf.append(ch)
                i += 1
                continue
            if ch in "'\"":
                quote = ch
                buf.append(ch)
                i += 1
                continue
            if ch == "#" and (not buf or buf[-1].isspace()):
                break
            buf.append(ch)
            i += 1
        out_lines.append("".join(buf))
    return "\n".join(out_lines)


def strip_heredocs(text: str) -> str:
    """Remove heredoc bodies, keeping the command that opened them.

    `cat > README.md <<'EOF' ... EOF` becomes `cat > README.md`. This is what makes
    "the agent wrote a document that mentions rm -rf" invisible to the classifier.
    An unterminated heredoc (truncated transcript) consumes to end of input, which
    is the safe direction.
    """
    lines = text.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _HEREDOC_RE.search(line)
        if not m:
            out.append(line)
            i += 1
            continue
        out.append(_HEREDOC_RE.sub(" ", line))
        term = m.group(2)
        i += 1
        while i < len(lines) and lines[i].strip() != term:
            i += 1
        i += 1  # skip the terminator line itself
    return "\n".join(out)


def extract_substitutions(text: str) -> tuple[str, list[str]]:
    """Split `$( ... )` / backtick bodies out of `text`.

    `echo $(rm -rf /tmp/x)` really does delete — the substitution runs. So the
    body is lifted into its own unit and judged independently, while the outer
    text keeps only a blank where it stood. Inside single quotes a `$(` is
    literal, so it is left in place.
    """
    out: list[str] = []
    subs: list[str] = []
    quote: Optional[str] = None
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if quote == "'":
            if ch == "'":
                quote = None
            out.append(ch)
            i += 1
            continue
        if quote == '"':
            if ch == "\\":
                out.append(ch)
                i += 1
                if i < n:
                    out.append(text[i])
                    i += 1
                continue
            if ch == '"':
                quote = None
                out.append(ch)
                i += 1
                continue
            # fall through: `$(` interpolates inside double quotes
        elif ch in "'\"":
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "$" and text.startswith("$(", i):
            depth = 1
            j = i + 2
            while j < n and depth:
                if text[j] == "(":
                    depth += 1
                elif text[j] == ")":
                    depth -= 1
                j += 1
            subs.append(text[i + 2: j - 1 if depth == 0 else j])
            out.append(" ")
            i = j
            continue
        if ch == "`":
            j = text.find("`", i + 1)
            if j == -1:
                j = n
            subs.append(text[i + 1: j])
            out.append(" ")
            i = j + 1
            continue
        out.append(ch)
        i += 1
    return "".join(out), subs


def split_on_ops(text: str, ops: Sequence[str]) -> list[str]:
    """Quote-aware split on shell operators. `ops` must be longest-first."""
    parts: list[str] = []
    buf: list[str] = []
    quote: Optional[str] = None
    depth = 0
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if quote:
            if ch == "\\" and quote == '"':
                buf.append(ch)
                i += 1
                if i < n:
                    buf.append(text[i])
                    i += 1
                continue
            if ch == quote:
                quote = None
            buf.append(ch)
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if depth == 0:
            hit = next((op for op in ops if text.startswith(op, i)), None)
            if hit is not None:
                parts.append("".join(buf))
                buf = []
                i += len(hit)
                continue
        buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


_PIPELINE_OPS = ("&&", "||", ";", "\n")
_STAGE_OPS = ("|&", "|")


def shell_units(command: str) -> list[str]:
    """Normalise a raw command into the list of pipelines that would really run."""
    text = strip_heredocs(strip_comments(command or ""))
    queue: list[str] = [text]
    units: list[str] = []
    while queue and len(units) < MAX_UNITS_PER_COMMAND:
        outer, subs = extract_substitutions(queue.pop())
        queue.extend(subs)
        units.extend(split_on_ops(outer, _PIPELINE_OPS))
    return units[:MAX_UNITS_PER_COMMAND]


def argv_of(stage: str) -> list[str]:
    """Best-effort word split. `shlex` is a word splitter, not a shell parser —
    when it refuses (unbalanced quotes in a truncated transcript) fall back to
    whitespace so we degrade instead of crashing."""
    try:
        toks = shlex.split(stage, comments=False, posix=True)
    except ValueError:
        toks = stage.split()
    return [t for t in toks if t]


_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# Wrappers that are not themselves the interesting command. `sudo` is deliberately
# NOT here: it must stay visible to the permission-escalation class.
_TRANSPARENT_HEADS = {
    "env", "nohup", "time", "exec", "command", "builtin", "stdbuf", "nice",
    "ionice", "setsid", "unbuffer", "script",
}
_REDIRECT_RE = re.compile(r"^\d*(?:>>|>|<<|<|&>|>&)")


def head_of(argv: Sequence[str]) -> str:
    """Executable name that a stage would actually invoke (basename, no .exe)."""
    for tok in argv:
        if _ENV_ASSIGN_RE.match(tok) or _REDIRECT_RE.match(tok):
            continue
        base = posixpath.basename(tok.replace("\\", "/")).lower()
        if base.endswith(".exe"):
            base = base[:-4]
        if base in _TRANSPARENT_HEADS:
            continue
        return base
    return ""


def git_subcommand(argv: Sequence[str]) -> tuple[str, list[str]]:
    """`git -C /repo push --force` -> ("push", ["--force"])."""
    for i, tok in enumerate(argv):
        base = posixpath.basename(tok.replace("\\", "/")).lower()
        if base in ("git", "git.exe"):
            rest = list(argv[i + 1:])
            j = 0
            while j < len(rest):
                if rest[j] in ("-C", "-c", "--git-dir", "--work-tree", "--namespace",
                               "--exec-path"):
                    j += 2
                    continue
                if rest[j].startswith("-"):
                    j += 1
                    continue
                break
            if j < len(rest):
                return rest[j], rest[j + 1:]
            return "", []
    return "", []


_INERT_LITERAL_RE = re.compile(r"'[^'$`\n]*'|\"[^\"$`\n]*\"")


def strip_inert_literals(text: str) -> str:
    """Remove quoted spans that contain no expansion.

    `echo 'rm -rf /'` carries no live command; `cat "$HOME/.aws/credentials"` does.
    Keeping `$`/backtick spans is what stops this from becoming a blanket amnesty.
    """
    return _INERT_LITERAL_RE.sub(" ", text)


_MESSAGE_FLAG_RE = re.compile(
    r"(?:^|\s)(?:-m|--message|--body|--title|--comment|--description|--annotate|"
    r"--notes|--summary)(?:=|\s+)(\"[^\"]*\"|'[^']*'|\S+)")


def strip_message_args(text: str) -> str:
    """Blank out commit-message / PR-body style values.

    `git commit -m "stop using rm -rf in docs"` is prose that happens to quote a
    command. Prose is not execution.
    """
    return _MESSAGE_FLAG_RE.sub(" ", text)


# ===========================================================================
# 3. CLASSIFICATION — ten irreversible classes
# ---------------------------------------------------------------------------
# "Irreversible" here means: once it has run, no amount of retrying gets you back
# to the prior state from inside the same session. Ordered most severe first; a
# command is assigned AT MOST ONE class, the first that matches, so `sudo rm -rf /`
# is a recursive-delete rather than a privilege escalation footnote.
# ===========================================================================

CLASSES: tuple[str, ...] = (
    "recursive-delete",
    "disk-write",
    "history-rewrite",
    "infra-destroy",
    "db-destructive",
    "remote-code-exec",
    "credential-access",
    "permission-escalation",
    "package-publish",
    "process-kill",
)

CLASS_BLURB: dict[str, str] = {
    "recursive-delete": "Recursive filesystem deletion. Nothing in a shell undoes it.",
    "disk-write": "Raw block-device or filesystem overwrite. Below the reach of any backup agent.",
    "history-rewrite": "Rewrote or discarded version-control history or uncommitted work.",
    "infra-destroy": "Destroyed or unconditionally mutated cloud / cluster infrastructure.",
    "db-destructive": "Dropped, truncated, or unfiltered-deleted persistent data.",
    "remote-code-exec": "Piped a network download straight into an interpreter. Unreviewed code, full privileges.",
    "credential-access": "Read or printed long-lived secrets. A secret that touched a transcript is a secret to rotate.",
    "permission-escalation": "Ran with, or granted, privileges above the session's own.",
    "package-publish": "Published an artifact to a registry the world can install from.",
    "process-kill": "Force-terminated processes or disabled services.",
}

SEVERITY_INDEX = {name: i for i, name in enumerate(CLASSES)}

# --- suppression sets -------------------------------------------------------
# Heads whose entire job is to LOOK at text. Anything they are handed is data.
SEARCH_HEADS = {
    "grep", "egrep", "fgrep", "rg", "ripgrep", "ag", "ack", "ack-grep", "pt",
    "ripgrep-all", "history", "fc", "locate", "mdfind", "apropos", "man",
    "whatis", "comm", "diff", "cmp", "wc", "sort", "uniq", "column", "jq",
    "fzf", "peco", "tree", "ls", "stat", "file", "du", "df",
}
# Heads that emit text. Only credential-access is evaluated for these, and only
# after inert quoted literals are removed — see classify_stage().
TEXT_EMITTERS = {"echo", "printf", "print", "cat", "bat", "tee", "pbcopy", "clip"}
# `git` subcommands that read, stage, or annotate but never destroy.
GIT_INERT_SUBCOMMANDS = {
    "log", "show", "diff", "blame", "grep", "status", "remote", "config",
    "fetch", "pull", "add", "commit", "tag", "describe", "rev-parse", "rev-list",
    "ls-files", "ls-remote", "shortlog", "bisect", "worktree", "switch", "init",
    "clone", "cherry", "notes", "reflog", "whatchanged", "apply", "am", "merge",
}
# Interpreters that turn a download into execution.
INTERPRETERS = {
    "sh", "bash", "zsh", "ksh", "dash", "ash", "fish", "csh", "tcsh",
    "python", "python2", "python3", "perl", "ruby", "node", "deno", "bun",
    "php", "pwsh", "powershell", "osascript",
}
DOWNLOADERS = {"curl", "wget", "fetch", "aria2c", "http", "httpie", "iwr", "irm"}

_DRY_RUN_RE = re.compile(
    r"(?:^|\s)--?(?:dry[-_]?run|what[-_]?if|whatif|no[-_]?op|noop|just[-_]?print)\b",
    re.IGNORECASE)


def is_dry_run(text: str) -> bool:
    """`--dry-run`, `--what-if`, `kubectl ... --dry-run=client`: a rehearsal, not an act."""
    return bool(_DRY_RUN_RE.search(text))


def _rx(*patterns: str, flags: int = re.IGNORECASE) -> list[re.Pattern[str]]:
    return [re.compile(p, flags) for p in patterns]


DISK_WRITE_RX = _rx(
    r"\bdd\b[^\n]{0,400}?\bof\s*=\s*/dev/",
    r"\bmkfs(?:\.[a-z0-9]+)?\b",
    r"\b(?:fdisk|sfdisk|cfdisk|gdisk|parted|wipefs|shred|blkdiscard|badblocks)\b",
    r"\bdiskutil\s+(?:erase\w*|partitionDisk|reformat)\b",
    r"\bdiskpart\b|\bformat\s+[a-z]:",
)
INFRA_DESTROY_RX = _rx(
    r"\bterra(?:form|grunt)\b[^\n]{0,200}?\bdestroy\b",
    r"\bterra(?:form|grunt)\b[^\n]{0,200}?\bapply\b[^\n]{0,200}?-auto-approve\b",
    r"\bpulumi\b[^\n]{0,120}?\bdestroy\b",
    r"\bkubectl\b[^\n]{0,200}?\bdelete\b",
    r"\bhelm\b[^\n]{0,120}?\b(?:uninstall|delete)\b",
    r"\baws\b[^\n]{0,200}?\bdelete-[a-z0-9-]+\b",
    r"\baws\s+s3(?:api)?\b[^\n]{0,200}?\b(?:rb|delete-bucket|delete-objects?)\b",
    r"\baws\s+s3\b[^\n]{0,200}?\brm\b[^\n]{0,200}?--recursive\b",
    r"\bgcloud\b[^\n]{0,200}?\bdelete\b",
    r"\baz\s+[a-z]+[^\n]{0,200}?\bdelete\b",
    r"\bdoctl\b[^\n]{0,200}?\bdelete\b",
    r"\bfly(?:ctl)?\b[^\n]{0,120}?\b(?:destroy|apps\s+destroy)\b",
    r"\bvercel\b[^\n]{0,120}?\b(?:rm|remove)\b",
    r"\bheroku\s+apps:destroy\b",
    r"\bdocker\s+swarm\s+leave\b[^\n]{0,60}--force",
)
DB_DESTRUCTIVE_RX = _rx(
    r"\bdrop\s+(?:table|database|schema|index|view|collection)\b",
    r"\btruncate\s+(?:table\s+)?[\w`\"\[.]",
    r"\bdelete\s+from\s+[\w`\"\[.]+(?![^;]*\bwhere\b)",
    r"\bflushall\b|\bflushdb\b",
    r"\bdb\s*\.\s*dropDatabase\s*\(|\bdropDatabase\s*\(",
    r"\bdb\s*\.\s*\w+\s*\.\s*(?:drop|remove)\s*\(",
    r"\balembic\s+downgrade\b",
    r"\bprisma\s+migrate\s+reset\b",
    r"\b(?:dropdb|dropuser)\b",
    r"\brails\s+db:(?:drop|reset)\b",
    r"\b(?:manage\.py|django-admin)\s+flush\b",
    r"\bmongo(?:sh)?\b[^\n]{0,200}?\bdrop\w*\s*\(",
)
REMOTE_EXEC_RX = _rx(
    r"\biex\s*\(\s*(?:irm|iwr|New-Object|Invoke-WebRequest|Invoke-RestMethod)",
    r"\bInvoke-Expression\b[^\n]{0,200}?(?:Invoke-WebRequest|Invoke-RestMethod|DownloadString)",
    r"\bDownloadString\s*\(",
    r"\b(?:ba|z|k|da|)sh\s+<\s*\(\s*(?:curl|wget)\b",
    r"\bcurl\b[^\n]{0,300}?\|\s*(?:sudo\s+)?(?:ba|z|k|da|)sh\b",
    r"\bwget\b[^\n]{0,300}?\|\s*(?:sudo\s+)?(?:ba|z|k|da|)sh\b",
)
CREDENTIAL_RX = _rx(
    r"\.ssh/id_(?:rsa|dsa|ecdsa|ed25519)\b",
    r"[~/]\.ssh/id_[\w.-]*",
    r"\.aws/credentials\b",
    r"[~/]\.netrc\b",
    r"\.docker/config\.json\b",
    r"\.kube/config\b",
    r"\bgcloud\s+auth\s+print-(?:access|identity)-token\b",
    r"\bsecurity\s+find-(?:generic|internet)-password\b",
    r"\bkubectl\s+get\s+secrets?\b",
    r"\bvault\s+(?:read|kv\s+get)\b",
    r"\bop\s+item\s+get\b",
    r"\baws\s+sts\s+get-session-token\b",
    r"\bprintenv\b[^\n]{0,80}?(?:KEY|TOKEN|SECRET|PASSWORD)",
    # Reading/exfiltrating a dotenv needs an actual reader verb — bare `.env` in a
    # path argument is far too common to flag.
    r"\b(?:cat|bat|less|more|head|tail|xxd|base64|strings|cp|scp|rsync|sftp|curl|source)\b"
    r"[^\n]{0,200}?(?:^|[\s/'\"=])\.env(?:\.[\w.-]+)?\b",
    # Printing a credential-shaped environment variable.
    r"\$\{?[A-Z0-9_]*(?:API_?KEY|APIKEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIALS?)[A-Z0-9_]*\}?",
)
PERMISSION_RX = _rx(
    r"(?:^|[\s;&|(])sudo\b",
    r"(?:^|[\s;&|(])doas\b",
    r"\bsu\s+(?:-|root)\b",
    r"\bchmod\s+(?:-[a-zA-Z]+\s+)*(?:0?777|a\+rwx)\b",
    r"\bchmod\s+(?:-[a-zA-Z]+\s+)*[ugoa]*\+s\b",
    r"\bchown\s+(?:-[a-zA-Z]+\s+)*root\b",
    r"\bsetcap\b",
    r"/etc/sudoers",
    r"\bvisudo\b",
    r"\brunas\s+/user:administrator\b",
    r"\bStart-Process\b[^\n]{0,120}?-Verb\s+RunAs",
)
PACKAGE_PUBLISH_RX = _rx(
    r"\bnpm\s+publish\b",
    r"\b(?:yarn|pnpm|bun)\s+publish\b",
    r"\btwine\s+upload\b",
    r"\bcargo\s+publish\b",
    r"\bdocker\s+push\b",
    r"\bgh\s+release\s+create\b",
    r"\bpoetry\s+publish\b",
    r"\b(?:uv|flit|hatch)\s+publish\b",
    r"\bgem\s+push\b",
    r"\bmvn\b[^\n]{0,120}?\bdeploy\b",
    r"\bpip3?\s+install\b[^\n]{0,300}?(?:https?://|git\+)",
)
PROCESS_KILL_RX = _rx(
    r"\bkill\s+(?:-9|-KILL|-SIGKILL|-s\s*(?:9|KILL|SIGKILL))\b",
    r"\bkillall\b",
    r"\bpkill\b",
    r"\bsystemctl\s+(?:stop|disable|mask)\b",
    r"\bservice\s+\S+\s+stop\b",
    r"\bdocker\s+(?:rm\s+-\w*f|kill|stop)\b",
    r"\bdocker\s+(?:system|container|image|volume|network|builder)\s+prune\b",
    r"\blaunchctl\s+(?:unload|bootout)\b",
    r"\bsupervisorctl\s+stop\b",
    r"\btaskkill\b[^\n]{0,80}?/f\b",
)
# `find ... -delete` / `-exec rm` is a recursive delete wearing a different hat.
FIND_DESTRUCTIVE = ("-delete", "-exec", "-execdir", "-ok", "-okdir")

DISPOSABLE_BASENAMES = {
    "node_modules", ".venv", "venv", "env", "dist", "build", "__pycache__",
    "target", ".next", ".nuxt", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".tox", ".cache", ".parcel-cache", ".turbo", ".gradle", ".terraform",
    "coverage", "htmlcov", ".coverage", "out", ".output", ".svelte-kit",
    ".angular", "bower_components", ".sass-cache", ".eslintcache", ".DS_Store",
    "vendor", ".nyc_output", "cmake-build-debug", "obj", "bin",
}
_TMP_PREFIXES = ("/tmp/", "/var/tmp/", "/private/tmp/", "$TMPDIR", "${TMPDIR}",
                 "%temp%", "/dev/shm/")
# Absolute paths rooted here are never "disposable" no matter what they are named.
# `/usr/bin` contains a component called `bin`; it is not a build directory.
_PROTECTED_ROOTS = {
    "usr", "etc", "var", "opt", "bin", "sbin", "lib", "lib64", "boot", "dev",
    "proc", "sys", "srv", "root", "home", "users", "mnt", "media", "applications",
    "system", "library", "volumes", "windows", "program files",
}


def _is_disposable_path(raw: str) -> bool:
    """True when a path is a regenerable build/temp artifact.

    gate.cat's published corpus methodology draws exactly this line, and the tool
    must match it: `rm -rf node_modules` is a chore, `rm -rf ~/Documents` is an
    incident. Mixing them is how a scan earns the word "FUD".
    """
    t = raw.strip().strip("'\"")
    if not t:
        return False
    low = t.lower()
    if any(low.startswith(p) for p in _TMP_PREFIXES):
        return True
    parts = [p for p in re.split(r"[\\/]+", t) if p and p != "."]
    if not parts:
        return False  # "/" or "." — the opposite of disposable
    if t.startswith("/") and parts[0].lower() in _PROTECTED_ROOTS:
        return False
    return any(p in DISPOSABLE_BASENAMES or p.endswith(".egg-info") or
               p.endswith(".log") for p in parts)


def _rm_flags_and_targets(argv: Sequence[str]) -> Optional[tuple[set[str], list[str]]]:
    """Locate an `rm` anywhere in the stage (sudo/xargs/absolute path all fine)."""
    for i, tok in enumerate(argv):
        base = posixpath.basename(tok.replace("\\", "/")).lower()
        if base not in ("rm", "rm.exe", "unlink"):
            continue
        opts: set[str] = set()
        targets: list[str] = []
        end_of_opts = False
        for u in argv[i + 1:]:
            if u == "--":
                end_of_opts = True
                continue
            if not end_of_opts and u.startswith("--"):
                opts.add(u[2:].split("=")[0].lower())
            elif not end_of_opts and u.startswith("-") and len(u) > 1:
                opts.update(u[1:])
            elif _REDIRECT_RE.match(u):
                continue
            else:
                targets.append(u)
        return opts, targets
    return None


def _match_recursive_delete(stage: str, argv: Sequence[str]) -> Optional[list[str]]:
    """Return the delete targets when the stage recursively removes something."""
    found = _rm_flags_and_targets(argv)
    if found is not None:
        opts, targets = found
        if opts & {"r", "R", "recursive"}:
            return targets
    if head_of(argv) == "find" and any(f in argv for f in FIND_DESTRUCTIVE):
        if "-delete" in argv or any(
                posixpath.basename(t) == "rm" for t in argv):
            return [t for t in argv[1:] if not t.startswith("-")]
    if re.search(r"\bshutil\s*\.\s*rmtree\s*\(", stage):
        return []
    if re.search(r"\bRemove-Item\b[^\n]{0,200}?-Recurse\b", stage, re.IGNORECASE):
        return []
    return None


def _match_history_rewrite(argv: Sequence[str]) -> bool:
    sub, rest = git_subcommand(argv)
    if not sub:
        return False
    flat = " ".join(rest)
    if sub == "push":
        forced = "--force" in rest or "-f" in rest or any(
            r.startswith("-") and not r.startswith("--") and "f" in r[1:] for r in rest)
        lease = any(r.startswith("--force-with-lease") for r in rest)
        return forced and not lease
    if sub == "reset":
        return "--hard" in rest
    if sub == "clean":
        return any(r.startswith("-") and not r.startswith("--") and "f" in r[1:]
                   for r in rest) or "--force" in rest
    if sub == "branch":
        return "-D" in rest or ("--delete" in rest and "--force" in rest)
    if sub in ("filter-branch", "filter-repo"):
        return True
    if sub == "rebase":
        return bool(rest) and (
            "-i" in rest or "--interactive" in rest or "--onto" in rest
            or any(r.startswith(("origin/", "upstream/")) or
                   r in ("main", "master", "develop", "trunk") for r in rest))
    if sub in ("checkout", "restore"):
        return "." in rest or (rest[:1] == ["--"] and "." in rest)
    if sub == "stash":
        return bool(rest) and rest[0] in ("drop", "clear")
    if sub == "update-ref":
        return "-d" in rest
    if sub == "reflog":
        return bool(rest) and rest[0] in ("delete", "expire")
    return False


def _any(rxs: Iterable[re.Pattern[str]], text: str) -> bool:
    return any(rx.search(text) for rx in rxs)


@dataclass(frozen=True)
class Verdict:
    """A classification outcome for one command."""
    klass: str
    disposable: bool
    evidence: str  # the pipeline stage that triggered it (still RAW — redact before output)


def stage_is_inert(stage: str) -> bool:
    """True when a stage only reads or searches — never a candidate for any class."""
    argv = argv_of(stage)
    if not argv:
        return True
    head = head_of(argv)
    if head in SEARCH_HEADS:
        return True
    if head == "git":
        sub, _rest = git_subcommand(argv)
        if sub in GIT_INERT_SUBCOMMANDS:
            return True
    if head == "find" and not any(f in argv for f in FIND_DESTRUCTIVE):
        return True
    return False


def classify_stage(stage: str) -> Optional[Verdict]:
    """Classify a single pipeline stage. Returns None when nothing irreversible."""
    argv = argv_of(stage)
    if not argv:
        return None
    head = head_of(argv)

    # (b) SEARCHING FOR a command is not RUNNING it.
    if stage_is_inert(stage):
        return None

    # (a) WRITING ABOUT a command is not RUNNING it. Text emitters get their inert
    # quoted literals removed and are then judged for credential exposure only.
    if head in TEXT_EMITTERS:
        text = strip_inert_literals(stage)
        if _any(CREDENTIAL_RX, text):
            return Verdict("credential-access", False, stage)
        return None

    text = strip_message_args(stage)
    argv = argv_of(text) or argv

    targets = _match_recursive_delete(text, argv)
    if targets is not None:
        disposable = bool(targets) and all(_is_disposable_path(t) for t in targets)
        return Verdict("recursive-delete", disposable, stage)
    if _any(DISK_WRITE_RX, text):
        return Verdict("disk-write", False, stage)
    if _match_history_rewrite(argv):
        return Verdict("history-rewrite", False, stage)
    if _any(INFRA_DESTROY_RX, text):
        return Verdict("infra-destroy", False, stage)
    if _any(DB_DESTRUCTIVE_RX, text):
        return Verdict("db-destructive", False, stage)
    if _any(REMOTE_EXEC_RX, text):
        return Verdict("remote-code-exec", False, stage)
    if _any(CREDENTIAL_RX, text):
        return Verdict("credential-access", False, stage)
    if _any(PERMISSION_RX, text):
        return Verdict("permission-escalation", False, stage)
    if _any(PACKAGE_PUBLISH_RX, text):
        return Verdict("package-publish", False, stage)
    if _any(PROCESS_KILL_RX, text):
        return Verdict("process-kill", False, stage)
    return None


def _pipes_download_into_interpreter(stages: Sequence[str]) -> bool:
    """Structural `curl … | sh` detection.

    Done on the STAGE LIST rather than on the raw text, so a quoted `'curl x | sh'`
    inside a grep pattern can never trigger it — there is only one stage there.
    """
    seen_download = False
    for st in stages:
        argv = argv_of(st)
        if not argv:
            continue
        head = head_of(argv)
        if head == "sudo":
            head = head_of(argv[1:])
        if seen_download and head in INTERPRETERS:
            return True
        if head in DOWNLOADERS:
            seen_download = True
    return False


def classify(command: str) -> Optional[Verdict]:
    """Classify a whole command string into at most one irreversible class."""
    if not command or not command.strip():
        return None
    hits: list[Verdict] = []
    for pipeline in shell_units(command):
        if is_dry_run(pipeline):
            continue  # a rehearsal is not an act
        stages = split_on_ops(pipeline, _STAGE_OPS)
        if stages and not stage_is_inert(stages[0]) \
                and _pipes_download_into_interpreter(stages):
            hits.append(Verdict("remote-code-exec", False, pipeline))
        for stage in stages:
            v = classify_stage(stage)
            if v is not None:
                hits.append(v)
    if not hits:
        return None
    real = [h for h in hits if not h.disposable]
    pool = real or hits
    pool.sort(key=lambda h: SEVERITY_INDEX[h.klass])
    return pool[0]


# ===========================================================================
# 4. TRANSCRIPT READING
# ---------------------------------------------------------------------------
# Transcripts are large, occasionally truncated mid-line, and sometimes contain
# bytes that are not UTF-8 at all. None of that may crash the scan or silently
# vanish: a bad line is skipped, counted, and reported. Everything streams —
# a 500 MB JSONL is never materialised as a string.
# ===========================================================================

SOURCE_KINDS = ("claude-code", "codex-cli", "fallback-json", "fallback-history")
FALLBACK_KINDS = {"fallback-json", "fallback-history"}


@dataclass
class Event:
    """One command a transcript attributes to an agent. `command` is RAW here and
    is redacted exactly once, at Finding construction."""
    command: str
    executed: bool
    status: str            # ok | error | denied | no-result
    source_path: str
    source_kind: str
    session: str
    timestamp: Optional[str] = None

    @property
    def confidence(self) -> str:
        return "low" if self.source_kind in FALLBACK_KINDS else "high"


@dataclass
class ScanStats:
    files_scanned: int = 0
    files_by_kind: dict[str, int] = field(default_factory=dict)
    lines_read: int = 0
    lines_skipped: int = 0
    invalid_utf8_lines: int = 0
    oversize_lines: int = 0
    unreadable: list[str] = field(default_factory=list)

    def note_file(self, kind: str) -> None:
        self.files_scanned += 1
        self.files_by_kind[kind] = self.files_by_kind.get(kind, 0) + 1


def _iter_raw_lines(fh: Any) -> Iterator[Optional[bytes]]:
    """Yield newline-delimited byte records; yield None for an oversize record."""
    buf = b""
    while True:
        chunk = fh.read(1 << 20)
        if not chunk:
            if buf:
                yield buf if len(buf) <= MAX_LINE_BYTES else None
            return
        buf += chunk
        while True:
            idx = buf.find(b"\n")
            if idx < 0:
                break
            line = buf[:idx]
            buf = buf[idx + 1:]
            yield line if len(line) <= MAX_LINE_BYTES else None
        if len(buf) > MAX_LINE_BYTES:
            # A record with no newline in sight; drop it rather than grow forever.
            yield None
            buf = b""


def iter_text_lines(path: Path, stats: ScanStats) -> Iterator[str]:
    """Stream a file as decoded lines, tolerating undecodable bytes."""
    try:
        fh = open(path, "rb")
    except OSError as exc:
        stats.unreadable.append(f"{path}: {exc.__class__.__name__}")
        return
    try:
        with fh:
            for raw in _iter_raw_lines(fh):
                if raw is None:
                    stats.lines_read += 1
                    stats.lines_skipped += 1
                    stats.oversize_lines += 1
                    continue
                stats.lines_read += 1
                try:
                    yield raw.decode("utf-8")
                except UnicodeDecodeError:
                    stats.invalid_utf8_lines += 1
                    yield raw.decode("utf-8", "replace")
    except OSError as exc:  # disappeared / permissions changed mid-read
        stats.unreadable.append(f"{path}: {exc.__class__.__name__}")


def iter_json_objects(path: Path, stats: ScanStats) -> Iterator[dict]:
    """Stream JSON objects, one per line. Malformed lines are counted and skipped."""
    for line in iter_text_lines(path, stats):
        s = line.strip()
        if not s or s[0] not in "{[":
            if s:
                stats.lines_skipped += 1
            continue
        try:
            obj = json.loads(s)
        except (ValueError, RecursionError):
            stats.lines_skipped += 1
            continue
        if isinstance(obj, dict):
            yield obj
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    yield item


# --- small shared helpers ---------------------------------------------------

SHELL_TOOL_NAMES = {
    "bash", "bashtool", "shell", "run_command", "runcommand", "execute_command",
    "run_terminal_cmd", "terminal", "local_shell", "container.exec",
    "exec_command", "shell_command", "sh",
}

DENIAL_MARKERS = (
    "the user doesn't want to proceed",
    "the user doesn't want to take this action",
    "tool use was rejected",
    "user rejected",
    "user denied",
    "denied by user",
    "permission denied by user",
    "requested permissions",
    "haven't granted it yet",
    "has not granted",
    "operation not permitted by hook",
    "blocked by hook",
    "blocked by policy",
    "denied by policy",
    "permission to use",
    "cancelled by user",
    "canceled by user",
    "aborted by user",
)


def is_shell_tool(name: Any) -> bool:
    if not isinstance(name, str):
        return False
    low = name.strip().lower()
    return low in SHELL_TOOL_NAMES or low.startswith("bash")


def command_from_value(value: Any) -> str:
    """Accept a command as a string or as an argv list (Codex sends argv)."""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        parts = [p for p in value if isinstance(p, str)]
        if not parts:
            return ""
        # ["bash", "-lc", "<script>"] — the script IS the command.
        if len(parts) >= 3 and posixpath.basename(parts[0]) in INTERPRETERS \
                and parts[1].startswith("-"):
            return parts[-1]
        try:
            return shlex.join(parts)
        except (TypeError, AttributeError):  # pragma: no cover - py<3.8 guard
            return " ".join(parts)
    return ""


def flatten_text(value: Any, depth: int = 0) -> str:
    """Squash a tool_result `content` (str | list | dict) into searchable text."""
    if depth > 4:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        if isinstance(value.get("text"), str):
            return value["text"]
        return " ".join(flatten_text(v, depth + 1) for v in value.values())
    if isinstance(value, (list, tuple)):
        return " ".join(flatten_text(v, depth + 1) for v in value[:64])
    return "" if value is None else str(value)


def result_status(is_error: bool, text: str) -> str:
    """ok | error | denied.

    A denial outranks a generic error because the two mean very different things
    to a buyer: `denied` is the counterfactual — proof that a gate, when present,
    actually stopped something.
    """
    low = (text or "").lower()
    if any(marker in low for marker in DENIAL_MARKERS):
        return "denied"
    if is_error:
        return "error"
    return "ok"


def norm_timestamp(value: Any) -> Optional[str]:
    """Normalise assorted timestamp shapes to an ISO-8601 string (UTC where known)."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            if value > 1e11:  # milliseconds
                value = value / 1000.0
            return _dt.datetime.fromtimestamp(value, _dt.timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            parsed = _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
            return parsed.isoformat()
        except ValueError:
            return s[:64]
    return None


def timestamp_date(ts: Optional[str]) -> Optional[str]:
    return ts[:10] if ts and len(ts) >= 10 and ts[4] == "-" else None


# --- parser: Claude Code ----------------------------------------------------

def parse_claude_code(path: Path, stats: ScanStats) -> list[Event]:
    """Claude Code JSONL sessions (`~/.claude/projects/<slug>/<session>.jsonl`).

    The whole point of this parser is the tool_use_id correlation. A `tool_use`
    without a matching non-error, non-denied `tool_result` was PROPOSED, not
    EXECUTED, and it goes in a different bucket. Without that distinction the
    headline number is just the model's imagination.
    """
    session = path.stem
    pending: dict[str, tuple[str, Optional[str]]] = {}
    order: list[str] = []
    events: list[Event] = []

    for obj in iter_json_objects(path, stats):
        ts = norm_timestamp(obj.get("timestamp") or obj.get("ts"))
        msg = obj.get("message")
        containers: list[Any] = []
        if isinstance(msg, dict):
            containers.append(msg.get("content"))
        containers.append(obj.get("content"))
        for content in containers:
            if not isinstance(content, list):
                continue
            for item in content:
                if not isinstance(item, dict):
                    continue
                itype = item.get("type")
                if itype == "tool_use" and is_shell_tool(item.get("name")):
                    inp = item.get("input")
                    cmd = command_from_value(inp.get("command")) if isinstance(inp, dict) \
                        else command_from_value(inp)
                    tid = str(item.get("id") or f"__anon{len(order)}")
                    if cmd.strip():
                        pending[tid] = (cmd, ts)
                        order.append(tid)
                elif itype == "tool_result":
                    tid = str(item.get("tool_use_id") or item.get("id") or "")
                    rec = pending.pop(tid, None)
                    if rec is None:
                        continue
                    cmd, cmd_ts = rec
                    status = result_status(bool(item.get("is_error")),
                                           flatten_text(item.get("content")))
                    events.append(Event(
                        command=cmd, executed=(status == "ok"), status=status,
                        source_path=str(path), source_kind="claude-code",
                        session=session, timestamp=cmd_ts or ts))

    for tid in order:
        rec = pending.pop(tid, None)
        if rec is None:
            continue
        cmd, cmd_ts = rec
        events.append(Event(command=cmd, executed=False, status="no-result",
                            source_path=str(path), source_kind="claude-code",
                            session=session, timestamp=cmd_ts))
    return events


# --- parser: Codex CLI ------------------------------------------------------

_CODEX_CALL_TYPES = {"function_call", "local_shell_call", "custom_tool_call"}
_CODEX_OUTPUT_TYPES = {"function_call_output", "local_shell_call_output",
                       "custom_tool_call_output"}


def _codex_command(payload: dict) -> str:
    """Pull the command out of a Codex shell call (arguments may be a JSON string)."""
    for key in ("arguments", "action", "input", "params"):
        raw = payload.get(key)
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except ValueError:
                return raw
        if isinstance(raw, dict):
            for ckey in ("command", "cmd", "commands"):
                if ckey in raw:
                    cmd = command_from_value(raw[ckey])
                    if cmd.strip():
                        return cmd
        elif isinstance(raw, (list, tuple)):
            cmd = command_from_value(raw)
            if cmd.strip():
                return cmd
    return command_from_value(payload.get("command"))


def _codex_status(payload: dict) -> str:
    """Codex records an exit code; treat non-zero as 'ran but failed' -> not counted."""
    out = payload.get("output")
    parsed: Any = out
    if isinstance(out, str):
        try:
            parsed = json.loads(out)
        except ValueError:
            parsed = out
    text = flatten_text(parsed)
    exit_code: Any = None
    if isinstance(parsed, dict):
        meta = parsed.get("metadata")
        if isinstance(meta, dict):
            exit_code = meta.get("exit_code")
        if exit_code is None:
            exit_code = parsed.get("exit_code")
    if exit_code is None:
        exit_code = payload.get("exit_code")
    if isinstance(payload.get("status"), str) and payload["status"] in ("failed", "error"):
        return result_status(True, text)
    is_error = bool(exit_code) if isinstance(exit_code, int) else False
    return result_status(is_error, text)


def parse_codex(path: Path, stats: ScanStats) -> list[Event]:
    """Codex CLI rollout logs (`~/.codex/sessions/**/rollout-*.jsonl`)."""
    session = path.stem
    pending: dict[str, tuple[str, Optional[str]]] = {}
    order: list[str] = []
    events: list[Event] = []

    for obj in iter_json_objects(path, stats):
        ts = norm_timestamp(obj.get("timestamp") or obj.get("ts"))
        payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else obj
        ptype = payload.get("type") or obj.get("type")
        if ptype in _CODEX_CALL_TYPES:
            name = payload.get("name") or ("shell" if ptype == "local_shell_call" else "")
            if not is_shell_tool(name):
                continue
            cmd = _codex_command(payload)
            if not cmd.strip():
                continue
            cid = str(payload.get("call_id") or payload.get("id") or f"__anon{len(order)}")
            pending[cid] = (cmd, ts)
            order.append(cid)
        elif ptype in _CODEX_OUTPUT_TYPES:
            cid = str(payload.get("call_id") or payload.get("id") or "")
            rec = pending.pop(cid, None)
            if rec is None:
                continue
            cmd, cmd_ts = rec
            status = _codex_status(payload)
            events.append(Event(command=cmd, executed=(status == "ok"), status=status,
                                source_path=str(path), source_kind="codex-cli",
                                session=session, timestamp=cmd_ts or ts))

    for cid in order:
        rec = pending.pop(cid, None)
        if rec is None:
            continue
        cmd, cmd_ts = rec
        events.append(Event(command=cmd, executed=False, status="no-result",
                            source_path=str(path), source_kind="codex-cli",
                            session=session, timestamp=cmd_ts))
    return events


# --- parser: permissive fallback -------------------------------------------

_COMMAND_KEYS = {"command", "cmd", "shell_command", "commandline", "command_line",
                 "bash_command", "script"}
_TS_KEYS = ("timestamp", "ts", "time", "created_at", "createdAt", "date")


def _walk_for_commands(node: Any, depth: int = 0) -> Iterator[tuple[str, Optional[str]]]:
    if depth > 8:
        return
    if isinstance(node, dict):
        ts = next((norm_timestamp(node[k]) for k in _TS_KEYS if k in node), None)
        for key, value in node.items():
            if key.lower() in _COMMAND_KEYS:
                cmd = command_from_value(value)
                if cmd.strip():
                    yield cmd, ts
                    continue
            for sub_cmd, sub_ts in _walk_for_commands(value, depth + 1):
                yield sub_cmd, sub_ts or ts
    elif isinstance(node, list):
        for item in node[:2000]:
            yield from _walk_for_commands(item, depth + 1)


def parse_generic_json(path: Path, stats: ScanStats) -> list[Event]:
    """Cursor / aider / anything-else JSON or JSONL.

    LOW CONFIDENCE BY CONSTRUCTION. There is no result correlation available here,
    so nothing found this way is ever counted as 'executed'; it is reported in a
    separate, clearly-labelled section.
    """
    events: list[Event] = []
    for obj in iter_json_objects(path, stats):
        for cmd, ts in _walk_for_commands(obj):
            events.append(Event(command=cmd, executed=False, status="unknown",
                                source_path=str(path), source_kind="fallback-json",
                                session=path.stem, timestamp=ts))
    return events


_ZSH_HISTORY_RE = re.compile(r"^:\s*(\d{9,13}):\d+;(.*)$")


def parse_shell_history(path: Path, stats: ScanStats) -> list[Event]:
    """Plain shell history. A shell history is NOT agent activity — it is a human's
    keystrokes plus, sometimes, an agent's. It is parsed only to give the report a
    denominator, and it never enters the headline number."""
    events: list[Event] = []
    carry = ""
    for line in iter_text_lines(path, stats):
        line = line.rstrip("\n")
        ts: Optional[str] = None
        m = _ZSH_HISTORY_RE.match(line)
        if m:
            ts = norm_timestamp(int(m.group(1)))
            line = m.group(2)
        if carry:
            line = carry + "\n" + line
            carry = ""
        if line.endswith("\\"):
            carry = line[:-1]
            continue
        if not line.strip():
            continue
        events.append(Event(command=line, executed=False, status="unknown",
                            source_path=str(path), source_kind="fallback-history",
                            session=path.name, timestamp=ts))
    return events


# ===========================================================================
# 5. DISCOVERY + FORMAT DETECTION
# ===========================================================================

DEFAULT_ROOT_GLOBS = (
    ".claude/projects",
    ".codex/sessions",
    ".cursor",
    ".aider*",
    ".config/aider",
)
SCAN_SUFFIXES = {".jsonl", ".json", ".ndjson", ".log", ".txt", ".history"}
HISTORY_NAMES = {".bash_history", ".zsh_history", ".sh_history", ".history",
                 ".python_history", "history"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache",
             ".pytest_cache", "site-packages", ".terraform"}


def default_roots(home: Optional[Path] = None) -> list[Path]:
    """Where agent transcripts live if nobody tells us otherwise."""
    base = home or Path.home()
    roots: list[Path] = []
    for pattern in DEFAULT_ROOT_GLOBS:
        if any(ch in pattern for ch in "*?["):
            roots.extend(sorted(base.glob(pattern)))
        else:
            roots.append(base / pattern)
    return [r for r in roots if r.exists()]


def discover_files(paths: Sequence[Path]) -> list[Path]:
    """Collect candidate transcript files. Symlinks are not followed (no loops,
    and no wandering out of the tree the user pointed at)."""
    found: list[Path] = []
    seen: set[str] = set()
    for root in paths:
        if root.is_file():
            key = str(root.resolve())
            if key not in seen:
                seen.add(key)
                found.append(root)
            continue
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                p = Path(dirpath) / name
                if p.suffix.lower() in SCAN_SUFFIXES or name in HISTORY_NAMES \
                        or name.endswith("_history"):
                    try:
                        key = str(p.resolve())
                    except OSError:
                        continue
                    if key in seen or p.is_symlink():
                        continue
                    seen.add(key)
                    found.append(p)
    return sorted(found)


def detect_format(path: Path) -> str:
    """Auto-detect a transcript format by sniffing content, with path hints as
    a tie-break. Detection is content-first on purpose: prospects copy transcripts
    into odd places, and a wrong guess silently loses their data.

    The sniff uses a throwaway counter: a detection pass must never inflate the
    parse-skip numbers the report publishes.
    """
    sniff_stats = ScanStats()
    posix = str(path).replace("\\", "/")
    name = path.name.lower()

    if name in HISTORY_NAMES or name.endswith("_history"):
        return "fallback-history"

    claude_score = 3 if "/.claude/projects/" in posix else 0
    codex_score = 3 if "/.codex/" in posix or "rollout-" in name else 0
    json_lines = 0
    text_lines = 0

    checked = 0
    for line in iter_text_lines(path, sniff_stats):
        s = line.strip()
        if not s:
            continue
        checked += 1
        if checked > 60:
            break
        if s[0] not in "{[":
            text_lines += 1
            continue
        try:
            obj = json.loads(s)
        except ValueError:
            continue
        if not isinstance(obj, dict):
            json_lines += 1
            continue
        json_lines += 1
        payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else obj
        ptype = str(payload.get("type") or obj.get("type") or "")
        if ptype in _CODEX_CALL_TYPES | _CODEX_OUTPUT_TYPES or \
                ptype in ("session_meta", "turn_context", "response_item", "event_msg"):
            codex_score += 2
        if isinstance(obj.get("message"), dict) or "uuid" in obj or \
                "parentUuid" in obj or "toolUseResult" in obj or \
                ptype in ("assistant", "user", "summary", "system"):
            claude_score += 2

    if claude_score == 0 and codex_score == 0:
        if json_lines == 0 and text_lines > 0:
            return "fallback-history"
        return "fallback-json"
    return "claude-code" if claude_score >= codex_score else "codex-cli"


PARSERS: dict[str, Callable[[Path, ScanStats], list[Event]]] = {
    "claude-code": parse_claude_code,
    "codex-cli": parse_codex,
    "fallback-json": parse_generic_json,
    "fallback-history": parse_shell_history,
}


# ===========================================================================
# 6. FINDINGS + REPORT MODEL
# ===========================================================================

@dataclass
class Finding:
    """A classified command, REDACTED. Nothing downstream ever sees raw text."""
    klass: str
    command: str
    timestamp: Optional[str]
    session: str
    source_path: str
    source_kind: str
    confidence: str
    status: str
    disposable: bool

    def to_json(self) -> dict:
        return {
            "class": self.klass,
            "command": self.command,
            "timestamp": self.timestamp,
            "session": self.session,
            "source": self.source_path,
            "source_kind": self.source_kind,
            "confidence": self.confidence,
            "result_status": self.status,
            "bucket": "disposable" if self.disposable else "headline",
        }


@dataclass
class Report:
    stats: ScanStats
    sessions: set[str] = field(default_factory=set)
    executed_total: int = 0
    proposed_total: int = 0
    unverified_total: int = 0
    proposed_by_status: dict[str, int] = field(default_factory=dict)
    dates: list[str] = field(default_factory=list)
    exec_dates: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)          # executed, headline
    disposable: list[Finding] = field(default_factory=list)        # executed, low severity
    proposed_findings: list[Finding] = field(default_factory=list) # not executed
    unverified_findings: list[Finding] = field(default_factory=list)  # fallback sources
    generated_at: str = ""
    scanned_paths: list[str] = field(default_factory=list)
    since: Optional[str] = None

    # -- derived ------------------------------------------------------------
    @property
    def date_range(self) -> tuple[Optional[str], Optional[str]]:
        """Span of the EXECUTED commands, because that is what the headline claims.

        Falls back to the full span only when nothing executable was dated — a
        shell history from 2019 must not stretch the sentence a buyer reads first.
        """
        pool = self.exec_dates or self.dates
        if not pool:
            return None, None
        return min(pool), max(pool)

    def counts_by_class(self, findings: Sequence[Finding]) -> dict[str, int]:
        counts = {c: 0 for c in CLASSES}
        for f in findings:
            counts[f.klass] = counts.get(f.klass, 0) + 1
        return counts

    @property
    def headline_count(self) -> int:
        return len(self.findings)


def scan_paths(paths: Sequence[Path], since: Optional[str] = None) -> Report:
    """Read every discovered transcript, classify, and assemble the report."""
    stats = ScanStats()
    report = Report(stats=stats, since=since)
    report.generated_at = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    report.scanned_paths = [str(p) for p in paths]

    for path in discover_files(paths):
        kind = detect_format(path)
        parser = PARSERS.get(kind, parse_generic_json)
        try:
            events = parser(path, stats)
        except Exception as exc:  # a single broken file must never end the scan
            stats.unreadable.append(f"{path}: {exc.__class__.__name__}: {exc}")
            continue
        stats.note_file(kind)
        for event in events:
            _absorb(report, event, since)
    return report


def _absorb(report: Report, event: Event, since: Optional[str]) -> None:
    date = timestamp_date(event.timestamp)
    if since and date and date < since:
        return
    report.sessions.add(f"{event.source_kind}:{event.session}")
    if date:
        report.dates.append(date)

    high = event.confidence == "high"
    if high and event.executed:
        report.executed_total += 1
        if date:
            report.exec_dates.append(date)
    elif high:
        report.proposed_total += 1
        report.proposed_by_status[event.status] = \
            report.proposed_by_status.get(event.status, 0) + 1
    else:
        report.unverified_total += 1

    verdict = classify(event.command)
    if verdict is None:
        return

    finding = Finding(
        klass=verdict.klass,
        command=redact(event.command),          # <-- the only place raw text leaves
        timestamp=event.timestamp,
        session=event.session,
        source_path=event.source_path,
        source_kind=event.source_kind,
        confidence=event.confidence,
        status=event.status,
        disposable=verdict.disposable,
    )
    if not high:
        report.unverified_findings.append(finding)
    elif not event.executed:
        report.proposed_findings.append(finding)
    elif verdict.disposable:
        report.disposable.append(finding)
    else:
        report.findings.append(finding)


# ===========================================================================
# 7. RENDERING
# ---------------------------------------------------------------------------
# The report has one job: be defensible. Every number is accompanied by what it
# excludes. The methodology section is written in the tool's own voice and is not
# optional — a scan that reports only its findings and not its blind spots is a
# sales deck with a monospace font.
# ===========================================================================

HONEST_LIMITS_LINE = (
    "The scan is certain only about what it found; an unparsed session is unknown, "
    "not clean."
)

NOT_PROOF_LINE = (
    "A command in an irreversible class is not proof that harm occurred. It is proof "
    "that the class was reachable — that at the moment it ran, nothing in the loop was "
    "positioned to stop it."
)


def methodology_lines(report: Report) -> list[str]:
    lo, hi = report.date_range
    s = report.stats
    kinds = ", ".join(f"{k}={v}" for k, v in sorted(s.files_by_kind.items())) or "none"
    return [
        f"What it counted: shell commands issued by an agent through a shell tool in "
        f"{len(report.sessions)} session(s) across {s.files_scanned} transcript file(s) "
        f"({kinds}), between {lo or 'unknown'} and {hi or 'unknown'}. A command counts "
        f"as EXECUTED only when the transcript carries a matching tool result that is "
        f"neither an error nor a permission denial.",
        f"What it deliberately excluded: {report.proposed_total} tool call(s) that were "
        f"proposed but have no clean result (denied, errored, or never returned), and "
        f"{len(report.disposable)} deletion(s) whose every target is a regenerable build "
        f"or temp artifact (node_modules, dist, __pycache__, /tmp/...). Those are counted "
        f"and shown separately, never in the headline.",
        "What it could not see: commands you or your agents ran outside an agent session "
        "(a terminal, CI, a container, a teammate's laptop); sessions already rotated, "
        "compacted, or deleted; and anything inside a transcript this parser could not "
        "read — " + f"{s.lines_skipped} malformed line(s), {s.invalid_utf8_lines} line(s) "
        f"with invalid UTF-8, {len(s.unreadable)} unreadable file(s).",
        "Lower-confidence sources: shell histories and unrecognised JSON are parsed with a "
        "permissive fallback that cannot correlate a command with a result, and a shell "
        "history is not agent activity at all. Everything from those sources is quarantined "
        "in its own section and excluded from every headline number.",
        NOT_PROOF_LINE,
        HONEST_LIMITS_LINE,
    ]


# --- terminal ---------------------------------------------------------------

def render_terminal(report: Report) -> str:
    lo, hi = report.date_range
    s = report.stats
    out: list[str] = []
    add = out.append
    add("=" * 72)
    add(f"  gate.cat retro-scan v{TOOL_VERSION} — read-only, offline, redacted")
    add("=" * 72)
    add(f"  sessions scanned .............. {len(report.sessions)}")
    add(f"  transcript files .............. {s.files_scanned} "
        f"({', '.join(f'{k}:{v}' for k, v in sorted(s.files_by_kind.items())) or 'none'})")
    add(f"  date range .................... {lo or 'unknown'} .. {hi or 'unknown'}")
    add(f"  commands EXECUTED ............. {report.executed_total}")
    add(f"  commands proposed, not run .... {report.proposed_total} "
        f"({', '.join(f'{k}={v}' for k, v in sorted(report.proposed_by_status.items())) or '-'})")
    add(f"  low-confidence (fallback) ..... {report.unverified_total}")
    add(f"  parse skips ................... {s.lines_skipped} "
        f"(invalid utf-8 lines: {s.invalid_utf8_lines}, oversize: {s.oversize_lines}, "
        f"unreadable files: {len(s.unreadable)})")
    add("-" * 72)
    add(f"  IRREVERSIBLE CLASSES — executed ({report.headline_count} total)")
    counts = report.counts_by_class(report.findings)
    for klass in CLASSES:
        marker = "!" if counts[klass] else " "
        add(f"   {marker} {klass:<24} {counts[klass]:>6}")
    add("-" * 72)
    add(f"  disposable artifact cleanups (low severity, excluded above): "
        f"{len(report.disposable)}")
    add(f"  irreversible-class calls PROPOSED but not executed: "
        f"{len(report.proposed_findings)}")
    add(f"  irreversible-class matches from LOW-CONFIDENCE sources: "
        f"{len(report.unverified_findings)}")
    add("-" * 72)
    add(f"  {NOT_PROOF_LINE}")
    add(f"  {HONEST_LIMITS_LINE}")
    add("=" * 72)
    return "\n".join(out)


# --- JSON -------------------------------------------------------------------

def render_json(report: Report) -> str:
    lo, hi = report.date_range
    s = report.stats
    doc = {
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "schema": SCHEMA_VERSION,
        "generated_at": report.generated_at,
        "scanned_paths": report.scanned_paths,
        "since": report.since,
        "totals": {
            "sessions": len(report.sessions),
            "files": s.files_scanned,
            "files_by_kind": s.files_by_kind,
            "commands_executed": report.executed_total,
            "commands_proposed_not_executed": report.proposed_total,
            "commands_low_confidence": report.unverified_total,
            "irreversible_executed": report.headline_count,
            "disposable_executed": len(report.disposable),
            "lines_read": s.lines_read,
            "lines_skipped": s.lines_skipped,
            "invalid_utf8_lines": s.invalid_utf8_lines,
            "oversize_lines": s.oversize_lines,
            "unreadable_files": s.unreadable,
        },
        "date_range": {"from": lo, "to": hi},
        "proposed_by_status": report.proposed_by_status,
        "counts_by_class": report.counts_by_class(report.findings),
        "counts_by_class_disposable": report.counts_by_class(report.disposable),
        "counts_by_class_proposed": report.counts_by_class(report.proposed_findings),
        "counts_by_class_low_confidence": report.counts_by_class(report.unverified_findings),
        "findings": [f.to_json() for f in report.findings],
        "disposable_findings": [f.to_json() for f in report.disposable],
        "proposed_findings": [f.to_json() for f in report.proposed_findings],
        "low_confidence_findings": [f.to_json() for f in report.unverified_findings],
        "methodology": methodology_lines(report),
        "honest_limits": HONEST_LIMITS_LINE,
    }
    return json.dumps(doc, indent=2, sort_keys=False, ensure_ascii=False)


# --- HTML -------------------------------------------------------------------

_CSS = """
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{margin:0;padding:0;background:#0e1116;color:#d7dde5;
 font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:32px 24px 80px}
h1{font-size:22px;margin:0 0 4px;letter-spacing:-.2px;color:#fff}
h2{font-size:17px;margin:36px 0 10px;color:#fff;border-bottom:1px solid #232b36;padding-bottom:6px}
h3{font-size:14px;margin:22px 0 6px;color:#fff}
p{margin:0 0 10px}
.sub{color:#8b96a5;font-size:13px;margin:0 0 24px}
.headline{background:#151b24;border:1px solid #263040;border-left:4px solid #e5484d;
 border-radius:6px;padding:18px 20px;margin:20px 0 8px}
.headline .big{font-size:26px;line-height:1.3;color:#fff;font-weight:600}
.headline .k{color:#ff8085}
.grid{display:flex;flex-wrap:wrap;gap:10px;margin:16px 0 4px}
.card{flex:1 1 150px;background:#151b24;border:1px solid #232b36;border-radius:6px;padding:12px 14px}
.card .n{font-size:20px;color:#fff;font-weight:600}
.card .l{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:#8b96a5;margin-top:2px}
table{width:100%;border-collapse:collapse;font-size:13px;margin:6px 0 4px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid #202832;vertical-align:top}
th{color:#8b96a5;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px}
td.cmd{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;
 color:#eaeef4;word-break:break-all;white-space:pre-wrap;max-width:620px}
td.meta{color:#8b96a5;font-size:12px;white-space:nowrap}
.scroll{overflow-x:auto}
.tag{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11px;
 background:#2a1b1d;color:#ff8085;border:1px solid #4a2429}
.tag.low{background:#1a2029;color:#8b96a5;border-color:#2b3542}
.blurb{color:#8b96a5;font-size:12.5px;margin:0 0 6px}
.note{background:#141a22;border:1px solid #232b36;border-radius:6px;padding:14px 16px;margin:14px 0}
.note.limits{border-left:4px solid #f5a623}
ul{margin:8px 0 8px 18px;padding:0}
li{margin:0 0 8px}
.foot{margin-top:40px;padding-top:14px;border-top:1px solid #232b36;color:#6d7887;font-size:12px}
.empty{color:#6d7887;font-style:italic;font-size:13px}
@media (prefers-color-scheme: light){
 body{background:#fff;color:#1c2430}
 h1,h2,h3,.card .n,.headline .big,td.cmd{color:#0b1017}
 .headline,.card,.note{background:#f7f8fa;border-color:#e2e6ec}
 th,td{border-bottom-color:#e8ebf0}
 .sub,.card .l,td.meta,.blurb,.foot{color:#5a6675}
}
"""


def _esc(text: Any) -> str:
    return html.escape("" if text is None else str(text), quote=True)


def _rows(findings: Sequence[Finding]) -> str:
    parts: list[str] = []
    for f in findings[:MAX_ROWS_PER_CLASS]:
        parts.append(
            "<tr>"
            f'<td class="cmd">{_esc(f.command)}</td>'
            f'<td class="meta">{_esc(f.timestamp or "—")}</td>'
            f'<td class="meta">{_esc(f.session)}</td>'
            "</tr>")
    if len(findings) > MAX_ROWS_PER_CLASS:
        extra = len(findings) - MAX_ROWS_PER_CLASS
        parts.append(f'<tr><td class="meta" colspan="3">… and {extra} more '
                     f"(complete list in the --json output)</td></tr>")
    return "".join(parts)


def _class_section(findings: Sequence[Finding], low: bool = False) -> str:
    by_class: dict[str, list[Finding]] = {}
    for f in findings:
        by_class.setdefault(f.klass, []).append(f)
    if not by_class:
        return '<p class="empty">Nothing in this bucket.</p>'
    out: list[str] = []
    for klass in CLASSES:
        group = by_class.get(klass)
        if not group:
            continue
        tag = "tag low" if low else "tag"
        out.append(f'<h3><span class="{tag}">{_esc(klass)}</span> &nbsp;{len(group)}</h3>')
        out.append(f'<p class="blurb">{_esc(CLASS_BLURB[klass])}</p>')
        out.append('<div class="scroll"><table><thead><tr>'
                   "<th>Command (secrets redacted)</th><th>When</th><th>Session</th>"
                   "</tr></thead><tbody>")
        out.append(_rows(group))
        out.append("</tbody></table></div>")
    return "".join(out)


def render_html(report: Report) -> str:
    lo, hi = report.date_range
    s = report.stats
    n = report.executed_total
    k = report.headline_count
    span = (f"between {_esc(lo)} and {_esc(hi)}" if lo and hi
            else "over the sessions on this machine")

    cards = [
        (report.executed_total, "commands executed"),
        (k, "irreversible class"),
        (report.proposed_total, "proposed, not run"),
        (len(report.disposable), "disposable cleanups"),
        (len(report.sessions), "sessions"),
        (s.lines_skipped, "parse skips"),
    ]
    card_html = "".join(
        f'<div class="card"><div class="n">{v}</div><div class="l">{_esc(l)}</div></div>'
        for v, l in cards)

    counts = report.counts_by_class(report.findings)
    summary_rows = "".join(
        f"<tr><td>{_esc(c)}</td><td class=\"meta\">{counts[c]}</td>"
        f"<td class=\"meta\">{_esc(CLASS_BLURB[c])}</td></tr>"
        for c in CLASSES)

    meth = "".join(f"<li>{_esc(line)}</li>" for line in methodology_lines(report))

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>gate.cat retro-scan</title>
<style>{_CSS}</style>
</head><body><div class="wrap">

<h1>gate.cat retro-scan</h1>
<p class="sub">Generated {_esc(report.generated_at)} · tool v{_esc(TOOL_VERSION)} ·
read-only, offline, secrets redacted before rendering. This file is self-contained:
no scripts, no fonts, no images, no network.</p>

<div class="headline">
  <div class="big">{n} command{"" if n == 1 else "s"} executed by your agents
  {span}. <span class="k">{k} of them {"was" if k == 1 else "were"} in an
  irreversible class.</span></div>
</div>

<div class="grid">{card_html}</div>

<h2>Irreversible classes — executed</h2>
<div class="scroll"><table><thead><tr><th>Class</th><th>Count</th><th>What it means</th>
</tr></thead><tbody>{summary_rows}</tbody></table></div>

{_class_section(report.findings)}

<h2>Low severity — disposable artifact cleanups ({len(report.disposable)})</h2>
<p class="blurb">Every target of these deletions is a regenerable build or temp
artifact. They are counted here and excluded from the headline on purpose: mixing
<code>rm -rf node_modules</code> into an incident number is how a scan earns the
word "FUD".</p>
{_class_section(report.disposable, low=True)}

<h2>Proposed, not executed ({len(report.proposed_findings)})</h2>
<p class="blurb">The agent asked to run these; the transcript shows no clean result
(denied, errored, or never returned). They are not in the headline. Where a denial
is recorded, that is the counterfactual worth reading twice: something stopped it.</p>
{_class_section(report.proposed_findings, low=True)}

<h2>Lower confidence — fallback-parsed sources ({len(report.unverified_findings)})</h2>
<p class="blurb">Parsed with the permissive fallback (unrecognised JSON, or a plain
shell history). These sources carry no result correlation, and a shell history is not
agent activity — it is a human's keystrokes, sometimes mixed with an agent's. Excluded
from every headline number.</p>
{_class_section(report.unverified_findings, low=True)}

<h2>Methodology</h2>
<div class="note"><ul>{meth}</ul></div>
<div class="note limits"><p><strong>{_esc(HONEST_LIMITS_LINE)}</strong></p></div>

<div class="foot">gate.cat retro-scan · stdlib-only, zero dependencies, zero network
calls, read-only. Verify the network claim yourself:
<code>{_esc(offline_verification_command())}</code>
</div>

</div></body></html>
"""


# ===========================================================================
# 8. CLI
# ===========================================================================

# Assembled from fragments on purpose: the auditor's grep must find NOTHING in
# this file, including in the line that tells them how to run the grep.
_NETWORK_TOKENS = ("sock" "et", "url" "lib", "http" ".cli" "ent", "req" "uests", "htt" "px")


def offline_verification_command(filename: str = "gatecat_retroscan.py") -> str:
    """The exact one-liner a sceptical CTO runs before trusting this tool."""
    pattern = "|".join(t.replace(".", "\\.") for t in _NETWORK_TOKENS)
    return f'grep -nE "{pattern}" {filename}'


_EPILOG = """\
examples:
  python3 gatecat_retroscan.py
  python3 gatecat_retroscan.py ~/.claude/projects --out /tmp/scan.html
  python3 gatecat_retroscan.py ~/.claude ~/.codex --json findings.json --since 2026-01-01

guarantees:
  * standard library only, no third-party imports, no install step
  * no network calls of any kind (verify with --verify-offline)
  * read-only: the only files written are --out and --json
  * every captured command is redacted before it reaches any output
"""


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gatecat_retroscan.py",
        description="Retro-scan your existing AI-agent transcripts for irreversible "
                    "commands that already ran. Offline, read-only, redacted.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("paths", nargs="*", metavar="PATHS",
                   help="files or directories to scan (default: auto-discover "
                        "~/.claude/projects, ~/.codex/sessions, ~/.cursor, ~/.aider*)")
    p.add_argument("--out", default="./gatecat-retroscan-report.html", metavar="FILE",
                   help="HTML report path (default: ./gatecat-retroscan-report.html)")
    p.add_argument("--json", dest="json_out", default=None, metavar="FILE",
                   help="also write machine-readable findings to FILE")
    p.add_argument("--since", default=None, metavar="YYYY-MM-DD",
                   help="ignore events dated before this day")
    p.add_argument("--no-redact-check", action="store_true",
                   help="skip the belt-and-braces pass that re-scans the rendered "
                        "output for surviving secrets (redaction itself is never "
                        "optional)")
    p.add_argument("--quiet", action="store_true", help="write files, print nothing")
    p.add_argument("--verify-offline", action="store_true",
                   help="print the grep that proves this file makes no network calls")
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    return p


_SINCE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def redact_check(rendered: str) -> tuple[str, list[str]]:
    """Final safety net: re-scan rendered output and redact anything that survived.

    `redact()` is idempotent, so on a healthy run this changes nothing and returns
    an empty list. A non-empty list is a bug report, and the tool says so out loud
    rather than shipping the secret.
    """
    residual = residual_secrets(rendered)
    if residual:
        rendered = redact(rendered)
    return rendered, residual


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.verify_offline:
        print("This tool makes no network calls. Verify it yourself:\n")
        print("    " + offline_verification_command())
        print("\nExpected output: nothing. Any hit means do not run this tool.")
        return 0

    if args.since and not _SINCE_RE.match(args.since):
        parser.error("--since expects YYYY-MM-DD")

    paths = [Path(os.path.expanduser(p)) for p in args.paths] or default_roots()
    if not paths:
        if not args.quiet:
            print("No agent transcript directories found. Point the scan at one:\n"
                  "    python3 gatecat_retroscan.py /path/to/transcripts",
                  file=sys.stderr)

    report = scan_paths(paths, since=args.since)

    html_doc = render_html(report)
    json_doc = render_json(report) if args.json_out else None
    residual: list[str] = []
    if not args.no_redact_check:
        html_doc, residual = redact_check(html_doc)
        if json_doc is not None:
            json_doc, more = redact_check(json_doc)
            residual = sorted(set(residual) | set(more))

    try:
        out_path = Path(os.path.expanduser(args.out))
        _write(out_path, html_doc)
        if json_doc is not None:
            _write(Path(os.path.expanduser(args.json_out)), json_doc)
    except OSError as exc:
        print(f"error: could not write report: {exc}", file=sys.stderr)
        return 2

    if not args.quiet:
        print(render_terminal(report))
        print(f"  HTML report: {out_path}")
        if args.json_out:
            print(f"  JSON findings: {args.json_out}")
        if report.stats.unreadable:
            print(f"  unreadable files ({len(report.stats.unreadable)}):")
            for item in report.stats.unreadable[:10]:
                print(f"    - {item}")
        if residual:
            print("  WARNING: the redaction self-check caught surviving secret "
                  f"shapes {residual} in the rendered output and redacted them. "
                  "Please report this — it is a bug in the redactor.", file=sys.stderr)
        print(f"  Offline proof: {offline_verification_command()}")

    # Exit 0 always on success. This is a diagnostic, not a gate: a non-zero exit
    # here would be indistinguishable from "the scan itself failed".
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
