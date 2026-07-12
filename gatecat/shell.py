#!/usr/bin/env python3
"""gate.cat gated shell — a third enforcement point beside the Claude Code hook
and the OpenAI-API proxy.

WHY THIS EXISTS
    The hook only fires inside Claude Code; the proxy only sees what an
    OpenAI-API agent's model layer emits. Most other agents (Codex, Gemini CLI,
    aider, OpenClaw, Hermes, Antigravity, a plain `subprocess`/`os.system`
    script) ultimately run a command through a shell — `sh -c "<command>"`.
    `gatecat-shell` sits AT that exec point: point the agent's shell at it and
    every command is vetted by the same deterministic engine the hook uses,
    BEFORE the real shell ever sees it. Model-independent enforcement.

TRUST CLASS (honest labeling — matches the site's "which is which")
    * As the agent's SHELL BINARY (`-c` mode below): enforcement is out-of-band
      — the model cannot skip a shell it does not control. This is real
      enforcement, in the same class as the hook.
    * As a bash DEBUG trap (`--install-bash`): weaker — a command inside the
      session can `trap - DEBUG` to disarm it. Use it where you cannot set the
      shell binary; prefer `-c` mode where you can.

MODES
    gatecat-shell -c "<cmd>" [name [args...]]   gate, then exec the real shell
    gatecat-shell -lc "<cmd>"                   combined flags tolerated (-l kept)
    gatecat-shell --check "<cmd>"               gate only: exit 0/2, no exec
    (cmd via stdin also accepted for --check)   e.g. echo "<cmd>" | gatecat-shell --check
    gatecat-shell --install-bash                print a DEBUG-trap snippet to source
    gatecat-shell -s / gatecat-shell < script   command STREAM: gated, then run
    gatecat-shell <scriptfile> [args]           script file: contents gated, then run
    gatecat-shell                               interactive TTY: exec real shell (a
                                                human session is not statically gated)

EXIT CODES (parity with the hook)
    0   allow (or warn — surfaced on stderr, then run) — proceed / exec
    2   BLOCK — the veto reason is on stderr; the command never runs

FAIL-CLOSED (a security tool must never run WITHOUT the policy the operator
believes is enforced):
    * engine import failure           -> exit 2, no exec
    * GATECAT_EXTRA_POLICIES fault     -> exit 2, no exec
    * evaluation error / crash         -> exit 2, no exec
    * evaluation exceeds the deadline  -> exit 2, no exec (watchdog)
    * `-c` given but no command string -> exit 2, no exec
Shadow mode (GATECAT_VETO_SHADOW=1) logs a would-be block and PROCEEDS (execs),
exactly as the hook exits 0 — except the two cannot-observe cases above
(engine/extra-policy) which still block, because an unobserved "shadow" is a lie.

The real shell is `/bin/sh` by default; override with GATECAT_SHELL_REAL
(e.g. /bin/bash). The command string is passed through byte-for-byte — the gate
saw the exact same string, so there is no re-parse gap between check and run.

All stderr is ASCII-safe (D1): a veto reason must not crash a cp1252 console.
"""

from __future__ import annotations

import os
import sys
import threading

SOURCE = "gatecat_shell"
BLOCK, ALLOW = 2, 0
_DEADLINE_ENV = "GATECAT_SHELL_DEADLINE_S"
_REAL_SHELL_ENV = "GATECAT_SHELL_REAL"
_TEST_SLEEP_ENV = "GATECAT_SHELL_TEST_SLEEP_S"  # internal: watchdog contract test only
_DEFAULT_REAL_SHELL = "/bin/sh"


def _ascii(text: str) -> str:
    """ASCII fallback usable BEFORE the engine imports."""
    return str(text).encode("ascii", "backslashreplace").decode("ascii")


def _start_watchdog() -> None:
    """Self-block before a hung engine wedges the agent's command forever.

    ``os._exit`` (not sys.exit): must fire from a daemon thread even if the main
    thread is stuck inside a C-extension import.
    """
    try:
        deadline = float(os.environ.get(_DEADLINE_ENV, "20"))
    except ValueError:
        deadline = 20.0
    if deadline <= 0:
        return  # opt-out for debugging; default always on

    def _expire() -> None:
        sys.stderr.write(_ascii(
            f"gate.cat VETO [SHELL_DEADLINE]: evaluation exceeded {deadline}s "
            "(fail-closed: a hung gate must block, not silently run)\n"))
        sys.stderr.flush()
        os._exit(BLOCK)

    timer = threading.Timer(deadline, _expire)
    timer.daemon = True
    timer.start()


def _real_shell() -> str:
    return os.environ.get(_REAL_SHELL_ENV, "").strip() or _DEFAULT_REAL_SHELL


# Options that consume a SEPARATE next-token argument. If the parser does not
# skip the argument, that argument (e.g. `pipefail` after `-o`, the file after
# `--rcfile`) looks like the command-name and the scan stops BEFORE a later `-c`
# — the exact hole the adversarial review used (`-o pipefail -c "<danger>"` ran
# ungated). Cover the bash short set-flags (`-o/-O/+o/+O`) and the arg-taking
# long options.
_SHORT_ARG_OPTS = frozenset({"-o", "-O", "+o", "+O"})
_LONG_ARG_OPTS = frozenset({"--rcfile", "--init-file"})


class ShellParse:
    """Result of ``parse_dash_c``. ``mode`` is one of:

      * ``"gate"``       — a `-c` command was cleanly isolated; gate ``command``
                           then exec ``[real, *flags, "-c", command, *positional]``.
      * ``"malformed"``  — `-c` present but no command string follows (fail-closed).
      * ``"ambiguous"``  — a `-c` cluster exists but is preceded by a token the
                           parser cannot classify as flag-or-operand; the string
                           that would run cannot be proven identical to the string
                           gated, so the caller FAILS CLOSED (exit 2). Better to
                           refuse a weird invocation than exec it ungated.
      * ``"passthrough"``— provably NO `-c` anywhere: a script file / interactive /
                           stream invocation, handled by the gated stream path.
    """
    __slots__ = ("mode", "flags", "command", "positional")

    def __init__(self, mode, flags=None, command=None, positional=None):
        self.mode = mode
        self.flags = flags or []
        self.command = command
        self.positional = positional or []

    def __eq__(self, other):  # ergonomics for tests
        if isinstance(other, ShellParse):
            return (self.mode, self.flags, self.command, self.positional) == \
                   (other.mode, other.flags, other.command, other.positional)
        return NotImplemented

    def __repr__(self):  # pragma: no cover
        return f"ShellParse({self.mode!r}, {self.flags!r}, {self.command!r}, {self.positional!r})"


def _has_short_c_cluster(tokens: list[str]) -> bool:
    """True if any token is a SHORT (single-dash) cluster containing 'c' — i.e. a
    shell `-c` in some position. Used to decide whether a bare-operand prefix is a
    safe passthrough (no `-c` anywhere) or ambiguous (a `-c` hides behind it)."""
    for t in tokens:
        if t.startswith("-") and not t.startswith("--") and t != "-" and "c" in t[1:]:
            return True
    return False


def parse_dash_c(argv: list[str]) -> ShellParse:
    """Parse a POSIX-ish ``sh [opts] -c cmd [name [args...]]`` invocation.

    Core invariant (adversarial-review hardening): this NEVER classifies an argv
    that contains a `-c` cluster as ``passthrough``. Either the `-c` command is
    cleanly isolated (``gate``) or, if a token before it cannot be classified, the
    result is ``ambiguous`` and the caller fails closed. The string handed to the
    gate is always byte-identical to the string handed to the real shell.
    """
    other_flags: list[str] = []
    i = 0
    n = len(argv)
    while i < n:
        tok = argv[i]
        # "--" ends option parsing: everything after is operands, so there is no
        # shell `-c` beyond this point (a `-c` after `--` is a script name).
        if tok == "--":
            return ShellParse("passthrough")
        # options that consume the next token as their argument — skip both, so a
        # later `-c` is still reachable and the argument is not mistaken for a name.
        if tok in _SHORT_ARG_OPTS or tok in _LONG_ARG_OPTS:
            if i + 1 < n:
                other_flags.extend([tok, argv[i + 1]])
                i += 2
                continue
            other_flags.append(tok)
            i += 1
            continue
        # `--opt=value` long option (single token, no separate arg): keep, continue.
        if tok.startswith("--"):
            other_flags.append(tok)
            i += 1
            continue
        # short cluster (single dash) containing 'c' => the `-c` form.
        is_short = tok.startswith("-") and tok != "-"
        if is_short and "c" in tok[1:]:
            rest = tok[1:].replace("c", "", 1)
            if rest:
                other_flags.append("-" + rest)
            if i + 1 >= n:
                return ShellParse("malformed", other_flags)  # -c with no command
            return ShellParse("gate", other_flags, argv[i + 1], argv[i + 2:])
        # any other option-shaped token (`-x`, `+x`, ...): keep, keep scanning.
        if (tok.startswith("-") or tok.startswith("+")) and tok != "-":
            other_flags.append(tok)
            i += 1
            continue
        # first bare operand (a command-name / script). POSIX ends options here, so
        # a `-c` from here on is an OPERAND, not a shell flag. If a `-c` cluster does
        # appear in the remainder we cannot prove which string would run => ambiguous
        # (fail closed). Otherwise it is a genuine no-`-c` passthrough.
        if _has_short_c_cluster(argv[i:]):
            return ShellParse("ambiguous", other_flags)
        return ShellParse("passthrough")
    return ShellParse("passthrough")  # only options consumed, no -c


def _read_check_command(argv_after_flag: list[str]) -> str:
    """Command for ``--check``: the next arg, else stdin (for DEBUG traps / pipes)."""
    if argv_after_flag:
        return argv_after_flag[0]
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return ""


_BASH_TRAP = r"""# gate.cat — veto every command before bash runs it.
# Source this into an agent's bash session (weaker than setting the shell binary:
# a command in the session can `trap - DEBUG` to disarm it — see gate.cat/coverage).
#   eval "$(gatecat-shell --install-bash)"
__gatecat_precmd() {
  # skip empty lines and the trap's own bookkeeping
  [ -n "$BASH_COMMAND" ] || return 0
  case "$BASH_COMMAND" in __gatecat_precmd*|trap\ -\ DEBUG*) return 0 ;; esac
  gatecat-shell --check "$BASH_COMMAND" || return 1
  return 0
}
# extdebug makes a non-zero DEBUG trap SKIP the command (real enforcement in-session)
shopt -s extdebug
trap '__gatecat_precmd' DEBUG
"""


def _gate(command: str):
    """Run the engine on *command*. Returns the Decision, or raises ActionVetoed
    on a hard block. Engine/extra-policy faults print a reason and exit(2)
    directly (fail-closed, even in shadow mode)."""
    try:
        from gatecat.integrations import (  # imported inside the guarded path (F1)
            ActionVetoed,
            ExtraPolicyError,
            ascii_safe,
            check_action,
            log_decision,
            policies_with_extras,
        )
    except BaseException as exc:  # noqa: BLE001 — ANY import failure blocks
        sys.stderr.write(_ascii(
            f"gate.cat VETO [ENGINE_UNAVAILABLE]: cannot import veto engine "
            f"(fail-closed): {exc!r}. Is gate.cat installed here? "
            "pip install gate.cat\n"))
        sys.exit(BLOCK)

    if os.environ.get(_TEST_SLEEP_ENV):  # watchdog contract test only
        import time
        time.sleep(float(os.environ[_TEST_SLEEP_ENV]))

    try:
        policies = policies_with_extras()  # DOGFOOD_DEFAULTS + GATECAT_EXTRA_POLICIES
    except ExtraPolicyError as exc:
        reason = f"gate.cat VETO [EXTRA_POLICIES]: {exc}"
        log_decision(source=SOURCE, decision="block", reason=reason, context="<startup>")
        sys.stderr.write(ascii_safe(reason) + "\n")
        sys.exit(BLOCK)  # config fault: block even in shadow mode

    # D-narrow: real cwd + real env let the delete-analyzer resolve $VAR targets
    # by value instead of fail-closing on an unknown path.
    return check_action(SOURCE, command, policies,
                        cwd=os.getcwd(), env=dict(os.environ))


def _decide(command: str) -> int:
    """Gate *command*; return the exit code (0 allow/warn, 2 block). Surfaces a
    warn notice on stderr. ActionVetoed already respects shadow mode inside
    check_action (a shadow block returns an allowing decision), so a raised
    ActionVetoed here is a real, enforced block."""
    from gatecat.integrations import ActionVetoed, ascii_safe
    try:
        decision = _gate(command)
    except ActionVetoed as exc:
        sys.stderr.write(str(exc) + "\n")  # already ASCII-safe
        return BLOCK
    except SystemExit:
        raise
    except Exception as exc:  # engine crashed mid-evaluation: fail closed
        sys.stderr.write(_ascii(
            f"gate.cat VETO [ENGINE_ERROR]: evaluation failed (fail-closed): {exc!r}\n"))
        return BLOCK
    if getattr(decision, "level", None) == "warn":
        sys.stderr.write(ascii_safe(f"gate.cat WARN (unchecked): {decision.reason}") + "\n")

    # FREE-CORE stagnation (local half): before we let this command run, feed it
    # to the disk-persisted per-session no-progress detector. On a trip it prints
    # a VISIBLE stderr warning and logs decision='stagnation'. Honest scope: this
    # warns on repeated no-progress commands routed through THIS shell; it does
    # NOT kill an external process. Warn-only by default (GATECAT_STAGNATION_HALT=1
    # opts into a soft halt) so legit retries / polling are not false-tripped.
    try:
        from gatecat.integrations import shell_stagnation
        reason = shell_stagnation.surface(command, source=SOURCE)
        if reason and shell_stagnation.halt_enabled():
            sys.stderr.write(_ascii(
                "gate.cat HALT [STAGNATION]: no progress across repeated commands "
                f"(soft halt, GATECAT_STAGNATION_HALT=1): {reason}\n"))
            return BLOCK
    except Exception:
        pass  # stagnation tracking is best-effort; never break the gate verdict
    return ALLOW


def _exec_real(other_flags: list[str], command: str, positional: list[str]) -> "int":
    """Replace this process with the real shell running the vetted command.
    Returns an exit code only if exec itself fails (then we fail closed)."""
    real = _real_shell()
    argv = [real, *other_flags, "-c", command, *positional]
    return _exec_argv(real, argv)


def _exec_argv(real: str, argv: list[str]) -> int:
    """os.execv wrapper that fails closed if exec itself fails."""
    try:
        os.execv(real, argv)
    except OSError as exc:
        sys.stderr.write(_ascii(
            f"gate.cat VETO [SHELL_EXEC_FAILED]: cannot exec real shell "
            f"{real!r} (fail-closed): {exc}\n"))
        return BLOCK
    return BLOCK  # unreachable if execv succeeds


def _stdin_is_tty() -> bool:
    try:
        return sys.stdin.isatty()
    except (ValueError, OSError):
        return False  # no usable stdin handle -> treat as a stream, not a human


def _no_dash_c_path(argv: list[str]) -> int:
    """The no-`-c` invocation. A command STREAM here must NOT be exec'd ungated
    (adversarial-review bypass: `gatecat-shell -s` read a whole command stream
    from stdin and ran it with the gate never firing). So we gate what we can:

      * a script FILE argument -> read + gate its contents, then exec the file
      * a command STREAM (`-s`, or piped non-tty stdin) -> read + gate, then run
        the vetted text as `-c`
      * a genuine interactive TTY (a human is typing) -> pass through untouched
        (documented: an interactive human session is not statically gateable)
    """
    real = _real_shell()

    # split leading option flags from the first non-option token (+ the rest)
    flags: list[str] = []
    rest: list[str] = []
    seen_nonopt = False
    for tok in argv:
        if not seen_nonopt and tok.startswith("-") and tok != "-":
            flags.append(tok)
        else:
            seen_nonopt = True
            rest.append(tok)
    has_s = any(not f.startswith("--") and "s" in f[1:] for f in flags)
    script = rest[0] if rest else None
    tty = _stdin_is_tty()

    # 1. script file: gate its contents, then exec the file verbatim (the real
    #    shell reads it). Only when it is an actual readable file and not -s.
    if script and not has_s:
        if os.path.isfile(script):
            try:
                text = open(script, "r", errors="replace").read()
            except OSError:
                text = None
            if text is not None and text.strip():
                if _decide(text) == BLOCK:
                    return BLOCK
            return _exec_argv(real, [real, *argv])
        # a non-file positional (e.g. a typo): let the real shell report it —
        # it is not a command stream, so there is nothing to gate/bypass.
        return _exec_argv(real, [real, *argv])

    # 2. command stream from stdin: `-s`, or piped (non-tty) stdin with no script.
    #    Read it, gate it as one action, then run the vetted text via -c.
    if (has_s or not script) and not tty:
        try:
            data = sys.stdin.read()
        except (OSError, ValueError):
            data = ""
        if not data.strip():
            return ALLOW  # nothing to run == nothing to block
        if _decide(data) == BLOCK:
            return BLOCK
        # preserve $1.. positionals ($0 name is conventional); drop the original
        # input-source flags (-s etc.) — they conflict with the -c form we run.
        return _exec_argv(real, [real, "-c", data, "gatecat-shell", *rest])

    # 3. genuine interactive TTY (a human) -> passthrough, documented limitation.
    return _exec_argv(real, [real, *argv])


def main(argv: "list[str] | None" = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # --install-bash: emit the DEBUG-trap snippet (no gating, pure output)
    if argv and argv[0] in ("--install-bash", "--install-bash-trap"):
        sys.stdout.write(_BASH_TRAP)
        return ALLOW

    _start_watchdog()

    # --check: gate only, never exec (the primitive for DEBUG traps, git hooks,
    # CI wrappers, other agents). Command from the next arg or stdin.
    if argv and argv[0] == "--check":
        command = _read_check_command(argv[1:])
        if not command.strip():
            return ALLOW  # nothing to run == nothing to block
        return _decide(command)

    parsed = parse_dash_c(argv)

    if parsed.mode == "passthrough":
        # Provably no -c: a script file, a command stream (`-s`/piped stdin), or a
        # genuine interactive session. Gate the stream/script; only a real TTY
        # passes through ungated (a human is driving). See _no_dash_c_path.
        return _no_dash_c_path(argv)

    if parsed.mode == "ambiguous":
        # A -c exists but sits behind a token we cannot classify as flag-or-operand,
        # so the string that would run cannot be proven identical to what we would
        # gate. Fail closed rather than exec it ungated (review hardening).
        sys.stderr.write(_ascii(
            "gate.cat VETO [SHELL_AMBIGUOUS]: cannot isolate the -c command from "
            "the surrounding arguments (fail-closed); use a plain `-c \"<cmd>\"` "
            "form or set GATECAT_SHELL_REAL and invoke without exotic pre-flags\n"))
        return BLOCK

    if parsed.mode == "malformed":
        sys.stderr.write(_ascii(
            "gate.cat VETO [SHELL_MALFORMED]: -c given with no command string "
            "(fail-closed)\n"))
        return BLOCK

    # mode == "gate"
    if _decide(parsed.command) == BLOCK:
        return BLOCK
    return _exec_real(parsed.flags, parsed.command, parsed.positional)


def _entry() -> None:
    """Console-script entry (``gatecat-shell``): outer guard — a bug in main()
    must fail closed (block), never crash with a stray code that runs the
    command."""
    try:
        code = main()
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 — last-resort fail-closed
        sys.stderr.write(_ascii(
            f"gate.cat VETO [SHELL_ERROR]: gated shell crashed (fail-closed): {exc!r}\n"))
        code = BLOCK
    sys.exit(code)


if __name__ == "__main__":
    _entry()
