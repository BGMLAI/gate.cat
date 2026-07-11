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
    gatecat-shell                               interactive: exec real shell (see note)

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


def parse_dash_c(argv: list[str]) -> "tuple[list[str], str | None, list[str]] | None":
    """Parse a POSIX-ish ``sh [opts] -c cmd [name [args...]]`` invocation.

    Returns ``(other_flags, command, positional)`` where:
      * ``other_flags`` are option tokens to hand back to the real shell with the
        ``c`` removed from any combined cluster (``-lc`` -> keep ``-l``),
      * ``command`` is the command string (``None`` if ``-c`` present but no
        string follows — a malformed invocation the caller fail-closes on),
      * ``positional`` are the ``$0 $1 ...`` args after the command string.

    Returns ``None`` when there is no ``-c`` at all (interactive / script-file
    invocation — the caller passes those straight through to the real shell).
    """
    other_flags: list[str] = []
    i = 0
    n = len(argv)
    while i < n:
        tok = argv[i]
        # a lone "--" ends option parsing; whatever's next is not a -c form
        if tok == "--":
            return None
        if tok.startswith("-") and tok != "-" and "c" in tok[1:]:
            # a short-flag cluster containing 'c' (e.g. -c, -lc, -ic). The command
            # string is the NEXT argv token; the rest of the cluster stays a flag.
            rest = tok[1:].replace("c", "", 1)
            if rest:
                other_flags.append("-" + rest)
            if i + 1 >= n:
                return (other_flags, None, [])  # -c with no command string
            command = argv[i + 1]
            positional = argv[i + 2:]
            return (other_flags, command, positional)
        if tok.startswith("-") and tok != "-":
            other_flags.append(tok)  # some other option, keep it, keep scanning
            i += 1
            continue
        # first non-option token and no -c seen yet: this is a script file /
        # interactive form — not our gated path.
        return None
    return None  # only options, no -c


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
    return ALLOW


def _exec_real(other_flags: list[str], command: str, positional: list[str]) -> "int":
    """Replace this process with the real shell running the vetted command.
    Returns an exit code only if exec itself fails (then we fail closed)."""
    real = _real_shell()
    argv = [real, *other_flags, "-c", command, *positional]
    try:
        os.execv(real, argv)
    except OSError as exc:
        sys.stderr.write(_ascii(
            f"gate.cat VETO [SHELL_EXEC_FAILED]: cannot exec real shell "
            f"{real!r} (fail-closed): {exc}\n"))
        return BLOCK
    return BLOCK  # unreachable if execv succeeds


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
    if parsed is None:
        # No -c: interactive shell or a script-file invocation. We cannot vet an
        # arbitrary interactive session statically, so we pass through to the real
        # shell. Honest limitation (documented): per-command gating is the -c path
        # and the --install-bash DEBUG trap.
        real = _real_shell()
        try:
            os.execv(real, [real, *argv])
        except OSError as exc:
            sys.stderr.write(_ascii(
                f"gate.cat VETO [SHELL_EXEC_FAILED]: cannot exec real shell "
                f"{real!r} (fail-closed): {exc}\n"))
            return BLOCK
        return BLOCK  # unreachable

    other_flags, command, positional = parsed
    if command is None:
        sys.stderr.write(_ascii(
            "gate.cat VETO [SHELL_MALFORMED]: -c given with no command string "
            "(fail-closed)\n"))
        return BLOCK

    verdict = _decide(command)
    if verdict == BLOCK:
        return BLOCK
    return _exec_real(other_flags, command, positional)


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
