#!/usr/bin/env bash
# gate.cat plugin — find a working Python 3.10+ interpreter and exec the given
# script with it. gate.cat requires Python >=3.10 (requires-python in
# pyproject); below that the package cannot be imported at all.
#
# Adapted from the claude-plugins-official security-guidance shim, which
# handles three real cross-platform breakages:
#   * Windows Microsoft Store `python3` stub (exits 49 silently in non-TTY
#     subprocess) — probe each candidate with `-c ""` and skip failures.
#   * Git Bash POSIX paths (`/c/Users/...`) fed to a native `python.exe` —
#     convert to Windows form with `cygpath -w` before exec.
#   * cp1252 default encoding on Windows crashing text IO on non-latin bytes —
#     force PEP 540 UTF-8 mode.
#
# Args after the shim path are passed straight through to the interpreter:
#   bash "${CLAUDE_PLUGIN_ROOT}/hooks/gatecat-python.sh" \
#        "${CLAUDE_PLUGIN_ROOT}/hooks/gatecat_veto_hook.py"
set -e

# PEP 540: force UTF-8 for all Python IO. No-op on macOS/Linux (already UTF-8);
# on Windows this prevents cp1252 crashes on non-latin path/filename bytes.
export PYTHONUTF8=1

# Git Bash hands script paths in POSIX form (`/c/Users/...`); a native
# python.exe would read the leading `/` as a drive root. Convert to Windows
# form. `cygpath` is a Git Bash builtin, absent on macOS/Linux (guard = no-op).
if command -v cygpath >/dev/null 2>&1; then
    converted=()
    for a in "$@"; do
        case "$a" in
            /*) converted+=("$(cygpath -w "$a")") ;;
            *)  converted+=("$a") ;;
        esac
    done
    set -- "${converted[@]}"
fi

probe() {
    "$@" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")' 2>/dev/null
}

# True iff "M.m" version string >= 3.10 (gate.cat requires-python).
is_compatible() {
    case "$1" in
        3.1[0-9]|3.[2-9][0-9]|[4-9].*|[1-9][0-9].*) return 0 ;;
        *) return 1 ;;
    esac
}

# Pass 1 — explicit minor-versioned binaries, highest first.
for cmd in "python3.13" "python3.12" "python3.11" "python3.10"; do
    v=$(probe "$cmd") || continue
    if is_compatible "$v"; then exec "$cmd" "$@"; fi
done

# Pass 2 — bare interpreters, only if >= 3.10.
for cmd in "python3" "python" "py -3"; do
    # shellcheck disable=SC2086
    v=$(probe $cmd) || continue
    # shellcheck disable=SC2086
    if is_compatible "$v"; then exec $cmd "$@"; fi
done

# Pass 3 — any Python 3 as a last resort. gate.cat can't import under <3.10,
# so the veto hook will then fail CLOSED (exit 2) with clear guidance rather
# than silently pass — which is the correct security posture. We still hand
# off so the hook can emit that guidance from Python.
for cmd in "python3" "python" "py -3"; do
    # shellcheck disable=SC2086
    v=$(probe $cmd) || continue
    case "$v" in
        [0-9]*.[0-9]*)
            # shellcheck disable=SC2086
            exec $cmd "$@" ;;
    esac
done

echo "gate.cat: no working Python 3 interpreter found (need >=3.10)." >&2
echo "  tried: python3.13, python3.12, python3.11, python3.10, python3, python, py -3" >&2
echo "  install Python 3.10+ from https://python.org (on Windows, NOT the Microsoft Store)." >&2
# Fail closed: a Bash/Write/Edit veto that cannot run must not wave the action through.
exit 2
