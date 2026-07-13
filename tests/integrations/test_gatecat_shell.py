"""Contract tests for the gate.cat gated shell (``gatecat-shell``, 0.4.12).

The gated shell is the third enforcement point beside the Claude Code hook and
the proxy: a drop-in ``sh -c`` gate for any agent that shells out. The contract:

    block  -> exit 2, the real shell is NEVER exec'd (proved by a marker file
              that a chained command would have created)
    allow  -> exit 0, the real shell runs the exact vetted command
    warn   -> exit 0, runs, but a WARN notice is on stderr
    fail-closed -> engine/extra-policy/eval/deadline faults exit 2, no exec

Dangerous command strings live in THIS file (data), so running the suite via a
normal ``pytest`` invocation is itself benign. Every case forces the gate ARMED
(``GATECAT_VETO_EPHEMERAL=0``) so a CI host's own CI markers cannot disarm a
block and make the test flap.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from gatecat.shell import ShellParse, parse_dash_c

MODULE = "gatecat.shell"
DEV = "/dev/sda"


def _run(args, *, stdin=None, env_extra=None, timeout=30):
    env = dict(os.environ)
    env["GATECAT_VETO_EPHEMERAL"] = "0"  # force armed regardless of CI markers
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        [sys.executable, "-m", MODULE, *args],
        input=stdin,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


# ---------- block: exit 2 AND no exec ----------

def test_block_disk_destroy_exits_2_and_never_execs(tmp_path):
    marker = tmp_path / "ran"
    # chain the veto with a marker-writer: if the shell had run, the marker
    # would exist. A hard block means the whole segment never reaches the shell.
    code, _out, err = _run(["-c", f"wipefs -af {DEV}; touch {marker}"])
    assert code == 2
    assert "VETO" in err
    assert not marker.exists()


def test_block_db_destructive_exits_2(tmp_path):
    marker = tmp_path / "ran"
    code, _out, err = _run(["-c", f"psql -c 'DROP TABLE users'; touch {marker}"])
    assert code == 2
    assert not marker.exists()


def test_block_reason_is_ascii(tmp_path):
    _code, _out, err = _run(["-c", f"wipefs -af {DEV}"])
    err.encode("ascii")  # must not raise


# ---------- allow: exit 0 AND real exec ----------

def test_allow_benign_execs_real_shell(tmp_path):
    marker = tmp_path / "ok"
    code, _out, _err = _run(["-c", f"touch {marker}"])
    assert code == 0
    assert marker.exists()


def test_allow_passes_through_exit_code():
    code, _out, _err = _run(["-c", "echo hi >/dev/null; exit 7"])
    assert code == 7


def test_lc_combined_flags_benign_runs(tmp_path):
    marker = tmp_path / "login"
    code, _out, _err = _run(["-lc", f"touch {marker}"])
    assert code == 0
    assert marker.exists()


def test_positional_args_after_command_are_passed(tmp_path):
    # sh -c 'printf %s "$1"' name ARG  -> "$1" is ARG
    code, out, _err = _run(["-c", 'printf "%s" "$1"', "gatecat", "PAYLOAD"])
    assert code == 0
    assert out == "PAYLOAD"


# ---------- warn: runs, but surfaced ----------

def test_warn_class_runs_and_surfaces(tmp_path):
    # RUNTIME_DELETE is a warn-level class (matched by the literal `shutil.rmtree(`
    # in the command). The command only prints that string, so it runs cleanly and
    # exits 0 — proving warn surfaces a notice yet still lets the command through.
    marker = tmp_path / "warned"
    code, _out, err = _run(
        ["-c", f"python3 -c \"print('shutil.rmtree(x)')\" >/dev/null; touch {marker}"])
    assert code == 0
    assert marker.exists()
    assert "WARN" in err


# ---------- --check: gate only, never exec ----------

def test_check_block_exits_2():
    code, _out, err = _run(["--check", "rm -rf ~/projects/app"])
    assert code == 2
    assert "VETO" in err


def test_check_via_stdin():
    code, _out, err = _run(["--check"], stdin="git push --force origin main")
    assert code == 2


def test_check_benign_exits_0():
    code, _out, _err = _run(["--check", "ls -la"])
    assert code == 0


def test_check_empty_is_allow():
    code, _out, _err = _run(["--check", "   "])
    assert code == 0


# ---------- malformed / fail-closed ----------

def test_dash_c_without_command_exits_2():
    code, _out, err = _run(["-c"])
    assert code == 2
    assert "MALFORMED" in err or "fail-closed" in err.lower()


def test_extra_policy_fault_fails_closed(tmp_path):
    marker = tmp_path / "ran"
    code, _out, err = _run(
        ["-c", f"touch {marker}"],
        env_extra={"GATECAT_EXTRA_POLICIES": "definitely_not_a_real_pack_xyz"},
    )
    assert code == 2
    assert "EXTRA_POLICIES" in err
    assert not marker.exists()


def test_watchdog_self_blocks_on_hang():
    code, _out, err = _run(
        ["-c", "echo hi"],
        env_extra={"GATECAT_SHELL_TEST_SLEEP_S": "3", "GATECAT_SHELL_DEADLINE_S": "1"},
        timeout=15,
    )
    assert code == 2
    assert "DEADLINE" in err


# ---------- shadow mode: log would-be block, then run ----------

def test_shadow_mode_runs_blocked_class(tmp_path):
    marker = tmp_path / "shadow"
    code, _out, _err = _run(
        ["-c", f"rm -rf ~/nonexistent-xyz-{os.getpid()}; touch {marker}"],
        env_extra={"GATECAT_VETO_SHADOW": "1"},
    )
    assert code == 0
    assert marker.exists()


def test_shadow_mode_does_not_hide_extra_policy_fault(tmp_path):
    # a config fault blocks even in shadow (an unobserved shadow is a lie)
    marker = tmp_path / "ran"
    code, _out, err = _run(
        ["-c", f"touch {marker}"],
        env_extra={"GATECAT_VETO_SHADOW": "1",
                   "GATECAT_EXTRA_POLICIES": "definitely_not_a_real_pack_xyz"},
    )
    assert code == 2
    assert not marker.exists()


# ---------- --install-bash ----------

def test_install_bash_emits_trap():
    code, out, _err = _run(["--install-bash"])
    assert code == 0
    assert "extdebug" in out
    assert "--check" in out
    assert "trap" in out and "DEBUG" in out


# ---------- non -c passthrough (script file) ----------

def test_script_file_passthrough_execs(tmp_path):
    marker = tmp_path / "scriptran"
    script = tmp_path / "s.sh"
    script.write_text(f"touch {marker}\n")
    code, _out, _err = _run([str(script)])
    assert code == 0
    assert marker.exists()


# ---------- adversarial-review regressions: stream bypass + long-option parse ----------

def test_dash_s_stdin_stream_is_gated(tmp_path):
    # REGRESSION: `gatecat-shell -s` used to exec `sh -s` verbatim and run the
    # whole piped command stream UNGATED. It must now gate the stream: a
    # dangerous line blocks (exit 2) and its chained marker is never created.
    marker = tmp_path / "s_ran"
    code, _out, err = _run(["-s"], stdin=f"wipefs -af {DEV}\ntouch {marker}\n")
    assert code == 2
    assert "VETO" in err
    assert not marker.exists()


def test_dash_s_benign_stream_runs(tmp_path):
    marker = tmp_path / "s_ok"
    code, _out, _err = _run(["-s"], stdin=f"echo hi >/dev/null\ntouch {marker}\n")
    assert code == 0
    assert marker.exists()


def test_piped_stdin_without_flags_is_gated(tmp_path):
    # `gatecat-shell < script` (piped stdin, no -c, no -s, no script arg) is a
    # command stream too and must be gated, not passed through ungated.
    marker = tmp_path / "piped_ran"
    code, _out, _err = _run([], stdin=f"rm -rf ~/projects/app\ntouch {marker}\n")
    assert code == 2
    assert not marker.exists()


def test_script_file_with_danger_is_blocked(tmp_path):
    # a script FILE whose contents contain a hard-block must be blocked before
    # the real shell runs it.
    marker = tmp_path / "script_ran"
    script = tmp_path / "bad.sh"
    script.write_text(f"wipefs -af {DEV}\ntouch {marker}\n")
    code, _out, err = _run([str(script)])
    assert code == 2
    assert not marker.exists()


def test_long_option_containing_c_is_not_a_dash_c_cluster():
    # REGRESSION: `--norc` / `--rcfile` must NOT be parsed as a `-c` cluster
    # (the old substring test misparsed them and gated a decoy string).
    assert parse_dash_c(["--norc"]).mode == "passthrough"
    # a real -c after a long option is still found correctly
    assert parse_dash_c(["--norc", "-c", "echo hi"]) == ShellParse("gate", ["--norc"], "echo hi", [])
    # a long option that CONSUMES an arg (--rcfile FILE) must not let a later -c
    # slip past: its command is still parsed and gated.
    assert parse_dash_c(["--rcfile", "/tmp/x", "-c", "echo hi"]) == ShellParse(
        "gate", ["--rcfile", "/tmp/x"], "echo hi", [])


def test_rcfile_then_dash_c_danger_is_blocked(tmp_path):
    # end-to-end: `--rcfile F -c "<danger>"` must block, not exec ungated.
    marker = tmp_path / "rc_ran"
    rc = tmp_path / "rc"
    rc.write_text("# empty rc\n")
    code, _out, err = _run(["--rcfile", str(rc), "-c", f"wipefs -af {DEV}; touch {marker}"])
    assert code == 2
    assert not marker.exists()


def test_short_arg_option_before_dash_c_is_gated(tmp_path):
    # CRITICAL REGRESSION (review): `-o pipefail -c "<danger>"` used to reach the
    # ungated passthrough (the `pipefail` arg looked like a script name and the
    # scan stopped before -c). `-o` now consumes its argument, so -c is gated.
    assert parse_dash_c(["-o", "pipefail", "-c", "echo hi"]) == ShellParse(
        "gate", ["-o", "pipefail"], "echo hi", [])
    marker = tmp_path / "o_ran"
    code, _out, _err = _run(["-o", "pipefail", "-c", f"wipefs -af {DEV}; touch {marker}"])
    assert code == 2
    assert not marker.exists()


def test_plus_flag_before_dash_c_is_gated(tmp_path):
    # `+x -c "<danger>"` (bash set-flag form) must also be gated, not passed through.
    assert parse_dash_c(["+x", "-c", "echo hi"]) == ShellParse("gate", ["+x"], "echo hi", [])
    marker = tmp_path / "plus_ran"
    code, _out, _err = _run(["+x", "-c", f"wipefs -af {DEV}; touch {marker}"])
    assert code == 2
    assert not marker.exists()


def test_unclassifiable_prefix_before_dash_c_fails_closed(tmp_path):
    # An unknown arg-taking option leaves a bare operand before -c that we cannot
    # classify. Rather than exec ungated, fail closed (SHELL_AMBIGUOUS, exit 2).
    assert parse_dash_c(["weirdname", "-c", "echo hi"]).mode == "ambiguous"
    marker = tmp_path / "amb_ran"
    code, _out, err = _run(["weirdname", "-c", f"echo x; touch {marker}"])
    assert code == 2
    assert "AMBIGUOUS" in err
    assert not marker.exists()


# ---------- parse_dash_c unit edges (pure function, no subprocess) ----------

@pytest.mark.parametrize("argv,expected", [
    (["-c", "echo hi"],            ShellParse("gate", [], "echo hi", [])),
    (["-lc", "echo hi"],           ShellParse("gate", ["-l"], "echo hi", [])),
    (["-ic", "echo hi"],           ShellParse("gate", ["-i"], "echo hi", [])),
    (["-c", "cmd", "n", "a"],      ShellParse("gate", [], "cmd", ["n", "a"])),
    (["-l", "-c", "cmd"],          ShellParse("gate", ["-l"], "cmd", [])),
])
def test_parse_dash_c_forms(argv, expected):
    assert parse_dash_c(argv) == expected


def test_parse_dash_c_malformed():
    assert parse_dash_c(["-c"]).mode == "malformed"


@pytest.mark.parametrize("argv", [
    [],                    # nothing
    ["script.sh"],         # script file
    ["--"],                # end of options
    ["-l"],                # options only, no -c
    ["-"],                 # stdin marker
    ["-o", "pipefail"],    # arg-consuming option, no -c
])
def test_parse_dash_c_non_c_is_passthrough(argv):
    assert parse_dash_c(argv).mode == "passthrough"
