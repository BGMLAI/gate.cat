"""One-time, opt-out, post-decision Team hint shown after a real veto.

This is purely cosmetic stderr output that runs *after* the block decision is
already made. It can never change a veto verdict or exit code: every path is
wrapped in a bare ``except`` and swallowed. It fires at most once per machine
(flag file under the existing ~/.gatecat state dir) and only when the user has
not opted out. The copy states a true limitation ("this machine only"), which
is also the real Cloud/Team value prop -- a heads-up, not a pitch.
"""
import os
import sys
import time

# Flag lives in the same state dir cache.py/cloud_reporter.py already own.
_FLAG = os.path.expanduser("~/.gatecat/.nudged")
# Daily rate-limit stamp for the CLI (status/stats) Solo hint.
_LAST = os.path.expanduser("~/.gatecat/nudge_last")
# Process-wide guard: at most ONE nudge of any kind per run. Future hint
# surfaces (e.g. the pack hint) must consult the same guard so two pitches
# can never stack in a single command's output.
_fired_this_run = False


def fired_this_run() -> bool:
    return _fired_this_run


def mark_fired() -> None:
    global _fired_this_run
    _fired_this_run = True

_MSG = (
    "gate.cat vetoed that locally - this machine only, no record leaves the box.\n"
    "Team plans keep an off-machine record of vetoes and alert teammates: "
    "https://gate.cat/teams.html\n"
    "(silence this once-per-machine notice: GATECAT_NO_NUDGE=1)\n"
)


def maybe_nudge_after_veto():
    """Print the first-veto Team hint at most once per machine.

    Best-effort: any failure is swallowed so it can never affect the gate
    verdict or exit code. Honors GATECAT_NO_NUDGE / GATECAT_QUIET opt-outs.
    """
    try:
        if os.environ.get("GATECAT_NO_NUDGE") or os.environ.get("GATECAT_QUIET"):
            return
        if os.path.exists(_FLAG):
            return
        os.makedirs(os.path.dirname(_FLAG), exist_ok=True)
        # Create the flag FIRST: if the write below races or fails, we still
        # never re-nudge -- one imperfect notice beats an accidental loop.
        with open(_FLAG, "w") as fh:
            fh.write("1\n")
        mark_fired()
        sys.stderr.write(_MSG)
    except Exception:
        pass


def maybe_nudge_cli(surface: str, interventions: int) -> None:
    """One short Solo hint on `gate.cat status`/`stats`, at most once per DAY.

    Fires only when there is something real to point at (interventions > 0)
    and the user is not already a Cloud customer (GATECAT_CLOUD_API_KEY set).
    Same contract as the post-veto nudge: stderr only, opt-out via
    GATECAT_NO_NUDGE / GATECAT_QUIET, best-effort -- it can never change an
    exit code, and never stacks with another nudge in the same run.
    """
    try:
        if os.environ.get("GATECAT_NO_NUDGE") or os.environ.get("GATECAT_QUIET"):
            return
        if _fired_this_run:
            return
        if interventions <= 0:
            return
        if os.environ.get("GATECAT_CLOUD_API_KEY"):
            return
        today = time.strftime("%Y-%m-%d", time.gmtime())
        try:
            with open(_LAST) as fh:
                if fh.read().strip() == today:
                    return
        except Exception:
            pass
        os.makedirs(os.path.dirname(_LAST), exist_ok=True)
        # Stamp FIRST (same race rule as the flag above): a lost notice beats
        # a repeating one.
        with open(_LAST, "w") as fh:
            fh.write(today + "\n")
        mark_fired()
        sys.stderr.write(
            f"\n{interventions} intervention(s) are recorded only in this machine's local log -- "
            "inside the agent's blast radius.\n"
            "The paid layer is the off-machine, append-only copy of that history "
            "(Solo EUR 19/mo): https://gate.cat/teams.html?source=cli\n"
            "See exactly what it caught, free and local: gate.cat report\n"
            "(once-a-day notice; silence it: GATECAT_NO_NUDGE=1)\n"
        )
    except Exception:
        pass
