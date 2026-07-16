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

# Flag lives in the same state dir cache.py/cloud_reporter.py already own.
_FLAG = os.path.expanduser("~/.gatecat/.nudged")

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
        sys.stderr.write(_MSG)
    except Exception:
        pass
