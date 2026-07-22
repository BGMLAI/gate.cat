"""One-time, opt-out policy-pack hint keyed off CLIs present on the machine.

Same contract as gatecat._nudge (the pattern is copied deliberately): stderr
only, best-effort (never raises, never changes an exit code), opt-out via
GATECAT_NO_NUDGE / GATECAT_QUIET, at most ONCE per machine (flag file in the
existing ~/.gatecat state dir), and never stacked with another nudge in the
same run (shared per-process guard in gatecat._nudge).

The detection is honest and local: ``shutil.which()`` on stack CLIs. A machine
with the ``stripe`` CLI plausibly holds credentials the Fintech pack guards; a
machine with ``vercel``/``fly``/... plausibly deploys where the PaaS pack
guards. Pack scopes below quote PRICING.md verbatim.
"""
import os
import shutil
import sys

from gatecat import _nudge

_FLAG = os.path.expanduser("~/.gatecat/.pack_nudged")

# (pack name, CLIs that suggest it, scope quoted from PRICING.md, checkout)
_PACKS = (
    ("Fintech", ("stripe",),
     "refund creation, payouts/transfers, customer & billing-config deletion",
     "https://buy.stripe.com/dRm5kw6Bn3iMfFS1Rk67S0c"),
    ("PaaS", ("vercel", "netlify", "fly", "heroku", "railway", "render", "supabase"),
     "`vercel remove`, `netlify sites:delete`, `fly/heroku apps destroy`, "
     "`railway down`, `render/supabase delete`",
     "https://buy.stripe.com/3cI5kw3pbaLeeBO2Vo67S0d"),
)


def _detect():
    """First (pack, matched CLI) whose tool exists on PATH, else None."""
    for name, clis, scope, url in _PACKS:
        for cli in clis:
            if shutil.which(cli):
                return name, cli, scope, url
    return None


def maybe_pack_hint() -> None:
    """Print the one-time pack hint if a matching stack CLI is installed."""
    try:
        if os.environ.get("GATECAT_NO_NUDGE") or os.environ.get("GATECAT_QUIET"):
            return
        if _nudge.fired_this_run():
            return
        if os.path.exists(_FLAG):
            return
        found = _detect()
        if not found:
            return
        name, cli, scope, url = found
        os.makedirs(os.path.dirname(_FLAG), exist_ok=True)
        # Flag FIRST (same race rule as _nudge): one lost notice beats a loop.
        with open(_FLAG, "w") as fh:
            fh.write(name + "\n")
        _nudge.mark_fired()
        sys.stderr.write(
            f"\n`{cli}` is installed on this machine. The one-time EUR 29 {name} "
            f"policy pack adds tested walls for: {scope}.\n"
            f"{url}\n"
            "(one-time-per-machine notice; silence it: GATECAT_NO_NUDGE=1)\n"
        )
    except Exception:
        pass
