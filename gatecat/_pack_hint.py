"""One-time, opt-out policy-pack hint keyed off CLIs present on the machine.

Same contract as gatecat._nudge (the pattern is copied deliberately): stderr
only, best-effort (never raises, never changes an exit code), opt-out via
GATECAT_NO_NUDGE / GATECAT_QUIET, at most ONCE per machine (flag file in the
existing ~/.gatecat state dir), and never stacked with another nudge in the
same run (shared per-process guard in gatecat._nudge).

The detection is honest and local: ``shutil.which()`` on stack CLIs. A machine
with the ``stripe`` CLI plausibly holds credentials the Fintech pack guards; a
machine with ``vercel``/``fly``/... plausibly deploys where the PaaS pack
guards; a machine with ``datadog-ci``/``sentry-cli`` plausibly holds the admin
API tokens the HTTP-API Breadth pack guards. Deliberately NO universal CLIs
(docker, gh, curl): they are on every dev box and would destroy the precision
that makes this a high-intent, once-per-machine hint. Pack scopes below quote
PRICING.md (ASCII-transliterated for stderr). Links go to the pack preview
page — full scope before checkout — never straight to a payment form.
"""
import os
import shutil
import sys

from gatecat import _nudge

_FLAG = os.path.expanduser("~/.gatecat/.pack_nudged")

# (pack name, CLIs that suggest it, scope quoted from PRICING.md, preview URL,
# GATECAT_EXTRA_POLICIES module -- same names the pack fulfiller ships in
# gatecat_fulfill.MODULE_FOR, so a hint stays silent once the pack is loaded).
_PACKS = (
    ("Fintech", ("stripe",),
     "refund creation, payouts/transfers, customer & billing-config deletion",
     "https://gate.cat/packs.html?source=hint#fintech", "fintech"),
    ("PaaS", ("vercel", "netlify", "fly", "heroku", "railway", "render", "supabase"),
     "`vercel remove`, `netlify sites:delete`, `fly/heroku apps destroy`, "
     "`railway down`, `render/supabase delete`",
     "https://gate.cat/packs.html?source=hint#paas", "paas"),
    ("HTTP-API Breadth", ("datadog-ci", "sentry-cli"),
     "destructive raw-HTTP calls to Datadog, Sentry, Slack admin, Atlassian, "
     "Docker Hub, PyPI, ... - the modality CLI-verb walls never see",
     "https://gate.cat/packs.html?source=hint#http-api", "http_api_breadth"),
)


def _owned(module: str) -> bool:
    """True if this pack's module is already loaded via GATECAT_EXTRA_POLICIES
    (comma/space/colon-separated). Suppress-only: never used to suggest a
    DIFFERENT pack, just to stay silent about one the user already bought."""
    extra = os.environ.get("GATECAT_EXTRA_POLICIES", "")
    tokens = extra.replace(",", " ").replace(":", " ").split()
    return any(t == module or t.endswith("." + module) for t in tokens)


def _detect():
    """First (pack, matched CLI) whose tool exists on PATH AND is not already
    owned, else None."""
    for name, clis, scope, url, module in _PACKS:
        if _owned(module):
            continue
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
