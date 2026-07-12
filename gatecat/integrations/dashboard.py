"""`gate.cat` — the user-facing dashboard. Makes the guardrail VISIBLE.

A guardrail that only speaks up when it blocks something is invisible the other
99% of the time - the user never sees it working, never trusts it, never knows
what they're paying for. This reads the veto audit log (already written on every
decision) and shows, in one command, that gate.cat is on duty:

    gate.cat            # live status: on-duty, watched N, stopped M, last events
    gate.cat stats      # full breakdown by decision + policy
    gate.cat log        # recent decisions, newest first
    gate.cat report     # monthly report (markdown) from the local log - free tier
    gate.cat why <cmd>  # explain what the gate would do with a command + why

Zero heavy deps (no ML) - it only reads JSONL the gate already wrote, so it runs
anywhere the guardrail is installed. ASCII-only output (D1: Windows cp1252-safe).
"""
from __future__ import annotations

import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


# --- reading the log the gate already writes -------------------------------
def _log_path() -> Path:
    env = os.environ.get("GATECAT_VETO_LOG")
    if env:
        return Path(env)
    return Path.home() / ".gatecat" / "veto_log.jsonl"


def _read(limit: int | None = None) -> list[dict]:
    """Read decision records (newest last). Best-effort: a malformed line is
    skipped, never fatal - the dashboard must never crash on a bad log."""
    path = _log_path()
    if not path.exists():
        return []
    out: list[dict] = []
    try:
        with path.open("r", encoding="ascii", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        return []
    return out[-limit:] if limit else out


# --- rendering (ASCII, optional color) -------------------------------------
def _color(enabled: bool):
    if not enabled:
        return lambda s, _c: s
    codes = {"red": "31", "yellow": "33", "green": "32", "cyan": "36",
             "grey": "90", "bold": "1"}
    return lambda s, c: f"\033[{codes.get(c, '0')}m{s}\033[0m"


def _use_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


# how each decision reads to a human + its color
_DECISION_LABEL = {
    "block": ("STOPPED", "red"),
    "warn": ("flagged", "yellow"),
    "allow": ("allowed", "green"),
    "disarmed": ("disarmed", "grey"),
    "disarmed_off": ("off-allowed", "grey"),
    "armed": ("armed", "green"),
    "shadow_block": ("would-stop", "cyan"),
    # FREE-CORE local control (protection.py)
    "override_allow": ("override", "cyan"),
    "override_grant": ("pre-approved", "cyan"),
    "stagnation": ("no-progress", "yellow"),
}


def _summary(records: list[dict]) -> dict:
    total = len(records)
    dec = Counter(r.get("decision", "?") for r in records)
    pol = Counter(r.get("policy") for r in records if r.get("decision") in ("block", "warn") and r.get("policy"))
    stopped = dec.get("block", 0)
    flagged = dec.get("warn", 0)
    return {"total": total, "dec": dec, "pol": pol,
            "stopped": stopped, "flagged": flagged,
            "interventions": stopped + flagged}


def render_status(records: list[dict], color: bool = True) -> str:
    """The default view: is the gate on duty, and what has it done. Short."""
    c = _color(color)
    if not records:
        return (c("gate.cat", "bold") + " is installed but has seen no commands yet.\n"
                "  Arm it as a Claude Code PreToolUse hook: add `gatecat-hook` to\n"
                "  .claude/settings.json (matcher \"Bash|Write|Edit\"), then it starts\n"
                "  watching. Full config: https://github.com/BGMLAI/gate.cat#the-hook--the-strongest-mode")
    s = _summary(records)
    # FREE-CORE: show the local on/off protection state up top (gate.cat status).
    try:
        from gatecat.integrations import protection as _prot
        _off = _prot.is_protection_off()
    except Exception:
        _off = False
    if _off:
        banner = c("gate.cat", "bold") + " " + c("PROTECTION OFF", "yellow") + \
            c(" (catastrophic classes still hard-block)", "grey")
    else:
        banner = c("gate.cat", "bold") + " " + c("ON DUTY", "green")
    lines = [
        banner,
        "=" * 40,
        f"  watched   {s['total']:>7} commands",
        f"  {c('STOPPED', 'red')}   {s['stopped']:>7} irreversible / dangerous",
        f"  {c('flagged', 'yellow')}   {s['flagged']:>7} surfaced for you to review",
        f"  allowed   {s['dec'].get('allow', 0):>7} everyday work, untouched",
    ]
    if s["dec"].get("disarmed"):
        lines.append(f"  disarmed  {s['dec']['disarmed']:>7} (throwaway/CI env)")
    # what it most often stops
    if s["pol"]:
        top = ", ".join(f"{name} ({n})" for name, n in s["pol"].most_common(3))
        lines.append("")
        lines.append(f"  most-caught: {top}")
    # last few interventions - proof it's real
    recent = [r for r in records if r.get("decision") in ("block", "warn")][-3:]
    if recent:
        lines.append("")
        lines.append("  recent stops:")
        for r in reversed(recent):
            lbl, col = _DECISION_LABEL.get(r.get("decision", ""), ("?", "grey"))
            cmd = (r.get("context") or "").replace("\n", " ")[:52]
            lines.append(f"    {c(lbl, col):>16}  {cmd}")
    lines.append("")
    lines.append(c(f"  {s['interventions']} interventions kept your machine safe. "
                   f"gate.cat is watching.", "grey"))
    return "\n".join(lines)


def render_stats(records: list[dict], color: bool = True) -> str:
    """Full breakdown: every decision type + every policy that fired."""
    c = _color(color)
    if not records:
        return "No decisions logged yet."
    s = _summary(records)
    lines = [c("gate.cat stats", "bold"), "=" * 40,
             f"total commands watched: {s['total']}", ""]
    lines.append("by decision:")
    for dec, n in s["dec"].most_common():
        lbl, col = _DECISION_LABEL.get(dec, (dec, "grey"))
        pct = 100 * n / s["total"]
        lines.append(f"  {c(lbl, col):>18}  {n:>7}  ({pct:.1f}%)")
    if s["pol"]:
        lines.append("")
        lines.append("what triggered an intervention (block/warn):")
        for name, n in s["pol"].most_common():
            lines.append(f"  {name:>22}  {n:>5}")
    return "\n".join(lines)


def render_log(records: list[dict], n: int = 20, color: bool = True) -> str:
    """Recent decisions, newest first - the raw feed."""
    c = _color(color)
    recent = records[-n:]
    if not recent:
        return "No decisions logged yet."
    lines = [c(f"last {len(recent)} decisions (newest first)", "bold"), "=" * 40]
    for r in reversed(recent):
        lbl, col = _DECISION_LABEL.get(r.get("decision", ""), (r.get("decision", "?"), "grey"))
        ts = (r.get("ts") or "")[11:19]  # HH:MM:SS
        cmd = (r.get("context") or "").replace("\n", " ")[:56]
        lines.append(f"  {c(ts, 'grey')}  {c(lbl, col):>16}  {cmd}")
    return "\n".join(lines)


def render_report(records: list[dict], month: str | None = None) -> str:
    """`gate.cat report [YYYY-MM]` - the free local monthly report (PRICING.md:
    "Local CLI dashboard + local reports"). Markdown, counts only - it never
    includes command text, so the output is safe to paste into a ticket or a
    channel. Generated 100% from the local log; nothing leaves the machine."""
    if not month:
        month = datetime.now(timezone.utc).strftime("%Y-%m")
    ev = [r for r in records if (r.get("ts") or "").startswith(month)]
    lines = [f"# gate.cat -- monthly report ({month})", ""]
    if not ev:
        lines += [f"No decisions logged in {month}. The gate appends to its local",
                  "veto log on every decision, so an empty month means no agent",
                  "traffic was watched - check that the hook is armed (`gate.cat`)."]
        return "\n".join(lines)
    s = _summary(ev)
    days = sorted({(r.get("ts") or "")[:10] for r in ev})
    rate = 100 * s["interventions"] / s["total"]
    lines += [
        f"**Period:** {days[0]} -> {days[-1]} | **Source:** local veto log "
        f"(this machine) | **Generated:** "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
        "",
        "## The month in one line",
        "",
        f"**{s['total']:,} agent commands watched - {s['stopped']} blocked - "
        f"{s['flagged']} warned - intervention rate {rate:.1f}%**",
        "",
        "> The gate is certain only about what it **blocks**; an unmatched",
        "> action is *unchecked*, not *safe*.",
        "",
        "## Verdicts",
        "",
        "| decision | count |",
        "|---|---|",
    ]
    for dec, n in s["dec"].most_common():
        lines.append(f"| {dec} | {n:,} |")
    if s["pol"]:
        lines += ["", "## Top policies that fired (block + warn)", "",
                  "| policy | interventions |", "|---|---|"]
        for name, n in s["pol"].most_common(8):
            lines.append(f"| {name} | {n:,} |")
    lines += [
        "",
        "## Timeline",
        "",
        f"Decisions on **{len(days)}** distinct day(s), {days[0]} to {days[-1]}.",
        "",
        "---",
        "*Generated locally by the free `gate.cat report` command - counts only,",
        "no command text, nothing sent anywhere. This log lives on the same",
        "machine the agent runs on; the paid tier keeps an off-machine copy",
        "precisely because of that (see PRICING.md).*",
    ]
    return "\n".join(lines)


def explain(command: str, color: bool = True) -> str:
    """`gate.cat why <cmd>` - run the FULL gate on a command and show the
    per-stage trace: which layer decided, and why. Makes the gate legible."""
    c = _color(color)
    try:
        from gatecat.action_pipeline import ActionPipeline
        from gatecat.integrations.action_analysis import DeletePolicy
        pipe = ActionPipeline(policy=DeletePolicy(),
                              home=os.path.expanduser("~").replace("\\", "/"),
                              cwd=os.getcwd().replace("\\", "/"))
        v = pipe.check(command)
    except Exception as exc:  # never crash the explainer
        return f"could not evaluate (fail-closed would BLOCK): {type(exc).__name__}: {exc}"
    lbl, col = _DECISION_LABEL.get(v.level, (v.level, "grey"))
    lines = [
        c("gate.cat why", "bold") + f"  {command[:70]}",
        "=" * 40,
        f"  verdict: {c(lbl.upper(), col)}   (decided by: {v.channel})",
        f"  reason:  {v.reason[:120]}",
    ]
    if getattr(v, "stages", None):
        lines.append("")
        lines.append("  how it got here:")
        for st in v.stages:
            if isinstance(st, dict):
                stage = st.get("stage", st.get("sub", "?"))
                info = st.get("level") or st.get("policy") or st.get("reason") or ""
                lines.append(f"    - {stage}: {str(info)[:60]}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    cmd = args[0] if args else "status"
    color = _use_color()

    # `gate.cat cloud <init|report|verify|key>` -- the E2EE off-machine history CLI
    if cmd == "cloud":
        from gatecat import cloud_cli
        cloud_cli.main(args[1:])
        return 0

    # --- FREE-CORE local control verbs (protection.py): on / off / allow ------
    # All LOCAL, all FREE - no cloud key, no entitlement. These write the state
    # files through the tool itself (not a shell redirect), so the
    # STATE_FILE_TAMPER wall - which blocks an agent's shell write to those same
    # files - never fires on the legitimate human CLI path.
    if cmd in ("off", "on"):
        from gatecat.integrations import protection as _prot
        state = _prot.set_protection(cmd)
        if state == "off":
            print("gate.cat protection is now OFF.\n"
                  "  Ordinary rules are downgraded to allow on THIS machine "
                  "(logged, never silent).\n"
                  "  Catastrophic classes (rm -rf /, cloud/disk destroy, guard/"
                  "security tamper,\n"
                  "  secret/DB wipe) STILL hard-block - they can never be disarmed.\n"
                  "  Re-arm with: gate.cat on")
        else:
            print("gate.cat protection is now ON. Every rule is enforced again.")
        return 0
    if cmd == "allow":
        from gatecat.integrations import protection as _prot
        if len(args) < 2:
            print('usage: gate.cat allow "<command>" [ttl_seconds]')
            return 2
        command = args[1]
        ttl = 300
        if len(args) > 2 and args[2].isdigit():
            ttl = int(args[2])
        entry = _prot.add_override(command, ttl_s=ttl)
        print(f"pre-approved ONE command for {ttl}s (single-use, then it expires):\n"
              f"  {entry['command_preview']}\n"
              "  It will pass ONCE if the gate would have blocked it - UNLESS it is a\n"
              "  catastrophic class (those can never be overridden). Granted by "
              f"{entry['who']}.")
        return 0

    if cmd in ("status", "", "-h", "--help") and cmd != "why":
        if cmd in ("-h", "--help"):
            print("gate.cat [status|on|off|allow '<cmd>' [ttl]|stats|log|report [YYYY-MM]|why <command>]")
            return 0
        print(render_status(_read(), color))
        return 0
    if cmd == "stats":
        print(render_stats(_read(), color))
        return 0
    if cmd == "log":
        n = int(args[1]) if len(args) > 1 and args[1].isdigit() else 20
        print(render_log(_read(), n, color))
        return 0
    if cmd == "report":
        month = args[1] if len(args) > 1 else None
        if month and not (len(month) == 7 and month[:4].isdigit()
                          and month[4] == "-" and month[5:].isdigit()):
            print("usage: gate.cat report [YYYY-MM]")
            return 2
        print(render_report(_read(), month))
        return 0
    if cmd == "why":
        if len(args) < 2:
            print("usage: gate.cat why '<command>'")
            return 2
        print(explain(" ".join(args[1:]), color))
        return 0
    print(f"unknown command: {cmd}\n"
          "gate.cat [status|on|off|allow '<cmd>' [ttl]|stats|log|report [YYYY-MM]|why <command>]")
    return 2


if __name__ == "__main__":
    sys.exit(main())
