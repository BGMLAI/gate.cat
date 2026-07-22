#!/usr/bin/env python3
"""Daily funnel snapshot from the gate.cat events log — one JSON line per day.

MEASUREMENT ONLY: this quantifies the middle of the funnel (page views ->
install copies -> checkout clicks) so pricing/copy iterations run on data
instead of memory. It blocks nothing and earns nothing by itself.

The events log lives on the VPS and the agent sandbox holds no key, so run
this WHERE THE LOG LIVES (same SSH pattern as scripts/launch_metrics.py):

    ssh -i ~/.ssh/vps/id_ed25519 root@204.168.129.200 \\
        'cat /var/log/nginx/gatecat-events.log' \\
      | python3 scripts/daily_funnel.py - --date 2026-07-22 >> METRICS.log

The output shape intentionally mirrors METRICS.log: a single JSON object per
line, so the same T+30 tooling can read both streams.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from funnel_report import summarize  # noqa: E402 — reuse the one true parser


def snapshot(lines: list[str], date: str) -> dict:
    """Funnel counts for one UTC day (``date`` = YYYY-MM-DD)."""
    stamp = datetime.strptime(date, "%Y-%m-%d").strftime("%d/%b/%Y")
    day = [line for line in lines if f"[{stamp}:" in line]
    s = summarize(day)
    events = s["events"]
    return {
        "date": date,
        "page_view": events.get("page_view", 0),
        "install_copy": events.get("install_copy", 0),
        "checkout_click": events.get("checkout_click", 0),
        "top_sources": dict(list(s["sources"].items())[:5]),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", help="events log path, or '-' for stdin")
    parser.add_argument("--date", required=True, help="UTC day to snapshot (YYYY-MM-DD)")
    args = parser.parse_args(argv)
    if args.log == "-":
        lines = sys.stdin.read().splitlines()
    else:
        lines = Path(args.log).read_text().splitlines()
    print(json.dumps(snapshot(lines, args.date), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
