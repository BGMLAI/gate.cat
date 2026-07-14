#!/usr/bin/env python3
"""Summarize the privacy-preserving gate.cat event log."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


REQUEST_RE = re.compile(r'"(?:GET|POST) ([^ ]+) HTTP/[^"]+"')


def summarize(lines: list[str]) -> dict[str, object]:
    events: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    campaigns: Counter[str] = Counter()
    sessions: defaultdict[str, set[str]] = defaultdict(set)

    for line in lines:
        match = REQUEST_RE.search(line)
        if not match:
            continue
        query = parse_qs(urlsplit(match.group(1)).query)
        event = query.get("e", [""])[0]
        if not event or event == "smoke_test":
            continue
        source = query.get("source", [""])[0] or "direct"
        campaign = query.get("campaign", [""])[0] or "none"
        session = query.get("sid", [""])[0]
        events[event] += 1
        sources[source] += 1
        campaigns[campaign] += 1
        if session:
            sessions[event].add(session)

    return {
        "events": dict(events.most_common()),
        "unique_sessions_by_event": {
            event: len(values) for event, values in sorted(sessions.items())
        },
        "sources": dict(sources.most_common()),
        "campaigns": dict(campaigns.most_common()),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    print(json.dumps(summarize(args.log.read_text().splitlines()), indent=2))


if __name__ == "__main__":
    main()
