"""Append one JSONL metrics line: GitHub repo stats + PyPI downloads.

Feeds METRICS.log for the pre-registered T+30 decision gate (runbook §5):
stars = GitHub `stargazers_count`; installs = pypistats trailing-30d downloads
WITHOUT mirrors (labeled "downloads, not users"). Failures write null, never
crash - a gap in the log is visible, a crashed cron is silent.
"""
import datetime
import json
import sys


def load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


repo = load(sys.argv[1])
pypi = load(sys.argv[2])  # pypistats.org /api/packages/gate-cat/recent
data = pypi.get("data") or {}

print(json.dumps({
    "date": datetime.date.today().isoformat(),
    "stars": repo.get("stargazers_count"),
    "forks": repo.get("forks_count"),
    "watchers": repo.get("subscribers_count"),
    "open_issues": repo.get("open_issues_count"),
    # pypistats "recent" counts exclude known mirrors; label stays honest.
    "pypi_downloads_last_month_no_mirrors": data.get("last_month"),
}, sort_keys=True))
