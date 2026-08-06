"""Tests for scripts/daily_funnel.py — the fixture-driven daily funnel snapshot.

The agent sandbox has no VPS key, so correctness is proven on a committed
fixture; the docstring documents where the real log run happens.
"""
import importlib.util
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "gatecat_events.log")
SCRIPT = os.path.join(ROOT, "scripts", "daily_funnel.py")


def _load():
    spec = importlib.util.spec_from_file_location("daily_funnel_t", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_snapshot_counts_one_day_only():
    df = _load()
    lines = open(FIXTURE).read().splitlines()

    snap = df.snapshot(lines, "2026-07-22")

    assert snap == {
        "date": "2026-07-22",
        "page_view": 3,          # s1(hn) + s2(pypi) + s3(direct); smoke_test ignored
        "install_copy": 1,
        "checkout_click": 1,     # the 23 Jul reddit click is OUT of this day
        "top_sources": {"hn": 2, "pypi": 2, "direct": 1},
    }


def test_snapshot_empty_day_is_all_zeroes():
    df = _load()
    lines = open(FIXTURE).read().splitlines()

    snap = df.snapshot(lines, "2026-07-01")

    assert snap["page_view"] == 0
    assert snap["checkout_click"] == 0
    assert snap["top_sources"] == {}


def test_cli_emits_single_json_line_metrics_log_shaped():
    out = subprocess.run(
        [sys.executable, SCRIPT, FIXTURE, "--date", "2026-07-22"],
        capture_output=True, text=True, check=True).stdout
    assert out.count("\n") == 1
    parsed = json.loads(out)
    assert parsed["date"] == "2026-07-22"
    assert set(parsed) == {"date", "page_view", "install_copy",
                           "checkout_click", "top_sources"}
