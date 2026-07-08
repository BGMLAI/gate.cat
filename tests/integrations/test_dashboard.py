"""The user-facing dashboard (`gate.cat`): makes the guardrail visible. These
pin that it reads the real veto log, renders honestly, and never crashes on a
bad/empty log or without ML deps installed.
"""
from __future__ import annotations

import json

import pytest

from gatecat.integrations import dashboard as d


def _write_log(tmp_path, records):
    p = tmp_path / "veto.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="ascii")
    return p


SAMPLE = [
    {"ts": "2026-07-05T10:00:00Z", "decision": "allow", "policy": None, "context": "ls -la"},
    {"ts": "2026-07-05T10:00:01Z", "decision": "block", "policy": "RM_RF", "context": "rm -rf /srv"},
    {"ts": "2026-07-05T10:00:02Z", "decision": "warn", "policy": "SECRET_READ", "context": "cat ~/.ssh/id_rsa"},
    {"ts": "2026-07-05T10:00:03Z", "decision": "block", "policy": "GH_DESTRUCTIVE", "context": "gh repo delete x"},
    {"ts": "2026-07-05T10:00:04Z", "decision": "allow", "policy": None, "context": "git status"},
]


def test_status_reports_on_duty_with_counts(tmp_path, monkeypatch):
    monkeypatch.setenv("GATECAT_VETO_LOG", str(_write_log(tmp_path, SAMPLE)))
    out = d.render_status(d._read(), color=False)
    assert "ON DUTY" in out
    assert "watched" in out and "5" in out
    assert "STOPPED" in out          # blocks shown
    assert "gh repo delete x" in out or "rm -rf /srv" in out  # a recent stop is proof


def test_empty_log_is_not_a_crash(tmp_path, monkeypatch):
    monkeypatch.setenv("GATECAT_VETO_LOG", str(tmp_path / "nope.jsonl"))
    out = d.render_status(d._read(), color=False)
    assert "no commands yet" in out.lower()


def test_malformed_lines_are_skipped(tmp_path, monkeypatch):
    p = tmp_path / "veto.jsonl"
    p.write_text('{"decision":"block","context":"rm -rf /"}\nnot json\n{bad\n', encoding="ascii")
    monkeypatch.setenv("GATECAT_VETO_LOG", str(p))
    recs = d._read()
    assert len(recs) == 1          # the one valid line, junk skipped
    assert "ON DUTY" in d.render_status(recs, color=False)


def test_stats_breaks_down_by_decision_and_policy(tmp_path):
    out = d.render_stats(SAMPLE, color=False)
    assert "by decision" in out
    assert "RM_RF" in out and "GH_DESTRUCTIVE" in out


def test_log_shows_newest_first(tmp_path):
    out = d.render_log(SAMPLE, n=3, color=False)
    # newest (10:00:04 git status) appears before oldest of the window
    assert out.index("git status") < out.index("gh repo delete x")


def test_why_explains_a_real_verdict():
    out = d.explain("gh repo delete prod", color=False)
    assert "STOPPED" in out or "BLOCK" in out.upper()
    assert "koryto" in out or "GH_DESTRUCTIVE" in out


def test_output_is_ascii_safe(tmp_path):
    # D1: everything the dashboard prints survives a cp1252 console
    for r in (d.render_status(SAMPLE, color=False),
              d.render_stats(SAMPLE, color=False),
              d.render_log(SAMPLE, color=False),
              d.explain("rm -rf /", color=False)):
        r.encode("ascii")


def test_dashboard_pulls_no_ml_deps():
    import sys
    before = set(sys.modules)
    d._read()
    d.render_status(SAMPLE, color=False)
    pulled = set(sys.modules) - before
    assert not [m for m in pulled if any(h in m for h in ("numpy", "onnx", "torch", "hnswlib"))]
