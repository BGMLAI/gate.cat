"""COMPONENT 1 — server-side tier-gating enforcement.

The paid managed layer is only sellable if the SERVER enforces the tier: a solo
key must be refused the team-only ledger export, the 11th machine on a team
account must be rejected, retention must be filtered off-machine, and the
entitlement endpoint must report the plan. These pin those contracts.

The cloud server is a path-loaded stdlib module (no package import); load it the
same way the existing hardening tests do.
"""
import importlib.util
import json
import os

import pytest


def _load_server(tmp_path):
    os.environ["CLOUD_DATA_DIR"] = str(tmp_path)
    path = os.path.join(os.path.dirname(__file__), "..", "products", "cloud", "cloud_server.py")
    spec = importlib.util.spec_from_file_location("cloud_server_tier", os.path.abspath(path))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m._ensure()
    return m


# ---- entitlement table ------------------------------------------------------

def test_entitlement_table_per_tier(tmp_path):
    srv = _load_server(tmp_path)
    assert srv.entitlement("free")["machine_cap"] == 1
    assert srv.entitlement("solo")["machine_cap"] == 1
    assert srv.entitlement("team")["machine_cap"] == 10
    # business is "unlimited" -> None over the wire, not the sentinel int
    assert srv.entitlement("business")["machine_cap"] is None
    assert srv.entitlement("free")["retention_days"] == 30
    assert srv.entitlement("team")["retention_days"] >= 365
    # an unknown tier degrades to free (never crashes / grants extra)
    assert srv.entitlement("wizard")["tier"] == "free"


def test_ledger_is_team_plus_only(tmp_path):
    srv = _load_server(tmp_path)
    assert srv.tier_has_feature("team", "ledger_export")
    assert srv.tier_has_feature("business", "ledger_export")
    assert not srv.tier_has_feature("solo", "ledger_export")
    assert not srv.tier_has_feature("free", "ledger_export")


# ---- fleet machine cap (Team = 10) ------------------------------------------

def test_team_machine_cap_rejects_eleventh(tmp_path):
    """(b) the 11th machine on a team account is rejected."""
    srv = _load_server(tmp_path)
    srv.issue_key("team@x", "team")
    results = [srv.bind_machine("team@x", f"m{i}", "team") for i in range(11)]
    accepted = [ok for ok, _, _ in results]
    assert accepted[:10] == [True] * 10          # first 10 bind
    assert accepted[10] is False                 # 11th rejected
    ok, count, cap = results[10]
    assert cap == 10 and count == 10


def test_machine_bind_is_idempotent(tmp_path):
    """A machine already bound never re-trips the cap on re-report."""
    srv = _load_server(tmp_path)
    srv.issue_key("team@x", "team")
    for i in range(10):
        srv.bind_machine("team@x", f"m{i}", "team")
    # re-report an existing machine: allowed, count unchanged
    ok, count, cap = srv.bind_machine("team@x", "m3", "team")
    assert ok is True and count == 10


def test_business_machine_cap_is_effectively_unlimited(tmp_path):
    srv = _load_server(tmp_path)
    srv.issue_key("biz@x", "business")
    results = [srv.bind_machine("biz@x", f"m{i}", "business") for i in range(50)]
    assert all(ok for ok, _, _ in results)


def test_solo_cap_is_one_machine(tmp_path):
    srv = _load_server(tmp_path)
    srv.issue_key("solo@x", "solo")
    assert srv.bind_machine("solo@x", "m0", "solo")[0] is True
    assert srv.bind_machine("solo@x", "m1", "solo")[0] is False


# ---- retention window filtering ---------------------------------------------

def test_retention_floor_scales_with_tier(tmp_path):
    srv = _load_server(tmp_path)
    now = 10_000_000_000
    free_floor = srv._retention_floor("free", now)
    team_floor = srv._retention_floor("team", now)
    # team keeps MORE history -> its floor is OLDER (smaller epoch) than free's
    assert team_floor < free_floor


def test_events_older_than_retention_are_filtered(tmp_path):
    """(retention) GET /v1/events must drop events older than the tier window."""
    srv = _load_server(tmp_path)
    import time
    now = int(time.time())
    old = now - 40 * 86400        # 40 days old — beyond free's 30d retention
    fresh = now - 1 * 86400
    srv._store("acct", [{"ts": old, "ct": "old"}, {"ts": fresh, "ct": "fresh"}])
    floor = srv._retention_floor("free", now)
    served = srv._read("acct", since=0, min_ts=floor)
    cts = {r["ct"] for r in served}
    assert "fresh" in cts and "old" not in cts
    # team keeps both (365d window)
    served_team = srv._read("acct", since=0, min_ts=srv._retention_floor("team", now))
    assert {"fresh", "old"} <= {r["ct"] for r in served_team}


# ---- ledger tag round-trips through the store -------------------------------

def test_store_preserves_ledger_kind_and_drops_others(tmp_path):
    srv = _load_server(tmp_path)
    srv._store("acct", [
        {"ts": 1, "ct": "a", "kind": "ledger"},
        {"ts": 2, "ct": "b", "kind": "smuggle"},   # any non-ledger tag is dropped
        {"ts": 3, "ct": "c"},
    ])
    rows = srv._read("acct", 0)
    kinds = {r["ct"]: r.get("kind") for r in rows}
    assert kinds["a"] == "ledger"
    assert kinds["b"] is None       # smuggled tag stripped
    assert kinds["c"] is None


# ---- alert store (Solo+) ----------------------------------------------------

def test_alert_store_roundtrip(tmp_path):
    srv = _load_server(tmp_path)
    srv.store_alert("acct", {"kind": "stagnation", "machine": "ci-1",
                             "reason": "repeat_action x3"})
    alerts = srv.read_alerts("acct", 0)
    assert len(alerts) == 1
    assert alerts[0]["machine"] == "ci-1"
    assert alerts[0]["seq"] == 1


# ---- HTTP endpoint enforcement (real server on a loopback port) -------------

import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer


@pytest.fixture
def live_server(tmp_path):
    """A running cloud server on an ephemeral port; yields (module, base_url)."""
    srv = _load_server(tmp_path)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), srv.Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        yield srv, base
    finally:
        httpd.shutdown()


def _get(base, path, key, headers=None):
    req = urllib.request.Request(base + path)
    if key:
        req.add_header("Authorization", "Bearer " + key)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def _post(base, path, key, body, headers=None):
    data = json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method="POST")
    if key:
        req.add_header("Authorization", "Bearer " + key)
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def test_http_solo_denied_team_ledger_but_team_gets_it(live_server):
    """(a) a SOLO key is denied the team ledger; a TEAM key gets it."""
    srv, base = live_server
    solo = srv.issue_key("solo@x", "solo")
    team = srv.issue_key("team@x", "team")

    code_solo, body_solo = _get(base, "/v1/ledger", solo)
    assert code_solo == 402
    assert body_solo["upgrade_to"] == "team"

    code_team, body_team = _get(base, "/v1/ledger", team)
    assert code_team == 200
    assert "ledger" in body_team and body_team["tier"] == "team"


def test_http_entitlement_endpoint(live_server):
    srv, base = live_server
    team = srv.issue_key("team@x", "team")
    code, body = _get(base, "/v1/entitlement", team)
    assert code == 200
    assert body["tier"] == "team"
    assert body["machine_cap"] == 10
    assert "ledger_export" in body["features"]


def test_http_eleventh_machine_report_rejected(live_server):
    """(b) end-to-end: the 11th machine's report is refused with an upgrade msg."""
    srv, base = live_server
    team = srv.issue_key("team@x", "team")
    for i in range(10):
        code, _ = _post(base, "/v1/events", team, [{"ts": 1, "ct": "x"}],
                        headers={"X-Gatecat-Machine": f"m{i}"})
        assert code == 200
    code, body = _post(base, "/v1/events", team, [{"ts": 1, "ct": "x"}],
                       headers={"X-Gatecat-Machine": "m10"})
    assert code == 402
    assert body["machine_cap"] == 10
    assert body["upgrade_to"] == "business"


def test_http_events_report_without_machine_header_still_works(live_server):
    """RED-LINE style: a report with no machine header is not cap-gated (the
    local product must keep working); the cap only counts declared machines."""
    srv, base = live_server
    solo = srv.issue_key("solo@x", "solo")
    code, body = _post(base, "/v1/events", solo, [{"ts": 1, "ct": "x"}])
    assert code == 200 and body["stored"] == 1


def test_http_alert_push_solo_plus_free_denied(live_server):
    srv, base = live_server
    solo = srv.issue_key("solo@x", "solo")
    free = srv.issue_key("free@x", "free")
    code_ok, _ = _post(base, "/v1/alert", solo,
                       {"kind": "stagnation", "reason": "x3", "machine": "m0"})
    assert code_ok == 200
    code_no, body_no = _post(base, "/v1/alert", free,
                             {"kind": "stagnation", "reason": "x3"})
    assert code_no == 402 and body_no["upgrade_to"] == "solo"


def test_http_bad_key_is_401(live_server):
    srv, base = live_server
    code, _ = _get(base, "/v1/entitlement", "gck_not_a_real_key")
    assert code == 401
