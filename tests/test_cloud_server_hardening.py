"""gate.cat Cloud server — crowd-hardening contracts.

The zero-knowledge store runs one thread per request (ThreadingHTTPServer) on a
box nginx does NOT front with limit_req. These pin the defenses that keep a
launch-day crowd (or a flood) from corrupting the store or exhausting the box:

  1. Concurrency-safe seq -- N parallel POSTs for one account never collide on
     the append cursor (no duplicate/interleaved seq).
  2. Body cap -- a Content-Length over MAX_BODY is rejected 413 without reading
     the body into RAM.
  3. Per-IP rate limit -- a flood from one IP gets 429 instead of eating threads.
  4. Path-traversal guard -- an account id can never escape the events dir.
  5. Accounts cache -- a hot path does not re-parse the whole accounts file per
     request, and still sees a newly issued key.
"""
import importlib.util
import json
import os
import threading

import pytest


def _load_server(tmp_path):
    os.environ["CLOUD_DATA_DIR"] = str(tmp_path)
    path = os.path.join(os.path.dirname(__file__), "..", "products", "cloud", "cloud_server.py")
    spec = importlib.util.spec_from_file_location("cloud_server_h", os.path.abspath(path))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m._ensure()
    return m


def test_concurrent_appends_never_collide_on_seq(tmp_path):
    """1000 events across 50 threads for ONE account -> 1000 unique, gapless seq."""
    srv = _load_server(tmp_path)
    srv.issue_key("acct", "solo")
    errs = []

    def worker(base):
        try:
            batch = [{"ts": base + i, "ct": f"ct{base + i}"} for i in range(20)]
            srv._store("acct", batch)
        except Exception as e:  # pragma: no cover
            errs.append(e)

    threads = [threading.Thread(target=worker, args=(t * 1000,)) for t in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errs
    rows = srv._read("acct", since=0)
    seqs = sorted(r["seq"] for r in rows)
    assert seqs == list(range(1, 1001))          # unique + gapless: no lost/dup write


def test_body_over_cap_is_rejected_without_reading(tmp_path):
    """A Content-Length above MAX_BODY -> 413, and rfile is never read (RAM safe)."""
    srv = _load_server(tmp_path)

    class FakeRfile:
        def read(self, n):  # pragma: no cover - must NOT be called
            raise AssertionError("body was read despite exceeding MAX_BODY")

    h = srv.Handler.__new__(srv.Handler)
    h.headers = {"Content-Length": str(srv.MAX_BODY + 1), "Authorization": "Bearer x"}
    h.rfile = FakeRfile()
    h.path = "/v1/events"
    h.client_address = ("9.9.9.9", 1)
    captured = {}
    h._json = lambda code, obj: captured.update(code=code, obj=obj)
    h.do_POST()
    assert captured["code"] == 413


def test_per_ip_rate_limit_trips(tmp_path):
    srv = _load_server(tmp_path)
    srv.IP_RATE_MAX = 10
    allowed = sum(1 for _ in range(25) if srv._rate_ok("1.2.3.4", 1000.0))
    assert allowed == 10                          # 11th..25th from same IP get refused
    assert srv._rate_ok("5.6.7.8", 1000.0)        # a different IP is unaffected


def test_account_id_cannot_traverse_out_of_events_dir(tmp_path):
    srv = _load_server(tmp_path)
    events_dir = os.path.realpath(os.path.join(str(tmp_path), "events"))
    for evil in ("../../etc/passwd", "..", "a/../../b", "/abs/path", "x\x00y"):
        srv._store(evil, [{"ts": 1, "ct": "x"}])
    # every stored file resolves to a flat name INSIDE events/ -- nothing escapes
    for f in os.listdir(events_dir):
        resolved = os.path.realpath(os.path.join(events_dir, f))
        assert os.path.dirname(resolved) == events_dir
        assert os.sep not in f                    # no path separator survived
    assert os.listdir(events_dir)                 # it still stored, just safely


def test_iso_and_junk_timestamps_are_coerced_never_crash(tmp_path):
    """Real veto logs carry ISO-8601 timestamps ('2026-07-11T00:00:00Z'). The
    server used to `int()` them bare -> ValueError -> 502 on every real ship.
    Every ts shape must store with a sane int ts, never raise."""
    srv = _load_server(tmp_path)
    srv.issue_key("acct", "solo")
    batch = [
        {"ts": 1720000000, "ct": "a"},               # epoch int
        {"ts": "1720000001", "ct": "b"},             # numeric string
        {"ts": "2026-07-11T00:00:00Z", "ct": "c"},   # ISO-8601 (the crash case)
        {"ts": None, "ct": "d"},                     # missing
        {"ts": "not-a-date", "ct": "e"},             # pure garbage
    ]
    assert srv._store("acct", batch) == 5            # all stored, none dropped/crashed
    for r in srv._read("acct", since=0):
        assert isinstance(r["ts"], int) and r["ts"] > 0


def test_handler_returns_500_json_not_502_on_internal_error(tmp_path, monkeypatch):
    """A request-thread crash must become a clean 500 JSON, not a dropped
    connection (nginx 502 reads as 'whole service down')."""
    srv = _load_server(tmp_path)

    def boom():
        raise RuntimeError("simulated internal fault")

    h = srv.Handler.__new__(srv.Handler)
    captured = {}
    h._json = lambda code, obj: captured.update(code=code, obj=obj)
    h._safely(boom)                                  # must swallow + emit 500, not raise
    assert captured["code"] == 500


def test_accounts_cache_refreshes_on_new_key(tmp_path):
    srv = _load_server(tmp_path)
    k1 = srv.issue_key("a", "solo")
    assert srv._account_for(k1)["account"] == "a"
    k2 = srv.issue_key("b", "team")               # file mtime changes -> cache invalidates
    assert srv._account_for(k2)["account"] == "b"
    assert srv._account_for(k1)["account"] == "a"  # old key still valid
    assert srv._account_for("gck_nope") is None
