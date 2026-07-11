#!/usr/bin/env python3
"""gate.cat Cloud — the zero-knowledge server.

Stores an off-machine, append-only copy of a client's veto history that the
client's own AI agent has no credentials for and cannot rewrite. Critically, the
server stores only **ciphertext** (encrypted on the client with a key we never
see) plus a cleartext timestamp for ordering/retention. It cannot read a single
policy id, reason, or command. A full compromise of this box yields opaque blobs.

Endpoints (Bearer <api_key>):
  POST /v1/events   body: [{"ts":<int>,"ct":"<b64 aes-gcm>"}...]  -> {"stored":n}
  GET  /v1/events?since=<seq>                                     -> {"events":[{seq,ts,ct}]}
  GET  /v1/health                                                 -> {"ok":true,...}

Auth: the API key is issued on subscription (Stripe webhook, see issue_key). Only
its sha256 is stored, so a leak of the accounts file does not expose live keys.

Zero third-party deps (stdlib), matching subscribe.py / stripe_fulfill.py.
Runs on 127.0.0.1:8094 behind nginx (cloud.gate.cat or gate.cat/cloud/).
"""
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

DATA = os.environ.get("CLOUD_DATA_DIR", "/opt/bgml/gatecat-cloud")
ACCOUNTS = os.path.join(DATA, "accounts.jsonl")   # {key_sha256, account, tier, ts}
EVENTS_DIR = os.path.join(DATA, "events")
MAX_BATCH = 500
MAX_CT = 64 * 1024        # a single event blob ceiling (sanity, not security)
MAX_BODY = 8 * 1024 * 1024  # reject a request body larger than this (RAM DoS guard)
RATE_WINDOW = 60          # per-account soft rate limit: events/min
RATE_MAX = 5000

# ThreadingHTTPServer runs each request in its own thread. Two concurrent POSTs
# for the SAME account both read the line-count for `seq` then append -> duplicate
# seq / interleaved lines. A per-account lock serializes the read+append. A single
# global lock would serialize ALL writers under a crowd; per-account keeps
# different customers parallel.
_LOCKS: dict = {}
_LOCKS_GUARD = threading.Lock()


def _lock_for(account: str) -> threading.Lock:
    with _LOCKS_GUARD:
        lk = _LOCKS.get(account)
        if lk is None:
            lk = _LOCKS[account] = threading.Lock()
        return lk


# tiny stat-keyed cache so a crowd doesn't re-read+parse the whole accounts file
# on every single request (O(n) per hit -> O(1) between changes). Keyed on
# (mtime, size): accounts.jsonl is append-only so size strictly grows on every
# issue_key -- this invalidates even when two keys land in the same mtime tick
# (mtime-only would hand a brand-new subscriber a stale "bad api key").
_ACCT_CACHE = {"stat": None, "by_hash": {}}
_ACCT_GUARD = threading.Lock()

# Application-layer per-IP rate limit (nginx does not front this with limit_req on
# a shared box, so the app defends itself). Fixed window; cheap and thread-safe.
# A flood from one IP gets 429s instead of exhausting threads/disk.
IP_RATE_WINDOW = 10        # seconds
IP_RATE_MAX = 200          # requests per IP per window
_RATE: dict = {}
_RATE_GUARD = threading.Lock()


def _rate_ok(ip: str, now: float) -> bool:
    win = int(now // IP_RATE_WINDOW)
    with _RATE_GUARD:
        w, c = _RATE.get(ip, (win, 0))
        if w != win:
            w, c = win, 0
        c += 1
        _RATE[ip] = (w, c)
        if len(_RATE) > 10000:              # bound memory: drop stale windows
            for k in [k for k, (kw, _) in _RATE.items() if kw < win]:
                _RATE.pop(k, None)
        return c <= IP_RATE_MAX


def _ensure():
    os.makedirs(EVENTS_DIR, exist_ok=True)
    if not os.path.exists(ACCOUNTS):
        open(ACCOUNTS, "a").close()


def issue_key(account: str, tier: str = "solo") -> str:
    """Provision a new API key for an account. Returns the key ONCE (only its
    hash is stored). Called by the Stripe subscription webhook."""
    _ensure()
    key = "gck_" + secrets.token_urlsafe(32)
    with open(ACCOUNTS, "a", encoding="utf-8") as f:
        f.write(json.dumps({"key_sha256": hashlib.sha256(key.encode()).hexdigest(),
                            "account": account, "tier": tier, "ts": int(time.time())}) + "\n")
    return key


def _load_accounts() -> dict:
    """Return {key_sha256: rec}, cached until accounts.jsonl changes."""
    try:
        st = os.stat(ACCOUNTS)
        stat = (st.st_mtime, st.st_size)
    except OSError:
        return {}
    with _ACCT_GUARD:
        if _ACCT_CACHE["stat"] == stat:
            return _ACCT_CACHE["by_hash"]
        by_hash = {}
        try:
            for line in open(ACCOUNTS, encoding="utf-8"):
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if rec.get("key_sha256"):
                    by_hash[rec["key_sha256"]] = rec
        except OSError:
            return _ACCT_CACHE["by_hash"]
        _ACCT_CACHE["stat"] = stat
        _ACCT_CACHE["by_hash"] = by_hash
        return by_hash


def _account_for(api_key: str):
    if not api_key:
        return None
    h = hashlib.sha256(api_key.encode()).hexdigest()
    # constant-time-ish: hashing already hides the key; dict lookup is fine since
    # the stored value is itself a hash (no secret compared byte-by-byte here).
    return _load_accounts().get(h)


def _sanitize_account(account: str) -> str:
    """Filename-safe account id (guard against path traversal in the store path)."""
    return "".join(c if c.isalnum() or c in "@._-" else "_" for c in account)[:200]


def _store(account: str, batch: list) -> int:
    account = _sanitize_account(account)
    path = os.path.join(EVENTS_DIR, account + ".jsonl")
    with _lock_for(account):                 # serialize read-seq + append per account
        seq = 0
        if os.path.exists(path):
            with open(path, "rb") as f:      # last seq = line count
                seq = sum(1 for _ in f)
        n = 0
        with open(path, "a", encoding="utf-8") as f:
            for e in batch:
                ct = e.get("ct")
                if not isinstance(ct, str) or len(ct) > MAX_CT:
                    continue
                seq += 1
                f.write(json.dumps({"seq": seq, "ts": int(e.get("ts") or time.time()),
                                    "ct": ct}) + "\n")
                n += 1
            f.flush()
        return n


def _read(account: str, since: int) -> list:
    path = os.path.join(EVENTS_DIR, _sanitize_account(account) + ".jsonl")
    if not os.path.exists(path):
        return []
    out = []
    for line in open(path, encoding="utf-8"):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if rec.get("seq", 0) > since:
            out.append(rec)
    return out


class Handler(BaseHTTPRequestHandler):
    def _bearer(self):
        h = self.headers.get("Authorization", "")
        return h[7:] if h.startswith("Bearer ") else ""

    def _json(self, code, obj):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode())

    def _rate_limited(self) -> bool:
        ip = (self.headers.get("X-Real-IP") or self.client_address[0] or "?")
        if not _rate_ok(ip, time.time()):
            self._json(429, {"error": "rate limited"})
            return True
        return False

    def do_GET(self):
        if self._rate_limited():
            return
        u = urlparse(self.path)
        if u.path == "/v1/health":
            return self._json(200, {"ok": True, "zero_knowledge": True,
                                    "stores": "ciphertext + timestamp only"})
        if u.path != "/v1/events":
            return self._json(404, {"error": "not found"})
        acct = _account_for(self._bearer())
        if not acct:
            return self._json(401, {"error": "bad api key"})
        since = int((parse_qs(u.query).get("since", ["0"])[0]) or 0)
        return self._json(200, {"events": _read(acct["account"], since)})

    def do_POST(self):
        if self._rate_limited():
            return
        if urlparse(self.path).path != "/v1/events":
            return self._json(404, {"error": "not found"})
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n > MAX_BODY:                     # RAM DoS guard: don't read a huge body
            return self._json(413, {"error": "payload too large"})
        acct = _account_for(self._bearer())
        if not acct:
            return self._json(401, {"error": "bad api key"})
        try:
            batch = json.loads(self.rfile.read(n) or b"[]")
        except Exception:
            return self._json(400, {"error": "bad json"})
        if not isinstance(batch, list) or len(batch) > MAX_BATCH:
            return self._json(400, {"error": "bad batch"})
        return self._json(200, {"stored": _store(acct["account"], batch)})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    _ensure()
    port = int(os.environ.get("CLOUD_PORT", "8094"))
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
