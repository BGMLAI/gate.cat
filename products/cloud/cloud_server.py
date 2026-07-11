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
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

DATA = os.environ.get("CLOUD_DATA_DIR", "/opt/bgml/gatecat-cloud")
ACCOUNTS = os.path.join(DATA, "accounts.jsonl")   # {key_sha256, account, tier, ts}
EVENTS_DIR = os.path.join(DATA, "events")
MAX_BATCH = 500
MAX_CT = 64 * 1024   # a single event blob ceiling (sanity, not security)


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


def _account_for(api_key: str):
    if not api_key:
        return None
    h = hashlib.sha256(api_key.encode()).hexdigest()
    if not os.path.exists(ACCOUNTS):
        return None
    for line in open(ACCOUNTS, encoding="utf-8"):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if hmac.compare_digest(rec.get("key_sha256", ""), h):
            return rec
    return None


def _store(account: str, batch: list) -> int:
    path = os.path.join(EVENTS_DIR, account + ".jsonl")
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
    return n


def _read(account: str, since: int) -> list:
    path = os.path.join(EVENTS_DIR, account + ".jsonl")
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

    def do_GET(self):
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
        if urlparse(self.path).path != "/v1/events":
            return self._json(404, {"error": "not found"})
        acct = _account_for(self._bearer())
        if not acct:
            return self._json(401, {"error": "bad api key"})
        n = int(self.headers.get("Content-Length", 0) or 0)
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
