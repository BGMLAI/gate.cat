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
MACHINES_DIR = os.path.join(DATA, "machines")     # per-account {machine_id: first_seen}
ALERTS_DIR = os.path.join(DATA, "alerts")         # per-account append-only alert feed
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


def _coerce_ts(v) -> int:
    """A client ts may be an epoch int, a numeric string, or an ISO-8601 string
    (real veto logs carry `2026-07-11T00:00:00Z`). Never trust it into int() bare
    -- `int("2026-...")` is a ValueError that would 500/502 the whole request.
    Parse what we can, fall back to server receive-time (ts is only for ordering)."""
    try:
        return int(v)
    except (TypeError, ValueError):
        pass
    if isinstance(v, str):
        try:
            from datetime import datetime
            return int(datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp())
        except Exception:
            pass
    return int(time.time())


def _ensure():
    os.makedirs(EVENTS_DIR, exist_ok=True)
    os.makedirs(MACHINES_DIR, exist_ok=True)
    os.makedirs(ALERTS_DIR, exist_ok=True)
    if not os.path.exists(ACCOUNTS):
        open(ACCOUNTS, "a").close()


# ---------------------------------------------------------------------------
# TIER ENTITLEMENTS (server-side source of truth).
#
# The whole point of server-side gating: the API key AUTHENTICATES, and the tier
# stored next to it DECIDES what the paid managed layer will serve. A solo key
# and a team key are different not by client honesty but because THIS server
# refuses the team-only endpoints for a solo key. The free/no-key path never
# touches this server at all -- the fully-local product works with zero key.
#
# RED LINE: nothing here gates a LOCAL safety capability (budget-cap / stagnation
# halt / on-off / override all live in the free local core). This table only
# scopes the OFF-MACHINE managed features: retention window, cross-machine
# aggregation, the tamper-evident ledger export, alert push, and the fleet
# machine cap.
# ---------------------------------------------------------------------------
UNLIMITED_MACHINES = 10 ** 9  # "unlimited" sentinel (business); avoids None math

TIERS: dict = {
    "free": {
        "retention_days": 30, "machine_cap": 1,
        "features": ["local_dashboard"],
    },
    "solo": {
        "retention_days": 90, "machine_cap": 1,
        "features": ["local_dashboard", "cloud_history", "alert_push"],
    },
    "team": {
        "retention_days": 365, "machine_cap": 10,
        "features": ["local_dashboard", "cloud_history", "alert_push",
                     "ledger_export", "fleet_aggregation"],
    },
    "business": {
        "retention_days": 1095, "machine_cap": UNLIMITED_MACHINES,
        "features": ["local_dashboard", "cloud_history", "alert_push",
                     "ledger_export", "fleet_aggregation", "priority_retention"],
    },
}
# order for "upgrade to X" messaging + >= comparisons
_TIER_RANK = {"free": 0, "solo": 1, "team": 2, "business": 3}


def _tier_of(acct: dict) -> str:
    t = str((acct or {}).get("tier", "free")).strip().lower()
    return t if t in TIERS else "free"


def entitlement(tier: str) -> dict:
    """Public entitlement dict for a tier (safe defaults to free)."""
    tier = tier if tier in TIERS else "free"
    ent = dict(TIERS[tier])
    cap = ent["machine_cap"]
    return {
        "tier": tier,
        "retention_days": ent["retention_days"],
        "machine_cap": None if cap >= UNLIMITED_MACHINES else cap,
        "features": list(ent["features"]),
    }


def tier_has_feature(tier: str, feature: str) -> bool:
    return feature in TIERS.get(tier if tier in TIERS else "free", {}).get("features", [])


def issue_key(account: str, tier: str = "solo") -> str:
    """Provision a new API key for an account. Returns the key ONCE (only its
    hash is stored). Called by the Stripe subscription webhook."""
    _ensure()
    key = "gck_" + secrets.token_urlsafe(32)
    with open(ACCOUNTS, "a", encoding="utf-8") as f:
        f.write(json.dumps({"key_sha256": hashlib.sha256(key.encode()).hexdigest(),
                            "account": account, "tier": tier, "status": "active",
                            "ts": int(time.time())}) + "\n")
    return key


def revoke_key(api_key: str, reason: str = "subscription_expired") -> bool:
    """Append a revocation for *api_key* without rewriting account history.

    The account log is last-event-wins per key hash, so revocation is durable,
    auditable and immediately invalidates the accounts cache. Returns False for
    an unknown key and never stores the plaintext key.
    """
    if not api_key:
        return False
    _ensure()
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    current = _load_accounts().get(key_hash)
    if not current or current.get("status", "active") != "active":
        return False
    with open(ACCOUNTS, "a", encoding="utf-8") as f:
        f.write(json.dumps({"key_sha256": key_hash,
                            "account": current.get("account", "unknown"),
                            "tier": current.get("tier", "free"),
                            "status": "revoked", "reason": reason,
                            "ts": int(time.time())}) + "\n")
    return True


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
    rec = _load_accounts().get(h)
    if not rec or rec.get("status", "active") != "active":
        return None
    return rec


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
                rec = {"seq": seq, "ts": _coerce_ts(e.get("ts")), "ct": ct}
                # Optional NON-sensitive routing tag so the server can serve the
                # override/toggle ledger separately (GET /v1/ledger) WITHOUT
                # decrypting: the command text stays inside the E2EE `ct`, only
                # the record CLASS ("ledger") rides in clear. Any other value is
                # dropped so a client cannot smuggle plaintext through here.
                kind = e.get("kind")
                if kind == "ledger":
                    rec["kind"] = "ledger"
                f.write(json.dumps(rec) + "\n")
                n += 1
            f.flush()
        return n


def _read(account: str, since: int, min_ts: int = 0) -> list:
    """Return events with seq > since AND ts >= min_ts. `min_ts` implements the
    tier retention window: events older than the tier's retention are filtered
    out server-side (the client cannot ask for more history than its plan)."""
    path = os.path.join(EVENTS_DIR, _sanitize_account(account) + ".jsonl")
    if not os.path.exists(path):
        return []
    out = []
    for line in open(path, encoding="utf-8"):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if rec.get("seq", 0) > since and int(rec.get("ts", 0)) >= min_ts:
            out.append(rec)
    return out


def _retention_floor(tier: str, now: float | None = None) -> int:
    """Oldest ts (epoch seconds) still served for *tier*. 0 == effectively no
    floor when retention is huge (kept as a plain int for the ts comparison)."""
    now = time.time() if now is None else now
    days = TIERS.get(tier if tier in TIERS else "free", {}).get("retention_days", 30)
    floor = int(now) - int(days) * 86400
    return max(0, floor)


# ---- fleet machine cap (Team = 10; Business = unlimited) --------------------
def _machines_path(account: str) -> str:
    return os.path.join(MACHINES_DIR, _sanitize_account(account) + ".json")


def _load_machines(account: str) -> dict:
    try:
        with open(_machines_path(account), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def bind_machine(account: str, machine_id: str, tier: str):
    """Register a machine reporting under an account, enforcing the tier cap.

    Returns (ok, count, cap). A machine already bound is idempotent (re-report
    never trips the cap). A NEW machine beyond the cap is rejected -> the caller
    returns a clear "upgrade" error. Serialized per-account so two machines
    binding at once cannot both slip past the cap.
    """
    machine_id = str(machine_id or "").strip()[:200]
    cap = TIERS.get(tier if tier in TIERS else "free", {}).get("machine_cap", 1)
    with _lock_for("machines:" + account):
        machines = _load_machines(account)
        if machine_id and machine_id in machines:
            return True, len(machines), cap                      # already bound
        if len(machines) >= cap:
            return False, len(machines), cap                     # cap reached
        if machine_id:
            machines[machine_id] = int(time.time())
            tmp = _machines_path(account) + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(machines, f)
            os.replace(tmp, _machines_path(account))
        return True, len(machines), cap


# ---- alert feed (stagnation / loop-guard push; Solo+) ----------------------
def store_alert(account: str, alert: dict) -> int:
    """Append a NON-sensitive alert (stagnation reason / machine) to the account
    feed. Alerts are metadata, not command text -- they can ride in the clear so
    the managed layer can notify (Slack/email) without breaking event E2EE."""
    path = os.path.join(ALERTS_DIR, _sanitize_account(account) + ".jsonl")
    with _lock_for("alerts:" + account):
        seq = 0
        if os.path.exists(path):
            with open(path, "rb") as f:
                seq = sum(1 for _ in f)
        seq += 1
        rec = {"seq": seq, "ts": _coerce_ts(alert.get("ts")),
               "kind": str(alert.get("kind", "stagnation"))[:64],
               "machine": str(alert.get("machine", ""))[:200],
               "reason": str(alert.get("reason", ""))[:400]}
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    return seq


def read_alerts(account: str, since: int = 0) -> list:
    path = os.path.join(ALERTS_DIR, _sanitize_account(account) + ".jsonl")
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

    def _safely(self, fn):
        """Never let an unhandled exception drop the connection into a 502. A
        crowd sends malformed input; a request-thread crash must become a clean
        500 JSON, not a bad-gateway that looks like the whole service is down."""
        try:
            fn()
        except Exception:
            try:
                self._json(500, {"error": "internal error"})
            except Exception:
                pass

    def do_GET(self):
        self._safely(self._handle_get)

    def do_POST(self):
        self._safely(self._handle_post)

    def _handle_get(self):
        if self._rate_limited():
            return
        u = urlparse(self.path)
        if u.path == "/v1/health":
            return self._json(200, {"ok": True, "zero_knowledge": True,
                                    "stores": "ciphertext + timestamp only"})
        if u.path not in ("/v1/events", "/v1/entitlement", "/v1/ledger", "/v1/alerts"):
            return self._json(404, {"error": "not found"})
        acct = _account_for(self._bearer())
        if not acct:
            return self._json(401, {"error": "bad api key"})
        tier = _tier_of(acct)

        # GET /v1/entitlement -> what this key's plan is entitled to (any tier).
        if u.path == "/v1/entitlement":
            return self._json(200, entitlement(tier))

        # GET /v1/ledger -> the tamper-evident override/toggle ciphertext ledger.
        # TEAM+ only (feature "ledger_export"); solo/free get a clear 402.
        if u.path == "/v1/ledger":
            if not tier_has_feature(tier, "ledger_export"):
                return self._json(402, {
                    "error": "ledger export is a Team feature",
                    "tier": tier, "upgrade_to": "team",
                    "message": ("The tamper-evident override/toggle ledger export "
                                "requires Team or Business. Upgrade to read it.")})
            try:
                since = int((parse_qs(u.query).get("since", ["0"])[0]) or 0)
            except (TypeError, ValueError):
                since = 0
            floor = _retention_floor(tier)
            rows = [r for r in _read(acct["account"], since, floor)
                    if r.get("kind") == "ledger"]
            return self._json(200, {"ledger": rows, "tier": tier})

        # GET /v1/alerts -> the stagnation/loop-guard alert feed. SOLO+.
        if u.path == "/v1/alerts":
            if not tier_has_feature(tier, "alert_push"):
                return self._json(402, {
                    "error": "alert push is a paid feature", "tier": tier,
                    "upgrade_to": "solo",
                    "message": "Alert push requires Solo or higher."})
            try:
                since = int((parse_qs(u.query).get("since", ["0"])[0]) or 0)
            except (TypeError, ValueError):
                since = 0
            return self._json(200, {"alerts": read_alerts(acct["account"], since)})

        # GET /v1/events -> encrypted event history, filtered to the tier retention.
        try:
            since = int((parse_qs(u.query).get("since", ["0"])[0]) or 0)
        except (TypeError, ValueError):
            since = 0                        # a junk ?since= must not 500
        floor = _retention_floor(tier)
        return self._json(200, {"events": _read(acct["account"], since, floor),
                                "retention_days": TIERS[tier]["retention_days"]})

    def _handle_post(self):
        if self._rate_limited():
            return
        path = urlparse(self.path).path
        if path not in ("/v1/events", "/v1/alert"):
            return self._json(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            return self._json(400, {"error": "bad content-length"})
        if n > MAX_BODY:                     # RAM DoS guard: don't read a huge body
            return self._json(413, {"error": "payload too large"})
        acct = _account_for(self._bearer())
        if not acct:
            return self._json(401, {"error": "bad api key"})
        tier = _tier_of(acct)
        try:
            body = json.loads(self.rfile.read(n) or b"[]")
        except Exception:
            return self._json(400, {"error": "bad json"})

        # POST /v1/alert -> push a stagnation/loop-guard alert (metadata, not
        # command text). SOLO+ (the free/local product surfaces stagnation
        # locally for free; the OFF-MACHINE alert push is the paid part).
        if path == "/v1/alert":
            if not tier_has_feature(tier, "alert_push"):
                return self._json(402, {
                    "error": "alert push is a paid feature", "tier": tier,
                    "upgrade_to": "solo",
                    "message": "Alert push requires Solo or higher."})
            if not isinstance(body, dict):
                return self._json(400, {"error": "bad alert"})
            return self._json(200, {"stored": store_alert(acct["account"], body)})

        # POST /v1/events -> ship encrypted events. Enforce the fleet machine cap
        # BEFORE storing: a machine id (X-Gatecat-Machine) beyond the tier cap is
        # rejected so the 11th machine on a Team account cannot report.
        if not isinstance(body, list) or len(body) > MAX_BATCH:
            return self._json(400, {"error": "bad batch"})
        machine_id = self.headers.get("X-Gatecat-Machine", "").strip()
        if machine_id:
            ok, count, cap = bind_machine(acct["account"], machine_id, tier)
            if not ok:
                upgrade = "business" if tier == "team" else "team"
                return self._json(402, {
                    "error": "machine cap reached",
                    "tier": tier, "machines": count, "machine_cap": cap,
                    "upgrade_to": upgrade,
                    "message": (f"This {tier} plan allows {cap} machine(s); "
                                f"machine {machine_id!r} is new and over the cap. "
                                f"Upgrade to {upgrade} for more machines.")})
        return self._json(200, {"stored": _store(acct["account"], body)})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    _ensure()
    port = int(os.environ.get("CLOUD_PORT", "8094"))
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
