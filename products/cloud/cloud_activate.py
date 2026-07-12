#!/usr/bin/env python3
"""gate.cat Cloud — subscription activation (Stripe redirect -> provision API key).

After a buyer subscribes (Solo $9/mo or Team $199/mo Payment Link), Stripe
redirects to ``/cloud/activate?session_id={CHECKOUT_SESSION_ID}``. We verify the
session server-side (paid + a live subscription), issue a per-account API key
ONCE (idempotent per session), and render a page with the key and the 3-line
setup. The key authenticates to the zero-knowledge cloud server; it does NOT
decrypt anything — the encryption key is generated locally by ``cloud init``.

Security: the session_id is the credential (unguessable cs_live_...). We
re-verify payment on every hit; nothing is provisioned for unpaid/unknown
sessions. Zero third-party deps (stdlib). Runs on 127.0.0.1:8095 behind nginx.
"""
import hashlib
import hmac
import json
import os
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import importlib.util as _il
_spec = _il.spec_from_file_location(
    "cloud_server", os.path.join(os.path.dirname(os.path.abspath(__file__)), "cloud_server.py"))
cloud_server = _il.module_from_spec(_spec); _spec.loader.exec_module(cloud_server)

# ---------------------------------------------------------------------------
# PAYMENT CHANNEL SELECTOR (2026-07-12 founder decision).
# Lemon Squeezy is the DEFAULT sales channel; Stripe is kept behind the selector
# (do not delete it). GATECAT_PAYMENT_CHANNEL = lemonsqueezy (default) | stripe.
# The activation server serves the LS webhook path AND the legacy Stripe redirect
# path; the channel only controls which is treated as primary / documented.
# ---------------------------------------------------------------------------
def payment_channel() -> str:
    ch = os.environ.get("GATECAT_PAYMENT_CHANNEL", "lemonsqueezy").strip().lower()
    return "stripe" if ch == "stripe" else "lemonsqueezy"


STRIPE_KEY = os.environ.get("STRIPE_KEY", "")
ISSUED = os.environ.get("CLOUD_ISSUED_LOG", "/opt/bgml/gatecat-cloud/issued.jsonl")
PRICE_TIER = {
    "price_1TsB84IesWcqqZ2OyrkmEFVQ": "solo",   # gate.cat Cloud Solo $9/mo (legacy)
    "price_1TsB84IesWcqqZ2OWn8HrgYR": "team",   # gate.cat Cloud Team $199/mo (legacy)
}
try:
    PRICE_TIER.update(json.loads(os.environ.get("CLOUD_PRICE_TIER", "{}")))
except Exception:
    pass

# ---------------------------------------------------------------------------
# LEMON SQUEEZY config (CONFIG-DRIVEN / TEST-MODE). The founder's LS account is
# still in verification -- there is NO live webhook secret or variant id yet. So
# every value comes from env; when unset we run in TEST-MODE and DO NOT crash
# (the module still imports, the Stripe path still works, tests can inject a test
# secret). Map LS variant id -> tier via env.
# ---------------------------------------------------------------------------
def _ls_secret() -> str:
    return os.environ.get("LEMONSQUEEZY_WEBHOOK_SECRET", "")


def ls_variant_tier() -> dict:
    """variant_id (str) -> tier. From the three per-tier env vars, plus an
    optional JSON override (LEMONSQUEEZY_VARIANT_TIER) for extra variants."""
    m = {}
    for env, tier in (("LEMONSQUEEZY_VARIANT_SOLO", "solo"),
                      ("LEMONSQUEEZY_VARIANT_TEAM", "team"),
                      ("LEMONSQUEEZY_VARIANT_BUSINESS", "business")):
        vid = os.environ.get(env, "").strip()
        if vid:
            m[vid] = tier
    try:
        extra = json.loads(os.environ.get("LEMONSQUEEZY_VARIANT_TIER", "{}"))
        if isinstance(extra, dict):
            m.update({str(k): str(v) for k, v in extra.items()})
    except Exception:
        pass
    return m


def verify_ls_signature(raw_body: bytes, signature: str, secret: str | None = None) -> bool:
    """HMAC-SHA256 over the RAW request body, compared constant-time to the
    X-Signature header. Lemon Squeezy signs the exact bytes with the store
    webhook secret. No secret configured (test-mode with none injected) -> reject
    (fail-closed: never provision on an unverifiable webhook)."""
    secret = _ls_secret() if secret is None else secret
    if not secret or not signature:
        return False
    digest = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    sig = signature.strip().lower()
    # LS sends hex; tolerate an optional "sha256=" prefix some proxies add.
    if sig.startswith("sha256="):
        sig = sig[7:]
    return hmac.compare_digest(digest, sig)


def _ls_extract(payload: dict):
    """From a subscription_created / order_created webhook body, pull
    (event_name, unique_id, account_email, variant_id). Tolerant of the two
    shapes LS uses (subscription vs order attributes)."""
    meta = payload.get("meta") or {}
    event_name = str(meta.get("event_name", ""))
    data = payload.get("data") or {}
    attrs = data.get("attributes") or {}
    # a stable idempotency key: prefer the resource id, else the order id.
    unique_id = str(data.get("id") or attrs.get("order_id") or attrs.get("first_order_item", {}).get("order_id") or "")
    email = (attrs.get("user_email") or attrs.get("customer_email")
             or attrs.get("email") or "")
    # variant id lives at attributes.variant_id (subscription) or inside
    # first_order_item.variant_id (order).
    variant_id = attrs.get("variant_id")
    if variant_id is None:
        variant_id = (attrs.get("first_order_item") or {}).get("variant_id")
    return event_name, unique_id, str(email or ""), (str(variant_id) if variant_id is not None else "")


def _stripe(path):
    req = urllib.request.Request("https://api.stripe.com/v1/" + path,
                                 headers={"Authorization": "Bearer " + STRIPE_KEY})
    return json.load(urllib.request.urlopen(req, timeout=20))


def _already(session_id):
    if not os.path.exists(ISSUED):
        return None
    for line in open(ISSUED, encoding="utf-8"):
        try:
            r = json.loads(line)
            if r.get("session") == session_id:
                return r
        except Exception:
            continue
    return None


def _record(session_id, account, tier, key):
    os.makedirs(os.path.dirname(ISSUED), exist_ok=True)
    with open(ISSUED, "a", encoding="utf-8") as f:
        f.write(json.dumps({"session": session_id, "account": account, "tier": tier,
                            "key": key, "ts": int(time.time())}) + "\n")


def activate_lemonsqueezy(raw_body: bytes, signature: str,
                          secret: str | None = None) -> dict:
    """Verify an LS webhook and provision a key. Returns a result dict:

        {"ok": True, "tier": .., "account": .., "key": .., "idempotent": bool}
        {"ok": False, "error": "..."}  on a bad signature / unmapped variant.

    Idempotent per LS resource id: a re-delivered webhook returns the SAME key
    (LS retries deliveries; we must not mint a second key). Test-mode safe: pass
    a `secret` (e.g. a test secret) to verify without env; with no secret and no
    env, verification fails closed and nothing is issued.
    """
    if not verify_ls_signature(raw_body, signature, secret):
        return {"ok": False, "error": "bad signature"}
    try:
        payload = json.loads(raw_body or b"{}")
    except Exception:
        return {"ok": False, "error": "bad json"}
    event_name, unique_id, account, variant_id = _ls_extract(payload)
    if event_name not in ("subscription_created", "order_created"):
        return {"ok": False, "error": f"ignored event {event_name!r}"}
    tier = ls_variant_tier().get(variant_id)
    if not tier:
        return {"ok": False, "error": f"unmapped variant {variant_id!r}"}
    ident = "ls:" + (unique_id or (account + ":" + variant_id))
    prev = _already(ident)
    if prev:
        return {"ok": True, "tier": prev["tier"], "account": prev["account"],
                "key": prev["key"], "idempotent": True}
    key = cloud_server.issue_key(account or "unknown", tier)
    _record(ident, account, tier, key)
    return {"ok": True, "tier": tier, "account": account, "key": key,
            "idempotent": False}


def activate(session_id: str):
    """Returns (tier, account, api_key) or raises ValueError with a reason."""
    if not session_id.startswith("cs_"):
        raise ValueError("invalid session")
    prev = _already(session_id)
    if prev:
        return prev["tier"], prev["account"], prev["key"]
    sess = _stripe(f"checkout/sessions/{session_id}?expand[]=line_items")
    if sess.get("payment_status") != "paid" or sess.get("mode") != "subscription":
        raise ValueError("not a paid subscription")
    account = (sess.get("customer_details") or {}).get("email") or sess.get("customer")
    tier = "solo"
    for li in (sess.get("line_items") or {}).get("data", []):
        pid = (li.get("price") or {}).get("id")
        if pid in PRICE_TIER:
            tier = PRICE_TIER[pid]
    key = cloud_server.issue_key(account or "unknown", tier)
    _record(session_id, account, tier, key)
    return tier, account, key


def _page(tier, key) -> str:
    return f"""<!doctype html><meta charset=utf-8><title>gate.cat Cloud — activated</title>
<style>body{{font-family:ui-monospace,Menlo,monospace;max-width:640px;margin:6vh auto;padding:0 20px;background:#fbfaf2;color:#0f0f0d;line-height:1.6}}
h1{{font-family:Arial,sans-serif}} code,pre{{background:#f2f7cf;border:1px solid #dbe79a;border-radius:8px}}
pre{{padding:14px;overflow-x:auto}} .k{{font-size:15px;word-break:break-all;padding:12px;display:block}}
a{{color:#788800}}</style>
<h1>gate.cat Cloud is on — <b>{tier}</b> ✓</h1>
<p>Your API key (shown once — save it):</p>
<code class=k>{key}</code>
<p>Three lines and your veto history ships off-machine, <b>encrypted on your box with a key we never see</b>:</p>
<pre>pip install -U 'gate-cat[cloud]'
export GATECAT_CLOUD_API_KEY={key}
gate.cat cloud init          # makes your local encryption key</pre>
<p>Then run the reporter on a timer (cron/systemd):</p>
<pre>python3 -m gatecat.cloud_reporter   # ships new events, end-to-end encrypted</pre>
<p>Read your history any time — decrypted locally, never on our server:</p>
<pre>gate.cat cloud report      # summary
gate.cat cloud verify      # did anything rewrite your local log? off-machine copy is truth</pre>
<p>Team: share one key across the fleet with <code>gate.cat cloud key export</code>.
Full boundary: <a href="https://gate.cat/THREAT_MODEL_CLOUD.md">threat model</a>.</p>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/cloud/health":
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.end_headers(); self.wfile.write(b'{"ok":true}'); return
        if u.path != "/cloud/activate":
            self.send_response(404); self.end_headers(); return
        sid = (parse_qs(u.query).get("session_id", [""])[0])
        try:
            tier, _acct, key = activate(sid)
            body = _page(tier, key).encode()
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
        except Exception as e:
            body = f"<p>Could not activate: {e}. If you just paid, refresh in a moment or email hello@gate.cat.</p>".encode()
            self.send_response(402); self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers(); self.wfile.write(body)

    def do_POST(self):
        u = urlparse(self.path)
        if u.path not in ("/cloud/lemonsqueezy/webhook", "/cloud/ls/webhook"):
            self.send_response(404); self.end_headers(); return
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            n = 0
        if n > 1024 * 1024:                  # a webhook body is small; cap RAM
            self.send_response(413); self.end_headers(); return
        raw = self.rfile.read(n) if n else b""
        sig = self.headers.get("X-Signature", "")
        res = activate_lemonsqueezy(raw, sig)
        if res.get("ok"):
            code, body = 200, {"ok": True, "tier": res["tier"],
                               "idempotent": res.get("idempotent", False)}
        else:
            # 401 for a bad signature (auth), 400 for a mapping/parse problem.
            code = 401 if res.get("error") == "bad signature" else 400
            body = {"ok": False, "error": res.get("error")}
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.end_headers(); self.wfile.write(json.dumps(body).encode())

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("CLOUD_ACTIVATE_PORT", "8095"))
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
