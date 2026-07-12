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

STRIPE_KEY = os.environ.get("STRIPE_KEY", "")
ISSUED = os.environ.get("CLOUD_ISSUED_LOG", "/opt/bgml/gatecat-cloud/issued.jsonl")
PRICE_TIER = {
    "price_1TsB84IesWcqqZ2OyrkmEFVQ": "solo",   # gate.cat Cloud Solo $9/mo
    "price_1TsB84IesWcqqZ2OWn8HrgYR": "team",   # gate.cat Cloud Team $199/mo
}
try:
    PRICE_TIER.update(json.loads(os.environ.get("CLOUD_PRICE_TIER", "{}")))
except Exception:
    pass


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

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("CLOUD_ACTIVATE_PORT", "8095"))
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
