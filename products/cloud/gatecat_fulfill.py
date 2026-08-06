#!/usr/bin/env python3
"""Verify a paid Stripe Checkout session and serve the purchased policy pack.

The Payment Link redirects to ``/packs/download`` with an unguessable Checkout
Session id. Every download is verified server-side and fails closed on any API
or mapping error. Zero third-party dependencies.
"""
import base64
import json
import os
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

STRIPE_KEY = os.environ["STRIPE_KEY"]
FILES_DIR = Path(os.environ.get("PACK_FILES_DIR", "/opt/bgml/gatecat-fulfill/files"))
PRICE_TO_FILE = {
    # Current €29 tax-inclusive prices.
    "price_1Tssxy2Va7XV3fWYzW4jFalP": "gatecat-pack-fintech-1.0.0.zip",
    "price_1Tssxy2Va7XV3fWYx2gu2ZcK": "gatecat-pack-paas-1.0.0.zip",
    "price_1Tssxy2Va7XV3fWYeh6jYFQh": "gatecat-pack-http-breadth-1.0.0.zip",
    # Keep already-issued legacy USD Checkout links fulfillable.
    "price_1TrZQ22Va7XV3fWYZF6Lwl9x": "gatecat-pack-fintech-1.0.0.zip",
    "price_1TrZQ32Va7XV3fWY06vslOjX": "gatecat-pack-paas-1.0.0.zip",
    "price_1TrZQ52Va7XV3fWYb3DZFSbm": "gatecat-pack-http-breadth-1.0.0.zip",
}
_CACHE: dict[str, tuple[float, str]] = {}
CACHE_TTL = 3600.0

PAGE = """<!doctype html><meta charset="utf-8">
<title>gate.cat — your pack</title>
<body style="font-family:system-ui;max-width:40rem;margin:4rem auto;line-height:1.6">
<h1>Thanks — your pack is ready.</h1>
<p><a href="/packs/file?session_id={sid}" style="font-size:1.2rem">&#11015; Download {fname}</a></p>
<p>Install the free core first using the safe two-step command at
<a href="https://gate.cat/#install">gate.cat</a>, then:</p>
<pre>unzip {fname}
pip install gatecat_packs_*.whl
export GATECAT_EXTRA_POLICIES=gatecat_packs.{mod}</pre>
<p>Full instructions are in INSTALL.md inside the zip. This download link keeps
working — bookmark this page. Receipt &amp; invoice arrive by email from Stripe.
Questions: bgml@bgml.ai</p>
{xsell}</body>"""

MODULE_FOR = {
    "gatecat-pack-fintech-1.0.0.zip": "fintech",
    "gatecat-pack-paas-1.0.0.zip": "paas",
    "gatecat-pack-http-breadth-1.0.0.zip": "http_api_breadth",
}

# Cross-sell on the thank-you page: the two packs NOT just bought, plus the
# Cloud line. Scopes quote PRICING.md; links go to the pack preview page
# (full scope before checkout — no blind €29 buy), and its ?source= shows up
# in the /events funnel log as checkout_click source=pack-xsell.
PACK_LINKS = {
    "gatecat-pack-fintech-1.0.0.zip": (
        "Fintech — refund creation, payouts/transfers, customer &amp; "
        "billing-config deletion",
        "https://gate.cat/packs.html?source=pack-xsell#fintech"),
    "gatecat-pack-paas-1.0.0.zip": (
        "PaaS — <code>vercel remove</code>, <code>netlify sites:delete</code>, "
        "<code>fly/heroku apps destroy</code>, <code>railway down</code>, "
        "<code>render/supabase delete</code>",
        "https://gate.cat/packs.html?source=pack-xsell#paas"),
    "gatecat-pack-http-breadth-1.0.0.zip": (
        "HTTP-API Breadth — destructive raw-HTTP calls the CLI-verb walls "
        "never see",
        "https://gate.cat/packs.html?source=pack-xsell#http-api"),
}


def xsell_html(purchased: str) -> str:
    """The 'Complete your coverage' block, excluding the pack just bought."""
    items = "".join(
        f'<li><a href="{url}">{label}</a>'
        " — &euro;29 one-time</li>"
        for fname, (label, url) in PACK_LINKS.items() if fname != purchased)
    return (
        "<hr><h2>Complete your coverage</h2>"
        "<p>Every rule in a pack is tested to fire on its danger and stay "
        "silent on the benign twin — same bar as the free core.</p>"
        f"<ul>{items}</ul>"
        "<p>And the one thing an agent can't reach: an off-machine, "
        "append-only copy of your veto history — "
        '<a href="https://gate.cat/teams.html?source=pack-xsell">'
        "Cloud Solo &euro;19/mo</a>.</p>")


def _stripe_get(path: str):
    req = urllib.request.Request("https://api.stripe.com/v1/" + path)
    token = base64.b64encode((STRIPE_KEY + ":").encode()).decode()
    req.add_header("Authorization", "Basic " + token)
    with urllib.request.urlopen(req, timeout=15) as response:
        return json.load(response)


def verify_session(session_id: str) -> str | None:
    if not session_id.startswith("cs_"):
        return None
    hit = _CACHE.get(session_id)
    if hit and hit[0] > time.time():
        return hit[1]
    try:
        session = _stripe_get(f"checkout/sessions/{session_id}")
        if session.get("payment_status") != "paid":
            return None
        items = _stripe_get(f"checkout/sessions/{session_id}/line_items")
        for item in items.get("data", []):
            filename = PRICE_TO_FILE.get((item.get("price") or {}).get("id", ""))
            if filename:
                _CACHE[session_id] = (time.time() + CACHE_TTL, filename)
                return filename
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, KeyError):
        return None
    return None


class Handler(BaseHTTPRequestHandler):
    server_version = "gatecat-fulfill/1.1"

    def _deny(self, code=403, msg="Payment not verified. If you just paid, retry in a minute; otherwise contact bgml@bgml.ai with your receipt."):
        body = msg.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        url = urlparse(self.path)
        session_id = (parse_qs(url.query).get("session_id") or [""])[0]
        filename = verify_session(session_id)
        if url.path == "/packs/download":
            if not filename:
                return self._deny()
            body = PAGE.format(sid=session_id, fname=filename,
                               mod=MODULE_FOR[filename],
                               xsell=xsell_html(filename)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif url.path == "/packs/file":
            if not filename:
                return self._deny()
            path = FILES_DIR / filename
            if not path.is_file():
                return self._deny(500, "Pack file missing on server - contact bgml@bgml.ai.")
            data = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif url.path == "/packs/health":
            self._deny(200, "ok")
        else:
            self._deny(404, "not found")

    def log_message(self, fmt, *args):
        print("%s %s" % (self.address_string(), fmt % args), flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 8791), Handler).serve_forever()
