#!/usr/bin/env python3
"""gate.cat Cloud — subscription activation (Stripe redirect -> provision API key).

After a buyer subscribes (Solo €19/mo, Team €149/mo, or Business €399/mo), Stripe
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

# Affiliate / referral tracking (self-hosted commission ledger). Loaded the same
# spec-based way as cloud_server so it resolves whether cloud_activate is imported
# as a package module or exec'd from a file path (tests do the latter). Affiliate
# accrual is ALWAYS best-effort: any failure here must NEVER block activation.
_aff_spec = _il.spec_from_file_location(
    "gatecat_affiliate", os.path.join(os.path.dirname(os.path.abspath(__file__)), "affiliate.py"))
affiliate = _il.module_from_spec(_aff_spec); _aff_spec.loader.exec_module(affiliate)


def _affiliate_safe(fn, *args, **kwargs):
    """Run an affiliate ledger action, swallowing ALL errors. Activation is
    sacred: the commission ledger is a side-effect that must never raise into
    the webhook's activation path. On error we log to stderr and continue."""
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - deliberately broad; activation-safe
        try:
            import sys
            sys.stderr.write("affiliate ledger error (ignored): %r\n" % (exc,))
        except Exception:
            pass
        return None

# ---------------------------------------------------------------------------
# PAYMENT CHANNEL SELECTOR (2026-07-12 founder decision).
# Lemon Squeezy is the DEFAULT sales channel; Stripe is kept behind the selector
# (do not delete it). GATECAT_PAYMENT_CHANNEL = lemonsqueezy (default) | stripe.
# The activation server serves the LS webhook path AND the legacy Stripe redirect
# path; the channel only controls which is treated as primary / documented.
# ---------------------------------------------------------------------------
def payment_channel() -> str:
    # Default flipped to stripe 2026-07-22 (reverses the 2026-07-12 founder
    # decision): Lemon Squeezy DECLINED the account application on 2026-07-14,
    # so Stripe is the only live channel. LS webhook path stays serviceable
    # behind the env override in case the channel ever reopens.
    ch = os.environ.get("GATECAT_PAYMENT_CHANNEL", "stripe").strip().lower()
    return "lemonsqueezy" if ch == "lemonsqueezy" else "stripe"


STRIPE_KEY = os.environ.get("STRIPE_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_SIG_TOLERANCE = 300
ISSUED = os.environ.get("CLOUD_ISSUED_LOG", "/opt/bgml/gatecat-cloud/issued.jsonl")
PRICE_TIER = {
    "price_1Tr0na2Va7XV3fWYCU40u4ZT": "solo",   # gate.cat Cloud Solo $9/mo (legacy)
    "price_1Tt2AB2Va7XV3fWYfJL9XCsW": "solo",   # gate.cat Cloud Solo €9/mo founding
    "price_1Tr0nc2Va7XV3fWYnUa29lL1": "team",   # gate.cat Cloud Team $199/mo (legacy)
    "price_1Tssxx2Va7XV3fWYp5TdkpEI": "solo",   # gate.cat Cloud Solo €19/mo
    "price_1Tssxx2Va7XV3fWYfsmO8kCS": "team",   # gate.cat Cloud Team €149/mo
    "price_1Tssxx2Va7XV3fWYXxKnAaDj": "business",  # gate.cat Cloud Business €399/mo
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


def _already_account_tier(account: str, tier: str):
    """Return the existing entitlement for duplicate order/subscription events.

    Lemon Squeezy emits both ``order_created`` and ``subscription_created`` for
    a subscription checkout. Without this account+tier dedupe one payment mints
    two active API keys.
    """
    if not account or not os.path.exists(ISSUED):
        return None
    for line in reversed(open(ISSUED, encoding="utf-8").readlines()):
        try:
            row = json.loads(line)
        except Exception:
            continue
        if row.get("account") == account and row.get("tier") == tier and row.get("key"):
            if cloud_server._account_for(row["key"]):
                return row
    return None


def _record(session_id, account, tier, key, **extra):
    os.makedirs(os.path.dirname(ISSUED), exist_ok=True)
    row = {"session": session_id, "account": account, "tier": tier,
           "key": key, "ts": int(time.time())}
    row.update({k: v for k, v in extra.items() if v})
    with open(ISSUED, "a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")


def _already_subscription(subscription_id: str):
    if not subscription_id or not os.path.exists(ISSUED):
        return None
    for line in reversed(open(ISSUED, encoding="utf-8").readlines()):
        try:
            row = json.loads(line)
        except Exception:
            continue
        if row.get("subscription") == subscription_id and row.get("key"):
            return row
    return None


def verify_stripe_signature(raw_body: bytes, signature: str,
                            secret: str | None = None,
                            now: int | None = None) -> bool:
    """Verify Stripe's ``t=...,v1=...`` signature over the exact request body."""
    secret = STRIPE_WEBHOOK_SECRET if secret is None else secret
    if not secret or not signature:
        return False
    timestamp = None
    candidates = []
    for part in signature.split(","):
        key, sep, value = part.partition("=")
        if not sep:
            continue
        if key == "t":
            timestamp = value
        elif key == "v1":
            candidates.append(value)
    try:
        ts = int(timestamp or "")
    except ValueError:
        return False
    current = int(time.time()) if now is None else int(now)
    if abs(current - ts) > STRIPE_SIG_TOLERANCE:
        return False
    expected = hmac.new(secret.encode(),
                        str(ts).encode() + b"." + raw_body,
                        hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, candidate)
               for candidate in candidates)


def handle_stripe_event(raw_body: bytes, signature: str,
                        secret: str | None = None) -> dict:
    """Provision or revoke Cloud access from a verified Stripe webhook.

    Checkout completion is idempotent per Checkout Session. Subscription
    cancellation/revocation is idempotent per API key because ``revoke_key``
    appends only when the current account state is active.
    """
    if not verify_stripe_signature(raw_body, signature, secret):
        return {"ok": False, "error": "bad signature"}
    try:
        event = json.loads(raw_body or b"{}")
    except Exception:
        return {"ok": False, "error": "bad json"}
    event_type = str(event.get("type", ""))
    obj = ((event.get("data") or {}).get("object") or {})

    if event_type == "checkout.session.completed":
        if obj.get("payment_status") != "paid":
            return {"ok": True, "ignored": True}
        mode = obj.get("mode")
        if mode == "subscription":
            was_existing = _already(str(obj.get("id", ""))) is not None
            try:
                tier, account, _key = activate(str(obj.get("id", "")))
            except Exception as exc:
                return {"ok": False, "error": str(exc)}
            # AFFILIATE (best-effort, never blocks activation). Capture the ref
            # (subscription_id -> ref) so renewals attribute, then accrue 30% of
            # this first payment. Ordered capture-then-accrue so the lookup
            # inside accrue resolves. Wrapped so a ledger failure can't break
            # the webhook (activation already succeeded above).
            aff = _affiliate_safe(affiliate.record_referral_stripe, event,
                                  account or "", tier)
            _affiliate_safe(affiliate.accrue_from_stripe, event, event_type)
            return {"ok": True, "tier": tier, "account": account,
                    "idempotent": was_existing, "affiliate": (aff or {})}
        if mode == "payment":
            # One-time pack: no subscription lifecycle to provision here (the
            # pack fulfiller serves the download). We still book the single 30%
            # commission immediately if the checkout carried a ref. The referral
            # is keyed on the session/object id (extract_subscription_id_stripe
            # falls back to it when there's no subscription).
            aff = _affiliate_safe(affiliate.record_referral_stripe, event)
            acc = _affiliate_safe(affiliate.accrue_from_stripe, event, event_type)
            return {"ok": True, "ignored": True, "mode": "payment",
                    "affiliate": (acc or aff or {})}
        return {"ok": True, "ignored": True}

    # Subscription RENEWALS: invoice.paid / invoice.payment_succeeded carry no
    # client_reference_id -- attribution comes from the stored subscription_id ->
    # ref map, which is what makes the 30% LIFETIME-recurring. Accrual only; key
    # provisioning follows the canonical Subscription status below.
    if event_type in ("invoice.paid", "invoice.payment_succeeded"):
        acc = _affiliate_safe(affiliate.accrue_from_stripe, event, event_type)
        return {"ok": True, "ignored": True, "event": event_type,
                "affiliate": (acc or {})}

    # Refund -> clawback (negative commission). charge.refunded carries the
    # refunded amount; the subscription is resolved via the stored ref map.
    if event_type == "charge.refunded":
        cb = _affiliate_safe(affiliate.clawback_from_stripe, event, event_type)
        return {"ok": True, "ignored": True, "event": event_type,
                "affiliate": (cb or {})}

    if event_type in ("customer.subscription.updated",
                      "customer.subscription.deleted"):
        subscription_id = str(obj.get("id", ""))
        status = str(obj.get("status", "")).lower()
        should_revoke = (event_type == "customer.subscription.deleted" or
                         status in {"canceled", "unpaid", "incomplete_expired", "paused"})
        if not should_revoke:
            return {"ok": True, "ignored": True, "status": status}
        prev = _already_subscription(subscription_id)
        if not prev:
            return {"ok": True, "ignored": True, "status": status}
        revoked = cloud_server.revoke_key(prev.get("key", ""), event_type)
        return {"ok": True, "tier": prev.get("tier"), "revoked": revoked,
                "idempotent": not revoked}

    # invoice.paid / invoice.payment_failed are accepted for observability, but
    # access follows the canonical Subscription status above (events can arrive
    # out of order, and a single failed retry should not revoke immediately).
    return {"ok": True, "ignored": True}


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

    # ------------------------------------------------------------------
    # AFFILIATE payment / refund events (do NOT provision or revoke a key --
    # they only move the commission ledger). Handled here, before the tier
    # logic, and wrapped so a ledger failure can never break the webhook.
    # subscription_payment_success  -> 30% accrual (lifetime: ref looked up by
    #   subscription_id, works on renewals with no custom_data).
    # subscription_payment_refunded -> negative commission (clawback).
    # ------------------------------------------------------------------
    if event_name == "subscription_payment_success":
        res = _affiliate_safe(affiliate.accrue_commission, payload, event_name)
        return {"ok": True, "ignored": True, "event": event_name,
                "affiliate": (res or {})}
    if event_name in ("subscription_payment_refunded",):
        res = _affiliate_safe(affiliate.clawback_commission, payload, event_name)
        return {"ok": True, "ignored": True, "event": event_name,
                "affiliate": (res or {})}
    # A cancellation that carries a refund flag/amount also claws back the
    # commission. A plain cancel (no refund) does NOT -- past paid months are
    # earned. This does not touch key revocation (that is subscription_expired).
    if event_name == "subscription_cancelled":
        _attrs = (payload.get("data") or {}).get("attributes") or {}
        _refunded = bool(_attrs.get("refunded")) or bool(_attrs.get("refunded_at"))
        if _refunded:
            res = _affiliate_safe(affiliate.clawback_commission, payload, event_name)
            return {"ok": True, "ignored": True, "event": event_name,
                    "affiliate": (res or {})}
        return {"ok": True, "ignored": True, "event": event_name}

    lifecycle = {"subscription_expired", "subscription_updated"}
    if event_name in lifecycle:
        ident = "ls:" + (unique_id or (account + ":" + variant_id))
        prev = _already(ident)
        status = str(((json.loads(raw_body or b"{}") or {}).get("data") or {})
                     .get("attributes", {}).get("status", "")).lower()
        should_revoke = event_name == "subscription_expired" or status == "expired"
        if not prev:
            return {"ok": False, "error": f"unknown subscription {unique_id!r}"}
        if should_revoke:
            revoked = cloud_server.revoke_key(prev.get("key", ""), event_name)
            return {"ok": True, "tier": prev["tier"], "account": prev["account"],
                    "revoked": revoked, "idempotent": not revoked}
        return {"ok": True, "tier": prev["tier"], "account": prev["account"],
                "revoked": False, "idempotent": True}
    if event_name not in ("subscription_created", "order_created"):
        return {"ok": False, "error": f"ignored event {event_name!r}"}
    tier = ls_variant_tier().get(variant_id)
    if not tier:
        return {"ok": False, "error": f"unmapped variant {variant_id!r}"}

    # AFFILIATE referral capture (best-effort, never blocks activation). Store
    # subscription_id -> ref_code on this FIRST event so later renewal payments
    # -- which drop custom_data -- still attribute. Idempotent per subscription.
    def _capture_referral():
        ref = affiliate.extract_ref(payload)
        if not ref:
            return
        sub_id = affiliate.extract_subscription_id(payload)
        affiliate.record_referral(sub_id, ref, account or "", tier)
    _affiliate_safe(_capture_referral)

    ident = "ls:" + (unique_id or (account + ":" + variant_id))
    prev = _already(ident)
    if prev:
        return {"ok": True, "tier": prev["tier"], "account": prev["account"],
                "key": prev["key"], "idempotent": True}
    existing = _already_account_tier(account, tier)
    if existing:
        _record(ident, account, tier, existing["key"])
        return {"ok": True, "tier": tier, "account": account,
                "key": existing["key"], "idempotent": True}
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
    tier = None
    matched_price = None
    for li in (sess.get("line_items") or {}).get("data", []):
        pid = (li.get("price") or {}).get("id")
        if pid in PRICE_TIER:
            tier = PRICE_TIER[pid]
            matched_price = pid
    if tier is None:
        raise ValueError("unmapped Stripe price")
    key = cloud_server.issue_key(account or "unknown", tier)
    subscription = sess.get("subscription")
    if isinstance(subscription, dict):
        subscription = subscription.get("id")
    _record(session_id, account, tier, key, provider="stripe",
            subscription=subscription, price=matched_price)
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


def affiliate_ledger_response(token: str):
    """Read-only per-code commission totals for MANUAL payouts. Gated by the
    GATECAT_ADMIN_TOKEN env var. Returns (http_code, body_dict).

    Fail-closed: if the admin token is UNSET, the endpoint refuses (403) rather
    than exposing the ledger. A wrong/missing token is 401. This holds PII
    (payout emails live in the affiliates table, not here) so it is admin-only.
    """
    admin = os.environ.get("GATECAT_ADMIN_TOKEN", "")
    if not admin:
        return 403, {"ok": False, "error": "affiliate ledger disabled "
                     "(set GATECAT_ADMIN_TOKEN to enable)"}
    if not token or not hmac.compare_digest(str(token), admin):
        return 401, {"ok": False, "error": "bad admin token"}
    try:
        data = affiliate.ledger()
    except Exception as exc:  # noqa: BLE001 - report cleanly, never 500 raw
        return 500, {"ok": False, "error": "ledger read failed: %r" % (exc,)}
    return 200, {"ok": True, "rate": affiliate.RATE, "by_code": data}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/cloud/health":
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.end_headers(); self.wfile.write(b'{"ok":true}'); return
        if u.path == "/affiliate/ledger":
            code, body = affiliate_ledger_response(parse_qs(u.query).get("token", [""])[0])
            self.send_response(code); self.send_header("Content-Type", "application/json")
            self.end_headers(); self.wfile.write(json.dumps(body).encode()); return
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
        if u.path not in ("/cloud/lemonsqueezy/webhook", "/cloud/ls/webhook",
                          "/cloud/stripe/webhook"):
            self.send_response(404); self.end_headers(); return
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            n = 0
        if n > 1024 * 1024:                  # a webhook body is small; cap RAM
            self.send_response(413); self.end_headers(); return
        raw = self.rfile.read(n) if n else b""
        if u.path == "/cloud/stripe/webhook":
            sig = self.headers.get("Stripe-Signature", "")
            res = handle_stripe_event(raw, sig)
        else:
            sig = self.headers.get("X-Signature", "")
            res = activate_lemonsqueezy(raw, sig)
        if res.get("ok"):
            code, body = 200, {"ok": True, "tier": res.get("tier"),
                               "idempotent": res.get("idempotent", False),
                               "revoked": res.get("revoked", False)}
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
