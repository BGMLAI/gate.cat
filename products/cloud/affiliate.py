#!/usr/bin/env python3
"""gate.cat Cloud - self-hosted, zero-cost AFFILIATE / referral tracking.

Purpose
-------
gate.cat converts poorly on cold traffic. Trusted creators drive qualified
traffic on a 30% LIFETIME-recurring commission. This module is the honest,
correct commission ledger. It EXTENDS the live Lemon Squeezy webhook handler
(``cloud_activate.py``) and NEVER touches tier activation: activation is sacred,
affiliate accrual is strictly best-effort (log-and-continue on any error).

Attribution mechanism
----------------------
LS checkout URLs carry custom data as ``checkout[custom][ref]=CODE`` query
params. LS echoes that back in the webhook body at ``meta.custom_data.ref``. On
subscription RENEWAL events custom_data is usually ABSENT, so we store
``subscription_id -> ref_code`` on the FIRST event and look it up on every
later payment. That is what makes the commission LIFETIME-recurring.

Storage
-------
SQLite (stdlib ``sqlite3``), one DB file under the cloud data dir
(``CLOUD_DATA_DIR`` -- the same dir the cloud server and the test suite use).
No new pip deps. PII stored = email only. Manual payouts (no payout rails):
the ledger endpoint reports per-code net owed for a human to pay out.

Money correctness
------------------
* 30% flat rate, PAID tiers only (solo/team/business + packs). The free core
  never accrues.
* amount_cents = round(0.30 * payment_total_cents). Integer cents throughout.
* Idempotency: every commission carries a UNIQUE ``event_uid`` (the LS
  invoice/event id). A re-delivered webhook (LS retries) is de-duped by the
  UNIQUE constraint, so a retry never double-pays.
* Clawback: a refund / refunded cancellation inserts a NEGATIVE commission
  referencing the same subscription, so the ledger nets out.
"""
import os
import sqlite3
import time

RATE = 0.30  # 30% commission (founder decision). Lifetime-recurring.

# Tiers that EARN commission. The free core never accrues. Pack purchases
# (order_created for a one-off pack) also earn -- any paid entitlement counts.
PAID_TIERS = {"solo", "team", "business"}


def _db_path() -> str:
    """DB file under the cloud data dir. Same env the cloud server / tests use
    (``CLOUD_DATA_DIR``); falls back to the prod path when unset."""
    data = os.environ.get("CLOUD_DATA_DIR", "/opt/bgml/gatecat-cloud")
    return os.path.join(data, "affiliate.db")


def _connect() -> sqlite3.Connection:
    """Open the affiliate DB, creating the schema if absent. Short busy timeout
    so a concurrent webhook thread waits for the writer rather than erroring."""
    path = _db_path()
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS affiliates (
            code       TEXT PRIMARY KEY,
            name       TEXT,
            email      TEXT,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS affiliate_referrals (
            subscription_id TEXT PRIMARY KEY,
            ref_code        TEXT,
            account_email   TEXT,
            tier            TEXT,
            created_at      TEXT
        );
        CREATE TABLE IF NOT EXISTS affiliate_commissions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            subscription_id TEXT,
            ref_code        TEXT,
            event           TEXT,
            event_uid       TEXT UNIQUE,
            amount_cents    INTEGER,
            currency        TEXT,
            rate            REAL,
            status          TEXT,
            created_at      TEXT
        );
        -- Stripe object ids that all point at the same referral: a real
        -- charge.refunded Charge has NO .subscription field, and a pack refund
        -- carries only a payment_intent while the referral is keyed on the
        -- Checkout Session id. Aliases are written at capture/accrual time so
        -- the clawback can resolve payment_intent/invoice/charge -> the key
        -- the referral was stored under.
        CREATE TABLE IF NOT EXISTS affiliate_ref_aliases (
            alias            TEXT PRIMARY KEY,
            subscription_key TEXT
        );
        """
    )
    conn.commit()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---------------------------------------------------------------------------
# Extraction from the real LS webhook body.
# ---------------------------------------------------------------------------
def extract_ref(payload: dict) -> str:
    """Pull the referral code LS echoes back. Primary location is
    ``meta.custom_data.ref`` (what LS returns for
    ``checkout[custom][ref]=CODE``). Guard every layer -- custom_data is ABSENT
    on most renewal payments, and may be a dict or missing entirely."""
    if not isinstance(payload, dict):
        return ""
    meta = payload.get("meta") or {}
    custom = meta.get("custom_data") or {}
    if isinstance(custom, dict):
        ref = custom.get("ref")
        if ref:
            return str(ref).strip()[:120]
    # Some LS event shapes surface custom data under data.attributes instead.
    attrs = ((payload.get("data") or {}).get("attributes") or {})
    custom2 = attrs.get("custom_data") or {}
    if isinstance(custom2, dict) and custom2.get("ref"):
        return str(custom2["ref"]).strip()[:120]
    return ""


def extract_subscription_id(payload: dict) -> str:
    """The subscription id used to link a payment back to its referral.

    For ``subscription_created`` the resource id (``data.id``) IS the
    subscription id. For ``subscription_payment_success`` /
    ``subscription_payment_refunded`` the payment/invoice is the resource and
    the subscription id lives at ``data.attributes.subscription_id``."""
    if not isinstance(payload, dict):
        return ""
    data = payload.get("data") or {}
    attrs = data.get("attributes") or {}
    meta = payload.get("meta") or {}
    event = str(meta.get("event_name", ""))
    if event.startswith("subscription_payment"):
        sid = attrs.get("subscription_id") or attrs.get("subscription")
        if sid:
            return str(sid)
    # subscription_created / subscription_cancelled etc: resource id is the sub.
    sid = data.get("id") or attrs.get("subscription_id")
    return str(sid) if sid else ""


def extract_payment_total_cents(payload: dict) -> tuple[int, str]:
    """(total_cents, currency) for a payment event. LS stores money in integer
    cents already (``total`` / ``total_usd``). We prefer ``total`` (store
    currency). Returns (0, "") when no amount is present."""
    attrs = ((payload.get("data") or {}).get("attributes") or {})
    currency = str(attrs.get("currency") or "")
    for field in ("total", "total_usd", "subtotal"):
        v = attrs.get(field)
        if isinstance(v, (int, float)) and v:
            return int(round(v)), currency
    return 0, currency


def extract_event_uid(payload: dict) -> str:
    """A stable idempotency key for the payment/refund event: the LS resource
    id (the invoice/payment id). Falls back to a composite so a malformed
    duplicate still de-dupes rather than double-paying."""
    data = payload.get("data") or {}
    attrs = data.get("attributes") or {}
    uid = data.get("id") or attrs.get("invoice_id") or attrs.get("order_id")
    if uid:
        return "ls:" + str(uid)
    sid = extract_subscription_id(payload)
    return "ls:" + sid + ":" + str(attrs.get("created_at") or "")


# ---------------------------------------------------------------------------
# Extraction from the real STRIPE webhook body.
#
# Stripe events wrap the resource at ``data.object`` and carry a stable event id
# at the TOP level (``event["id"]``, e.g. ``evt_...``) -- that is the idempotency
# key. Two shapes matter:
#   * checkout.session.completed -- the referral-capture / first-payment event.
#       object.client_reference_id  = the ref code (from ?client_reference_id=)
#       object.mode                 = 'subscription' | 'payment'
#       object.subscription         = subscription id (subs only)
#       object.amount_total, .currency
#   * invoice.paid / invoice.payment_succeeded -- subscription RENEWALS. These
#     carry NO client_reference_id, so the ref is resolved via the stored
#     subscription_id -> ref map (that's what makes commission lifetime).
#       object.subscription         = subscription id (link back to the ref)
#       object.amount_paid, .currency
#   * charge.refunded / invoice.payment_failed(+refund) -- clawback.
# ---------------------------------------------------------------------------
def _stripe_object(payload: dict) -> dict:
    """The Stripe resource: ``data.object``. Guarded for malformed bodies."""
    if not isinstance(payload, dict):
        return {}
    return ((payload.get("data") or {}).get("object") or {})


def extract_ref_stripe(payload: dict) -> str:
    """The ref code Stripe echoes back at ``data.object.client_reference_id``
    (set by appending ``?client_reference_id=CODE`` to a buy.stripe.com link).
    Present only on checkout.session.completed; absent on renewals."""
    obj = _stripe_object(payload)
    ref = obj.get("client_reference_id")
    if ref:
        return str(ref).strip()[:120]
    return ""


def extract_subscription_id_stripe(payload: dict) -> str:
    """The subscription id used to link a payment back to its referral.

    On checkout.session.completed and on invoice events the subscription id is
    at ``data.object.subscription`` (a string, or a dict with an ``id``). For a
    one-time pack (``mode == 'payment'``) there is no subscription -- we fall
    back to the session/object id so the single accrual still keys on something
    stable."""
    obj = _stripe_object(payload)
    sub = obj.get("subscription")
    if isinstance(sub, dict):
        sub = sub.get("id")
    if sub:
        return str(sub)
    # one-time pack: no subscription -- use the object id (session/invoice id).
    oid = obj.get("id")
    return str(oid) if oid else ""


def extract_amount_stripe(payload: dict) -> tuple[int, str]:
    """(amount_cents, currency) for a Stripe payment/refund. Stripe money is
    integer cents already. Checkout uses ``amount_total``; invoices use
    ``amount_paid``; refunds use ``amount_refunded`` (charge.refunded). Currency
    is lower-case per Stripe; upper-cased for ledger consistency."""
    obj = _stripe_object(payload)
    currency = str(obj.get("currency") or "").upper()
    for field in ("amount_total", "amount_paid", "amount_refunded", "amount"):
        v = obj.get(field)
        if isinstance(v, (int, float)) and v:
            return int(round(v)), currency
    return 0, currency


def extract_event_uid_stripe(payload: dict) -> str:
    """The Stripe event id (``evt_...``) is the idempotency key: a re-delivered
    webhook carries the SAME id, so the UNIQUE event_uid de-dupes the retry.
    Falls back to a composite so a malformed duplicate still de-dupes."""
    if isinstance(payload, dict):
        eid = payload.get("id")
        if eid:
            return "stripe:" + str(eid)
    obj = _stripe_object(payload)
    return "stripe:" + str(obj.get("id") or "") + ":" + str(
        payload.get("type") if isinstance(payload, dict) else "")


def _alias_put(aliases: dict[str, str]) -> None:
    """Store Stripe object-id aliases -> the referral's subscription key.
    Best-effort and idempotent (INSERT OR IGNORE keeps the FIRST mapping)."""
    pairs = [(str(a), str(k)) for a, k in aliases.items() if a and k]
    if not pairs:
        return
    conn = _connect()
    try:
        conn.executemany(
            "INSERT OR IGNORE INTO affiliate_ref_aliases(alias, subscription_key) "
            "VALUES (?, ?)", pairs)
        conn.commit()
    finally:
        conn.close()


def _alias_resolve(*candidates: str) -> str:
    """First subscription key any of the candidate Stripe ids maps to, or ''."""
    keys = [str(c) for c in candidates if c]
    if not keys:
        return ""
    conn = _connect()
    try:
        for key in keys:
            row = conn.execute(
                "SELECT subscription_key FROM affiliate_ref_aliases "
                "WHERE alias=?", (key,)).fetchone()
            if row and row[0]:
                return str(row[0])
    finally:
        conn.close()
    return ""


def _payment_uid_stripe(payload: dict, event_name: str) -> str:
    """Idempotency key for an ACCRUAL, keyed on the underlying invoice/payment
    rather than the delivery event.

    Stripe announces the SAME first subscription payment up to three times
    (checkout.session.completed, invoice.paid, invoice.payment_succeeded),
    each under a different ``evt_`` id -- keying accruals on the event id
    books 60-90% of month one instead of 30%. The underlying invoice id is
    identical across all three, so it is the correct dedupe key:

      * invoice.*                      -> stripe:inv:<invoice id>
      * checkout (subscription mode)   -> stripe:inv:<obj.invoice>, falling
        back to stripe:cs:<session id> when the session carries no invoice
      * checkout (payment mode / pack) -> stripe:pi:<obj.payment_intent>,
        falling back to stripe:cs:<session id>

    Webhook re-deliveries reuse the same underlying ids, so retries stay
    idempotent too (strictly stronger than the old evt-id key)."""
    obj = _stripe_object(payload)
    if event_name.startswith("invoice."):
        inv = obj.get("id")
        if inv:
            return "stripe:inv:" + str(inv)
    if event_name == "checkout.session.completed":
        if obj.get("mode") == "payment":
            pi = obj.get("payment_intent")
            if isinstance(pi, dict):
                pi = pi.get("id")
            if pi:
                return "stripe:pi:" + str(pi)
        else:
            inv = obj.get("invoice")
            if isinstance(inv, dict):
                inv = inv.get("id")
            if inv:
                return "stripe:inv:" + str(inv)
        if obj.get("id"):
            return "stripe:cs:" + str(obj.get("id"))
    # Unknown shape: fall back to the event id (old behavior, still UNIQUE).
    return extract_event_uid_stripe(payload)


def record_referral_stripe(payload: dict, account_email: str = "",
                           tier: str = "") -> dict:
    """Capture a Stripe referral on checkout.session.completed: read the ref from
    client_reference_id, store subscription_id -> ref so later renewals (which
    carry no client_reference_id) still attribute. Idempotent per subscription.
    Also aliases the session's payment_intent / invoice / session id to the
    referral key, so a later charge.refunded (which carries none of the ref
    context) can still resolve its clawback. Never raises into activation."""
    ref = extract_ref_stripe(payload)
    if not ref:
        return {"affiliate": False, "reason": "no ref"}
    sub_id = extract_subscription_id_stripe(payload)
    if not sub_id:
        return {"affiliate": False, "reason": "no subscription id"}
    record_referral(sub_id, ref, account_email or "", tier or "")
    obj = _stripe_object(payload)
    pi = obj.get("payment_intent")
    if isinstance(pi, dict):
        pi = pi.get("id")
    inv = obj.get("invoice")
    if isinstance(inv, dict):
        inv = inv.get("id")
    _alias_put({str(pi or ""): sub_id, str(inv or ""): sub_id,
                str(obj.get("id") or ""): sub_id})
    return {"affiliate": True, "ref_code": ref, "subscription_id": sub_id}


def accrue_from_stripe(payload: dict, event_name: str) -> dict:
    """Accrue 30% from a Stripe payment. Reuses the same ledger + idempotency as
    the LS path, keyed by the Stripe subscription id and the Stripe event id.

    Works for BOTH the first payment (checkout.session.completed for a
    subscription, or a one-time pack in mode=='payment') AND renewals
    (invoice.paid, resolved via the stored subscription_id -> ref map)."""
    subscription_id = extract_subscription_id_stripe(payload)
    ref_code = lookup_ref(subscription_id)
    if not ref_code:
        return {"affiliate": False, "reason": "no referral"}
    total_cents, currency = extract_amount_stripe(payload)
    if total_cents <= 0:
        return {"affiliate": False, "reason": "no amount"}
    amount = int(round(RATE * total_cents))
    # Key on the underlying invoice/payment, NOT the delivery event: the same
    # first payment arrives as up to three different event types with three
    # different evt_ ids (see _payment_uid_stripe).
    event_uid = _payment_uid_stripe(payload, event_name)
    inserted = _insert_commission(subscription_id, ref_code, event_name,
                                  event_uid, amount, currency, "accrued")
    # Alias this payment's charge/payment_intent to the referral key so a
    # later charge.refunded (a Charge object with NO .subscription field on
    # real Stripe payloads) can resolve its clawback.
    obj = _stripe_object(payload)
    charge = obj.get("charge")
    if isinstance(charge, dict):
        charge = charge.get("id")
    pi = obj.get("payment_intent")
    if isinstance(pi, dict):
        pi = pi.get("id")
    _alias_put({str(charge or ""): subscription_id,
                str(pi or ""): subscription_id,
                str(obj.get("id") or ""): subscription_id})
    return {"affiliate": True, "ref_code": ref_code, "amount_cents": amount,
            "currency": currency, "idempotent": not inserted,
            "event_uid": event_uid}


def clawback_from_stripe(payload: dict, event_name: str) -> dict:
    """Clawback from a Stripe refund (charge.refunded / refunded invoice): insert
    a NEGATIVE commission for the same subscription so the ledger nets out.
    Amount = -30% of the refunded amount (falls back to the most recent accrual
    when the refund carries no amount). Idempotent per Stripe event id.

    Resolution chain (a REAL charge.refunded Charge has no .subscription, and
    a pack refund carries only payment_intent while the referral is keyed on
    the Checkout Session id): obj.subscription -> alias(payment_intent) ->
    alias(invoice) -> alias(charge id / obj id)."""
    obj = _stripe_object(payload)
    sub = obj.get("subscription")
    if isinstance(sub, dict):
        sub = sub.get("id")
    subscription_id = str(sub) if sub else ""
    if not subscription_id or not lookup_ref(subscription_id):
        pi = obj.get("payment_intent")
        if isinstance(pi, dict):
            pi = pi.get("id")
        inv = obj.get("invoice")
        if isinstance(inv, dict):
            inv = inv.get("id")
        resolved = _alias_resolve(str(pi or ""), str(inv or ""),
                                  str(obj.get("id") or ""))
        subscription_id = resolved or subscription_id or str(obj.get("id") or "")
    ref_code = lookup_ref(subscription_id)
    if not ref_code:
        return {"affiliate": False, "reason": "no referral"}
    total_cents, currency = extract_amount_stripe(payload)
    if total_cents <= 0:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT amount_cents,currency FROM affiliate_commissions "
                "WHERE subscription_id=? AND status='accrued' "
                "ORDER BY id DESC LIMIT 1", (subscription_id,)).fetchone()
        finally:
            conn.close()
        if not row:
            return {"affiliate": False, "reason": "no accrual to claw back"}
        amount = -int(row[0])
        currency = currency or row[1]
    else:
        amount = -int(round(RATE * total_cents))
    event_uid = extract_event_uid_stripe(payload) + ":clawback"
    inserted = _insert_commission(subscription_id, ref_code, event_name,
                                  event_uid, amount, currency, "clawback")
    return {"affiliate": True, "ref_code": ref_code, "amount_cents": amount,
            "currency": currency, "idempotent": not inserted,
            "event_uid": event_uid}


# ---------------------------------------------------------------------------
# Affiliate onboarding.
# ---------------------------------------------------------------------------
def add_affiliate(code: str, name: str = "", email: str = "") -> dict:
    """Create (or update contact info for) an affiliate code. Onboarding a
    creator = add their code; their link is then ``gate.cat/?ref=<code>``."""
    code = str(code or "").strip()
    if not code:
        raise ValueError("empty affiliate code")
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO affiliates(code,name,email,created_at) VALUES(?,?,?,?) "
            "ON CONFLICT(code) DO UPDATE SET "
            "name=COALESCE(NULLIF(excluded.name,''), affiliates.name), "
            "email=COALESCE(NULLIF(excluded.email,''), affiliates.email)",
            (code, name or "", email or "", _now()),
        )
        conn.commit()
    finally:
        conn.close()
    return {"code": code, "name": name, "email": email}


def _ensure_affiliate(conn: sqlite3.Connection, code: str) -> None:
    """Auto-create a PENDING affiliate row (code only) if the ref code arrives
    on a checkout before the creator was formally onboarded. Never clobbers an
    existing row's contact info."""
    conn.execute(
        "INSERT OR IGNORE INTO affiliates(code,name,email,created_at) "
        "VALUES(?,?,?,?)",
        (code, "", "", _now()),
    )


# ---------------------------------------------------------------------------
# Referral capture (on subscription_created / order_created).
# ---------------------------------------------------------------------------
def record_referral(subscription_id: str, ref_code: str,
                    account_email: str = "", tier: str = "") -> None:
    """Store subscription_id -> ref_code on the FIRST event so renewals (which
    drop custom_data) can still be attributed. Idempotent per subscription_id
    (PRIMARY KEY); a re-delivered create keeps the first mapping."""
    if not subscription_id or not ref_code:
        return
    conn = _connect()
    try:
        _ensure_affiliate(conn, ref_code)
        conn.execute(
            "INSERT OR IGNORE INTO affiliate_referrals"
            "(subscription_id,ref_code,account_email,tier,created_at) "
            "VALUES(?,?,?,?,?)",
            (subscription_id, ref_code, account_email or "", tier or "", _now()),
        )
        conn.commit()
    finally:
        conn.close()


def lookup_ref(subscription_id: str):
    """ref_code for a subscription, or None. This is the lifetime link:
    renewals with no custom_data resolve their commission through here."""
    if not subscription_id:
        return None
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT ref_code FROM affiliate_referrals WHERE subscription_id=?",
            (subscription_id,),
        ).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Commission accrual + clawback.
# ---------------------------------------------------------------------------
def _insert_commission(subscription_id: str, ref_code: str, event: str,
                       event_uid: str, amount_cents: int, currency: str,
                       status: str) -> bool:
    """Insert one ledger row. Returns True if inserted, False if the UNIQUE
    event_uid already existed (idempotent de-dupe of webhook retries)."""
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT OR IGNORE INTO affiliate_commissions"
            "(subscription_id,ref_code,event,event_uid,amount_cents,currency,"
            " rate,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (subscription_id, ref_code, event, event_uid, int(amount_cents),
             currency or "", RATE, status, _now()),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def accrue_commission(payload: dict, event_name: str) -> dict:
    """On a successful payment: 30% of the payment total to the referring code.
    Looks the ref up by subscription_id (works on renewals with no custom_data).
    Idempotent per LS event uid. Returns a small result dict for observability;
    NEVER raises to the caller path that owns activation."""
    subscription_id = extract_subscription_id(payload)
    ref_code = lookup_ref(subscription_id)
    if not ref_code:
        return {"affiliate": False, "reason": "no referral"}
    total_cents, currency = extract_payment_total_cents(payload)
    if total_cents <= 0:
        return {"affiliate": False, "reason": "no amount"}
    amount = int(round(RATE * total_cents))
    event_uid = extract_event_uid(payload)
    inserted = _insert_commission(subscription_id, ref_code, event_name,
                                  event_uid, amount, currency, "accrued")
    return {"affiliate": True, "ref_code": ref_code, "amount_cents": amount,
            "currency": currency, "idempotent": not inserted,
            "event_uid": event_uid}


def clawback_commission(payload: dict, event_name: str) -> dict:
    """On a refund / refunded cancellation: insert a NEGATIVE commission for the
    same subscription so the ledger nets out. Amount = -30% of the refunded
    total (falls back to the original accrual total if the refund carries no
    amount). Idempotent per event uid."""
    subscription_id = extract_subscription_id(payload)
    ref_code = lookup_ref(subscription_id)
    if not ref_code:
        return {"affiliate": False, "reason": "no referral"}
    total_cents, currency = extract_payment_total_cents(payload)
    if total_cents <= 0:
        # Refund event without an amount: claw back the most recent accrual.
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT amount_cents,currency FROM affiliate_commissions "
                "WHERE subscription_id=? AND status='accrued' "
                "ORDER BY id DESC LIMIT 1", (subscription_id,)).fetchone()
        finally:
            conn.close()
        if not row:
            return {"affiliate": False, "reason": "no accrual to claw back"}
        amount = -int(row[0])
        currency = currency or row[1]
    else:
        amount = -int(round(RATE * total_cents))
    event_uid = extract_event_uid(payload) + ":clawback"
    inserted = _insert_commission(subscription_id, ref_code, event_name,
                                  event_uid, amount, currency, "clawback")
    return {"affiliate": True, "ref_code": ref_code, "amount_cents": amount,
            "currency": currency, "idempotent": not inserted,
            "event_uid": event_uid}


# ---------------------------------------------------------------------------
# Read-only ledger (per ref_code totals) for MANUAL payouts.
# ---------------------------------------------------------------------------
def ledger() -> dict:
    """Per ref_code: accrued_cents, clawback_cents, net_owed_cents,
    referrals_count, currency. net = accrued + clawback (clawbacks are stored
    negative, so a plain sum nets out)."""
    conn = _connect()
    try:
        out: dict = {}
        rows = conn.execute(
            "SELECT ref_code, "
            "  SUM(CASE WHEN status='accrued'  THEN amount_cents ELSE 0 END), "
            "  SUM(CASE WHEN status='clawback' THEN amount_cents ELSE 0 END), "
            "  SUM(amount_cents), "
            "  MAX(currency) "
            "FROM affiliate_commissions GROUP BY ref_code"
        ).fetchall()
        for ref_code, accrued, clawback, net, currency in rows:
            out[ref_code] = {
                "accrued_cents": int(accrued or 0),
                "clawback_cents": int(clawback or 0),
                "net_owed_cents": int(net or 0),
                "currency": currency or "",
                "referrals_count": 0,
            }
        for ref_code, cnt in conn.execute(
                "SELECT ref_code, COUNT(*) FROM affiliate_referrals "
                "GROUP BY ref_code").fetchall():
            out.setdefault(ref_code, {
                "accrued_cents": 0, "clawback_cents": 0, "net_owed_cents": 0,
                "currency": "", "referrals_count": 0})
            out[ref_code]["referrals_count"] = int(cnt or 0)
        return out
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# CLI: onboard a creator.  python -m affiliate add-affiliate CODE "Name" email
# ---------------------------------------------------------------------------
def _main(argv=None) -> int:
    import sys
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print("usage:")
        print("  add-affiliate CODE [NAME] [EMAIL]   onboard a creator")
        print("  ledger                              print per-code net owed")
        return 0
    cmd = argv[0]
    if cmd == "add-affiliate":
        if len(argv) < 2:
            print("error: add-affiliate needs a CODE")
            return 2
        code = argv[1]
        name = argv[2] if len(argv) > 2 else ""
        email = argv[3] if len(argv) > 3 else ""
        add_affiliate(code, name, email)
        print("added affiliate: " + code + "  link: gate.cat/?ref=" + code)
        return 0
    if cmd == "ledger":
        import json as _json
        print(_json.dumps(ledger(), indent=2))
        return 0
    print("unknown command: " + cmd)
    return 2


if __name__ == "__main__":
    raise SystemExit(_main())
