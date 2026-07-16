"""Affiliate / referral tracking on the LIVE STRIPE payment path.

The live gate.cat checkout uses Stripe Payment Links (buy.stripe.com), which
attribute a creator via ``client_reference_id`` (set by the landing JS from
``?ref=CODE``). Stripe echoes it back at ``data.object.client_reference_id`` on
``checkout.session.completed``. These tests pin the money-correctness and the
invariant that STRIPE ACTIVATION IS SACRED (never blocked by affiliate errors):

  * referral capture from client_reference_id on checkout.session.completed
  * 30% accrual on the first payment (subscription AND one-time pack)
  * LIFETIME recurring: a later invoice.paid (NO client_reference_id) is
    attributed via the stored subscription_id -> ref map
  * idempotency: a re-delivered event (same Stripe event id) inserts ONE row
  * clawback: charge.refunded inserts a NEGATIVE commission; net_owed nets out
  * no-client_reference_id checkout still ACTIVATES and creates NO affiliate rows
    (the existing Stripe activation path is provably untouched)

Signing idiom is copied from tests/test_paid_stripe.py.
"""
import hashlib
import hmac
import importlib.util
import json
import os
import time

import pytest


SECRET = "whsec_stripe_test"
SOLO_PRICE = "price_1Tr0na2Va7XV3fWYCU40u4ZT"


def _load_activate(tmp_path, env=None):
    """Load cloud_activate fresh with an isolated data dir + issued log, so the
    SQLite affiliate DB (under CLOUD_DATA_DIR) and the accounts log are per-test."""
    os.environ["CLOUD_DATA_DIR"] = str(tmp_path)
    os.environ["CLOUD_ISSUED_LOG"] = str(tmp_path / "issued.jsonl")
    for key, value in (env or {}).items():
        os.environ[key] = value
    path = os.path.join(os.path.dirname(__file__), "..", "products", "cloud",
                        "cloud_activate.py")
    spec = importlib.util.spec_from_file_location("cloud_activate_aff_stripe",
                                                  os.path.abspath(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _signed(payload: dict, secret: str = SECRET, timestamp: int | None = None):
    body = json.dumps(payload).encode()
    ts = int(time.time()) if timestamp is None else timestamp
    digest = hmac.new(secret.encode(), str(ts).encode() + b"." + body,
                      hashlib.sha256).hexdigest()
    return body, f"t={ts},v1={digest}"


def _checkout(session_id="cs_live_1", sub_id="sub_1", ref=None, mode="subscription",
              amount_total=1900, currency="usd", event_id="evt_checkout_1",
              price=SOLO_PRICE, email="buyer@x"):
    """checkout.session.completed. When ref is given it rides in
    client_reference_id exactly as Stripe echoes ?client_reference_id=CODE."""
    obj = {
        "id": session_id, "mode": mode, "payment_status": "paid",
        "amount_total": amount_total, "currency": currency,
        "customer_details": {"email": email},
        "line_items": {"data": [{"price": {"id": price}}]},
    }
    if mode == "subscription":
        obj["subscription"] = sub_id
    if ref is not None:
        obj["client_reference_id"] = ref
    return {"id": event_id, "type": "checkout.session.completed",
            "data": {"object": obj}}


def _invoice(sub_id="sub_1", amount_paid=1900, currency="usd",
             event_id="evt_invoice_1", event_type="invoice.paid"):
    """invoice.paid (a RENEWAL): NO client_reference_id -- attribution must come
    from the stored subscription_id -> ref mapping."""
    return {"id": event_id, "type": event_type,
            "data": {"object": {"id": "in_" + event_id, "subscription": sub_id,
                                "amount_paid": amount_paid, "currency": currency}}}


def _refund(sub_id="sub_1", amount_refunded=1900, currency="usd",
            event_id="evt_refund_1"):
    """charge.refunded. The subscription id rides on the charge object so the
    clawback resolves the stored referral (real Stripe subscription charges
    carry the subscription link)."""
    return {"id": event_id, "type": "charge.refunded",
            "data": {"object": {"id": "ch_" + event_id, "subscription": sub_id,
                                "amount_refunded": amount_refunded,
                                "currency": currency}}}


@pytest.fixture
def env_vars():
    keys = ["STRIPE_KEY", "STRIPE_WEBHOOK_SECRET", "CLOUD_PRICE_TIER"]
    saved = {key: os.environ.get(key) for key in keys}
    yield
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def _sub_env():
    return {"STRIPE_WEBHOOK_SECRET": SECRET}


# ---- 1. referral capture from client_reference_id ---------------------------

def test_referral_captured_on_checkout_completed(tmp_path, env_vars):
    ca = _load_activate(tmp_path, _sub_env())
    ca._stripe = lambda _path: _checkout(ref="juliangoldie")["data"]["object"]
    body, sig = _signed(_checkout(ref="juliangoldie"))
    res = ca.handle_stripe_event(body, sig)
    assert res["ok"] is True and res["tier"] == "solo"
    # row exists mapping subscription -> code
    assert ca.affiliate.lookup_ref("sub_1") == "juliangoldie"
    # affiliate auto-created (pending) even though never onboarded
    conn = ca.affiliate._connect()
    try:
        row = conn.execute("SELECT code FROM affiliates WHERE code=?",
                           ("juliangoldie",)).fetchone()
    finally:
        conn.close()
    assert row is not None


# ---- 2. 30% accrual (subscription first payment) ----------------------------

def test_thirty_percent_accrual_subscription(tmp_path, env_vars):
    ca = _load_activate(tmp_path, _sub_env())
    ca._stripe = lambda _path: _checkout(ref="creator1", amount_total=1900)["data"]["object"]
    body, sig = _signed(_checkout(ref="creator1", amount_total=1900))
    res = ca.handle_stripe_event(body, sig)
    assert res["ok"] is True
    assert res["affiliate"]["affiliate"] is True
    led = ca.affiliate.ledger()
    assert led["creator1"]["accrued_cents"] == round(0.30 * 1900)   # 570
    assert led["creator1"]["net_owed_cents"] == 570
    assert led["creator1"]["currency"] == "USD"
    # activation ran: exactly one cloud account exists
    assert len(ca.cloud_server._load_accounts()) == 1


# ---- 2b. 30% accrual (one-time pack, mode=='payment') -----------------------

def test_thirty_percent_accrual_one_time_pack(tmp_path, env_vars):
    ca = _load_activate(tmp_path, _sub_env())
    pack = _checkout(session_id="cs_pack_1", ref="creator1", mode="payment",
                     amount_total=2900, event_id="evt_pack_1")
    body, sig = _signed(pack)
    res = ca.handle_stripe_event(body, sig)
    assert res["ok"] is True
    # a pack is not a subscription -> no cloud account provisioned here
    assert ca.cloud_server._load_accounts() == {}
    led = ca.affiliate.ledger()
    assert led["creator1"]["accrued_cents"] == round(0.30 * 2900)   # 870
    assert led["creator1"]["net_owed_cents"] == 870


# ---- 3. lifetime recurring (renewal invoice, no client_reference_id) --------

def test_lifetime_recurring_renewal_invoice(tmp_path, env_vars):
    ca = _load_activate(tmp_path, _sub_env())
    ca._stripe = lambda _path: _checkout(ref="creator1")["data"]["object"]
    # month 1: checkout completes (capture + first accrual)
    b, s = _signed(_checkout(ref="creator1", amount_total=1900))
    ca.handle_stripe_event(b, s)
    # month 2: a renewal invoice with NO client_reference_id; attributed via sub id
    ib, isig = _signed(_invoice(sub_id="sub_1", amount_paid=1900,
                                event_id="evt_invoice_2"))
    res2 = ca.handle_stripe_event(ib, isig)
    assert res2["affiliate"]["ref_code"] == "creator1"
    led = ca.affiliate.ledger()
    assert led["creator1"]["accrued_cents"] == 1140          # two months x 570
    assert led["creator1"]["referrals_count"] == 1


# ---- 4. idempotency (same Stripe event id twice) ----------------------------

def test_payment_idempotent_same_event_id(tmp_path, env_vars):
    ca = _load_activate(tmp_path, _sub_env())
    ca._stripe = lambda _path: _checkout(ref="creator1")["data"]["object"]
    # capture referral via checkout
    b, s = _signed(_checkout(ref="creator1"))
    ca.handle_stripe_event(b, s)
    # a renewal delivered twice (LS/Stripe retries) with the SAME event id
    ib, isig = _signed(_invoice(sub_id="sub_1", event_id="evt_dup"))
    r1 = ca.handle_stripe_event(ib, isig)
    r2 = ca.handle_stripe_event(ib, isig)
    assert r1["affiliate"]["idempotent"] is False
    assert r2["affiliate"]["idempotent"] is True
    # exactly TWO commission rows total (checkout accrual + one renewal), the
    # duplicate renewal did NOT insert a second row.
    conn = ca.affiliate._connect()
    try:
        n = conn.execute("SELECT COUNT(*) FROM affiliate_commissions").fetchone()[0]
    finally:
        conn.close()
    assert n == 2
    assert ca.affiliate.ledger()["creator1"]["accrued_cents"] == 1140


# ---- 5. clawback (charge.refunded) ------------------------------------------

def test_refund_clawback_nets_out(tmp_path, env_vars):
    ca = _load_activate(tmp_path, _sub_env())
    ca._stripe = lambda _path: _checkout(ref="creator1")["data"]["object"]
    b, s = _signed(_checkout(ref="creator1", amount_total=1900))
    ca.handle_stripe_event(b, s)   # accrues 570
    rb, rs = _signed(_refund(sub_id="sub_1", amount_refunded=1900))
    res = ca.handle_stripe_event(rb, rs)
    assert res["affiliate"]["amount_cents"] == -570
    led = ca.affiliate.ledger()
    assert led["creator1"]["accrued_cents"] == 570
    assert led["creator1"]["clawback_cents"] == -570
    assert led["creator1"]["net_owed_cents"] == 0


# ---- 6. no-ref path: Stripe activation is PROVABLY untouched -----------------

def test_no_client_reference_id_activates_and_creates_no_affiliate_rows(
        tmp_path, env_vars):
    ca = _load_activate(tmp_path, _sub_env())
    session = _checkout(ref=None)["data"]["object"]     # a plain checkout, no ref
    ca._stripe = lambda _path: session
    body, sig = _signed(_checkout(ref=None))
    res = ca.handle_stripe_event(body, sig)
    # activation path PROVABLY untouched: same success shape (tier + account)
    assert res["ok"] is True
    assert res["tier"] == "solo"
    assert res["account"] == "buyer@x"
    # a real cloud account/key was issued (the sacred path ran)
    assert len(ca.cloud_server._load_accounts()) == 1
    row = json.loads((tmp_path / "issued.jsonl").read_text().splitlines()[0])
    assert row["subscription"] == "sub_1"
    assert row["provider"] == "stripe"
    # NO affiliate rows of any kind
    conn = ca.affiliate._connect()
    try:
        assert conn.execute("SELECT COUNT(*) FROM affiliate_referrals").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM affiliate_commissions").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM affiliates").fetchone()[0] == 0
    finally:
        conn.close()
    # a renewal on an unreferred subscription accrues nothing
    ib, isig = _signed(_invoice(sub_id="sub_1", event_id="evt_invoice_x"))
    ires = ca.handle_stripe_event(ib, isig)
    assert ires["ok"] is True
    assert ires["affiliate"].get("affiliate") is False
    assert ca.affiliate.ledger() == {}


# ---- 7. affiliate failure never blocks Stripe activation --------------------

def test_affiliate_failure_never_blocks_stripe_activation(tmp_path, env_vars,
                                                          monkeypatch):
    """Even if the ledger blows up, the subscription is still activated."""
    ca = _load_activate(tmp_path, _sub_env())
    ca._stripe = lambda _path: _checkout(ref="creator1")["data"]["object"]

    def boom(*a, **k):
        raise RuntimeError("ledger on fire")
    monkeypatch.setattr(ca.affiliate, "record_referral_stripe", boom)
    monkeypatch.setattr(ca.affiliate, "accrue_from_stripe", boom)
    body, sig = _signed(_checkout(ref="creator1"))
    res = ca.handle_stripe_event(body, sig)
    assert res["ok"] is True and res["tier"] == "solo"
    assert len(ca.cloud_server._load_accounts()) == 1
