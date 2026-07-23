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
              price=SOLO_PRICE, email="buyer@x", invoice=None, payment_intent=None):
    """checkout.session.completed. When ref is given it rides in
    client_reference_id exactly as Stripe echoes ?client_reference_id=CODE.
    Real subscription sessions carry the FIRST invoice id at ``invoice``;
    real payment-mode (pack) sessions carry ``payment_intent``."""
    obj = {
        "id": session_id, "mode": mode, "payment_status": "paid",
        "amount_total": amount_total, "currency": currency,
        "customer_details": {"email": email},
        "line_items": {"data": [{"price": {"id": price}}]},
    }
    if mode == "subscription":
        obj["subscription"] = sub_id
        obj["invoice"] = invoice if invoice is not None else "in_first_" + sub_id
    if payment_intent is not None:
        obj["payment_intent"] = payment_intent
    if ref is not None:
        obj["client_reference_id"] = ref
    return {"id": event_id, "type": "checkout.session.completed",
            "data": {"object": obj}}


def _invoice(sub_id="sub_1", amount_paid=1900, currency="usd",
             event_id="evt_invoice_1", event_type="invoice.paid",
             invoice_id=None, charge=None, payment_intent=None):
    """invoice.paid / invoice.payment_succeeded: NO client_reference_id --
    attribution must come from the stored subscription_id -> ref mapping.
    ``invoice_id`` defaults to a per-event id (a RENEWAL); pass the checkout's
    invoice id to simulate Stripe announcing the SAME first payment again."""
    obj = {"id": invoice_id or ("in_" + event_id), "subscription": sub_id,
           "amount_paid": amount_paid, "currency": currency}
    if charge is not None:
        obj["charge"] = charge
    if payment_intent is not None:
        obj["payment_intent"] = payment_intent
    return {"id": event_id, "type": event_type, "data": {"object": obj}}


def _refund(amount_refunded=1900, currency="usd", event_id="evt_refund_1",
            charge_id=None, payment_intent=None, invoice=None):
    """charge.refunded with a REALISTIC Charge shape: a Charge has NO
    ``subscription`` field (the old fixture invented one, which made the
    clawback look testable while the production lookup could never resolve).
    Resolution must run through payment_intent / invoice / charge-id aliases."""
    obj = {"id": charge_id or ("ch_" + event_id),
           "amount_refunded": amount_refunded, "currency": currency}
    if payment_intent is not None:
        obj["payment_intent"] = payment_intent
    if invoice is not None:
        obj["invoice"] = invoice
    return {"id": event_id, "type": "charge.refunded", "data": {"object": obj}}


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


# ---- 5. clawback (charge.refunded, REAL Charge shapes) -----------------------

def test_refund_clawback_nets_out_realistic_charge(tmp_path, env_vars):
    """A real Charge in charge.refunded has NO .subscription field — the
    clawback must resolve through the payment_intent alias captured at
    checkout time."""
    ca = _load_activate(tmp_path, _sub_env())
    ca._stripe = lambda _path: _checkout(ref="creator1")["data"]["object"]
    b, s = _signed(_checkout(ref="creator1", amount_total=1900,
                             payment_intent="pi_sub_first"))
    ca.handle_stripe_event(b, s)   # accrues 570, aliases pi_sub_first -> sub_1
    rb, rs = _signed(_refund(amount_refunded=1900,
                             payment_intent="pi_sub_first"))
    res = ca.handle_stripe_event(rb, rs)
    assert res["affiliate"]["amount_cents"] == -570
    led = ca.affiliate.ledger()
    assert led["creator1"]["accrued_cents"] == 570
    assert led["creator1"]["clawback_cents"] == -570
    assert led["creator1"]["net_owed_cents"] == 0


def test_pack_refund_resolves_via_payment_intent_alias(tmp_path, env_vars):
    """Pack referral is keyed on the Checkout SESSION id (cs_...), but the
    refund Charge only carries the payment_intent (pi_...). Without the alias
    the promised clawback would never fire on production shapes."""
    ca = _load_activate(tmp_path, _sub_env())
    pack = _checkout(session_id="cs_pack_9", ref="creator1", mode="payment",
                     amount_total=2900, event_id="evt_pack_9",
                     payment_intent="pi_pack_9")
    b, s = _signed(pack)
    ca.handle_stripe_event(b, s)                       # accrues 870
    rb, rs = _signed(_refund(amount_refunded=2900, event_id="evt_refund_p9",
                             payment_intent="pi_pack_9"))
    res = ca.handle_stripe_event(rb, rs)
    assert res["affiliate"]["amount_cents"] == -870
    assert ca.affiliate.ledger()["creator1"]["net_owed_cents"] == 0


def test_unrecognized_refund_is_no_referral_not_an_exception(tmp_path, env_vars):
    ca = _load_activate(tmp_path, _sub_env())
    rb, rs = _signed(_refund(amount_refunded=1900, event_id="evt_refund_alien",
                             payment_intent="pi_never_seen"))
    res = ca.handle_stripe_event(rb, rs)
    assert res["ok"] is True
    assert res["affiliate"].get("affiliate") is False
    assert res["affiliate"].get("reason") == "no referral"


# ---- 5b. the same FIRST payment announced under multiple event types --------

def test_first_invoice_announced_three_times_books_thirty_percent_once(
        tmp_path, env_vars):
    """Stripe announces the first subscription payment as
    checkout.session.completed AND invoice.paid AND invoice.payment_succeeded,
    each under a DIFFERENT evt_ id. Keying accruals on the underlying invoice
    books 30% exactly once (the old evt-id key booked 90%)."""
    ca = _load_activate(tmp_path, _sub_env())
    ca._stripe = lambda _path: _checkout(ref="creator1")["data"]["object"]
    b, s = _signed(_checkout(ref="creator1", amount_total=1900,
                             invoice="in_first_sub_1"))
    ca.handle_stripe_event(b, s)
    for etype, eid in (("invoice.paid", "evt_first_paid"),
                       ("invoice.payment_succeeded", "evt_first_succ")):
        ib, isig = _signed(_invoice(sub_id="sub_1", amount_paid=1900,
                                    event_id=eid, event_type=etype,
                                    invoice_id="in_first_sub_1"))
        ca.handle_stripe_event(ib, isig)
    led = ca.affiliate.ledger()
    assert led["creator1"]["accrued_cents"] == 570       # once, not 1710
    conn = ca.affiliate._connect()
    try:
        n = conn.execute("SELECT COUNT(*) FROM affiliate_commissions").fetchone()[0]
    finally:
        conn.close()
    assert n == 1


def test_out_of_order_first_invoice_still_books_exactly_once(tmp_path, env_vars):
    """Stripe does not guarantee delivery order: invoice.paid may land BEFORE
    checkout.session.completed. The early invoice has no referral yet (skipped);
    the checkout then books month 1 exactly once."""
    ca = _load_activate(tmp_path, _sub_env())
    ca._stripe = lambda _path: _checkout(ref="creator1")["data"]["object"]
    ib, isig = _signed(_invoice(sub_id="sub_1", amount_paid=1900,
                                event_id="evt_early", invoice_id="in_first_sub_1"))
    early = ca.handle_stripe_event(ib, isig)
    assert early["affiliate"].get("affiliate") is False   # no referral yet
    b, s = _signed(_checkout(ref="creator1", amount_total=1900,
                             invoice="in_first_sub_1"))
    ca.handle_stripe_event(b, s)
    assert ca.affiliate.ledger()["creator1"]["accrued_cents"] == 570


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
