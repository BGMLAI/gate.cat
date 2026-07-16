"""Affiliate / referral tracking -- the self-hosted, zero-cost commission engine.

Extends the LIVE Lemon Squeezy webhook handler (cloud_activate.py). These pin
the money-correctness and the invariant that activation is SACRED:

  * referral capture on subscription_created (meta.custom_data.ref -> row)
  * 30% accrual on subscription_payment_success (amount == round(0.30*total))
  * LIFETIME recurring: a SECOND payment (no custom_data) is attributed via the
    stored subscription_id -> ref lookup
  * idempotency: a re-delivered event (same event_uid) inserts ONE row
  * clawback: a refund inserts a NEGATIVE commission; net_owed nets out
  * no-ref path: a checkout WITHOUT ref creates no affiliate rows AND tier
    activation still succeeds (the existing path is untouched)
  * the ledger endpoint reports correct per-code net_owed
  * add-affiliate onboarding

Signing idiom is copied from tests/test_paid_lemonsqueezy.py.
"""
import hashlib
import hmac
import importlib.util
import json
import os

import pytest


SECRET = "whsec_test_123"
SOLO_VARIANT = "111"


def _load_activate(tmp_path, env=None):
    """Load cloud_activate fresh with an isolated data dir + issued log, so the
    SQLite affiliate DB (under CLOUD_DATA_DIR) and the accounts log are per-test."""
    os.environ["CLOUD_DATA_DIR"] = str(tmp_path)
    os.environ["CLOUD_ISSUED_LOG"] = str(tmp_path / "issued.jsonl")
    for k, v in (env or {}).items():
        os.environ[k] = v
    path = os.path.join(os.path.dirname(__file__), "..", "products", "cloud", "cloud_activate.py")
    spec = importlib.util.spec_from_file_location("cloud_activate_aff", os.path.abspath(path))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _signed(payload: dict, secret: str = SECRET):
    body = json.dumps(payload).encode()
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return body, sig


def _created(variant_id=SOLO_VARIANT, email="buyer@x", sub_id="sub_1", ref=None):
    """subscription_created. When ref is given it rides in meta.custom_data
    exactly as LS echoes checkout[custom][ref]=CODE back."""
    payload = {"meta": {"event_name": "subscription_created"},
               "data": {"id": sub_id, "attributes": {"user_email": email,
                                                      "variant_id": variant_id}}}
    if ref is not None:
        payload["meta"]["custom_data"] = {"ref": ref}
    return payload


def _payment(sub_id="sub_1", total=1900, currency="USD", pay_id="pay_1",
             event="subscription_payment_success"):
    """subscription_payment_success. NOTE: NO custom_data (renewals drop it) --
    attribution must come from the stored subscription_id -> ref mapping."""
    return {"meta": {"event_name": event},
            "data": {"id": pay_id, "attributes": {
                "subscription_id": sub_id, "total": total, "currency": currency}}}


@pytest.fixture
def env_vars():
    keys = ["LEMONSQUEEZY_WEBHOOK_SECRET", "LEMONSQUEEZY_VARIANT_SOLO",
            "LEMONSQUEEZY_VARIANT_TEAM", "LEMONSQUEEZY_VARIANT_BUSINESS",
            "LEMONSQUEEZY_VARIANT_TIER", "GATECAT_PAYMENT_CHANNEL",
            "GATECAT_ADMIN_TOKEN"]
    saved = {k: os.environ.get(k) for k in keys}
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def _base_env():
    return {"LEMONSQUEEZY_WEBHOOK_SECRET": SECRET,
            "LEMONSQUEEZY_VARIANT_SOLO": SOLO_VARIANT}


# ---- 1. referral capture ----------------------------------------------------

def test_referral_captured_on_subscription_created(tmp_path, env_vars):
    ca = _load_activate(tmp_path, _base_env())
    body, sig = _signed(_created(ref="juliangoldie"))
    res = ca.activate_lemonsqueezy(body, sig)
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


# ---- 2. 30% accrual ---------------------------------------------------------

def test_thirty_percent_accrual(tmp_path, env_vars):
    ca = _load_activate(tmp_path, _base_env())
    # capture first, then a payment
    b, s = _signed(_created(ref="creator1"))
    ca.activate_lemonsqueezy(b, s)
    pb, ps = _signed(_payment(total=1900))       # $19.00
    res = ca.activate_lemonsqueezy(pb, ps)
    assert res["ok"] is True
    assert res["affiliate"]["affiliate"] is True
    assert res["affiliate"]["amount_cents"] == round(0.30 * 1900)  # 570
    led = ca.affiliate.ledger()
    assert led["creator1"]["accrued_cents"] == 570
    assert led["creator1"]["net_owed_cents"] == 570
    assert led["creator1"]["currency"] == "USD"


# ---- 3. lifetime recurring (second payment, no custom_data) -----------------

def test_lifetime_recurring_second_payment(tmp_path, env_vars):
    ca = _load_activate(tmp_path, _base_env())
    b, s = _signed(_created(ref="creator1"))
    ca.activate_lemonsqueezy(b, s)
    # month 1
    pb1, ps1 = _signed(_payment(total=1900, pay_id="pay_1"))
    ca.activate_lemonsqueezy(pb1, ps1)
    # month 2 -- a renewal invoice with NO custom_data; attributed via sub id
    pb2, ps2 = _signed(_payment(total=1900, pay_id="pay_2"))
    res2 = ca.activate_lemonsqueezy(pb2, ps2)
    assert res2["affiliate"]["ref_code"] == "creator1"
    led = ca.affiliate.ledger()
    assert led["creator1"]["accrued_cents"] == 1140          # two months x 570
    assert led["creator1"]["referrals_count"] == 1


# ---- 4. idempotency (same event_uid twice) ----------------------------------

def test_payment_idempotent_same_event_uid(tmp_path, env_vars):
    ca = _load_activate(tmp_path, _base_env())
    b, s = _signed(_created(ref="creator1"))
    ca.activate_lemonsqueezy(b, s)
    pb, ps = _signed(_payment(total=1900, pay_id="pay_dup"))
    r1 = ca.activate_lemonsqueezy(pb, ps)
    r2 = ca.activate_lemonsqueezy(pb, ps)       # LS retry
    assert r1["affiliate"]["idempotent"] is False
    assert r2["affiliate"]["idempotent"] is True
    # exactly ONE commission row
    conn = ca.affiliate._connect()
    try:
        n = conn.execute("SELECT COUNT(*) FROM affiliate_commissions").fetchone()[0]
    finally:
        conn.close()
    assert n == 1
    assert ca.affiliate.ledger()["creator1"]["accrued_cents"] == 570


# ---- 5. clawback ------------------------------------------------------------

def test_refund_clawback_nets_out(tmp_path, env_vars):
    ca = _load_activate(tmp_path, _base_env())
    b, s = _signed(_created(ref="creator1"))
    ca.activate_lemonsqueezy(b, s)
    pb, ps = _signed(_payment(total=1900, pay_id="pay_1"))
    ca.activate_lemonsqueezy(pb, ps)
    # refund the same amount
    rb, rs = _signed(_payment(total=1900, pay_id="pay_1",
                              event="subscription_payment_refunded"))
    res = ca.activate_lemonsqueezy(rb, rs)
    assert res["affiliate"]["amount_cents"] == -570
    led = ca.affiliate.ledger()
    assert led["creator1"]["accrued_cents"] == 570
    assert led["creator1"]["clawback_cents"] == -570
    assert led["creator1"]["net_owed_cents"] == 0


def test_cancellation_with_refund_claws_back(tmp_path, env_vars):
    ca = _load_activate(tmp_path, _base_env())
    b, s = _signed(_created(ref="creator1"))
    ca.activate_lemonsqueezy(b, s)
    pb, ps = _signed(_payment(total=1900, pay_id="pay_1"))
    ca.activate_lemonsqueezy(pb, ps)
    cancel = {"meta": {"event_name": "subscription_cancelled"},
              "data": {"id": "sub_1", "attributes": {
                  "subscription_id": "sub_1", "refunded": True,
                  "total": 1900, "currency": "USD"}}}
    cb, cs = _signed(cancel)
    ca.activate_lemonsqueezy(cb, cs)
    assert ca.affiliate.ledger()["creator1"]["net_owed_cents"] == 0


def test_plain_cancellation_keeps_earned_commission(tmp_path, env_vars):
    """A cancel WITHOUT a refund does not claw back earned months."""
    ca = _load_activate(tmp_path, _base_env())
    b, s = _signed(_created(ref="creator1"))
    ca.activate_lemonsqueezy(b, s)
    pb, ps = _signed(_payment(total=1900, pay_id="pay_1"))
    ca.activate_lemonsqueezy(pb, ps)
    cancel = {"meta": {"event_name": "subscription_cancelled"},
              "data": {"id": "sub_1", "attributes": {"subscription_id": "sub_1"}}}
    cb, cs = _signed(cancel)
    ca.activate_lemonsqueezy(cb, cs)
    assert ca.affiliate.ledger()["creator1"]["net_owed_cents"] == 570


# ---- 6. no-ref path: activation is untouched --------------------------------

def test_no_ref_creates_no_affiliate_rows_and_activation_succeeds(tmp_path, env_vars):
    ca = _load_activate(tmp_path, _base_env())
    body, sig = _signed(_created(ref=None))     # a plain checkout, no ?ref
    res = ca.activate_lemonsqueezy(body, sig)
    # activation path PROVABLY untouched: same success shape as before
    assert res["ok"] is True
    assert res["tier"] == "solo"
    assert res["account"] == "buyer@x"
    assert res["key"].startswith("gck_")
    assert res["idempotent"] is False
    # a real cloud account/key was issued (the sacred path ran)
    assert ca.cloud_server._account_for(res["key"])["tier"] == "solo"
    # NO affiliate rows of any kind
    conn = ca.affiliate._connect()
    try:
        assert conn.execute("SELECT COUNT(*) FROM affiliate_referrals").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM affiliate_commissions").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM affiliates").fetchone()[0] == 0
    finally:
        conn.close()
    # a payment on an unreferred subscription accrues nothing
    pb, ps = _signed(_payment(total=1900))
    pres = ca.activate_lemonsqueezy(pb, ps)
    assert pres["ok"] is True
    assert pres["affiliate"].get("affiliate") is False
    assert ca.affiliate.ledger() == {}


def test_affiliate_failure_never_blocks_activation(tmp_path, env_vars, monkeypatch):
    """Even if the ledger blows up, the key is still issued (activation sacred)."""
    ca = _load_activate(tmp_path, _base_env())

    def boom(*a, **k):
        raise RuntimeError("ledger on fire")
    monkeypatch.setattr(ca.affiliate, "record_referral", boom)
    body, sig = _signed(_created(ref="creator1"))
    res = ca.activate_lemonsqueezy(body, sig)
    assert res["ok"] is True and res["key"].startswith("gck_")


# ---- 7. ledger endpoint -----------------------------------------------------

def test_ledger_endpoint_requires_token(tmp_path, env_vars):
    ca = _load_activate(tmp_path, _base_env())          # no admin token set
    code, body = ca.affiliate_ledger_response("")
    assert code == 403 and body["ok"] is False
    # with a token configured, wrong token -> 401
    os.environ["GATECAT_ADMIN_TOKEN"] = "s3cret"
    code, body = ca.affiliate_ledger_response("nope")
    assert code == 401


def test_ledger_endpoint_reports_net_owed(tmp_path, env_vars):
    ca = _load_activate(tmp_path, {**_base_env(), "GATECAT_ADMIN_TOKEN": "s3cret"})
    # two creators, different earnings
    for code, sub in (("alice", "sub_a"), ("bob", "sub_b")):
        b, s = _signed(_created(ref=code, sub_id=sub, email=code + "@x"))
        ca.activate_lemonsqueezy(b, s)
    pb, ps = _signed(_payment(sub_id="sub_a", total=1900, pay_id="pa"))
    ca.activate_lemonsqueezy(pb, ps)
    pb, ps = _signed(_payment(sub_id="sub_b", total=14900, pay_id="pb"))  # team
    ca.activate_lemonsqueezy(pb, ps)
    # bob refunds
    rb, rs = _signed(_payment(sub_id="sub_b", total=14900, pay_id="pb",
                              event="subscription_payment_refunded"))
    ca.activate_lemonsqueezy(rb, rs)
    code, body = ca.affiliate_ledger_response("s3cret")
    assert code == 200 and body["ok"] is True and body["rate"] == 0.30
    by = body["by_code"]
    assert by["alice"]["net_owed_cents"] == round(0.30 * 1900)     # 570
    assert by["bob"]["net_owed_cents"] == 0                        # refunded out
    assert by["alice"]["referrals_count"] == 1


# ---- 8. onboarding CLI ------------------------------------------------------

def test_add_affiliate_onboarding(tmp_path, env_vars):
    ca = _load_activate(tmp_path, _base_env())
    ca.affiliate.add_affiliate("juliangoldie", "Julian Goldie", "julian@x")
    conn = ca.affiliate._connect()
    try:
        row = conn.execute("SELECT code,name,email FROM affiliates WHERE code=?",
                           ("juliangoldie",)).fetchone()
    finally:
        conn.close()
    assert row == ("juliangoldie", "Julian Goldie", "julian@x")
    # onboarding then a referral keeps the contact info (no clobber to pending)
    b, s = _signed(_created(ref="juliangoldie"))
    ca.activate_lemonsqueezy(b, s)
    conn = ca.affiliate._connect()
    try:
        name = conn.execute("SELECT name FROM affiliates WHERE code=?",
                           ("juliangoldie",)).fetchone()[0]
    finally:
        conn.close()
    assert name == "Julian Goldie"


def test_add_affiliate_cli_main(tmp_path, env_vars, capsys):
    ca = _load_activate(tmp_path, _base_env())
    rc = ca.affiliate._main(["add-affiliate", "creatorx", "Creator X", "cx@x"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "gate.cat/?ref=creatorx" in out


# ---- landing-page JS patch presence (static assertion) ----------------------

def test_landing_page_referral_js_injected(tmp_path, env_vars):
    """The referral-capture JS is present and well-formed in the landing bundle.
    (Live browser behavior is verified via preview; this pins the injection.)"""
    site = os.path.join(os.path.dirname(__file__), "..", "..",
                        "gatecat-release-0.2.1", "site", "cd_redesign.html")
    if not os.path.exists(site):
        pytest.skip("landing bundle not present in this checkout")
    data = open(site, encoding="utf-8").read()
    assert 'id="gc-affiliate-ref"' in data
    assert "gc_ref" in data
    assert "SameSite=Lax" in data
    assert "checkout[custom][ref]" in data
    assert 'lemonsqueezy.com/checkout' in data
    # idempotency guard + ?/& handling present
    assert 'indexOf("?")' in data
