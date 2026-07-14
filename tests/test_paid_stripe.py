"""Stripe Cloud activation: signed lifecycle webhook -> entitlement state."""
import hashlib
import hmac
import importlib.util
import json
import os
import time

import pytest


SECRET = "whsec_stripe_test"
SOLO_PRICE = "price_1Tr0na2Va7XV3fWYCU40u4ZT"
FOUNDING_SOLO_EUR_PRICE = "price_1Tt2AB2Va7XV3fWYfJL9XCsW"


def _load_activate(tmp_path, env=None):
    os.environ["CLOUD_DATA_DIR"] = str(tmp_path)
    os.environ["CLOUD_ISSUED_LOG"] = str(tmp_path / "issued.jsonl")
    for key, value in (env or {}).items():
        os.environ[key] = value
    path = os.path.join(os.path.dirname(__file__), "..", "products", "cloud",
                        "cloud_activate.py")
    spec = importlib.util.spec_from_file_location("cloud_activate_stripe_t",
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


def test_stripe_signature_accepts_valid_and_rejects_bad(tmp_path, env_vars):
    ca = _load_activate(tmp_path, {"STRIPE_WEBHOOK_SECRET": SECRET})
    body, signature = _signed({"type": "invoice.paid", "data": {"object": {}}})
    assert ca.verify_stripe_signature(body, signature)
    assert not ca.verify_stripe_signature(body + b"x", signature)
    assert not ca.verify_stripe_signature(body, "t=1,v1=deadbeef")


def test_founding_eur_price_maps_to_solo(tmp_path, env_vars):
    ca = _load_activate(tmp_path)
    assert ca.PRICE_TIER[FOUNDING_SOLO_EUR_PRICE] == "solo"


def test_stripe_signature_rejects_replay(tmp_path, env_vars):
    ca = _load_activate(tmp_path, {"STRIPE_WEBHOOK_SECRET": SECRET})
    body, signature = _signed({}, timestamp=1000)
    assert not ca.verify_stripe_signature(body, signature, now=2000)


def test_checkout_completed_provisions_once_and_records_subscription(tmp_path,
                                                                    env_vars):
    ca = _load_activate(tmp_path, {"STRIPE_WEBHOOK_SECRET": SECRET})
    session = {
        "id": "cs_live_test", "mode": "subscription", "payment_status": "paid",
        "subscription": "sub_test", "customer_details": {"email": "buyer@x"},
        "line_items": {"data": [{"price": {"id": SOLO_PRICE}}]},
    }
    ca._stripe = lambda _path: session
    payload = {"type": "checkout.session.completed", "data": {"object": session}}
    body, signature = _signed(payload)
    first = ca.handle_stripe_event(body, signature)
    second = ca.handle_stripe_event(body, signature)
    assert first["ok"] is True and second["ok"] is True
    assert len(ca.cloud_server._load_accounts()) == 1
    row = json.loads((tmp_path / "issued.jsonl").read_text().splitlines()[0])
    assert row["subscription"] == "sub_test"
    assert row["provider"] == "stripe"


def test_subscription_deleted_revokes_idempotently(tmp_path, env_vars):
    ca = _load_activate(tmp_path, {"STRIPE_WEBHOOK_SECRET": SECRET})
    key = ca.cloud_server.issue_key("buyer@x", "solo")
    ca._record("cs_live_test", "buyer@x", "solo", key,
               provider="stripe", subscription="sub_test", price=SOLO_PRICE)
    payload = {"type": "customer.subscription.deleted",
               "data": {"object": {"id": "sub_test", "status": "canceled"}}}
    body, signature = _signed(payload)
    first = ca.handle_stripe_event(body, signature)
    second = ca.handle_stripe_event(body, signature)
    assert first["revoked"] is True and second["revoked"] is False
    assert second["idempotent"] is True
    assert ca.cloud_server._account_for(key) is None


def test_past_due_does_not_revoke_until_subscription_terminal(tmp_path, env_vars):
    ca = _load_activate(tmp_path, {"STRIPE_WEBHOOK_SECRET": SECRET})
    key = ca.cloud_server.issue_key("buyer@x", "team")
    ca._record("cs_live_test", "buyer@x", "team", key,
               provider="stripe", subscription="sub_test")
    payload = {"type": "customer.subscription.updated",
               "data": {"object": {"id": "sub_test", "status": "past_due"}}}
    body, signature = _signed(payload)
    result = ca.handle_stripe_event(body, signature)
    assert result["ignored"] is True
    assert ca.cloud_server._account_for(key)["tier"] == "team"


def test_unmapped_stripe_price_fails_closed(tmp_path, env_vars):
    ca = _load_activate(tmp_path)
    ca._stripe = lambda _path: {
        "id": "cs_live_unknown", "mode": "subscription", "payment_status": "paid",
        "subscription": "sub_unknown", "customer_details": {"email": "buyer@x"},
        "line_items": {"data": [{"price": {"id": "price_unknown"}}]},
    }
    with pytest.raises(ValueError, match="unmapped Stripe price"):
        ca.activate("cs_live_unknown")
    assert ca.cloud_server._load_accounts() == {}
