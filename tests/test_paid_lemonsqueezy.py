"""COMPONENT 2 — Lemon Squeezy activation (HMAC webhook -> tier key).

Founder decision: LS is the DEFAULT channel, built config-driven / test-mode
(no live secret/variant ids yet). Stripe is KEPT behind the channel selector.
These pin: a valid test-signature issues the right tier, an invalid signature is
rejected, unmapped variants are refused, activation is idempotent, and the
module is test-mode safe (no crash) when the LS env is unset.
"""
import hashlib
import hmac
import importlib.util
import json
import os

import pytest


def _load_activate(tmp_path, env=None):
    os.environ["CLOUD_DATA_DIR"] = str(tmp_path)
    os.environ["CLOUD_ISSUED_LOG"] = str(tmp_path / "issued.jsonl")
    for k, v in (env or {}).items():
        os.environ[k] = v
    path = os.path.join(os.path.dirname(__file__), "..", "products", "cloud", "cloud_activate.py")
    spec = importlib.util.spec_from_file_location("cloud_activate_t", os.path.abspath(path))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


SECRET = "whsec_test_123"


def _signed(payload: dict, secret: str = SECRET):
    body = json.dumps(payload).encode()
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return body, sig


def _sub(variant_id, email="buyer@x", rid="sub_1", event="subscription_created"):
    return {"meta": {"event_name": event},
            "data": {"id": rid, "attributes": {"user_email": email,
                                               "variant_id": variant_id}}}


@pytest.fixture
def env_vars():
    """Clean up injected LS env after each test."""
    keys = ["LEMONSQUEEZY_WEBHOOK_SECRET", "LEMONSQUEEZY_VARIANT_SOLO",
            "LEMONSQUEEZY_VARIANT_TEAM", "LEMONSQUEEZY_VARIANT_BUSINESS",
            "LEMONSQUEEZY_VARIANT_TIER", "GATECAT_PAYMENT_CHANNEL"]
    saved = {k: os.environ.get(k) for k in keys}
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


# ---- channel selector -------------------------------------------------------

def test_default_channel_is_lemonsqueezy(tmp_path, env_vars):
    os.environ.pop("GATECAT_PAYMENT_CHANNEL", None)
    ca = _load_activate(tmp_path)
    assert ca.payment_channel() == "lemonsqueezy"


def test_channel_selector_keeps_stripe(tmp_path, env_vars):
    ca = _load_activate(tmp_path, {"GATECAT_PAYMENT_CHANNEL": "stripe"})
    assert ca.payment_channel() == "stripe"
    # (c) the Stripe activate() function is still present/callable
    assert callable(ca.activate)


# ---- signature verification -------------------------------------------------

def test_valid_signature_issues_team_key(tmp_path, env_vars):
    """(c) a valid test signature issues the correct tier."""
    ca = _load_activate(tmp_path, {
        "LEMONSQUEEZY_WEBHOOK_SECRET": SECRET,
        "LEMONSQUEEZY_VARIANT_TEAM": "555",
        "LEMONSQUEEZY_VARIANT_SOLO": "111"})
    body, sig = _signed(_sub("555"))
    res = ca.activate_lemonsqueezy(body, sig)
    assert res["ok"] is True
    assert res["tier"] == "team"
    assert res["account"] == "buyer@x"
    assert res["key"].startswith("gck_")


def test_invalid_signature_rejected(tmp_path, env_vars):
    """(c) an invalid signature is rejected (fail-closed, nothing issued)."""
    ca = _load_activate(tmp_path, {
        "LEMONSQUEEZY_WEBHOOK_SECRET": SECRET,
        "LEMONSQUEEZY_VARIANT_TEAM": "555"})
    body, _ = _signed(_sub("555"))
    res = ca.activate_lemonsqueezy(body, "deadbeef")
    assert res["ok"] is False
    assert res["error"] == "bad signature"


def test_signature_from_wrong_secret_rejected(tmp_path, env_vars):
    ca = _load_activate(tmp_path, {
        "LEMONSQUEEZY_WEBHOOK_SECRET": SECRET,
        "LEMONSQUEEZY_VARIANT_TEAM": "555"})
    body, sig = _signed(_sub("555"), secret="the_wrong_secret")
    assert ca.activate_lemonsqueezy(body, sig)["ok"] is False


def test_sha256_prefix_tolerated(tmp_path, env_vars):
    ca = _load_activate(tmp_path, {
        "LEMONSQUEEZY_WEBHOOK_SECRET": SECRET,
        "LEMONSQUEEZY_VARIANT_TEAM": "555"})
    body, sig = _signed(_sub("555"))
    assert ca.activate_lemonsqueezy(body, "sha256=" + sig)["ok"] is True


# ---- variant mapping --------------------------------------------------------

def test_solo_and_business_variants(tmp_path, env_vars):
    ca = _load_activate(tmp_path, {
        "LEMONSQUEEZY_WEBHOOK_SECRET": SECRET,
        "LEMONSQUEEZY_VARIANT_SOLO": "111",
        "LEMONSQUEEZY_VARIANT_BUSINESS": "999"})
    b1, s1 = _signed(_sub("111", rid="s_solo"))
    b2, s2 = _signed(_sub("999", rid="s_biz"))
    assert ca.activate_lemonsqueezy(b1, s1)["tier"] == "solo"
    assert ca.activate_lemonsqueezy(b2, s2)["tier"] == "business"


def test_unmapped_variant_refused(tmp_path, env_vars):
    ca = _load_activate(tmp_path, {
        "LEMONSQUEEZY_WEBHOOK_SECRET": SECRET,
        "LEMONSQUEEZY_VARIANT_TEAM": "555"})
    body, sig = _signed(_sub("42424242"))
    res = ca.activate_lemonsqueezy(body, sig)
    assert res["ok"] is False and "unmapped" in res["error"]


def test_order_created_event_supported(tmp_path, env_vars):
    ca = _load_activate(tmp_path, {
        "LEMONSQUEEZY_WEBHOOK_SECRET": SECRET,
        "LEMONSQUEEZY_VARIANT_SOLO": "111"})
    payload = {"meta": {"event_name": "order_created"},
               "data": {"id": "ord_1", "attributes": {
                   "user_email": "s@x", "first_order_item": {"variant_id": 111}}}}
    body, sig = _signed(payload)
    assert ca.activate_lemonsqueezy(body, sig)["tier"] == "solo"


def test_ignored_event_not_provisioned(tmp_path, env_vars):
    ca = _load_activate(tmp_path, {
        "LEMONSQUEEZY_WEBHOOK_SECRET": SECRET,
        "LEMONSQUEEZY_VARIANT_TEAM": "555"})
    body, sig = _signed(_sub("555", event="subscription_updated"))
    res = ca.activate_lemonsqueezy(body, sig)
    assert res["ok"] is False and "ignored" in res["error"]


# ---- idempotency ------------------------------------------------------------

def test_activation_is_idempotent(tmp_path, env_vars):
    ca = _load_activate(tmp_path, {
        "LEMONSQUEEZY_WEBHOOK_SECRET": SECRET,
        "LEMONSQUEEZY_VARIANT_TEAM": "555"})
    body, sig = _signed(_sub("555", rid="sub_dup"))
    r1 = ca.activate_lemonsqueezy(body, sig)
    r2 = ca.activate_lemonsqueezy(body, sig)
    assert r1["key"] == r2["key"]        # same key on redelivery
    assert r1["idempotent"] is False and r2["idempotent"] is True


# ---- test-mode safety (LS env unset) ----------------------------------------

def test_test_mode_no_crash_when_env_unset(tmp_path, env_vars):
    for k in ("LEMONSQUEEZY_WEBHOOK_SECRET", "LEMONSQUEEZY_VARIANT_SOLO",
              "LEMONSQUEEZY_VARIANT_TEAM", "LEMONSQUEEZY_VARIANT_BUSINESS"):
        os.environ.pop(k, None)
    ca = _load_activate(tmp_path)           # imports without crashing
    assert ca.ls_variant_tier() == {}
    # verification fails closed with no secret; nothing is issued
    assert ca.verify_ls_signature(b"{}", "abc") is False
    res = ca.activate_lemonsqueezy(b"{}", "abc")
    assert res["ok"] is False


def test_explicit_test_secret_overrides_env(tmp_path, env_vars):
    """A test can pass a secret directly (test-mode) without env."""
    os.environ.pop("LEMONSQUEEZY_WEBHOOK_SECRET", None)
    ca = _load_activate(tmp_path, {"LEMONSQUEEZY_VARIANT_TEAM": "555"})
    body, sig = _signed(_sub("555"), secret="inline_secret")
    res = ca.activate_lemonsqueezy(body, sig, secret="inline_secret")
    assert res["ok"] is True and res["tier"] == "team"
