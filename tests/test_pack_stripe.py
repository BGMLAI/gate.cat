"""Stripe policy-pack fulfillment remains paid-only and price-mapped."""
import importlib.util
import os


def _load(monkeypatch):
    monkeypatch.setenv("STRIPE_KEY", "sk_test_local")
    path = os.path.join(os.path.dirname(__file__), "..", "products", "cloud",
                        "gatecat_fulfill.py")
    spec = importlib.util.spec_from_file_location("gatecat_fulfill_t",
                                                   os.path.abspath(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module._CACHE.clear()
    return module


def test_current_eur_prices_are_mapped(monkeypatch):
    fulfill = _load(monkeypatch)
    assert fulfill.PRICE_TO_FILE["price_1Tssxy2Va7XV3fWYzW4jFalP"].endswith("fintech-1.0.0.zip")
    assert fulfill.PRICE_TO_FILE["price_1Tssxy2Va7XV3fWYx2gu2ZcK"].endswith("paas-1.0.0.zip")
    assert fulfill.PRICE_TO_FILE["price_1Tssxy2Va7XV3fWYeh6jYFQh"].endswith("http-breadth-1.0.0.zip")


def test_unpaid_and_unmapped_sessions_fail_closed(monkeypatch):
    fulfill = _load(monkeypatch)
    fulfill._stripe_get = lambda path: ({"payment_status": "unpaid"}
                                        if "/line_items" not in path else {"data": []})
    assert fulfill.verify_session("cs_unpaid") is None

    fulfill._stripe_get = lambda path: ({"payment_status": "paid"}
                                        if "/line_items" not in path else
                                        {"data": [{"price": {"id": "price_unknown"}}]})
    assert fulfill.verify_session("cs_unmapped") is None


def test_paid_current_price_is_cached(monkeypatch):
    fulfill = _load(monkeypatch)
    calls = []

    def stripe_get(path):
        calls.append(path)
        if "/line_items" in path:
            return {"data": [{"price": {"id": "price_1Tssxy2Va7XV3fWYzW4jFalP"}}]}
        return {"payment_status": "paid"}

    fulfill._stripe_get = stripe_get
    expected = "gatecat-pack-fintech-1.0.0.zip"
    assert fulfill.verify_session("cs_paid") == expected
    assert fulfill.verify_session("cs_paid") == expected
    assert len(calls) == 2


def test_xsell_excludes_purchased_pack(monkeypatch):
    m = _load(monkeypatch)
    html = m.xsell_html("gatecat-pack-fintech-1.0.0.zip")
    assert "Fintech" not in html                       # bought -> excluded
    assert "PaaS" in html and "HTTP-API Breadth" in html
    # preview page before checkout, never a blind buy.stripe.com link
    assert html.count("packs.html?source=pack-xsell") == 2
    assert "buy.stripe.com" not in html
    assert "teams.html?source=pack-xsell" in html      # Cloud Solo line
    assert "&euro;29" in html and "&euro;19" in html


def test_xsell_renders_into_page(monkeypatch):
    m = _load(monkeypatch)
    body = m.PAGE.format(sid="cs_x", fname="gatecat-pack-paas-1.0.0.zip",
                         mod="paas",
                         xsell=m.xsell_html("gatecat-pack-paas-1.0.0.zip"))
    assert "Complete your coverage" in body
    assert "PaaS" not in body.split("Complete your coverage")[1].split("</ul>")[0].replace(
        "render/supabase", "")  # purchased PaaS pack not offered again
