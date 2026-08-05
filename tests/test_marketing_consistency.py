"""Public install and pricing surfaces must not drift from the live offer."""

from pathlib import Path

import tomllib


ROOT = Path(__file__).resolve().parents[1]


def test_llms_txt_tracks_current_package_and_offer():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    llms = (ROOT / "docs" / "llms.txt").read_text()

    assert f"version {project['project']['version']}" in llms
    assert "71 default policies" in llms
    assert "Team €299/month" in llms
    assert "Business €399/month" in llms
    assert "Compliance from €900/month" in llms
    assert "Solo €19/month" in llms


def test_readme_exposes_a_direct_paid_path():
    readme = (ROOT / "README.md").read_text()

    assert "Business (€399/mo)" in readme
    assert "Start Solo (€19/mo)" in readme
    assert "https://buy.stripe.com/7sYdR2e3PcTm2T6cvY67S0b" in readme
    assert "https://buy.stripe.com/7sY6oAaRD5qU79m2Vo67S09" in readme
    assert "https://buy.stripe.com/dRm5kw6Bn3iMfFS1Rk67S0c" in readme
    assert "https://buy.stripe.com/3cI5kw3pbaLeeBO2Vo67S0d" in readme
    assert "https://buy.stripe.com/aFa8wIgbX06AdxK67A67S0e" in readme


def test_claude_design_landing_uses_the_live_stripe_offer():
    landing = (ROOT / "docs" / "index.html").read_text()

    assert "your agent runs shell commands" in landing
    # Business is the primary paid CTA: the price a team on client infra can
    # sign off, and the only high tier whose Stripe link already exists.
    assert "https://buy.stripe.com/7sYdR2e3PcTm2T6cvY67S0b" in landing
    assert "start business · €399/mo" in landing
    assert landing.count("https://buy.stripe.com/") == 5
    assert "lemonsqueezy.com" not in landing
    assert "pip install" not in landing.lower()
    assert "install safely →" in landing
    assert "curl -fsSL https://gate.cat/install.sh" in landing
    assert "sh /tmp/gatecat-install.sh" in landing


def test_landing_tracks_cookieless_funnel_events():
    landing = (ROOT / "docs" / "index.html").read_text()

    for event in (
        "page_view",
        "install_copy",
        "checkout_click",
        "github_click",
        "pypi_click",
    ):
        assert f'track("{event}"' in landing

    assert "navigator.sendBeacon" in landing
    assert 'cache: "no-store"' in landing
    assert "(new Image()).src = url" in landing
    assert "utm_source" in landing
    assert "utm_medium" in landing
    assert "utm_campaign" in landing
    # Funnel analytics stay cookieless (sendBeacon/Image, no cookie). The
    # affiliate ref-capture legitimately sets ONE first-party attribution
    # cookie (gc_ref), added after this guard — so the guarantee is "the only
    # cookie is gc_ref", not "no cookie at all". Any new/extra cookie (e.g. an
    # analytics tracker regressing to cookies) trips this.
    assert '"gc_ref"' in landing
    assert landing.count("document.cookie") == 2  # readCookie + writeCookie for gc_ref only


def test_no_public_surface_advertises_a_price_pricing_md_does_not_carry():
    """Every price shown to a buyer must exist in PRICING.md.

    The 2026-07-29 incident was a number leaving the building ahead of its
    source of truth. Prices are the same failure mode with an invoice attached:
    a landing page that says €299 while Stripe charges €149 is a chargeback and
    a refund, not a typo. PRICING.md is the register; the surfaces mirror it.
    """
    pricing = (ROOT / "PRICING.md").read_text()
    surfaces = {
        "landing": (ROOT / "docs" / "index.html").read_text(),
        "llms.txt": (ROOT / "docs" / "llms.txt").read_text(),
        "README": (ROOT / "README.md").read_text(),
    }
    # Retired ladder — these must not survive anywhere a buyer can read them.
    for retired in ("€149", "up to 10 machines", "founding price"):
        assert retired not in pricing, f"PRICING.md still carries {retired!r}"
        for name, text in surfaces.items():
            assert retired not in text, f"{name} still advertises {retired!r}"

    for live in ("€299", "€399", "€900", "€19"):
        assert live in pricing, f"PRICING.md lost the {live} tier"


def test_unresolved_stripe_placeholders_never_reach_a_buyer():
    """Tiers whose Stripe object does not exist yet must not render a CTA.

    Team €299 and the maintained packs are marked with a placeholder in
    PRICING.md until the Stripe products exist. The placeholder is allowed to
    sit in PRICING.md — that is the to-do list — but a placeholder on the
    landing page is a dead buy button.
    """
    for surface in ("docs/index.html", "docs/llms.txt", "README.md"):
        text = (ROOT / surface).read_text()
        assert "⟦STRIPE:" not in text, f"{surface} carries an unresolved Stripe placeholder"


def test_published_retention_matches_what_the_server_enforces():
    """Retention is a contract term, so the copy tracks `TIERS`, not a memory.

    PRICING.md and THREAT_MODEL_CLOUD.md both said a flat "12 months" from
    launch until 2026-07-31. The server has always enforced 30/90/365/1095 by
    tier — so a Solo subscriber was promised nine months they would not get.
    FACTS.md F14 pins the real figures; this test stops the flat claim coming
    back.
    """
    import re

    server = (ROOT / "products" / "cloud" / "cloud_server.py").read_text()
    enforced = dict(
        re.findall(r'"(free|solo|team|business)":\s*\{\s*"retention_days":\s*(\d+)', server)
    )
    assert enforced == {"free": "30", "solo": "90", "team": "365", "business": "1095"}, (
        f"TIERS changed to {enforced} — update FACTS.md F14 and PRICING.md together"
    )

    for surface in ("PRICING.md", "THREAT_MODEL_CLOUD.md"):
        text = (ROOT / surface).read_text()
        assert "Retention: 12 months" not in text, (
            f"{surface} reintroduced the flat 12-month retention claim (FACTS.md F14)"
        )


def test_no_surface_sells_email_alerts_while_no_mailer_exists():
    """Do not sell a delivery channel the product does not have.

    FACTS.md F15: the server exposes an alert *feed* at `GET /v1/alerts`; there
    is no mail-sending integration anywhere in the product. If someone wires a
    real mailer, this test fails and tells them to re-pin F15 and put the word
    back on purpose — which is the correct order of operations.
    """
    product_code = "\n".join(
        p.read_text()
        for p in list((ROOT / "products").rglob("*.py")) + list((ROOT / "gatecat").rglob("*.py"))
        if "policies.py" not in p.name  # deny-list patterns mention mail APIs by design
    )
    mailer_present = any(
        token in product_code
        for token in ("import smtplib", "sendgrid", "resend.", "postmark", "mailgun")
    )
    assert not mailer_present, "a mailer landed — re-pin FACTS.md F15 before selling email alerts"

    for surface in ("PRICING.md", "docs/index.html", "docs/llms.txt", "README.md",
                    "docs/SAMPLE_REPORT.md"):
        text = (ROOT / surface).read_text()
        # A *quoted* "email alerts" is the retired phrase being documented —
        # that is how FACTS.md records a withdrawn claim, and it must stay
        # legal. An unquoted one is a sale.
        offending = [
            line for line in text.splitlines()
            if "email alert" in line.lower()
            and '"email alert' not in line.lower()
            and "not shipping" not in line.lower()
            and "roadmap" not in line.lower()
        ]
        assert not offending, f"{surface} sells email alerts: {offending[:1]}"


def test_site_pages_make_no_third_party_requests():
    """No page we serve may hand a visitor's IP to anyone we have not declared.

    We sell "no third-party analytics, one first-party cookie". A Google Fonts
    stylesheet undoes that quietly: the browser connects, and the IP plus
    User-Agent arrive at Google before the page has rendered. `coverage.html`
    did exactly this and `index.html` kept `preconnect` hints to Google while
    loading no font from it — the handshake happened for nothing. Both removed
    2026-07-31; docs/legal/SUBPROCESSORS.md carries the dated entry.

    Only tags that make the browser fetch something are checked. Prose and
    example commands legitimately mention third-party hostnames — the whole
    product is a wall in front of destructive calls to them.
    """
    import re

    allowed = (
        "gate.cat", "github.com", "githubusercontent.com", "pypi.org",
        "buy.stripe.com", "js.stripe.com", "w3.org", "schema.org",
    )
    fetching = re.compile(
        r'<(?:link|script|img|iframe|source|video|audio)\b[^>]*?'
        r'(?:href|src)\s*=\s*\\?["\']https?://([a-z0-9.-]+)',
        re.IGNORECASE,
    )
    for page in ("index.html", "coverage.html", "teams.html", "partners.html"):
        path = ROOT / "docs" / page
        if not path.exists():
            continue
        for host in fetching.findall(path.read_text()):
            assert any(host == a or host.endswith("." + a) for a in allowed), (
                f"docs/{page} fetches from {host} — declare it in "
                f"docs/legal/SUBPROCESSORS.md or drop it"
            )


def test_landing_html_cannot_keep_stale_install_copy():
    nginx_site = (ROOT / "ops" / "nginx" / "gatecat.site.conf").read_text()

    assert 'add_header Cache-Control "no-cache, no-store, must-revalidate" always;' in nginx_site
