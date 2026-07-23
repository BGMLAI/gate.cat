"""Public install and pricing surfaces must not drift from the live offer."""

from pathlib import Path

import tomllib


ROOT = Path(__file__).resolve().parents[1]


def test_llms_txt_tracks_current_package_and_offer():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    llms = (ROOT / "docs" / "llms.txt").read_text()

    assert f"version {project['project']['version']}" in llms
    assert "71 default policies" in llms
    assert "Solo €19/month" in llms
    assert "Team €149/month" in llms
    assert "€29 each, one-time" in llms


def test_readme_exposes_a_direct_paid_path():
    readme = (ROOT / "README.md").read_text()

    assert "Start Solo (€19/mo)" in readme
    assert "https://buy.stripe.com/7sY6oAaRD5qU79m2Vo67S09" in readme
    assert "https://buy.stripe.com/dRm5kw6Bn3iMfFS1Rk67S0c" in readme
    assert "https://buy.stripe.com/3cI5kw3pbaLeeBO2Vo67S0d" in readme
    assert "https://buy.stripe.com/aFa8wIgbX06AdxK67A67S0e" in readme


def test_packs_page_shows_scope_before_checkout():
    packs = (ROOT / "docs" / "packs.html").read_text()

    # the three live Payment Links, tagged with the page source
    assert "https://buy.stripe.com/dRm5kw6Bn3iMfFS1Rk67S0c?source=packs" in packs
    assert "https://buy.stripe.com/3cI5kw3pbaLeeBO2Vo67S0d?source=packs" in packs
    assert "https://buy.stripe.com/aFa8wIgbX06AdxK67A67S0e?source=packs" in packs
    # scope verbatim from PRICING.md (modulo HTML escaping)
    assert "refund creation, payouts/transfers, customer &amp; billing-config deletion" in packs
    assert "PayPal/Braintree/Adyen/Wise/Mercury (5 policies)" in packs
    assert "railway down" in packs and "deploy/list/info stay allowed" in packs
    assert "requires gate.cat ≥ 0.4.9" in packs
    # honest framing + terms
    assert "€29" in packs
    assert "30-day full refund" in packs
    assert "GATECAT_EXTRA_POLICIES" in packs
    assert "fail-closed" in packs
    assert "lemonsqueezy.com/checkout" not in packs.replace(
        'a[href*="lemonsqueezy.com/checkout"]', "")  # affiliate selector only
    # anchors the cross-sells deep-link to
    for anchor in ('id="fintech"', 'id="paas"', 'id="http-api"'):
        assert anchor in packs

    sitemap = (ROOT / "docs" / "sitemap.xml").read_text()
    assert "https://gate.cat/packs.html" in sitemap

    readme = (ROOT / "README.md").read_text()
    assert "gate.cat/packs.html?source=pypi" in readme

    teams = (ROOT / "docs" / "teams.html").read_text()
    assert "packs.html?source=teams" in teams

    pricing = (ROOT / "PRICING.md").read_text()
    assert "gate.cat/packs.html?source=pricing-md" in pricing


def test_teams_page_tracks_cookieless_funnel_events():
    """teams.html is the highest-LTV page; without events the owner cannot
    tell 'nobody clicks' from 'clicks we never see'. Same /events contract
    as packs.html (source param wins, utm_source fallback, teams-direct)."""
    teams = (ROOT / "docs" / "teams.html").read_text()

    assert 'id="gc-funnel-events"' in teams
    for event in ("page_view", "checkout_click", "github_click"):
        assert f'track("{event}"' in teams
    assert '"/events?"' in teams
    assert "teams-direct" in teams
    assert "navigator.sendBeacon" in teams
    assert "document.cookie" not in teams.split('id="gc-funnel-events"')[1]


def test_self_verify_block_on_every_purchase_surface():
    """The reproduce-it block must appear where the buy decision happens, and
    its headline numbers must never travel without their published caveats
    (FACTS.md F4: named gap + benign false-block; F1b: adjudicated allows)."""
    for surface in ("README.md", "docs/teams.html", "docs/packs.html"):
        # normalize hard-wrapped markdown so phrases match across line breaks
        text = " ".join((ROOT / surface).read_text().split())

        assert "python -m gatecat.integrations.bypass_suite" in text, surface
        assert "178/178" in text, surface
        # honesty coupling: the caveats ride along or the number doesn't ship
        assert "runtime-assembly gap" in text, surface
        assert "benign false-block in 129 cases" in text, surface
        assert "1,085,159" in text, surface
        assert "FACTS.md" in text, surface


def test_claude_design_landing_uses_the_live_stripe_offer():
    landing = (ROOT / "docs" / "index.html").read_text()

    assert "your agent runs shell commands" in landing
    assert "https://buy.stripe.com/14AaEQ6BncTmctGbrU67S0f" in landing
    assert landing.count("https://buy.stripe.com/") == 6
    assert "lemonsqueezy.com" not in landing
    assert "start solo · €9" in landing
    assert "founding price — locked for life, then €19" in landing
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
    assert "document.cookie" not in landing


def test_landing_html_cannot_keep_stale_install_copy():
    nginx_site = (ROOT / "ops" / "nginx" / "gatecat.site.conf").read_text()

    assert 'add_header Cache-Control "no-cache, no-store, must-revalidate" always;' in nginx_site
