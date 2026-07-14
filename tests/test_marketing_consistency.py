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
