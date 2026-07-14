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
    assert "pip install gate.cat" not in landing
    assert "curl -fsSL https://gate.cat/install.sh" in landing
    assert "sh /tmp/gatecat-install.sh" in landing
