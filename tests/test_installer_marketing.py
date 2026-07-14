from pathlib import Path


ROOT = Path(__file__).parents[1]
TRACKED_PRICING_URL = (
    "https://gate.cat/?utm_source=installer&utm_medium=cli&"
    "utm_campaign=launch_20260714#pricing"
)


def test_public_installer_matches_repository_installer():
    assert (ROOT / "install.sh").read_bytes() == (ROOT / "docs" / "install.sh").read_bytes()


def test_paid_offer_is_optional_tracked_and_only_printed_after_success():
    installer = (ROOT / "install.sh").read_text()

    assert installer.count(TRACKED_PRICING_URL) == 1
    assert "The local gate stays free and works without an account." in installer
    assert "Optional signed policy sync and stack-specific packs:" in installer

    success_check = installer.index('print("gate.cat installed:"')
    success_summary = installer.index("Installed gate.cat into")
    paid_offer = installer.index(TRACKED_PRICING_URL)
    assert success_check < success_summary < paid_offer
