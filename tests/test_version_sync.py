"""The runtime version string must track pyproject — regression for the
0.4.18 wheel, which shipped with distribution metadata 0.4.18 but
``gatecat.__version__ == "0.4.17"`` (caught 2026-07-23 during the F9 re-pin;
cosmetic, but it makes support and bug reports lie about the installed
version). A bare literal comparison keeps this deterministic in dev checkouts
where importlib.metadata may see no installed distribution.
"""
import json
from pathlib import Path

import tomllib

import gatecat

ROOT = Path(__file__).resolve().parents[1]


def _pyproject_version() -> str:
    return tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]


def test_runtime_version_matches_pyproject():
    assert gatecat.__version__ == _pyproject_version()


def test_plugin_manifests_match_pyproject():
    """The Claude Code plugin manifests advertise a version too — a stale one
    makes `/plugin install gatecat@gatecat` claim a different release than
    `pip install` delivers."""
    version = _pyproject_version()

    plugin = json.loads(
        (ROOT / "plugins" / "gatecat" / ".claude-plugin" / "plugin.json").read_text())
    assert plugin["version"] == version

    marketplace = json.loads(
        (ROOT / ".claude-plugin" / "marketplace.json").read_text())
    listed = [p["version"] for p in marketplace["plugins"]]
    assert listed == [version]


def test_pack_hint_urls_anchor_to_real_packs_page_ids():
    """Every once-per-machine pack hint deep-links packs.html#<anchor> — the
    only EUR 29 conversion link a machine ever prints. A renamed id on the
    page would silently land every hint on the top of the page instead."""
    from gatecat._pack_hint import _PACKS

    packs_html = (ROOT / "docs" / "packs.html").read_text()
    for _name, _clis, _scope, url in _PACKS:
        anchor = url.split("#", 1)[1]
        assert f'id="{anchor}"' in packs_html, url
