"""Public install and pricing surfaces must not drift from the live offer."""

from pathlib import Path

import tomllib


ROOT = Path(__file__).resolve().parents[1]


def _hook_json_block(text: str) -> str:
    """The PreToolUse hook JSON, normalized (whitespace-insensitive) so the
    README and llms.txt copies are compared by content, not formatting."""
    import json
    marker = '"PreToolUse"'
    i = text.index(marker)
    a = text.rindex("{", 0, i)
    depth = 0
    for j in range(a, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return json.dumps(json.loads(text[a:j + 1]), sort_keys=True)
    raise AssertionError("unbalanced hook JSON")


def test_hook_json_identical_in_readme_and_llms_txt():
    """The copy-paste hook config is the single most-copied artifact; a drift
    between the README (PyPI long_description) and llms.txt (answer-engine
    channel) would hand users two different configs. Compare by parsed content
    (replaces a manual grep — the config can never silently diverge)."""
    readme = _hook_json_block((ROOT / "README.md").read_text())
    llms = _hook_json_block((ROOT / "docs" / "llms.txt").read_text())
    assert readme == llms
    # and it is the exact PreToolUse block the setup CLI writes (the extractor
    # anchors on "PreToolUse", so compare that inner object)
    from gatecat._setup_cli import HOOK_ENTRY
    import json
    expected = json.dumps({"PreToolUse": [HOOK_ENTRY]}, sort_keys=True)
    assert readme == expected


def test_plugin_hooks_json_matches_setup_cli_entry():
    """The Claude Code plugin ships plugins/gatecat/hooks/hooks.json; it must
    register the SAME PreToolUse entry the setup CLI writes and the README/
    llms.txt document — otherwise `/plugin install` arms a different hook than
    `gate.cat setup claude-code`. Closes the hook-JSON guard family."""
    import json
    from gatecat._setup_cli import HOOK_ENTRY

    hooks = json.loads(
        (ROOT / "plugins" / "gatecat" / "hooks" / "hooks.json").read_text())
    assert hooks == {"hooks": {"PreToolUse": [HOOK_ENTRY]}}


def test_recall_md_split_matches_the_reproducible_script():
    """RECALL.md's block/warn split must equal what scripts/recall_danger_axis.py
    actually prints — a skeptic running the exact command FACTS F1a invites must
    see the same numbers as the method page. Guards the 31/12 pin without
    re-running the (slow, import-heavy) corpus here: the doc and scripts/README
    must agree, and scripts/README must cite the script."""
    recall = (ROOT / "RECALL.md").read_text()
    assert "31 `block`, 12 `warn`, **0 allowed**" in recall
    assert "30 `block`, 13 `warn`" not in recall

    scripts_readme = (ROOT / "scripts" / "README.md").read_text()
    assert "recall_danger_axis.py" in scripts_readme
    assert "31 `block`, 12 `warn`" in scripts_readme
    # the stale hard-coded test count is gone
    assert "892 green in CI as of v0.4.1" not in scripts_readme


def test_readme_comparison_is_veto_axis_not_cache():
    """The Comparison section is the last thing an evaluator reads before
    License — it must position the veto (linking COMPARISON.md), not lead with
    the old semantic-cache table."""
    readme = (ROOT / "README.md").read_text()
    comparison = readme.split("## Comparison", 1)[1].split("## License", 1)[0]
    assert "COMPARISON.md" in comparison
    assert "irreversible-action" in comparison
    assert "GPTCache" not in comparison           # cache table moved under Cache
    # the cache table still exists, just not as THE comparison
    assert "GPTCache" in readme


def test_llms_txt_tracks_current_package_and_offer():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    llms = (ROOT / "docs" / "llms.txt").read_text()

    assert f"version {project['project']['version']}" in llms
    assert "71 default policies" in llms
    assert "Solo €19/month" in llms
    assert "Team €149/month" in llms
    assert "€29 each, one-time" in llms


def test_readme_has_no_relative_markdown_links():
    """README is the PyPI long_description; PyPI does not rewrite relative
    paths, so every relative link (evidence docs, examples, LICENSE badge) is
    a 404 on the biggest discovery surface. Every link target must be absolute
    (http/https), an in-page anchor, or a mailto. Catches BOTH plain links and
    image/badge links like `[![x](img)](LICENSE)`."""
    import re

    readme = (ROOT / "README.md").read_text()
    # any ](target) whose target is not absolute/anchor/mailto is relative
    bad = []
    for m in re.finditer(r"\]\(([^)]+)\)", readme):
        tgt = m.group(1).strip()
        if tgt.startswith(("http://", "https://", "#", "mailto:")):
            continue
        bad.append(tgt)
    assert bad == [], f"relative link targets 404 on PyPI: {bad}"
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


def test_teams_page_links_the_data_boundary_evidence():
    """The €149/€399 decision page must let a team lead verify the data
    boundary in one click — threat model, telemetry field list, and the real
    sample report — as absolute GitHub blob URLs (the .md docs SPA-fallback or
    serve as octet-stream on the production site)."""
    teams = (ROOT / "docs" / "teams.html").read_text()

    for doc in ("docs/THREAT_MODEL.md", "TELEMETRY.md", "docs/SAMPLE_REPORT.md"):
        assert f"https://github.com/BGMLAI/gate.cat/blob/master/{doc}" in teams, doc
    # vendor-continuity line, no new numbers
    assert "if Cloud is down" in teams
    # footer reaches the orphaned live surfaces
    assert 'href="/coverage.html"' in teams
    assert 'href="/answers/"' in teams


def test_docs_markdown_evidence_links_resolve_from_their_location():
    """Relative links inside docs/*.md resolve from docs/, not the repo root.
    A bare [FACTS.md](FACTS.md) in docs/ 404s on GitHub blob; it must be
    ../FACTS.md. Guards the two pointers a buyer follows from the sample
    report and threat model."""
    sample = (ROOT / "docs" / "SAMPLE_REPORT.md").read_text()
    assert "[FACTS.md](../FACTS.md)" in sample
    assert "[FACTS.md](FACTS.md)" not in sample

    threat = (ROOT / "docs" / "THREAT_MODEL.md").read_text()
    # the "readable Python" verify pointer must carry a real URL now
    assert "readable Python](../products/cloud/cloud_server.py)" in threat
    assert "readable Python])" not in threat
    assert (ROOT / "products" / "cloud" / "cloud_server.py").exists()


def test_self_verify_block_on_every_purchase_surface():
    """The reproduce-it block must appear where the buy decision happens, and
    its headline numbers must never travel without their published caveats
    (FACTS.md F4: named gap + benign false-block; F1b: adjudicated allows)."""
    for surface in ("README.md", "docs/teams.html", "docs/packs.html",
                    "docs/partners.html"):
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
    # no Lemon Squeezy CHECKOUT LINKS may return to the page; the affiliate
    # script's a[href*=...] selector (appended last) is not a link.
    assert "lemonsqueezy.com" not in landing.split('id="gc-affiliate-ref"')[0]
    assert 'href="https://lemonsqueezy.com' not in landing
    assert 'href="https://checkout.lemonsqueezy.com' not in landing
    assert "start solo · €9" in landing
    assert "founding price — locked for life, then €19" in landing
    assert "pip install" not in landing.lower()
    assert "install safely →" in landing
    assert "curl -fsSL https://gate.cat/install.sh" in landing
    assert "sh /tmp/gatecat-install.sh" in landing


def test_landing_has_static_social_meta():
    """The root domain is the most-shared URL (PyPI, GitHub About, every live
    channel). Social-preview and answer-engine bots (GPTBot/ClaudeBot/
    PerplexityBot, invited in robots.txt) do NOT run the bundler JS, so the
    og/twitter/canonical tags must be in the STATIC <head> — before the
    bundler manifest — or every share renders a blank card. index.html was the
    only production page missing them."""
    landing = (ROOT / "docs" / "index.html").read_text()

    head = landing.split("__bundler", 1)[0]   # everything before the bundle
    for tag in ('rel="canonical"', 'property="og:image"',
                'property="og:title"', 'name="twitter:card"',
                'property="og:url"'):
        assert tag in head, f"{tag} missing from the static head"
    # summary_large_image + the shared poster asset (same as teams/partners)
    assert "summary_large_image" in head
    assert "https://gate.cat/veto-demo-poster.png" in head
    # the noscript fallback now carries real value + discovery links, not just
    # "requires JavaScript"
    noscript = landing.split("<noscript>", 1)[1].split("</noscript>", 1)[0]
    assert "github.com/BGMLAI/gate.cat" in noscript
    assert "pypi.org/project/gate.cat" in noscript
    # and it does NOT reintroduce the banned bare pip-install install story
    assert "pip install" not in noscript.lower()


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
    # ANALYTICS stays cookieless: no document.cookie anywhere before the
    # gc-affiliate-ref block (appended last). The affiliate script's gc_ref
    # cookie is functional attribution, not analytics — it may not leak
    # earlier into the page.
    before_affiliate = landing.split('id="gc-affiliate-ref"')[0]
    assert "document.cookie" not in before_affiliate


def test_landing_html_cannot_keep_stale_install_copy():
    nginx_site = (ROOT / "ops" / "nginx" / "gatecat.site.conf").read_text()

    assert 'add_header Cache-Control "no-cache, no-store, must-revalidate" always;' in nginx_site
