"""A7: the adversarial bypass-suite is pinned in CI so the published catch-rate
/ false-block map can never silently drift from what the policies actually do.

If a preset regex changes, one of these assertions flips - forcing the gap map
(and any published number) to be updated deliberately, not by accident.
"""

from __future__ import annotations

from gatecat.integrations import bypass_suite as bs


def test_every_case_behaves_as_its_expect_label_says():
    """The corpus is only honest if each case's ``expect`` matches reality.
    'block'/'allow' cases must do exactly that; 'gap' cases must genuinely
    slip through (a gap that started being caught is good news but must be
    RE-LABELLED, not left claiming to be a gap)."""
    wrong = [
        (r.case.text, r.case.expect, "blocked" if r.blocked else "allowed")
        for r in bs.run()
        if not r.is_correct
    ]
    assert not wrong, f"bypass-suite drift - relabel these cases: {wrong}"


def test_known_gaps_are_really_uncaught():
    """Each KNOWN_GAP marked 'gap' must in fact NOT be blocked; each marked
    'false_block' must in fact BE blocked. Otherwise we publish a gap that no
    longer exists (dishonest in the safe direction, but still drift)."""
    by_text = {r.case.text: r for r in bs.run()}
    for case in bs.KNOWN_GAP:
        if case.expect == "gap":
            assert by_text[case.text].blocked is False, (
                f"claimed gap is actually caught now, relabel: {case.text}"
            )
        elif case.expect == "false_block":
            assert by_text[case.text].blocked is True, (
                f"claimed false-block no longer false-blocks, relabel: {case.text}"
            )


def test_clean_benign_corpus_has_no_false_blocks():
    """The vetted benign corpus (the _BENIGN look-alikes) must stay at zero
    false blocks. Disclosed false_block gaps live in KNOWN_GAP, counted
    separately - they are exactly one, and named."""
    clean_benign_false_blocks = [
        r for r in bs.run()
        if not r.case.danger and r.case.expect == "allow" and r.blocked
    ]
    assert not clean_benign_false_blocks, (
        f"a look-alike command is being blocked: "
        f"{[r.case.text for r in clean_benign_false_blocks]}"
    )
    # the ONLY false block in the whole suite is the one we disclose
    disclosed = [c for c in bs.KNOWN_GAP if c.expect == "false_block"]
    m = bs.metrics(bs.run())
    assert m["false_blocks"] == len(disclosed) == 1


def test_catch_rate_is_total_over_claimed_dangers():
    """We only claim to catch the non-gap dangers; over THAT set catch-rate
    must be 100% (anything we can't catch belongs in KNOWN_GAP, disclosed)."""
    m = bs.metrics(bs.run())
    assert m["caught"] == m["claimed_dangers"]
    assert m["catch_rate"] == 1.0
    # gaps are disclosed, not zero-claimed. Coverage expansions closed former
    # gaps (2026-07-05: base64|sh, curl|sh, runtime rmtree; 0.4.10: the
    # terraform-destroy agent pipe-yes bypass) - the remaining gaps stay
    # published. This count shrinks honestly as coverage grows; the floor is >=1
    # so at least one real limit is always disclosed (never a zero-gap claim).
    assert m["known_gaps"] >= 1


def test_silent_gap_count_is_pinned_to_the_published_number():
    """The 'silent limits' we publish on veto-catches.html / the honest-limits
    doc = gaps that slip the WHOLE product, not just this regex wall. That count
    is pinned here so the page and the mechanized suite can never drift apart
    (fatal flaw #2, launch council V3: the proof must be bulletproof).

    Exactly TWO product-silent gaps are published: the homoglyph 'rm' and the
    printf-hex 'rm'. The runtime-assembled $'\\x72m' is a regex-WALL gap only -
    the delete-analyzer still catches it downstream - so it is NOT silent."""
    m = bs.metrics(bs.run())
    silent = [c for c in bs.KNOWN_GAP if c.expect == "gap" and c.product_silent]
    assert m["product_silent_gaps"] == len(silent) == 2, (
        "silent-gap count drifted from the published '2 silent limits' - "
        "update veto-catches.html/honest-limits doc IN THE SAME CHANGE"
    )
    # a product-silent gap must genuinely be a wall gap too (blocked is False)
    by_text = {r.case.text: r for r in bs.run()}
    for c in silent:
        assert by_text[c.text].blocked is False, f"silent gap now blocked, relabel: {c.text}"
    # the runtime-assembled gap stays WALL-ONLY (not published as silent)
    runtime_gap = [c for c in bs.KNOWN_GAP
                   if c.expect == "gap" and "runtime" in c.note and not c.product_silent]
    assert len(runtime_gap) == 1, "the $'\\x72m' regex-wall-only gap must stay non-silent"


def test_report_reconciles_wall_and_silent_gaps_and_is_ascii():
    """The published report must (a) survive cp1252 even though a gap carries a
    non-ASCII homoglyph, and (b) show the wall-vs-silent split so a reader who
    runs the suite AND reads the page sees the same reconciliation."""
    report = bs.format_report()
    report.encode("ascii")  # D1: homoglyph must be backslash-escaped, not raw
    assert "[SILENT]" in report and "[WALL-ONLY]" in report
    assert "\\uff52m" in report  # the homoglyph rendered as its codepoint, not raw bytes


def test_report_is_ascii_and_lists_gaps():
    """The published artifact must be cp1252-safe (D1) and actually contain the
    gap map + honest line - it's the map we point HN at, not marketing."""
    report = bs.format_report()
    report.encode("ascii")  # D1: survives Windows consoles / CI logs
    assert "KNOWN GAPS" in report
    assert "runtime" in report or "-destroy" in report  # a named remaining gap is disclosed
    assert "KNOWN FALSE-BLOCKS" in report  # false positives disclosed too
    assert "BLOCKS" in report and "NOT verified safe" in report  # honest line
