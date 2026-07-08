"""Dowodowy test progu jakosci snippetu web (branches.py).

CEL (decyzja usera 'dodaj DOWOD'): udowodnic ze prog jakosci snippetu FAKTYCZNIE
odcina web-szum. Research Badanie C: web-trafny snippet naprawia ~76%, web-szum
ponizej progu psuje base-correct 2-3x mocniej niz zly cache -> szum MUSI byc
NIE-wstrzykiwany. Te testy sa formalnym dowodem ze koryto progu (WEB_SNIPPET_MIN
dla retrieval_score, WEB_OVERLAP_MIN dla token-overlap) trzyma rzeke szumu w ryzach.

Spojny z reszta tests/: sync, mock search_fn (zero sieci), ASCII-only, realny
import z gatecat.branches. asyncio_mode=auto w pyproject (tu nie potrzebne).
"""
from gatecat.branches import (
    best_web_snippet_score,
    WebBranch,
    WEB_SNIPPET_MIN,
    WEB_OVERLAP_MIN,
)


# ----------------------------------------------------------------------
# Kontrakt stalych (Badanie C: 0.55 retrieval_score / 0.25 token-overlap).
# Jesli ktos podmieni prog, ten test pada PRZED reszta = jawny sygnal.
# ----------------------------------------------------------------------

def test_threshold_constants_match_research():
    assert WEB_SNIPPET_MIN == 0.55
    assert WEB_OVERLAP_MIN == 0.25


# ----------------------------------------------------------------------
# 1. Trafny snippet (gold obecny, wysoki overlap) -> score >= prog -> wstrzykuje.
# ----------------------------------------------------------------------

def test_relevant_snippet_passes_threshold():
    query = "who wrote Hamlet"
    # Snippet zawiera wszystkie istotne tokeny pytania + gold answer.
    results = [{
        "title": "Hamlet",
        "snippet": "Hamlet was written by William Shakespeare around 1600",
    }]

    score, used_rs = best_web_snippet_score(results, query)
    assert used_rs is False                 # brak retrieval_score -> token-overlap
    assert score >= WEB_OVERLAP_MIN         # przechodzi prog overlap

    res = WebBranch(search_fn=lambda q: results).fetch(query)
    assert res.used is True                 # DOWOD: trafny -> wstrzykniety
    assert res.score == score
    assert "Shakespeare" in res.context     # gold trafil do kontekstu


# ----------------------------------------------------------------------
# 2. Snippet-szum (zero overlap, off-topic) -> score < prog -> NIE wstrzykuje.
#    To jest dowod ze trucizna (W_noise) jest odcinana.
# ----------------------------------------------------------------------

def test_noise_snippet_below_threshold_rejected():
    query = "who wrote Hamlet"
    noise = [{
        "title": "Tomato pasta",
        "snippet": "best fresh basil marinara recipe simmered slowly",
    }]

    score, used_rs = best_web_snippet_score(noise, query)
    assert used_rs is False
    assert score == 0.0                     # zero wspolnych tokenow
    assert score < WEB_OVERLAP_MIN

    res = WebBranch(search_fn=lambda q: noise).fetch(query)
    assert res.used is False                # DOWOD: szum odciety, brak wstrzykniecia
    assert res.context == ""                # nic nie wycieka do promptu


# ----------------------------------------------------------------------
# 3. Off-by-one guard: tuz-pod progiem odrzucony, NA progu i tuz-nad przyjety.
#    Semantyka: WebBranch.fetch odrzuca przy `score < thr`, wiec score==thr PRZECHODZI.
#    Uzywamy jawnego threshold + retrieval_score (kontrolowany, deterministyczny score).
# ----------------------------------------------------------------------

def test_threshold_boundary():
    thr = 0.55

    def branch(rs_value):
        results = [{"title": "x", "snippet": "y", "retrieval_score": rs_value}]
        return WebBranch(search_fn=lambda q: results, threshold=thr).fetch("q")

    just_below = branch(0.5499)
    at_boundary = branch(0.55)
    just_above = branch(0.5501)

    assert just_below.used is False         # < prog -> odciety
    assert at_boundary.used is True         # == prog -> przyjety (dowod: `<`, NIE `<=`)
    assert just_above.used is True          # > prog -> przyjety


# ----------------------------------------------------------------------
# 4. Dwie sciezki scoringu: retrieval_score (prog 0.55) vs token-overlap (0.25).
#    Ten sam liczbowy score (0.30) ma ODWROTNY werdykt zaleznie od sciezki:
#    - jako retrieval_score 0.30 < 0.55 -> odciety
#    - jako overlap 0.30 (lub 0.25) >= 0.25 -> przyjety
#    Dowod ze prog jest dobierany per-sciezka, nie globalnie.
# ----------------------------------------------------------------------

def test_retrieval_score_path():
    # --- sciezka A: dostawca daje retrieval_score -> prog 0.55 ---
    rs_high = [{"title": "h", "snippet": "ctx", "retrieval_score": 0.80}]
    rs_low = [{"title": "h", "snippet": "ctx", "retrieval_score": 0.30}]

    score_hi, used_hi = best_web_snippet_score(rs_high, "q")
    score_lo, used_lo = best_web_snippet_score(rs_low, "q")
    assert used_hi is True and used_lo is True          # sciezka retrieval_score
    assert score_hi == 0.80 and score_lo == 0.30

    assert WebBranch(search_fn=lambda q: rs_high).fetch("q").used is True   # 0.80 >= 0.55
    assert WebBranch(search_fn=lambda q: rs_low).fetch("q").used is False   # 0.30 <  0.55

    # --- sciezka B: brak retrieval_score -> token-overlap, prog 0.25 ---
    # Query ma dokladnie 4 istotne tokeny (>=3 znaki); snippet pokrywa 1 -> overlap 0.25.
    query = "alpha bravo charlie delta"
    overlap_hit = [{"title": "", "snippet": "alpha is unrelated filler"}]
    score_ov, used_ov = best_web_snippet_score(overlap_hit, query)
    assert used_ov is False                              # sciezka token-overlap
    assert score_ov == 0.25                              # 1 z 4 tokenow

    # 0.25 == prog 0.25 -> przechodzi (== nie jest < ), wiec wstrzykuje.
    assert WebBranch(search_fn=lambda q: overlap_hit).fetch(query).used is True

    # ta sama liczba 0.30 jako retrieval_score bylaby odcieta (0.30<0.55),
    # ale jako overlap byla powyzej 0.25 -> DOWOD ze prog zalezy od sciezki.
    assert score_lo == 0.30 and 0.30 < WEB_SNIPPET_MIN and 0.30 > WEB_OVERLAP_MIN


# ----------------------------------------------------------------------
# 5. Pusta lista wynikow -> score 0.0, brak wstrzykniecia, brak crasha.
#    Fail-safe: brak danych nigdy nie wstrzykuje (zero trucizny przy braku web).
# ----------------------------------------------------------------------

def test_empty_results_safe():
    # pusta lista
    score, used_rs = best_web_snippet_score([], "anything")
    assert score == 0.0
    assert used_rs is False

    res = WebBranch(search_fn=lambda q: []).fetch("anything")
    assert res.used is False
    assert res.score == 0.0
    assert res.context == ""
    assert res.results == []

    # None z dostawcy (np. blad sieci zwrocil None) -> tez bez crasha
    score_none, used_none = best_web_snippet_score(None, "anything")
    assert score_none == 0.0
    assert used_none is False

    res_none = WebBranch(search_fn=lambda q: None).fetch("anything")
    assert res_none.used is False
    assert res_none.score == 0.0
    assert res_none.context == ""


# ----------------------------------------------------------------------
# G1 (adversarial review): regresja DEFAULTU progu na sciezce retrieval_score
#    cwiczona BEHAWIORALNIE (bez podawania threshold=). Asercja na stalej jest krucha;
#    ten test lapie zepsucie AUTO-progu przez ZACHOWANIE.
# ----------------------------------------------------------------------

def test_auto_threshold_rejects_low_retrieval_score():
    """rs=0.30 BEZ jawnego threshold -> auto-prog 0.55 -> odciety. Lapie regresje defaultu."""
    low = [{"title": "h", "snippet": "ctx", "retrieval_score": 0.30}]
    assert WebBranch(search_fn=lambda q: low).fetch("q").used is False   # auto-0.55, nie podany
    high = [{"title": "h", "snippet": "ctx", "retrieval_score": 0.60}]
    assert WebBranch(search_fn=lambda q: high).fetch("q").used is True


# ----------------------------------------------------------------------
# G2 (adversarial review): lista MIESZANA (jeden z retrieval_score, drugi bez)
#    UJAWNIA REALNA ASYMETRIE SKAL. used_rs flipuje na True gdy KTORYKOLWIEK element
#    ma retrieval_score -> prog robi sie 0.55. ALE element BEZ rs dostaje overlap-score
#    (skala ~0.25), wiec dobry-overlap-bez-rs (0.33) jest mierzony skala overlap a
#    bramkowany progiem rs (0.55) -> FALSZYWIE odrzucony. To znany bug mieszania skal
#    z Badania C — test pinuje go SWIADOMIE, by regresja/poprawka byla widoczna.
# ----------------------------------------------------------------------

def test_mixed_results_scale_asymmetry_is_pinned():
    query = "who wrote Hamlet"
    mixed = [
        {"title": "x", "snippet": "y", "retrieval_score": 0.10},          # niski rs
        {"title": "Hamlet", "snippet": "Hamlet written by Shakespeare"},  # dobry overlap, BEZ rs
    ]
    score, used_rs = best_web_snippet_score(mixed, query)
    assert used_rs is True              # ktorykolwiek ma retrieval_score -> prog 0.55
    # ZNANE ZACHOWANIE: overlap dobrego snippetu (~0.33 skala overlap) < prog rs 0.55.
    # MAX bierze najwyzszy z {0.10 rs, 0.33 overlap} = 0.33, ale bramka to 0.55 -> odciety.
    assert score < WEB_SNIPPET_MIN      # asymetria: dobry-overlap-bez-rs przegrywa z progiem rs
    used_in_branch = WebBranch(search_fn=lambda q: mixed).fetch(query).used
    assert used_in_branch is False      # skutek asymetrii: mieszana lista odcina trafny overlap


# ----------------------------------------------------------------------
# G3 (adversarial review): score liczy title+snippet+description+url (NIE sam snippet).
#    Pinujemy to ZACHOWANIE swiadomie (nie milczaca dziura): query-slowa w TITLE licza sie.
# ----------------------------------------------------------------------

def test_query_tokens_in_title_count_toward_score():
    query = "alpha bravo charlie delta"
    title_match = [{"title": "alpha bravo charlie delta", "snippet": "unrelated filler"}]
    score, _ = best_web_snippet_score(title_match, query)
    assert score >= WEB_OVERLAP_MIN     # title pokrywa query -> overlap mimo szumu w snippet