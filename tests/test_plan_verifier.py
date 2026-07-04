"""plan_verifier — testy + REGRESJA na bypassy z adversarial review (workflow w6nan2dis).

Kazdy test 'bypass_*' odtwarza KONKRETNY bypass zmierzony przez panel adversarialny
i dowodzi, ze v2 go ZAMYKA. To jest produkt eats-own-dogfood: verifier nie moze byc
oszukany przez agenta dostarczajacego trywialny dowod.
"""

from cacheback.plan_verifier import PlanStep, PlanVerifier, PlanReport, _binary_allowed


def _v(**kw):
    return PlanVerifier(**kw)


# ---- SEDNO: deklaracja bez dowodu = unproven ----

def test_no_evidence_is_unproven():
    """Krok bez dowodu (kind=none) ZAWSZE unproven — 'zrobione' bez dowodu = confident-wrong."""
    v = _v().verify_step(PlanStep(id="x", desc="zrobilem", evidence_kind="none"))
    assert v.status == "unproven" and v.caught


# ---- BYPASS 1 (panel: command:["true"]/["echo ok"]) ----

def test_bypass_echo_command_refused():
    """echo/true spoza allow-listy binarek -> unproven+flagged (nie proven HARD)."""
    v = _v().verify_step(PlanStep(id="x", desc="d", evidence_kind="command",
                                  argv=("echo", "ok")))
    assert v.status == "unproven" and v.flagged

def test_bypass_true_command_refused():
    v = _v().verify_step(PlanStep(id="x", desc="d", evidence_kind="command", argv=("true",)))
    assert v.status == "unproven" and v.flagged


# ---- BYPASS 1c (panel: touch 1-bajt bez contains) ----

def test_bypass_file_without_must_contain_refused():
    """file bez must_contain -> unproven (samo 'plik istnieje' to nie dowod etapu)."""
    v = _v().verify_step(PlanStep(id="x", desc="d", evidence_kind="file",
                                  path="pyproject.toml"))  # istnieje, ale bez must_contain
    assert v.status == "unproven"


# ---- BYPASS DOGFOOD (panel 3: repo-root fallback trafial w stary plik) ----

def test_bypass_no_repo_root_fallback():
    """file path liczony TYLKO od PKG_ROOT; brak fallback na repo-root (dziura z review).
    'ARCHITECTURE.md' bez must_contain -> unproven (nie trafia w stary bgml.ai/ARCHITECTURE.md)."""
    v = _v().verify_step(PlanStep(id="x", desc="d", evidence_kind="file",
                                  path="ARCHITECTURE.md"))  # brak must_contain -> i tak unproven
    assert v.status == "unproven"


# ---- BYPASS 5 (panel: url-soft liczony jak hard w progress) ----

def test_url_is_soft_stale_not_proven():
    """url 2xx -> 'stale' (hard=False, needs_recheck), NIGDY proven."""
    v = _v(fetch_fn=lambda u: (200, "Hamulec bezpieczenstwa")).verify_step(
        PlanStep(id="x", desc="d", evidence_kind="url",
                 url="https://example/", must_contain="Hamulec"))
    assert v.status == "stale" and v.hard is False and v.needs_recheck

def test_progress_counts_only_proven_hard():
    """progress_pct liczy TYLKO proven AND hard. url-stale NIE podbija twardego postepu."""
    steps = [
        PlanStep(id="a", desc="d", evidence_kind="file", path="pyproject.toml",
                 must_contain="cacheback"),                         # proven-hard
        PlanStep(id="b", desc="d", evidence_kind="url", url="https://e/",
                 must_contain="x"),                                 # stale (soft)
        PlanStep(id="c", desc="d", evidence_kind="none"),           # unproven
    ]
    rep = _v(fetch_fn=lambda u: (200, "x")).verify_plan(steps)
    assert rep.proven_hard == 1            # tylko file
    assert rep.stale == 1                  # url nie liczy sie do twardego
    assert rep.unproven == 1
    assert rep.progress_pct == round(100 * 1 / 3, 1)   # 33.3, NIE 66.7


# ---- BYPASS 1d (panel: benchmark drukuje metryke = tautologia) ----

def test_benchmark_is_soft_not_hard():
    """benchmark (metryka z agent-skryptu) NIE jest proven-hard -> stale. Nie podbija postepu."""
    # python jest na allow-liscie; skrypt drukuje metryke
    v = _v().verify_step(PlanStep(
        id="x", desc="d", evidence_kind="benchmark",
        argv=("python", "-c", "print('{\"acc\": 0.99}')"),
        metric_key="acc", threshold=0.8))
    assert v.status == "stale" and v.hard is False   # NIE proven


# ---- allow-list pozytywnie (pytest/python przechodzi) ----

def test_allowed_binary_pytest():
    assert _binary_allowed(["pytest", "tests/"]) is True
    assert _binary_allowed(["python", "-c", "x"]) is True

def test_denied_binary_shell():
    assert _binary_allowed(["bash", "-c", "x"]) is False
    assert _binary_allowed(["mv", "a", "b"]) is False         # move-aside (CLAUDE.md #11)
    assert _binary_allowed(["powershell", "Remove-Item"]) is False
    assert _binary_allowed([]) is False                       # pusty argv fail-closed


# ---- file proven pozytywnie (realny plik + token) ----

def test_file_proven_with_token():
    """Realny plik pakietu z wymaganym tokenem -> proven-hard."""
    v = _v().verify_step(PlanStep(id="x", desc="d", evidence_kind="file",
                                  path="pyproject.toml", must_contain="cacheback"))
    assert v.status == "proven" and v.hard


# ---- semantyka pustego planu (panel 2: pusty != ukonczony) ----

def test_empty_plan_not_complete():
    rep = _v().verify_plan([])
    assert rep.all_proven is False        # pusty plan NIE jest ukonczony
    assert rep.progress_pct == 0.0
    assert rep.total == 0


# ---- fail-closed: zly fetch -> unproven, nie crash ----

def test_url_fetch_error_unproven():
    def boom(u):
        raise ConnectionError("down")
    v = _v(fetch_fn=boom).verify_step(PlanStep(id="x", desc="d", evidence_kind="url",
                                               url="https://e/", must_contain="x"))
    assert v.status == "unproven"
