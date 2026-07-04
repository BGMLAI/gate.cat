"""Smoke tests for TruthGate (gate + branches + agent loop)."""
from cacheback.gate import Gate
from cacheback.branches import calculate, ToolBranch, WebBranch, best_web_snippet_score
from cacheback.agent import GatedLoop, StepResult


# ---- Gate ----

def test_gate_confident_vs_uncertain():
    g = Gate(threshold=0.30)
    assert g.check_samples(["Paris"] * 5).uncertain is False
    assert g.check_samples(["Paris", "London", "Berlin", "Madrid", "Rome"]).uncertain is True


def test_gate_scores():
    g = Gate(threshold=0.30)
    assert g.check_scores([0.9, 0.91, 0.89, 0.92]).uncertain is False
    assert g.check_scores([0.9, 0.3, 0.5, 0.2]).uncertain is True


def test_gate_callback():
    import itertools
    ans = itertools.cycle(["Shakespeare wrote Hamlet"] * 3)
    g = Gate(sample_fn=lambda p: next(ans), n_samples=3, threshold=0.30)
    assert g.check("Who wrote Hamlet?").uncertain is False


# ---- Gate edge-cases (audyt 2026-06-27 should-fix) ----

def test_gate_none_samples_not_confident():
    """None próbki NIE mogą udawać pewnej odpowiedzi (None→'None' dawał disagreement=0.0)."""
    g = Gate(threshold=0.30)
    v = g.check_samples([None, None, None])
    assert v.uncertain is True
    assert v.n == 0


def test_gate_single_sample_not_confident():
    """<2 realnych próbek = brak sygnału rozrzutu → uncertain=True, nie fałszywe 'pewny'."""
    g = Gate(threshold=0.30)
    v = g.check_samples(["tylko jedna"])
    assert v.uncertain is True


def test_gate_empty_strings_filtered():
    """Puste/whitespace próbki odfiltrowane; sama pustka → uncertain=True."""
    g = Gate(threshold=0.30)
    v = g.check_samples(["", "   ", ""])
    assert v.uncertain is True


# ---- Tools branch ----

def test_calculate():
    assert calculate("2*(3+4)") == "14"
    assert calculate("(10+5)*2") == "30"
    assert calculate("2**8") == "256"
    assert "error" in calculate("import os").lower() or "brak" in calculate("import os").lower()


def test_tool_branch_math_routing():
    tb = ToolBranch()
    assert tb.maybe_run("ile to 12 * 7?") == ("calculate", "84")
    assert tb.maybe_run("who wrote Hamlet?") is None


# ---- Web branch ----

def test_web_threshold_gates_noise():
    good = [{"title": "Hamlet", "snippet": "Hamlet was written by William Shakespeare in 1600"}]
    noise = [{"title": "Pasta", "snippet": "best tomato recipe"}]
    assert WebBranch(search_fn=lambda q: good).fetch("who wrote Hamlet").used is True
    assert WebBranch(search_fn=lambda q: noise).fetch("who wrote Hamlet").used is False


def test_web_retrieval_score_threshold():
    rs = [{"title": "H", "snippet": "x", "retrieval_score": 0.8}]
    assert WebBranch(search_fn=lambda q: rs).fetch("q").used is True
    low = [{"title": "H", "snippet": "x", "retrieval_score": 0.2}]
    assert WebBranch(search_fn=lambda q: low).fetch("q").used is False


# ---- Agent loop (the agents pitch) ----

def test_gated_loop_stops_runaway():
    import random
    random.seed(1)
    loop = GatedLoop(
        step_fn=lambda s: StepResult(output=s + 1, done=False, prompt="stuck", cost=0.1),
        sample_fn=lambda p: random.choice(["A", "B", "C", "D", "E"]),
        max_uncertain_steps=3, max_steps=50,
    )
    r = loop.run(0)
    assert r.stopped_reason == "runaway_guessing"
    assert r.steps < 50  # stopped before the cap = before the burn


def test_gated_loop_lets_healthy_finish():
    loop = GatedLoop(
        step_fn=lambda s: StepResult(output=s + 1, done=(s >= 4), prompt="clear", cost=0.1),
        sample_fn=lambda p: "the answer is 42",
        max_uncertain_steps=3,
    )
    r = loop.run(0)
    assert r.stopped_reason == "done"
    assert r.uncertain_steps == 0


def test_gated_loop_escalation_rescues():
    import random
    random.seed(1)
    loop = GatedLoop(
        step_fn=lambda s: StepResult(output=s + 1, done=False, prompt="stuck", cost=0.1),
        sample_fn=lambda p: random.choice(["A", "B", "C"]),
        max_uncertain_steps=3, max_steps=8,
        on_uncertain=lambda i, v, s: True,  # always rescue
    )
    r = loop.run(0)
    assert r.stopped_reason == "max_steps"  # rescue prevents runaway


# --- audyt 2026-06-27 #4: gate all-samples-fail → uncertain=True (fail-closed) ---

def test_gate_all_samples_fail_returns_uncertain():
    """Gdy model jest niedostępny (sample_fn ZAWSZE rzuca), gate NIE może raportować
    'pewny' — to było fail-open. Brak sygnału = uncertain=True."""
    def broken(prompt):
        raise RuntimeError("model down")
    gate = Gate(sample_fn=broken, n_samples=5)
    v = gate.check("anything")
    assert v.uncertain is True
    assert v.n == 0


# --- audyt 2026-06-27 #5: wyjątek w on_uncertain NIE crashuje pętli ---

def test_gated_loop_callback_exception_does_not_crash():
    """Callback on_uncertain który rzuca → degraduj do rescued=False, pętla żyje dalej
    (był to nieobsłużony crash całego agenta)."""
    import random
    random.seed(2)

    def boom(i, v, s):
        raise ValueError("callback exploded")

    loop = GatedLoop(
        step_fn=lambda s: StepResult(output=s + 1, done=False, prompt="stuck", cost=0.1),
        sample_fn=lambda p: random.choice(["A", "B", "C", "D"]),
        max_uncertain_steps=2, max_steps=8,
        on_uncertain=boom,
    )
    r = loop.run(0)  # NIE może rzucić ValueError
    assert r.stopped_reason in ("runaway_guessing", "max_steps")
