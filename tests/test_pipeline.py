"""Testy TruthPipeline — uniwersalny pipeline prawdy i compliance.

Macierz werdyktów (uczciwa): confirmed / refuted / uncertain / unchecked +
fail-closed compliance (guard) + audit trail + stagnacja koryta.
"""
import pytest

from cacheback import ActionPolicy, ActionVetoed, TruthPipeline
from cacheback.koryto import FactBase, Koryto, KorytoVerdict


# ----------------------------------------------------------------------
# oś PRAWDY: koryto twarde (exec / calc)
# ----------------------------------------------------------------------

def test_hard_refute_via_calc():
    """Kalkulator liczy jawne wyrażenie → confident-wrong złapany od razu (hard)."""
    pipe = TruthPipeline()
    r = pipe.evaluate("Evaluate: 6 / 2 * 3", answer="1")
    assert r.verdict == "refuted"
    assert r.hard is True
    assert r.channel == "calc"
    assert r.truth == "9"
    assert r.caught and not r.trusted


def test_hard_confirm_via_calc():
    pipe = TruthPipeline()
    r = pipe.evaluate("Evaluate: 6 / 2 * 3", answer="9")
    assert r.verdict == "confirmed"
    assert r.hard is True
    assert r.trusted


def test_hard_refute_via_exec_stmts():
    """Interpreter wykonuje kod z pytania — klasyk lambda-closure [0,1,2]→[2,2,2]."""
    pipe = TruthPipeline()
    stmts = ["fns = [lambda: i for i in range(3)]", "[g() for g in fns]"]
    r = pipe.evaluate("fns=[lambda: i for i in range(3)]; [g() for g in fns]?",
                      answer="[0, 1, 2]", exec_stmts=stmts)
    assert r.verdict == "refuted"
    assert r.hard is True
    assert r.channel == "exec"
    assert "2, 2, 2" in r.truth


def test_hard_confirm_via_exec_correct_answer():
    """Poprawna odpowiedź modelu NIE może być odrzucona (lekcja z żywego demo:
    print() jako ostatni statement doklejał 'None' do atomu → fałszywe refute)."""
    pipe = TruthPipeline()
    stmts = ["fns = [lambda: i for i in range(3)]", "[g() for g in fns]"]
    r = pipe.evaluate("fns=[lambda: i for i in range(3)]; [g() for g in fns]?",
                      answer="[2, 2, 2]", exec_stmts=stmts)
    assert r.verdict == "confirmed"
    assert r.hard is True


# ----------------------------------------------------------------------
# oś PRAWDY: koryto miękkie (lookup) — NIGDY twarda blokada solo
# ----------------------------------------------------------------------

FACTS = {"capital of france": "Paris"}


def test_soft_refute_without_arbiter_is_uncertain():
    """Miękka rozbieżność bez arbitra → uncertain, NIE refuted (lookup może być stale)."""
    pipe = TruthPipeline(fact_base=FACTS)
    r = pipe.evaluate("What is the capital of France?", answer="Lyon")
    assert r.verdict == "uncertain"
    assert r.hard is False
    assert r.channel == "lookup"
    assert r.truth == "Paris"


def test_soft_refute_arbiter_confirms_koryto():
    pipe = TruthPipeline(fact_base=FACTS, arbiter_fn=lambda q, a, kv: True)
    r = pipe.evaluate("What is the capital of France?", answer="Lyon")
    assert r.verdict == "refuted"
    assert r.arbiter == "koryto-potwierdzone"


def test_soft_refute_arbiter_says_model_right():
    """Arbiter: model miał rację, koryto stale → confirmed, bez kary dla odpowiedzi."""
    pipe = TruthPipeline(fact_base=FACTS, arbiter_fn=lambda q, a, kv: False)
    r = pipe.evaluate("What is the capital of France?", answer="Lyon")
    assert r.verdict == "confirmed"
    assert r.arbiter == "model-mial-racje"
    assert r.truth is None  # atom koryta zdyskwalifikowany, nie raportujemy go jako prawdy


def test_soft_refute_arbiter_raises_fail_safe():
    """Wyjątek arbitra NIE blokuje twardo — degradacja do uncertain."""
    def boom(q, a, kv):
        raise RuntimeError("web arbiter down")
    pipe = TruthPipeline(fact_base=FACTS, arbiter_fn=boom)
    r = pipe.evaluate("What is the capital of France?", answer="Lyon")
    assert r.verdict == "uncertain"
    assert any(s.get("stage") == "arbiter" and "error" in s for s in r.stages)


def test_soft_confirm():
    pipe = TruthPipeline(fact_base=FACTS)
    r = pipe.evaluate("What is the capital of France?", answer="Paris")
    assert r.verdict == "confirmed"
    assert r.hard is False


def test_lookup_hard_block_refutes_without_arbiter():
    """Jawny opt-in usera (baza aktualna) → rozbieżność lookup blokuje od razu."""
    pipe = TruthPipeline(fact_base=FACTS, lookup_hard_block=True)
    r = pipe.evaluate("What is the capital of France?", answer="Lyon")
    assert r.verdict == "refuted"
    assert r.hard is False  # dowód dalej nie jest fizycznie niezależny
    assert any(s.get("stage") == "lookup_hard_block" for s in r.stages)


def test_lookup_hard_block_does_not_touch_confirm():
    pipe = TruthPipeline(fact_base=FACTS, lookup_hard_block=True)
    r = pipe.evaluate("What is the capital of France?", answer="Paris")
    assert r.verdict == "confirmed"


def test_reliable_only_for_confirmed():
    """reliable = tylko confirmed; unchecked jest trusted, ale NIE reliable."""
    pipe = TruthPipeline(fact_base=FACTS)
    confirmed = pipe.evaluate("Evaluate: 2 + 2", answer="4")
    unchecked = pipe.evaluate("Unknowable question?", answer="idk")
    uncertain = pipe.evaluate("What is the capital of France?", answer="Lyon")
    assert confirmed.reliable and confirmed.trusted
    assert unchecked.trusted and not unchecked.reliable
    assert not uncertain.trusted and not uncertain.reliable


def test_fact_base_as_callable():
    """fact_base może być gołym callable(question)->atom."""
    pipe = TruthPipeline(fact_base=lambda q: "42" if "answer to everything" in q else None)
    r = pipe.evaluate("What is the answer to everything?", answer="42")
    assert r.verdict == "confirmed"


# ----------------------------------------------------------------------
# oś PRAWDY: gate (rozrzut rzeki) gdy koryto nie zna atomu
# ----------------------------------------------------------------------

def test_unknown_gate_uncertain():
    """Koryto nie zna atomu, model odpowiada za każdym razem inaczej → uncertain."""
    answers = iter(["Krakow", "Warsaw", "Gdansk", "Poznan", "Lodz"])
    pipe = TruthPipeline(sample_fn=lambda p: next(answers))
    r = pipe.evaluate("Largest city of Poland by nightlife?", answer="Warsaw")
    assert r.verdict == "uncertain"
    assert r.channel == "gate"
    assert r.gate is not None and r.gate.uncertain


def test_unknown_gate_consistent_is_unchecked():
    """Model spójny + brak atomu → UNCHECKED (nie 'prawda' — jawna granica)."""
    pipe = TruthPipeline(sample_fn=lambda p: "Warsaw")
    r = pipe.evaluate("Largest city of Poland by nightlife?", answer="Warsaw")
    assert r.verdict == "unchecked"
    assert r.trusted  # wolno publikować, ale świadomie bez dowodu


def test_unknown_no_gate_is_unchecked():
    pipe = TruthPipeline()  # bez sample_fn → bez gate
    r = pipe.evaluate("Largest city of Poland by nightlife?", answer="Warsaw")
    assert r.verdict == "unchecked"
    assert r.gate is None


def test_gate_skipped_when_koryto_knows():
    """Koryto zna atom → gate NIE woła modelu (koszt N wywołań oszczędzony)."""
    calls = []
    pipe = TruthPipeline(sample_fn=lambda p: calls.append(p) or "9")
    r = pipe.evaluate("Evaluate: 6 / 2 * 3", answer="9")
    assert r.verdict == "confirmed"
    assert calls == []


# ----------------------------------------------------------------------
# ask() — generuj i weryfikuj jednym wejściem
# ----------------------------------------------------------------------

def test_ask_generates_and_verifies():
    pipe = TruthPipeline(sample_fn=lambda p: "1")
    r = pipe.ask("Evaluate: 6 / 2 * 3")
    assert r.answer == "1"
    assert r.verdict == "refuted"
    assert r.truth == "9"  # korekta dostępna dla wołającego


def test_ask_without_sample_fn_raises():
    with pytest.raises(ValueError):
        TruthPipeline().ask("anything")


# ----------------------------------------------------------------------
# oś COMPLIANCE: guard / check_action (fail-closed)
# ----------------------------------------------------------------------

POLICY = ActionPolicy(
    deny=[r"terraform.*(destroy|apply).*prod"],
    require_human=[r"send_wire"],
    max_amount=100.0,
)


def test_guard_denies_matching_action():
    pipe = TruthPipeline(policy=POLICY)
    executed = []

    @pipe.guard()
    def deploy(target):
        executed.append(target)

    with pytest.raises(ActionVetoed) as exc:
        deploy(target="terraform apply prod-eu")
    assert exc.value.mur == "policy-deny"
    assert executed == []  # akcja NIE dotknęła świata


def test_guard_allows_safe_action():
    pipe = TruthPipeline(policy=POLICY)

    @pipe.guard()
    def deploy(target):
        return f"deployed {target}"

    assert deploy(target="terraform plan staging") == "deployed terraform plan staging"


def test_guard_amount_over_threshold():
    pipe = TruthPipeline(policy=POLICY)

    @pipe.guard()
    def charge(*, amount):
        return "charged"

    with pytest.raises(ActionVetoed) as exc:
        charge(amount=5000)
    assert exc.value.mur == "policy-amount"


def test_guard_on_veto_callback_instead_of_raise():
    pipe = TruthPipeline(policy=POLICY)

    @pipe.guard(on_veto=lambda dec: f"BLOCKED:{dec.mur}")
    def deploy(target):
        return "deployed"

    assert deploy(target="terraform destroy prod") == "BLOCKED:policy-deny"


async def test_guard_async_function():
    pipe = TruthPipeline(policy=POLICY)

    @pipe.guard()
    async def deploy(target):
        return f"deployed {target}"

    assert await deploy(target="staging") == "deployed staging"
    with pytest.raises(ActionVetoed):
        await deploy(target="terraform apply prod")


def test_guard_without_policy_raises():
    """Pusta bramka przepuszczałaby wszystko → fail-closed ValueError."""
    pipe = TruthPipeline()
    with pytest.raises(ValueError):
        pipe.guard()
    with pytest.raises(ValueError):
        pipe.check_action("anything()")


def test_check_action_records_both_outcomes():
    pipe = TruthPipeline(policy=POLICY)
    ok = pipe.check_action("deploy(args=(), kwargs={'target': 'staging'})")
    bad = pipe.check_action("deploy terraform apply prod")
    assert ok.allowed and not bad.allowed
    kinds = [e for e in pipe.audit if e["kind"] == "action"]
    assert len(kinds) == 2
    assert kinds[0]["allowed"] is True and kinds[1]["allowed"] is False


# ----------------------------------------------------------------------
# audyt + compliance_report + stagnacja
# ----------------------------------------------------------------------

def test_audit_and_compliance_report():
    events = []
    pipe = TruthPipeline(fact_base=FACTS, policy=POLICY, on_event=events.append)
    pipe.evaluate("Evaluate: 2 + 2", answer="4")          # confirmed (calc)
    pipe.evaluate("Evaluate: 2 + 2", answer="5")          # refuted (calc)
    pipe.evaluate("Unknowable question?", answer="idk")   # unchecked
    pipe.check_action("deploy terraform apply prod")      # veto
    rep = pipe.compliance_report()
    assert rep["evaluations"] == {"confirmed": 1, "refuted": 1, "unchecked": 1}
    assert rep["actions_vetoed"] == 1
    assert rep["actions_allowed"] == 0
    assert rep["events_retained"] == 4
    assert len(events) == 4  # on_event dostał każde zdarzenie


def test_on_event_exception_does_not_break_decision():
    def bad_sink(e):
        raise IOError("disk full")
    pipe = TruthPipeline(on_event=bad_sink)
    r = pipe.evaluate("Evaluate: 2 + 2", answer="5")
    assert r.verdict == "refuted"  # decyzja niezależna od telemetrii


def test_stagnation_flags_rotten_koryto():
    """Seria miękkich odrzuceń (stale baza odrzuca wszystko) → koryto_suspect."""
    stale = FactBase({"capital of morocco": "Casablanca"})  # stale: prawda to Rabat
    pipe = TruthPipeline(koryto=Koryto(stale))
    last = None
    for _ in range(4):
        last = pipe.evaluate("What is the capital of Morocco?", answer="Rabat")
    assert last.stagnation is not None
    assert last.stagnation.koryto_suspect
    assert pipe.compliance_report()["koryto_suspect"] is True


def test_stagnation_disabled():
    pipe = TruthPipeline(stagnation=False)
    r = pipe.evaluate("Evaluate: 2 + 2", answer="4")
    assert r.stagnation is None


# ----------------------------------------------------------------------
# raport: serializacja i ślad etapów
# ----------------------------------------------------------------------

def test_report_to_dict_and_stages():
    pipe = TruthPipeline(fact_base=FACTS, arbiter_fn=lambda q, a, kv: True)
    r = pipe.evaluate("What is the capital of France?", answer="Lyon")
    d = r.to_dict()
    assert d["verdict"] == "refuted"
    stage_names = [s["stage"] for s in d["stages"]]
    assert stage_names[0] == "koryto"
    assert "arbiter" in stage_names
    import json
    json.dumps(d)  # serializowalny bez błędu


def test_audit_max_bounded():
    pipe = TruthPipeline(audit_max=3)
    for i in range(10):
        pipe.evaluate(f"Evaluate: {i} + 1", answer=str(i + 1))
    assert len(pipe.audit) == 3


# ----------------------------------------------------------------------
# workflow review 2026-07-02 — regresje (confirmed findings)
# ----------------------------------------------------------------------

def test_falsy_answer_zero_is_confirmed():
    """P1: answer=0 to poprawna odpowiedź, nie brak odpowiedzi (str(answer or '') kasował)."""
    pipe = TruthPipeline()
    r = pipe.evaluate("Evaluate: 3 - 3", answer=0)
    assert r.verdict == "confirmed"
    assert r.answer == "0"


def test_answer_none_is_uncertain_not_refuted():
    """P1: None (awaria backendu) ≠ confident-wrong — uncertain, nie refuted."""
    pipe = TruthPipeline()
    r = pipe.evaluate("Evaluate: 2 + 2", answer=None)
    assert r.verdict == "uncertain"
    assert not r.caught
    assert {"stage": "input", "no_answer": True} in r.stages


def test_atoms_match_no_substring_false_confirm():
    """P1: '19' NIE zawiera atomu '9' (substring-fallback dawał confirmed+hard)."""
    from cacheback.koryto import atoms_match
    assert not atoms_match("19", "9")
    assert not atoms_match("90", "9")
    assert not atoms_match("comparison", "Paris")
    assert atoms_match("the answer is 9", "9")
    assert atoms_match("9.0", "9")
    pipe = TruthPipeline()
    r = pipe.evaluate("Evaluate: 4 + 5", answer="19")
    assert r.verdict == "refuted"


def test_positional_amount_hits_max_amount_cap():
    """P1: charge(5000) pozycyjnie NIE omija progu kwoty (binding sygnatury)."""
    pipe = TruthPipeline(policy=ActionPolicy(max_amount=100.0))

    @pipe.guard()
    def charge(amount):
        return f"charged {amount}"

    with pytest.raises(ActionVetoed):
        charge(5000)
    assert charge(50) == "charged 50"


def test_empty_action_policy_rejected_at_construction():
    """P1/P2: pusta ActionPolicy() = pusta bramka → ValueError (strict fail-closed)."""
    with pytest.raises(ValueError):
        TruthPipeline(policy=ActionPolicy())


def test_ask_none_from_sample_fn_is_uncertain():
    """P2: sample_fn→None nie staje się odpowiedzią 'None' (spójnie z gate)."""
    pipe = TruthPipeline(sample_fn=lambda p: None, fact_base={"q": "x"})
    r = pipe.ask("Evaluate: 2 + 2")
    assert r.verdict == "uncertain"
    assert r.answer == ""


def test_gate_consistent_but_answer_disagrees_is_uncertain():
    """P2: model spójnie mówi co innego niż oceniana odpowiedź → uncertain, nie trusted."""
    pipe = TruthPipeline(sample_fn=lambda p: "Krakow")
    r = pipe.evaluate("Largest city of Poland by nightlife?", answer="Warsaw")
    assert r.verdict == "uncertain"
    assert r.channel == "gate"
    assert any(s.get("stage") == "gate_answer_check" for s in r.stages)


def test_async_on_veto_is_awaited():
    """P2: async on_veto musi być awaited (nie zwracać surowej coroutine)."""
    import asyncio
    pipe = TruthPipeline(policy=ActionPolicy(deny=[r"deploy"]))
    ran = []

    async def notify(dec):
        ran.append(dec.mur)
        return "handled"

    @pipe.guard(on_veto=notify)
    async def deploy(target):
        return "DEPLOYED"

    out = asyncio.run(deploy(target="prod"))
    assert out == "handled"
    assert ran == ["policy-deny"]


def test_question_none_does_not_crash():
    """P3: question=None nie wywala TypeError w audycie (_finish)."""
    pipe = TruthPipeline()
    r = pipe.evaluate(None, "x")
    assert r.verdict in ("unchecked", "uncertain")
    assert r.question == ""


def test_compliance_report_keeps_koryto_suspect_history():
    """P3: zgnilizna koryta wyczyszczona confirmami zostaje w koryto_suspect_events."""
    stale = FactBase({"capital of morocco": "Casablanca",
                      "capital of france": "Paris"})
    pipe = TruthPipeline(koryto=Koryto(stale))
    for _ in range(4):
        pipe.evaluate("What is the capital of Morocco?", answer="Rabat")
    for _ in range(6):
        pipe.evaluate("What is the capital of France?", answer="Paris")
    rep = pipe.compliance_report()
    assert rep["koryto_suspect"] is False           # ostatni stan czysty...
    assert rep["koryto_suspect_events"] >= 1        # ...ale historia nie znika


def test_audit_event_distinguishes_gate_run():
    """P3: zdarzenie audytowe odróżnia 'unchecked bez gate' od 'unchecked po gate'."""
    events = []
    no_gate = TruthPipeline(on_event=events.append)
    no_gate.evaluate("Unknowable?", answer="idk")
    with_gate = TruthPipeline(sample_fn=lambda p: "idk", on_event=events.append)
    with_gate.evaluate("Unknowable?", answer="idk")
    assert events[0]["gate_ran"] is False
    assert events[1]["gate_ran"] is True
    assert events[1]["gate_disagreement"] is not None


def test_compliance_report_thread_safe_with_concurrent_evaluate():
    """P2: compliance_report() podczas równoległych evaluate() bez RuntimeError."""
    import threading
    pipe = TruthPipeline()
    errors = []

    def worker():
        try:
            for i in range(50):
                pipe.evaluate(f"Evaluate: {i} + 1", answer=str(i + 1))
        except Exception as e:
            errors.append(e)

    def reader():
        try:
            for _ in range(200):
                pipe.compliance_report()
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(4)] + \
              [threading.Thread(target=reader) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []


def test_atoms_match_diacritics_normalized():
    """Benchmark 50q 2026-07-02: 'Brasília' (poprawna, z diakrytykiem) dawała
    soft-refute vs atom 'Brasilia' — _norm musi zdejmować diakrytyki."""
    from cacheback.koryto import atoms_match
    assert atoms_match("Brasília", "Brasilia")
    assert atoms_match("Brasilia", "Brasília")
    assert atoms_match("Kraków is lovely", "Krakow")
    pipe = TruthPipeline(fact_base={"capital of brazil": "Brasilia"})
    r = pipe.evaluate("What is the capital of Brazil?", answer="Brasília")
    assert r.verdict == "confirmed"
