"""The compliance split-log (_audit): the properties every jurisdiction we
researched actually requires, pinned as tests.

Not a compliance CERTIFICATION - a mechanical guarantee that the record has the
shape those laws ask for: hash-chained non-personal skeleton (immutability /
traceability - EU AI Act Art.12), redactable PII sidecar (GDPR/NZ/Canada
erasure), human-oversight fields (Art.14 / Singapore), region routing +
residency (China CSL / India). If any of these regress, a published
"globally-compliance-ready" claim would become false - so they are CI-gated.
"""

from __future__ import annotations

import json

import pytest

from gatecat.integrations._audit import (
    AuditRecord,
    HumanOversight,
    record_decision,
    redact_entry,
    verify_chain,
)


@pytest.fixture()
def audit(tmp_path, monkeypatch):
    """Isolate the audit dir per test; default (redacted) mode unless a test
    opts raw/actor in explicitly."""
    d = tmp_path / "audit"
    monkeypatch.setenv("GATECAT_AUDIT_DIR", str(d))
    monkeypatch.delenv("GATECAT_AUDIT_RAW", raising=False)
    monkeypatch.delenv("GATECAT_AUDIT_ACTOR", raising=False)
    monkeypatch.delenv("GATECAT_AUDIT_HMAC_KEY", raising=False)
    return d


def _skel(d):
    return [json.loads(l) for l in (d / "skeleton.jsonl").read_text().splitlines()]


def _side(d):
    p = d / "pii_sidecar.jsonl"
    return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []


def test_skeleton_is_hash_chained(audit):
    """EU AI Act Art.12 traceability: every entry commits to the previous, so a
    later rewrite of the middle is detectable."""
    for i in range(3):
        record_decision(AuditRecord(decision="block", reason=f"r{i}",
                                    source="hook", raw_action=f"cmd{i}"))
    rows = _skel(audit)
    assert len(rows) == 3
    assert rows[0]["prev_hash"] == "0" * 64  # genesis anchor
    assert rows[1]["prev_hash"] == rows[0]["entry_hash"]
    assert rows[2]["prev_hash"] == rows[1]["entry_hash"]
    ok, n, bad = verify_chain(audit / "skeleton.jsonl")
    assert ok and n == 3 and bad is None


def test_tamper_is_detected(audit):
    """Rewriting any entry breaks verify_chain - tamper-evidence, the point of
    the hash-chain on a mutable filesystem."""
    for i in range(3):
        record_decision(AuditRecord(decision="allow", reason=f"r{i}", source="hook"))
    skel = audit / "skeleton.jsonl"
    raw = skel.read_text().splitlines()
    rec = json.loads(raw[1]); rec["reason"] = "TAMPERED"; raw[1] = json.dumps(rec)
    skel.write_text("\n".join(raw) + "\n")
    ok, _, bad = verify_chain(skel)
    assert ok is False and bad is not None


def test_pii_never_in_skeleton_by_default(audit):
    """GDPR data-minimization: with no opt-in, the raw command and actor id are
    absent from BOTH streams, and the skeleton is flagged was_redacted."""
    record_decision(AuditRecord(decision="block", reason="secret op",
                                source="hook", raw_action="rm -rf /home/alice",
                                actor_id="alice-agent", host="alice-pc"))
    rows = _skel(audit)
    assert all("raw_action" not in r for r in rows)
    assert all("actor_id" not in r for r in rows)
    assert rows[0]["was_redacted"] is True
    assert _side(audit) == []  # nothing personal was stored at all


def test_raw_and_actor_are_opt_in(audit, monkeypatch):
    """Opt-in (deployer's explicit choice) puts raw command + actor in the
    SIDECAR only, keyed by entry_id - never in the skeleton."""
    monkeypatch.setenv("GATECAT_AUDIT_RAW", "1")
    monkeypatch.setenv("GATECAT_AUDIT_ACTOR", "1")
    eid = record_decision(AuditRecord(decision="block", reason="op",
                                      source="hook", raw_action="vastai destroy 1",
                                      actor_id="agent-x", host="host-1"))
    rows = _skel(audit)
    side = _side(audit)
    assert all("raw_action" not in r for r in rows)  # still not in skeleton
    assert rows[0]["was_redacted"] is False
    assert any(s["entry_id"] == eid and s.get("raw_action") == "vastai destroy 1"
               for s in side)


def test_erasure_keeps_chain_valid(audit, monkeypatch):
    """GDPR/NZ/Canada right-to-erasure: purging a decision's PII sidecar row
    leaves the skeleton's hash-chain intact (the skeleton never held the PII)."""
    monkeypatch.setenv("GATECAT_AUDIT_RAW", "1")
    eid = record_decision(AuditRecord(decision="block", reason="op1",
                                      source="hook", raw_action="secret-cmd"))
    record_decision(AuditRecord(decision="allow", reason="op2", source="hook",
                                raw_action="ls"))
    assert verify_chain(audit / "skeleton.jsonl")[0] is True
    assert redact_entry(eid) is True
    ok, n, _ = verify_chain(audit / "skeleton.jsonl")
    assert ok is True and n == 2  # both decisions still auditable
    assert all(s.get("raw_action") != "secret-cmd" for s in _side(audit))


def test_human_oversight_fields_present(audit):
    """EU AI Act Art.14 + Singapore Agentic framework: an escalated decision
    records the human verdict + latency (=> override-rate computable) in the
    skeleton; the reviewer identity (personal) is opt-in sidecar."""
    rec = AuditRecord(
        decision="block", reason="needs human", source="hook",
        human=HumanOversight(escalated_to_human=True, human_decision="override_allow",
                             reviewer_id="rev-1", intervention_latency_s=8.0),
    )
    record_decision(rec)
    row = _skel(audit)[0]
    assert row["escalated_to_human"] is True
    assert row["human_decision"] == "override_allow"
    assert row["intervention_latency_s"] == 8.0
    # reviewer_id is personal -> not in skeleton
    assert "reviewer_id" not in row


def test_region_and_provenance_recorded(audit):
    """China CSL / India residency: a jurisdiction tag on every record. Plus
    rule provenance (rule_id/version + human-readable logic - Quebec/Chile/MX)
    so a decision is reproducible and explainable."""
    record_decision(AuditRecord(
        decision="block", reason="r", source="hook", region="CN",
        rule_id="RM_RF", rule_version="0.2.0",
        rule_logic_human_readable="blocks recursive force delete of protected roots",
        risk_tier="high"))
    row = _skel(audit)[0]
    assert row["region"] == "CN"
    assert row["rule_id"] == "RM_RF" and row["rule_version"] == "0.2.0"
    assert "recursive force delete" in row["rule_logic_human_readable"]
    assert row["risk_tier"] == "high"


def test_records_are_ascii_safe(audit):
    """D1: Polish / non-ASCII in a reason must survive cp1252 pipelines in both
    streams (the skeleton is read by auditors on any console)."""
    record_decision(AuditRecord(decision="block",
                                reason="zniszczyloby srodowisko żłób",
                                source="hook"))
    txt = (audit / "skeleton.jsonl").read_text()
    txt.encode("ascii")  # must not raise


def test_log_decision_mirrors_into_audit(audit, tmp_path, monkeypatch):
    """The production entrypoint (log_decision, called by guard.py/hook) must
    populate the compliance log automatically - no separate wiring needed."""
    monkeypatch.setenv("GATECAT_VETO_LOG", str(tmp_path / "veto.jsonl"))
    from gatecat.integrations import log_decision

    log_decision(source="claude_code_hook", decision="block",
                 reason="rm -rf home", policy="DELETE_ANALYZER",
                 context="rm -rf ~/x")
    rows = _skel(audit)
    assert len(rows) == 1
    assert rows[0]["decision"] == "block"
    assert rows[0]["rule_id"] == "DELETE_ANALYZER"
    # and the flat telemetry log still got its own line, unchanged
    flat = (tmp_path / "veto.jsonl").read_text().splitlines()
    assert len(flat) == 1
    assert set(json.loads(flat[0])) == {"ts", "source", "policy",
                                        "decision", "reason", "context"}


def test_keyed_chain_resists_forgery(audit, monkeypatch):
    """With a deploy-held HMAC key, an attacker who has the (public) code but not
    the key cannot forge a verifying rewrite. Recomputing downstream hashes with
    plain SHA-256 (the keyless algorithm) fails verify. (forgeable-chain fix)."""
    import hashlib

    monkeypatch.setenv("GATECAT_AUDIT_HMAC_KEY", "deploy-secret")
    for i in range(4):
        record_decision(AuditRecord(decision="allow", reason=f"r{i}", source="hook"))
    skel = audit / "skeleton.jsonl"
    assert verify_chain(skel)[0] is True

    rows = _skel(audit)
    rows[1]["reason"] = "FORGED"
    prev = rows[0]["entry_hash"]
    for i in range(1, len(rows)):
        rows[i]["prev_hash"] = prev
        body = {k: v for k, v in rows[i].items() if k != "entry_hash"}
        # attacker WITHOUT the key can only use plain sha256
        rows[i]["entry_hash"] = hashlib.sha256(
            (prev + json.dumps(body, sort_keys=True)).encode()).hexdigest()
        prev = rows[i]["entry_hash"]
    skel.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    ok, _, bad = verify_chain(skel)
    assert ok is False and bad is not None


def test_entry_ids_unique_for_identical_content(audit, monkeypatch):
    """Two decisions with byte-identical (reason, raw_action, decision) in the
    same second get DISTINCT entry_ids, so a GDPR erasure of one cannot
    collateral-delete the other. (entry_id-collision fix)."""
    monkeypatch.setenv("GATECAT_AUDIT_RAW", "1")
    monkeypatch.setenv("GATECAT_AUDIT_ACTOR", "1")
    e1 = record_decision(AuditRecord(decision="block", reason="op", source="hook",
                                     raw_action="cmd-A", actor_id="alice"))
    e2 = record_decision(AuditRecord(decision="block", reason="op", source="hook",
                                     raw_action="cmd-A", actor_id="bob"))
    assert e1 != e2
    redact_entry(e1)
    side = _side(audit)
    assert any(s.get("actor_id") == "bob" for s in side)   # bob survives
    assert all(s.get("actor_id") != "alice" for s in side)  # alice erased


def test_stage_trace_is_recorded_for_every_decision(audit, tmp_path, monkeypatch):
    """Every decision logs the FULL per-stage trace (AI Act Art.12 traceability):
    which stage ran, its verdict, and why - not just the final verdict. This is
    what lets a recall audit see whether any stage flagged an allowed action."""
    monkeypatch.setenv("GATECAT_VETO_LOG", str(tmp_path / "veto.jsonl"))
    monkeypatch.setenv("GATECAT_VETO_EPHEMERAL", "0")
    from gatecat.integrations import check_action, ActionVetoed
    from gatecat.integrations.policies import DOGFOOD_DEFAULTS

    # an allow and a block, both must carry a stage trace in the skeleton
    check_action("hook", "ls -la", DOGFOOD_DEFAULTS, cwd="/w", home="/root")
    try:
        check_action("hook", "rm -rf /srv", DOGFOOD_DEFAULTS, cwd="/w", home="/root")
    except ActionVetoed:
        pass
    rows = _skel(audit)
    assert len(rows) == 2
    for r in rows:
        assert r["stages"], f"no stage trace for {r['decision']}"
        names = [s[0] for s in r["stages"]]
        assert "ephemeral-disarm" in names  # every path records the first gate
    # the allow ran all the way to the regex walls; the block stopped at analyzer
    allow = next(r for r in rows if r["decision"] == "allow")
    block = next(r for r in rows if r["decision"] == "block")
    assert any(s[0] == "deny-regex-walls" for s in allow["stages"])
    assert any(s[1] == "block" for s in block["stages"])


def test_stage_trace_returned_on_allow_decision(monkeypatch, tmp_path):
    """check_action's returned Decision carries the trace too (callers can
    inspect the path without reading the log)."""
    monkeypatch.setenv("GATECAT_VETO_EPHEMERAL", "0")
    monkeypatch.setenv("GATECAT_AUDIT_DIR", str(tmp_path / "a"))
    monkeypatch.setenv("GATECAT_VETO_LOG", str(tmp_path / "v.jsonl"))
    from gatecat.integrations import check_action
    from gatecat.integrations.policies import DOGFOOD_DEFAULTS

    d = check_action("hook", "rm -rf ./dist", DOGFOOD_DEFAULTS, cwd="/w", home="/root")
    assert d.level == "allow"
    assert any(s[0] == "delete-analyzer" for s in d.stages)


def test_concurrent_writers_do_not_fork_the_chain(audit):
    """Many threads writing at once must not fork the hash-chain or lose entries
    (the per-command hook runs as separate processes; a multi-agent host runs
    many concurrently). The file lock serializes read-prev + append.
    (concurrent-corruption fix). Threads share the process but still exercise the
    read-prev-then-append race the lock closes."""
    import threading

    def writer(tag):
        for i in range(50):
            record_decision(AuditRecord(decision="allow", reason=f"{tag}-{i}",
                                        source="hook"))

    threads = [threading.Thread(target=writer, args=(t,)) for t in "ABCD"]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    rows = _skel(audit)
    assert len(rows) == 200  # 4 threads * 50, none lost
    prevs = [r["prev_hash"] for r in rows]
    assert len(prevs) == len(set(prevs))  # no duplicate prev_hash => no fork
    ok, n, _ = verify_chain(audit / "skeleton.jsonl")
    assert ok is True and n == 200
