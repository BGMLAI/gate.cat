"""Compliance-ready audit log (the split-log design, globally clearable).

Why this is a SEPARATE module from :mod:`_log`:
    ``_log.log_decision`` writes a flat 6-field telemetry line to
    ``veto_log.jsonl`` - a stable contract that adapters, the hook, and older
    tooling already read. We do NOT touch that shape. This module adds a
    second, richer stream that satisfies audit-record obligations across every
    jurisdiction researched (EU AI Act Art.12/14, GDPR, US, China CSL, India
    CERT-In, Singapore PDPA, AU/NZ, LatAm, Middle East, Canada). ``_log``
    delegates here; both streams stay in sync, neither breaks the other.

THE DESIGN PRINCIPLE (resolves the global floors-vs-ceilings contradiction):
    Split every decision into TWO records.

    1. DECISION SKELETON - append-only, hash-chained, contains NO personal data.
       Retained to the LONGEST floor (5y: KSA/BR). This is the tamper-evident
       spine: prev_hash + entry_hash chain every entry to the last. With a
       deploy-held key (``GATECAT_AUDIT_HMAC_KEY``) the chain is HMAC-SHA256,
       so an adversary who has this (public) code but not the key cannot forge a
       verifying rewrite. WITHOUT a key it is a plain SHA-256 chain: it catches a
       NAIVE editor who forgets to recompute downstream hashes, but NOT an
       adversary who recomputes them - so for adversarial tamper-evidence set a
       key, and treat the keyless mode as an integrity check against accidental
       corruption, not a security guarantee. Because the skeleton holds no PII,
       no privacy law forces it to be shortened or erased.

    2. PII SIDECAR - redactable / crypto-shreddable, keyed by ``entry_id`` back
       to the skeleton. Holds the raw command, actor identity, host, anything
       that could be personal or secret. Retained to the SHORTEST necessity
       ceiling (GDPR / NZ / Canada purpose-limitation). Can be purged on a
       data-subject request WITHOUT breaking the skeleton's hash-chain -
       because redaction happens BEFORE hashing (only a hash of the raw input
       enters the skeleton, never the raw input itself).

    Every tunable - retention, breach clock, residency - is a per-region config
    field resolved to the STRICTEST applicable value at deploy time, never a
    global constant.

LEGAL FRAMING (REJESTR_PRAWD 2026-07-05): gate.cat running locally is an
    evidence-PRODUCER, not a regulated entity. It emits records aligned with
    AI Act Art.12/14; it must never be marketed as "certified/compliant". The
    moment a hosted/telemetry/escalation backend appears, the operator (not
    this OSS) becomes the GDPR processor. This module makes the *local* record
    strong enough that a deployer CAN meet those obligations - it does not
    claim to meet them on their behalf.

Best-effort, exactly like ``_log``: an audit-write failure must NEVER turn a
    block into an allow or crash the gate. The decision is already made before
    we get here; we only record it.
"""

from __future__ import annotations

import hashlib
import json
import itertools
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from gatecat.integrations._log import ascii_safe

# Process-unique nonce source for entry_id: the OS pid plus a monotonic counter.
# Two decisions with byte-identical (reason, raw_action, decision) in the same
# UTC second previously collided on entry_id, so a GDPR erasure of one could
# collateral-delete the other (E2E audit 2026-07-05, MED). pid+counter makes the
# id unique per (process, call) without needing Math.random/uuid (unavailable /
# non-deterministic); across processes the pid differs, within a process the
# counter differs.
_PID = os.getpid()
_ENTRY_COUNTER = itertools.count()


@contextmanager
def _file_lock(lock_path: Path):
    """Advisory exclusive lock so concurrent writers (the hook runs as a separate
    OS process per command; multi-agent hosts run many at once) serialize their
    read-prev-hash + append. Without it two writers read the same prev_hash and
    fork the chain, silently losing entries and failing verify (E2E audit
    2026-07-05, HIGH). Cross-platform: msvcrt on Windows, fcntl on POSIX. Falls
    back to no-op if neither is available (best-effort, never crashes the gate)."""
    fh = None
    try:
        fh = open(lock_path, "a+b")
        try:
            import msvcrt  # Windows
            msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
            locked = "msvcrt"
        except (ImportError, OSError):
            try:
                import fcntl  # POSIX
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                locked = "fcntl"
            except (ImportError, OSError):
                locked = None
        try:
            yield
        finally:
            if locked == "msvcrt":
                try:
                    fh.seek(0)
                    import msvcrt
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
            elif locked == "fcntl":
                try:
                    import fcntl
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
    finally:
        if fh is not None:
            fh.close()

# --- where the two streams live ---------------------------------------------
# Region-resident by design: the whole audit dir is one relocatable root, so a
# deployer under a data-localization regime (China CSL, Kenya s.50, KSA) points
# it at in-country storage. Cross-border export is OFF by default - there is no
# implicit network sink here; shipping the log anywhere is the deployer's own,
# explicit act.
_AUDIT_DIR_ENV = "GATECAT_AUDIT_DIR"
_DEFAULT_AUDIT_DIR = Path.home() / ".gatecat" / "audit"
_SKELETON_NAME = "skeleton.jsonl"   # immutable, hash-chained, non-personal
_SIDECAR_NAME = "pii_sidecar.jsonl"  # redactable / crypto-shreddable

# Redaction is ON by default (GDPR data-minimization; India/Singapore/China
# secret-and-PII-at-write). The raw command only reaches the sidecar, and only
# when the deployer opts in. The skeleton never sees it - it carries a SHA-256
# input_hash so the decision can be re-derived/verified without the plaintext.
_RAW_OPT_IN_ENV = "GATECAT_AUDIT_RAW"   # "1"/"true" -> store raw cmd in sidecar
_ACTOR_OPT_IN_ENV = "GATECAT_AUDIT_ACTOR"  # "1"/"true" -> store raw actor id

# Region tag flows into every record so a multi-region deployer can shard /
# resolve retention per-jurisdiction. Not a promise of compliance - a routing key.
_REGION_ENV = "GATECAT_AUDIT_REGION"

# Stamp the REAL package version into every audit record's provenance field.
# Derived from the package so a version bump can never leave a stale, misleading
# `gatecat_version` in a compliance-retained, hash-chained record (0.3.0 shipped
# with this hardcoded at 0.2.1 until it was made dynamic).
try:
    from gatecat import __version__ as _GATECAT_VERSION
except Exception:  # pragma: no cover - never let provenance import break audit
    _GATECAT_VERSION = "unknown"
_SCHEMA_VERSION = "audit-1"


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def audit_dir() -> Path:
    return Path(os.environ.get(_AUDIT_DIR_ENV, str(_DEFAULT_AUDIT_DIR)))


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


# Optional keyed chain: when a deploy-held secret is set, each entry_hash is an
# HMAC-SHA256 keyed by that secret, so an attacker who has the (public) code but
# NOT the key cannot recompute a forged chain that verifies (forgeable-chain fix,
# MED). Without the key we fall back to a plain SHA-256 chain, which is only
# tamper-EVIDENT against a naive editor who forgets to recompute downstream
# hashes - documented honestly in verify_chain / the module docstring.
_HMAC_KEY_ENV = "GATECAT_AUDIT_HMAC_KEY"


def _chain_mac(prev_hash: str, body_json: str) -> str:
    """The per-entry chain hash over (prev_hash + body). HMAC-SHA256 if a key is
    configured (unforgeable without the key), else plain SHA-256 (naive-tamper-
    evident only). The two forms are distinguishable at verify time only by
    having the same key set, so a deployer who turns keying ON keeps it on."""
    key = os.environ.get(_HMAC_KEY_ENV, "")
    msg = (prev_hash + body_json).encode("utf-8", errors="replace")
    if key:
        import hmac
        return hmac.new(key.encode("utf-8", errors="replace"), msg,
                        hashlib.sha256).hexdigest()
    return hashlib.sha256(msg).hexdigest()


def _now_iso() -> str:
    # UTC ISO-8601. NTP sync is the host's responsibility; we record what the
    # host clock says and stamp it as UTC so cross-region logs collate.
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _last_entry_hash(skeleton: Path) -> str:
    """Return the entry_hash of the last skeleton line, or the genesis anchor.

    Reads only the final line (seek from end) so the chain head is O(1)-ish even
    when the log is large. Any read failure yields genesis - a fresh chain start
    is safe (a later verifier sees the break, it is never silently papered over).
    """
    genesis = "0" * 64
    try:
        if not skeleton.exists() or skeleton.stat().st_size == 0:
            return genesis
        with skeleton.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            # walk backwards to the start of the last non-empty line
            step = min(size, 4096)
            fh.seek(size - step)
            tail = fh.read().splitlines()
            for raw in reversed(tail):
                if raw.strip():
                    rec = json.loads(raw.decode("ascii"))
                    return rec.get("entry_hash", genesis)
    except (OSError, ValueError):
        return genesis
    return genesis


# Human-oversight fields are first-class (Singapore Agentic-AI Framework: the
# most distinguishing new requirement). A decision that surfaces to a human
# carries the reviewer verdict + latency so an override-RATE and response-time
# can be computed straight from the log.
@dataclass(frozen=True)
class HumanOversight:
    escalated_to_human: bool = False
    human_decision: str | None = None      # "override_allow" | "confirm_block" | None
    reviewer_id: str | None = None          # pseudonymous; goes to sidecar
    intervention_latency_s: float | None = None
    rationale_for_non_escalation: str | None = None  # DIFC breach-register style


@dataclass(frozen=True)
class AuditRecord:
    """One decision, pre-split. :func:`record_decision` divides it into the
    non-personal skeleton (hashed) and the personal sidecar (redactable)."""

    decision: str                       # "block" | "allow" | "warn" | "disarmed" | "shadow_block"
    reason: str
    source: str                         # framework: claude_code_hook | crewai | ...
    # rule provenance - which layer/rule decided, and its version, so a
    # decision is reproducible and a rule-change is a traceable corrective action
    rule_id: str | None = None
    rule_version: str | None = None
    rule_logic_human_readable: str | None = None  # Quebec/Chile/MX disclosable
    # risk
    risk_tier: str | None = None        # SDAIA/DIFC per-decision tier
    # the personal / secret side (only these ever get redacted)
    raw_action: str = ""                # the command - sidecar only, opt-in
    actor_id: str | None = None         # agent/model id or human-on-behalf
    actor_role: str | None = None       # "agent" | "human" | "agent+human"
    host: str | None = None
    region: str | None = None           # jurisdiction routing key
    # oversight + integrity flags
    human: HumanOversight = field(default_factory=HumanOversight)
    was_encrypted: bool = False         # NZ s.113 safe-harbour flag
    awareness_timestamp: str | None = None  # ME/AU breach-clock: when KNOWN
    # full per-stage decision trace: ((stage, verdict, detail), ...). Non-personal
    # (rule/verdict names, no PII) so it lives in the hash-chained skeleton - the
    # AI Act Art.12 traceability record: WHICH stage decided and why.
    stages: tuple[tuple[str, str, str], ...] = ()


def _skeleton_entry(
    rec: AuditRecord, *, entry_id: str, prev_hash: str, event_ts: str, input_hash: str
) -> dict[str, Any]:
    """Build the NON-PERSONAL, hashable skeleton. No raw command, no actor
    name, no host - only their hashes / roles / flags. This is what is retained
    to the longest floor and what the hash-chain protects."""
    body = {
        "schema": _SCHEMA_VERSION,
        "entry_id": entry_id,
        "event_timestamp": event_ts,
        "awareness_timestamp": rec.awareness_timestamp or event_ts,
        "decision": rec.decision,
        "reason": ascii_safe(rec.reason),
        "rule_id": rec.rule_id,
        "rule_version": rec.rule_version,
        "rule_logic_human_readable": (
            ascii_safe(rec.rule_logic_human_readable)
            if rec.rule_logic_human_readable else None
        ),
        "risk_tier": rec.risk_tier,
        "actor_role": rec.actor_role,     # role is not personal; identity is (sidecar)
        "region": rec.region,
        "stages": [[ascii_safe(str(a)), ascii_safe(str(b)), ascii_safe(str(c))]
                   for (a, b, c) in rec.stages],  # per-stage trace (Art.12)
        "input_hash": input_hash,          # re-derive the decision w/o the plaintext
        "was_encrypted": rec.was_encrypted,
        "was_redacted": not _truthy(_RAW_OPT_IN_ENV),  # true unless raw opted in
        # human oversight - non-personal parts (reviewer_id is personal -> sidecar)
        "escalated_to_human": rec.human.escalated_to_human,
        "human_decision": rec.human.human_decision,
        "intervention_latency_s": rec.human.intervention_latency_s,
        "rationale_for_non_escalation": (
            ascii_safe(rec.human.rationale_for_non_escalation)
            if rec.human.rationale_for_non_escalation else None
        ),
        "gatecat_version": _GATECAT_VERSION,
    }
    # the chain: this entry commits to the previous entry's hash. entry_hash
    # covers prev_hash + the whole body, so any later edit to a middle entry
    # invalidates every hash after it.
    body["prev_hash"] = prev_hash
    body["entry_hash"] = _chain_mac(prev_hash, json.dumps(body, sort_keys=True))
    return body


def _sidecar_entry(rec: AuditRecord, *, entry_id: str) -> dict[str, Any] | None:
    """Build the PERSONAL / secret sidecar, keyed to the skeleton by entry_id.
    Returns None when there is nothing personal to store (so we don't write an
    empty line). Raw command + actor id are each opt-in; without opt-in the
    slot is omitted entirely - GDPR minimization, not just masked."""
    store_raw = _truthy(_RAW_OPT_IN_ENV)
    store_actor = _truthy(_ACTOR_OPT_IN_ENV)
    payload: dict[str, Any] = {"schema": _SCHEMA_VERSION, "entry_id": entry_id}
    wrote_personal = False
    if store_raw and rec.raw_action:
        payload["raw_action"] = ascii_safe(rec.raw_action[:2000])
        wrote_personal = True
    if store_actor and rec.actor_id:
        payload["actor_id"] = ascii_safe(rec.actor_id)
        wrote_personal = True
    if store_actor and rec.human.reviewer_id:
        payload["reviewer_id"] = ascii_safe(rec.human.reviewer_id)
        wrote_personal = True
    if rec.host:
        # host is country-level residency-relevant but low-sensitivity; still
        # gated behind actor opt-in since it can identify a person's machine
        if store_actor:
            payload["host"] = ascii_safe(rec.host)
            wrote_personal = True
    return payload if wrote_personal else None


def record_decision(rec: AuditRecord) -> str | None:
    """Append one decision to the split audit log. Returns the entry_id (so a
    caller can later attach a human-oversight follow-up to the same decision),
    or None if audit writing is unavailable.

    Best-effort and fail-OPEN-for-logging (never for the gate): any error here
    is swallowed - the block/allow was already decided upstream."""
    try:
        event_ts = _now_iso()
        # entry_id = event_ts + a process-unique nonce (pid + monotonic counter).
        # The nonce guarantees uniqueness even when two decisions share a byte-
        # identical (reason, raw_action, decision) in the same UTC second, so a
        # GDPR erasure targets exactly one subject's row (collision fix, MED).
        nonce = f"{_PID:x}-{next(_ENTRY_COUNTER):x}"
        entry_id = f"{event_ts}-{_sha256(nonce)[:12]}"
        input_hash = _sha256(rec.raw_action) if rec.raw_action else _sha256(rec.reason)

        directory = audit_dir()
        directory.mkdir(parents=True, exist_ok=True)
        skeleton = directory / _SKELETON_NAME
        # Serialize read-prev-hash + append under an exclusive lock so concurrent
        # writers (per-command hook processes, multi-agent hosts) cannot both
        # read the same prev_hash and fork the chain (concurrent-corruption fix,
        # HIGH). The lock spans the read AND the write - that atomicity is the
        # whole point; a lock around only the write would not stop the fork.
        with _file_lock(directory / ".audit.lock"):
            prev_hash = _last_entry_hash(skeleton)
            skel = _skeleton_entry(
                rec, entry_id=entry_id, prev_hash=prev_hash,
                event_ts=event_ts, input_hash=input_hash,
            )
            # WORM-ish: append-only. Real immutability is the deployer's FS/ACL
            # job (documented); the hash-chain makes any in-place edit DETECTABLE
            # (against a naive editor) on a mutable FS - see verify_chain's note
            # on the keyed-MAC option for adversarial tamper-EVIDENCE.
            with skeleton.open("a", encoding="ascii") as fh:
                fh.write(json.dumps(skel) + "\n")

            side = _sidecar_entry(rec, entry_id=entry_id)
            if side is not None:
                sidecar = directory / _SIDECAR_NAME
                with sidecar.open("a", encoding="ascii") as fh:
                    fh.write(json.dumps(side) + "\n")
        return entry_id
    except (OSError, ValueError, TypeError):
        return None  # best-effort; never mask or alter the gate's decision


def verify_chain(skeleton: Path | None = None) -> tuple[bool, int, str | None]:
    """Re-walk the skeleton and confirm every entry_hash chains to the prior.

    Returns (ok, entries_checked, first_bad_entry_id). This is what a
    ``gate.cat audit --verify`` command / an auditor runs to prove the log was
    not rewritten. Pure read; no side effects."""
    path = skeleton or (audit_dir() / _SKELETON_NAME)
    prev = "0" * 64
    checked = 0
    try:
        if not path.exists():
            return True, 0, None
        with path.open("r", encoding="ascii") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                stored = rec.get("entry_hash")
                stored_prev = rec.get("prev_hash")
                # Recompute exactly as _skeleton_entry did. There, prev_hash is
                # set on body FIRST, then entry_hash = sha256(prev + body) with
                # body still carrying prev_hash and WITHOUT entry_hash. Mirror
                # that: drop only entry_hash, keep prev_hash in the hashed body.
                body = {k: v for k, v in rec.items() if k != "entry_hash"}
                recomputed = _chain_mac(stored_prev, json.dumps(body, sort_keys=True))
                if stored_prev != prev or recomputed != stored:
                    return False, checked, rec.get("entry_id")
                prev = stored
                checked += 1
        return True, checked, None
    except (OSError, ValueError):
        return False, checked, None


def redact_entry(entry_id: str, sidecar: Path | None = None) -> bool:
    """Crypto-shred one decision's PII sidecar row on a data-subject request,
    WITHOUT touching the skeleton (its hash-chain stays valid - the skeleton
    never held the PII). Rewrites the sidecar minus that entry_id. Returns True
    if a row was removed.

    This is the GDPR/NZ/Canada erasure path: the personal side goes, the
    non-personal tamper-evident decision record remains for the retention floor."""
    path = sidecar or (audit_dir() / _SIDECAR_NAME)
    try:
        if not path.exists():
            return False
        kept: list[str] = []
        removed = False
        with path.open("r", encoding="ascii") as fh:
            for line in fh:
                s = line.strip()
                if not s:
                    continue
                rec = json.loads(s)
                if rec.get("entry_id") == entry_id:
                    removed = True
                    continue
                kept.append(s)
        if removed:
            tmp = path.with_suffix(".tmp")
            tmp.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="ascii")
            tmp.replace(path)
        return removed
    except (OSError, ValueError):
        return False


def _cli(argv: list[str] | None = None) -> int:
    """`python -m gatecat.integrations._audit verify|redact <entry_id>`.

    The auditor-facing tool: ``verify`` re-walks the hash-chain and PROVES the
    skeleton was not rewritten (exit 0 = intact, 1 = tampered); ``redact``
    crypto-shreds one decision's PII sidecar row on a data-subject request while
    leaving the tamper-evident skeleton whole. ASCII-only output (D1)."""
    import sys

    args = list(sys.argv[1:] if argv is None else argv)
    cmd = args[0] if args else "verify"

    if cmd == "verify":
        skel = audit_dir() / _SKELETON_NAME
        ok, n, bad = verify_chain(skel)
        if ok:
            print(f"gate.cat audit: OK - {n} entries, hash-chain intact ({skel})")
            return 0
        print(f"gate.cat audit: TAMPERED - chain breaks at entry {bad} "
              f"after {n} good entries ({skel})")
        return 1

    if cmd == "redact":
        if len(args) < 2:
            print("usage: ... redact <entry_id>   (erases that decision's PII sidecar row)")
            return 2
        removed = redact_entry(args[1])
        print(f"gate.cat audit: {'redacted' if removed else 'no matching sidecar row for'} "
              f"{args[1]}")
        return 0 if removed else 1

    print("usage: python -m gatecat.integrations._audit verify | redact <entry_id>")
    return 2


if __name__ == "__main__":  # pragma: no cover
    import sys
    sys.exit(_cli())
