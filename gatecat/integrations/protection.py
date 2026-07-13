"""FREE-CORE local control layer (2026-07-12): on/off toggle + per-command
manual override, both LOCAL, both FREE, neither able to bypass a catastrophic
policy class.

Red line (non-negotiable, tested in tests/test_redline_invariant.py):
    100% of SAFETY is free. Local control is NEVER paywalled. A human can
    disarm THEIR OWN machine for ORDINARY rules, and can pre-approve ONE exact
    command for a short window - but NEITHER the off-toggle NOR a manual
    override can EVER bypass a catastrophic / irreversible policy class
    (:data:`NEVER_DISARM`). This module needs no cloud key and no entitlement.

Two state files (both under ~/.gatecat/, override the dir root only via the
files' own env vars so tests stay isolated):

  * protection.json  (GATECAT_PROTECTION_FILE) - {"protection": "on"|"off", ...}
  * overrides.json   (GATECAT_OVERRIDES_FILE)  - pre-approved exact commands
                                                 with a TTL and a 'who'.

Every on/off flip and every override grant appends a TAMPER-EVIDENT record to
the veto log: each record carries the sha256 of the PREVIOUS such record
(hash-chained), so a silent edit of one record breaks the chain from there on.
The flip is NEVER silent - it always logs.

SECURITY NOTE: these files are a new attack surface. A shell that WRITES them
via redirect / tee / sed -i / cp / python open('w') is BLOCKED by the
STATE_FILE_TAMPER policy (a NEVER_DISARM class) - the agent must not flip its
own guard or self-approve. The LEGIT path is this module's writers, which the
human reaches through the `gate.cat on/off/allow` CLI - the tool writes the
file itself, not through a gated shell.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Optional

from gatecat.integrations._log import ascii_safe, log_decision, log_path

# ---------------------------------------------------------------------------
# NEVER_DISARM: the catastrophic / irreversible policy CLASSES that neither the
# off-toggle NOR a manual override can ever bypass. A human can turn off the
# ordinary rules on their own machine; they can never turn off these.
#
# Picked from the real policy names in policies.py. Grouped by what they
# destroy:
#   - whole-disk / raw-device / filesystem-root wipes
#   - paid cloud infra + prod IaC teardown
#   - the guard itself + host security controls + the audit trail
#   - the state files that hold THIS layer's own on/off + overrides
#   - secret-file / secret-store / DB destroyers (irreplaceable data/creds)
# DELETE_ANALYZER is included: a catastrophic-root `rm -rf /` blocks through the
# target-anchored analyzer (policy name "DELETE_ANALYZER"), not through RM_RF -
# so a never-disarm gate keyed only on RM_RF would miss it.
# ---------------------------------------------------------------------------
NEVER_DISARM: frozenset[str] = frozenset({
    # filesystem-root / raw-disk / whole-disk erase
    "RM_RF", "DELETE_ANALYZER",
    "DISK_DESTROY", "DISK_DESTROY_EXTRA", "DISK_ERASE_EXTRA",
    "MACOS_DISK_DESTROY", "WINDOWS_DESTROY", "WINDOWS_DESTROY_EXTRA",
    # paid cloud infra + prod infrastructure-as-code teardown
    "CLOUD_DESTROY", "CLOUD_DESTROY_EXTRA",
    "TERRAFORM_PROD", "IAC_STATE_DESTROY", "IAC_STATE_DESTROY_EXTRA",
    "KMS_KEY_DESTROY",
    # the guard itself, host security controls, the audit trail
    "GUARD_TAMPER", "SECURITY_CONTROL_DISABLE", "AUDIT_LOG_TAMPER",
    "STATE_FILE_TAMPER",
    # secret-file / secret-store / DB destroyers (irreplaceable creds/data)
    "SECRET_FILE_DELETE", "SECRET_FILE_OVERWRITE",
    "SECRET_STORE_DELETE", "SECRET_STORE_DELETE_EXTRA", "SECRET_STORE_DELETE_EXTRA2",
    "SECRET_DELETE",
    "DB_DESTRUCTIVE", "DB_DESTRUCTIVE_EXTRA", "DB_DESTRUCTIVE_EXTRA2",
})


def is_never_disarm(policy: Optional[str]) -> bool:
    """True if *policy* names a catastrophic class that neither OFF nor an
    override can ever bypass. None (unknown policy) is NOT never-disarm - the
    off-toggle only downgrades KNOWN block/warn walls, and an override only
    matches an exact pre-approved command, so an unknown-policy block is handled
    by the caller's normal path, not here."""
    return bool(policy) and policy in NEVER_DISARM


# ---------------------------------------------------------------------------
# state file locations (dir isolation for tests via the env vars)
# ---------------------------------------------------------------------------
_PROTECTION_ENV = "GATECAT_PROTECTION_FILE"
_OVERRIDES_ENV = "GATECAT_OVERRIDES_FILE"
_DEFAULT_DIR = Path.home() / ".gatecat"
_DEFAULT_OVERRIDE_TTL_S = 300  # a one-shot pre-approval expires; never permanent


def protection_file() -> Path:
    env = os.environ.get(_PROTECTION_ENV)
    return Path(env) if env else _DEFAULT_DIR / "protection.json"


def overrides_file() -> Path:
    env = os.environ.get(_OVERRIDES_ENV)
    return Path(env) if env else _DEFAULT_DIR / "overrides.json"


# ---------------------------------------------------------------------------
# tamper-evident hash chain: each on/off / override record carries the sha256 of
# the PREVIOUS such record. We keep the tip in a tiny sidecar so we never have to
# re-scan the whole log to append.
# ---------------------------------------------------------------------------
def _chain_tip_file() -> Path:
    # co-located with the veto log so it moves with GATECAT_VETO_LOG in tests.
    return log_path().parent / ".gatecat_chain_tip"


def _read_chain_tip() -> str:
    try:
        return _chain_tip_file().read_text(encoding="ascii").strip() or "GENESIS"
    except OSError:
        return "GENESIS"


def _write_chain_tip(digest: str) -> None:
    try:
        p = _chain_tip_file()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(digest, encoding="ascii")
    except OSError:
        pass  # best-effort; the record still logged with the prev-hash it had


def _chain_record(kind: str, payload: dict) -> str:
    """Compute this record's digest from (prev_tip, kind, canonical payload)."""
    prev = _read_chain_tip()
    body = json.dumps({"prev": prev, "kind": kind, "payload": payload},
                      sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _log_chained(*, decision: str, reason: str, policy: Optional[str],
                 context: str, kind: str, payload: dict) -> str:
    """Append a hash-chained audit record via the standard veto log. Returns the
    new chain digest. The prev-hash + this digest ride in the reason so the flat
    6-field log stays byte-compatible while carrying the chain."""
    prev = _read_chain_tip()
    digest = _chain_record(kind, payload)
    chained_reason = f"{reason} [chain prev={prev[:16]} self={digest[:16]}]"
    log_decision(source="gatecat_control", decision=decision,
                 reason=chained_reason, policy=policy, context=context)
    _write_chain_tip(digest)
    return digest


# ---------------------------------------------------------------------------
# FEATURE 1 - on/off toggle
# ---------------------------------------------------------------------------
def read_protection() -> str:
    """'on' (default) or 'off'. A missing/corrupt file reads as 'on' (fail-safe:
    the gate is ARMED unless a valid file explicitly says off)."""
    p = protection_file()
    try:
        data = json.loads(p.read_text(encoding="ascii"))
    except (OSError, ValueError):
        return "on"
    state = str(data.get("protection", "on")).strip().lower()
    return "off" if state == "off" else "on"


def is_protection_off() -> bool:
    return read_protection() == "off"


def set_protection(state: str, *, who: Optional[str] = None) -> str:
    """Flip protection on/off. TOOL-OWNED writer (the CLI path): writes the file
    directly, then appends a tamper-evident hash-chained audit record. Never a
    silent flip. Returns the resulting state."""
    state = "off" if str(state).strip().lower() == "off" else "on"
    who = who or os.environ.get("USER") or os.environ.get("USERNAME") or "local"
    p = protection_file()
    p.parent.mkdir(parents=True, exist_ok=True)
    record = {"protection": state, "who": who,
              "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    p.write_text(json.dumps(record, indent=2), encoding="ascii")
    _log_chained(
        decision="disarmed" if state == "off" else "armed",
        reason=(f"protection toggled {state} by {ascii_safe(who)} "
                f"(catastrophic classes still hard-block)"),
        policy=None, context=f"gate.cat {state}",
        kind="toggle", payload={"protection": state, "who": who},
    )
    return state


# ---------------------------------------------------------------------------
# FEATURE 2 - per-command manual override
# ---------------------------------------------------------------------------
def normalize_command(command: str) -> str:
    """Canonical form used as the override key: collapse runs of whitespace and
    strip ends. Deliberately conservative - an override matches the EXACT command
    (modulo incidental spacing), never a family of commands."""
    return " ".join(str(command).split())


def override_hash(command: str) -> str:
    return hashlib.sha256(normalize_command(command).encode("utf-8")).hexdigest()


def _read_overrides() -> dict:
    p = overrides_file()
    try:
        data = json.loads(p.read_text(encoding="ascii"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_overrides(data: dict) -> None:
    p = overrides_file()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2), encoding="ascii")


def add_override(command: str, *, ttl_s: int = _DEFAULT_OVERRIDE_TTL_S,
                 who: Optional[str] = None) -> dict:
    """Pre-approve ONE exact command for *ttl_s* seconds. TOOL-OWNED writer.
    Appends a tamper-evident hash-chained audit record. Returns the entry."""
    who = who or os.environ.get("USER") or os.environ.get("USERNAME") or "local"
    now = time.time()
    h = override_hash(command)
    entry = {"who": who, "granted_at": now, "expires_at": now + float(ttl_s),
             "command_preview": ascii_safe(normalize_command(command))[:80]}
    data = _read_overrides()
    data[h] = entry
    _write_overrides(data)
    _log_chained(
        decision="override_grant",
        reason=(f"manual override granted by {ascii_safe(who)} for one command, "
                f"ttl={int(ttl_s)}s (catastrophic classes can NEVER be overridden)"),
        policy=None, context=entry["command_preview"],
        kind="override_grant",
        payload={"cmd_sha256": h, "who": who, "expires_at": entry["expires_at"]},
    )
    return entry


def consume_override(command: str) -> Optional[dict]:
    """If a VALID, non-expired override exists for the exact normalized command,
    return its entry (and CONSUME it: single-use). Else None. Expired/consumed
    entries are pruned. This does NOT check NEVER_DISARM - the guard does that
    BEFORE calling here, so a never-disarm command can never even look one up."""
    h = override_hash(command)
    data = _read_overrides()
    entry = data.get(h)
    now = time.time()
    changed = False
    # prune expired
    for k in [k for k, v in data.items()
              if isinstance(v, dict) and float(v.get("expires_at", 0)) < now]:
        del data[k]
        changed = True
    if entry is not None and float(entry.get("expires_at", 0)) >= now:
        # valid: consume it (single-use so a pre-approval is not a standing allow)
        del data[h]
        _write_overrides(data)
        return entry
    if changed:
        _write_overrides(data)
    return None


def has_valid_override(command: str) -> bool:
    """Peek without consuming (for the CLI status view)."""
    h = override_hash(command)
    entry = _read_overrides().get(h)
    return bool(entry) and float(entry.get("expires_at", 0)) >= time.time()
