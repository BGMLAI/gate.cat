"""gate.cat Cloud reporter -- the OPTIONAL client that ships veto events off-machine.

Architecture contract (public, load-bearing -- see PRICING.md):
  * NEVER in the gate's execution path. The gate writes its local veto_log and
    returns; this reporter tails that log on its own schedule. If this module
    crashes, hangs, or the network is down, verdicts are unaffected.
  * OFF by default. Activates only when GATECAT_CLOUD_API_KEY is set.
  * Hash-by-default: unless GATECAT_CLOUD_SEND_RAW=1, the command text never
    leaves the machine -- only sha256(context) does.
  * Fail-silent by design, but not *invisible*: a stopped reporter produces a
    gap in the off-machine timeline, and a gap is itself signal.

Usage (cron / systemd timer / manual):
    python3 -m gatecat.cloud_reporter          # ship new events since last run

Stdlib-only on purpose: the reporter must run on a plain `pip install gate-cat`
(zero-dep core) and must never pull the ML stack.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.request

DEFAULT_ENDPOINT = "https://gate.cat/cloud/v1/events"   # overridable for self-hosted
STATE_SUFFIX = ".cloud_cursor"
BATCH = 200

# The free-core (protection.py) writes tamper-evident, HASH-CHAINED audit records
# to the same veto log for every on/off flip and every override grant/allow. Those
# decisions form the OFF-MACHINE LEDGER. We detect them by decision type and lift
# the chain hashes out of the reason (`... [chain prev=<hex16> self=<hex16>]`) so
# the CLIENT can verify the chain after decrypting -- the server never sees it.
LEDGER_DECISIONS = frozenset({
    "armed", "disarmed", "disarmed_off",
    "override_grant", "override_allow", "override_deny",
})
_CHAIN_RE = re.compile(r"\[chain prev=(GENESIS|[0-9a-fA-F]+) self=([0-9a-fA-F]+)\]")


def _chain_fields(reason: str):
    """(prev, self) 16-hex chain tips embedded in a ledger reason, else (None, None)."""
    m = _CHAIN_RE.search(reason or "")
    return (m.group(1), m.group(2)) if m else (None, None)


def _log_paths():
    """Every veto log this machine writes. GATECAT_VETO_LOG (the same override
    the dashboard honors) wins; otherwise the two default locations."""
    env = os.environ.get("GATECAT_VETO_LOG")
    candidates = [env] if env else [
        os.path.expanduser("~/.gatecat/veto_log.jsonl"),
        os.path.expanduser("~/.cacheback/veto_log.jsonl"),
    ]
    for p in candidates:
        if p and os.path.exists(p):
            yield p


def _redact(event: dict, send_raw: bool) -> dict:
    ctx = event.get("context") or ""
    decision = event.get("decision")
    reason = (event.get("reason") or "")
    out = {
        "ts": event.get("ts"), "source": event.get("source"),
        "policy": event.get("policy"), "decision": decision,
        "reason": reason[:256],
        "ctx_sha256": hashlib.sha256(ctx.encode()).hexdigest() if ctx else None,
        "gate_version": event.get("gate_version"),
        "redaction": "raw" if send_raw else "hash",
    }
    # LEDGER events carry their hash-chain tips structured inside the (encrypted)
    # payload so the client can verify the chain locally without string-parsing.
    if decision in LEDGER_DECISIONS:
        prev, self_ = _chain_fields(reason)
        if self_ is not None:
            out["ledger"] = True
            out["chain_prev"] = prev
            out["chain_self"] = self_
    if send_raw:
        out["context"] = ctx[:4096]
    return out


def ship(endpoint: str | None = None, api_key: str | None = None,
         send_raw: bool | None = None, timeout: float = 10.0) -> dict:
    """Ship new veto events, END-TO-END ENCRYPTED. Returns stats; raises nothing.

    Each event is encrypted on this machine (gatecat.cloud_crypto) with the local
    account key before it is posted. The server stores an opaque blob plus a
    cleartext timestamp (needed for ordering/retention) and nothing else — it
    cannot read the policy, the reason, or the command. ``send_raw`` controls
    only what goes INSIDE the encrypted blob (hash vs raw command); either way
    the wire and the server see ciphertext.
    """
    api_key = api_key or os.environ.get("GATECAT_CLOUD_API_KEY")
    if not api_key:
        return {"shipped": 0, "reason": "no api key (cloud off -- this is the default)"}
    endpoint = endpoint or os.environ.get("GATECAT_CLOUD_ENDPOINT", DEFAULT_ENDPOINT)
    if send_raw is None:
        send_raw = os.environ.get("GATECAT_CLOUD_SEND_RAW") == "1"
    from gatecat import cloud_crypto  # [cloud] extra; only imported on the ship path
    key = cloud_crypto.load_or_create_key()
    shipped = 0
    for path in _log_paths():
        cursor_file = path + STATE_SUFFIX
        try:
            offset = int(open(cursor_file).read().strip())
        except Exception:
            offset = 0
        try:
            size = os.path.getsize(path)
            if size < offset:          # log rotated/truncated -> start over
                offset = 0
            with open(path, "r", errors="ignore") as f:
                f.seek(offset)
                batch = []
                for line in f:
                    try:
                        ev = _redact(json.loads(line), send_raw)
                        item = {"ts": ev.get("ts"),
                                "ct": cloud_crypto.encrypt_event(key, ev)}
                        # tag ledger records so the server can serve them via
                        # GET /v1/ledger (TEAM+). The tag is the CLASS only; the
                        # command/reason stay inside the encrypted `ct`.
                        if ev.get("ledger"):
                            item["kind"] = "ledger"
                        batch.append(item)
                    except Exception:
                        continue
                    if len(batch) >= BATCH:
                        shipped += _post(endpoint, api_key, batch, timeout)
                        batch = []
                if batch:
                    shipped += _post(endpoint, api_key, batch, timeout)
                new_offset = f.tell()
            with open(cursor_file, "w") as cf:      # advance cursor ONLY after successful ship
                cf.write(str(new_offset))
        except Exception as e:                       # fail-silent: never disturb the gate
            return {"shipped": shipped, "reason": f"stopped: {type(e).__name__}"}
    return {"shipped": shipped, "reason": "ok (e2e-encrypted)"}


def _user_agent() -> str:
    """A named UA, NOT the stdlib default. gate.cat's own endpoint sits behind
    Cloudflare, which 403s (error 1010) the `Python-urllib/x.y` signature -- so a
    default-UA reporter would silently fail to ship for every subscriber. A named
    UA passes and also tags the version server-side for debugging."""
    try:
        from gatecat import __version__ as v
    except Exception:
        v = "0"
    return "gatecat-cloud/" + v


def _post(endpoint: str, api_key: str, batch: list, timeout: float) -> int:
    req = urllib.request.Request(endpoint, data=json.dumps(batch).encode(),
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + api_key,
                 "User-Agent": _user_agent()})
    resp = json.load(urllib.request.urlopen(req, timeout=timeout))
    return int(resp.get("stored", 0))


if __name__ == "__main__":
    print(json.dumps(ship()))
