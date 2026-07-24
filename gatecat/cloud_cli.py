"""gate.cat Cloud — the client CLI: init, report, verify, key.

  gate.cat cloud init            create the local encryption key (once)
  gate.cat cloud report          fetch your off-machine history, decrypt it
                                 locally, and summarize — the server never sees
                                 any of this in the clear
  gate.cat cloud verify          compare the off-machine copy against the local
                                 log: entries the agent deleted/rewrote locally
                                 but that already left the machine show up here;
                                 ALSO verifies the tamper-evident ledger chain
  gate.cat cloud ledger          fetch the override/toggle ledger (Team+),
                                 decrypt locally, verify the hash-chain, print it
  gate.cat cloud ledger export [file]
                                 write a portable JSON export of the ledger
  gate.cat cloud key export      print the key (to share with a Team machine)
  gate.cat cloud key import <b64>  install a shared key

The off-machine copy is the point: an agent with shell access can rewrite the
local veto_log, but it has no credentials for the server and cannot alter what
already shipped. `verify` turns that into a tamper alarm.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

from gatecat.cloud_reporter import (
    DEFAULT_ENDPOINT, LEDGER_DECISIONS, _log_paths, _redact,
)


def _endpoint() -> str:
    return os.environ.get("GATECAT_CLOUD_ENDPOINT", DEFAULT_ENDPOINT)


def _api_key() -> str:
    k = (os.environ.get("GATECAT_CLOUD_API_KEY") or "").strip()
    if not k:
        sys.exit("cloud is off: set GATECAT_CLOUD_API_KEY (Solo/Team subscription)\n"
                 "  get a key: https://gate.cat/teams.html?source=cli "
                 "(Solo EUR 19/mo, Team EUR 149/mo flat)")
    return k


def _base() -> str:
    """The /v1 base of the cloud endpoint (strip the trailing resource)."""
    return _endpoint().rsplit("/events", 1)[0]


class _UpgradeRequired(Exception):
    """The server returned 402/403 -- this is a paid (Team+) feature."""


def _http_get_json(url: str) -> dict:
    """The SINGLE choke point for every authenticated cloud GET.

    All network/auth failure handling lives here, once, so no subcommand ever
    dumps a raw Python traceback on a paying user:
      * 401 -> the key is wrong/expired: one clear line + exit 1 (not a stack).
      * 402/403 -> _UpgradeRequired, so the caller prints a tailored upgrade line.
      * other HTTP / unreachable host / timeout -> one clear line + exit 1.
    Happy path returns the decoded JSON dict.
    """
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + _api_key()})
    try:
        return json.load(urllib.request.urlopen(req, timeout=15))
    except urllib.error.HTTPError as e:
        if e.code in (402, 403):
            try:
                msg = json.load(e).get("message") or "this is a Team feature"
            except Exception:
                msg = "this is a Team feature"
            raise _UpgradeRequired(msg)
        if e.code == 401:
            sys.exit("gate.cat cloud: unauthorized (401) — GATECAT_CLOUD_API_KEY is "
                     "wrong or expired.\n"
                     "  double-check the key, or get a new one: "
                     "https://gate.cat/teams.html?source=cli")
        sys.exit(f"gate.cat cloud: server error (HTTP {e.code}) — try again shortly.")
    except (urllib.error.URLError, TimeoutError) as e:
        reason = getattr(e, "reason", e)
        sys.exit(f"gate.cat cloud: server unreachable ({reason}) — check your network "
                 "or GATECAT_CLOUD_ENDPOINT.")


def _fetch(since: int = 0) -> list:
    """GET the account's encrypted events from the server."""
    return _http_get_json(_base() + f"/events?since={since}").get("events", [])


def _get_json(path: str) -> dict:
    """GET an arbitrary cloud path through the shared choke point (which turns
    402/403 into _UpgradeRequired for a clear upgrade message)."""
    return _http_get_json(_base() + path)


def _decrypt_all(rows: list) -> list:
    from gatecat import cloud_crypto
    key = cloud_crypto.load_or_create_key()
    out = []
    for r in rows:
        try:
            ev = cloud_crypto.decrypt_event(key, r["ct"])
            ev["_seq"] = r.get("seq")
            out.append(ev)
        except Exception:
            out.append({"_seq": r.get("seq"), "_undecryptable": True})
    return out


def cmd_init() -> None:
    from gatecat import cloud_crypto
    key = cloud_crypto.load_or_create_key()
    fp = hashlib.sha256(key).hexdigest()[:16]
    print(f"cloud key ready at {cloud_crypto.key_path()}  (fingerprint {fp})")
    print("This key never leaves your machine. The server stores only ciphertext.")
    print("Lose this file and your off-machine history is unreadable — even to us.")
    print("Back it up (`gate.cat cloud key export`) if that history matters.")


def cmd_report() -> None:
    events = [e for e in _decrypt_all(_fetch()) if not e.get("_undecryptable")]
    if not events:
        print("no events shipped yet (or wrong key).")
        return
    from collections import Counter
    by_policy = Counter(e.get("policy") for e in events if e.get("decision") == "block")
    warns = sum(1 for e in events if e.get("decision") == "warn")
    print(f"gate.cat Cloud report — {len(events)} events, decrypted locally\n")
    print(f"  blocks: {sum(by_policy.values())}   warns: {warns}")
    print("  top blocked policies:")
    for pol, n in by_policy.most_common(8):
        print(f"    {n:4}  {pol}")


def cmd_verify() -> None:
    """Off-machine copy vs local log: what the agent tried to erase."""
    remote = [e for e in _decrypt_all(_fetch()) if not e.get("_undecryptable")]
    remote_fp = {_fp(e) for e in remote}
    local_fp = set()
    for path in _log_paths():
        for line in open(path, errors="ignore"):
            try:
                local_fp.add(_fp(_redact(json.loads(line), False)))
            except Exception:
                continue
    only_remote = remote_fp - local_fp   # shipped, then vanished locally = tamper
    print(f"off-machine events: {len(remote_fp)}   local log events: {len(local_fp)}")

    # ALSO verify the tamper-evident LEDGER chain (Team+). If the account is not
    # entitled, skip quietly — verify still reports on the event set above.
    ledger_broken = False
    try:
        led_rows = _decrypt_all(_get_json("/ledger").get("ledger", []))
        led = [r for r in led_rows if not r.get("_undecryptable")
               and r.get("ledger")]
        chk = verify_chain(led)
        if led:
            if chk["ok"]:
                print(f"ledger: hash-chain intact across {chk['n']} record(s).")
            else:
                ledger_broken = True
                print(f"\n⚠ ledger hash-chain BROKEN at {len(chk['breaks'])} "
                      "point(s) — the off-machine ledger was tampered/reordered.")
    except _UpgradeRequired:
        pass  # ledger is a Team feature; verify of events still stands

    if only_remote:
        print(f"\n⚠ {len(only_remote)} event(s) exist off-machine but NOT in the local "
              "log — something rewrote your local history after it shipped.")
        sys.exit(3)
    if ledger_broken:
        sys.exit(3)
    print("\n✓ local log matches the off-machine copy — no tampering detected.")


def verify_chain(rows: list) -> dict:
    """Verify the hash-chain over decrypted ledger records (ordered by _seq).

    Each ledger record embeds ``chain_prev`` and ``chain_self`` (the free-core's
    hash-chain tips). A valid chain has record[i].chain_prev == record[i-1].
    chain_self, starting from GENESIS. A tampered / reordered / dropped record
    breaks the link at that point. Returns:

        {"ok": bool, "n": int, "breaks": [{"seq":.., "why":..}...]}
    """
    ledger = sorted(
        [r for r in rows if r.get("ledger") and r.get("chain_self")],
        key=lambda r: (r.get("_seq") if r.get("_seq") is not None else 0),
    )
    breaks = []
    expected_prev = "GENESIS"
    for r in ledger:
        prev = r.get("chain_prev")
        # the chain stores 16-hex prefixes; compare on the same width.
        exp = expected_prev[:16] if expected_prev != "GENESIS" else "GENESIS"
        if prev != exp:
            breaks.append({"seq": r.get("_seq"),
                           "why": f"prev={prev} expected={exp}"})
        expected_prev = r.get("chain_self")
    return {"ok": not breaks, "n": len(ledger), "breaks": breaks}


def cmd_ledger(argv: list) -> None:
    """`gate.cat cloud ledger [export [file]]` — fetch the tamper-evident
    override/toggle ledger (TEAM+), decrypt locally, VERIFY the hash-chain, and
    print the history (or write a portable JSON export)."""
    export = bool(argv) and argv[0] == "export"
    export_file = argv[1] if export and len(argv) > 1 else None
    try:
        raw = _get_json("/ledger").get("ledger", [])
    except _UpgradeRequired as e:
        sys.exit(f"gate.cat: the cloud ledger is a Team feature — {e}\n"
                 "Upgrade to Team or Business to read/export it.")
    rows = _decrypt_all(raw)
    ledger = [r for r in rows if not r.get("_undecryptable")
              and r.get("decision") in LEDGER_DECISIONS]
    chk = verify_chain(ledger)

    if export:
        payload = {"ledger": ledger, "chain_verified": chk["ok"],
                   "chain": chk, "count": len(ledger)}
        text = json.dumps(payload, indent=2, sort_keys=True)
        if export_file:
            with open(export_file, "w", encoding="utf-8") as f:
                f.write(text)
            print(f"exported {len(ledger)} ledger record(s) -> {export_file} "
                  f"(chain {'OK' if chk['ok'] else 'BROKEN'})")
        else:
            print(text)
        if not chk["ok"]:
            sys.exit(3)
        return

    if not ledger:
        print("no ledger records shipped yet (toggle/override history is empty, "
              "or wrong key).")
        return
    print(f"gate.cat Cloud ledger — {len(ledger)} record(s), decrypted locally\n")
    for r in sorted(ledger, key=lambda r: (r.get("_seq") or 0)):
        dec = r.get("decision", "?")
        ts = (str(r.get("ts") or "")).replace("T", " ")[:19]
        preview = (r.get("context") or r.get("ctx_sha256") or "")[:40]
        print(f"  #{r.get('_seq'):>4}  {ts:<20}  {dec:<14}  {preview}")
    print()
    if chk["ok"]:
        print(f"✓ hash-chain intact across {chk['n']} record(s) — "
              "no tamper, gap, or reorder detected.")
    else:
        print(f"⚠ hash-chain BROKEN at {len(chk['breaks'])} point(s) — the "
              "off-machine ledger was tampered with, reordered, or is missing a "
              "record:")
        for b in chk["breaks"]:
            print(f"    seq {b['seq']}: {b['why']}")
        sys.exit(3)


def _fp(ev: dict) -> str:
    return hashlib.sha256(
        json.dumps([ev.get("ts"), ev.get("policy"), ev.get("decision"),
                    ev.get("ctx_sha256")], separators=(",", ":")).encode()
    ).hexdigest()


def main(argv: list | None = None) -> None:
    argv = argv if argv is not None else sys.argv[1:]
    # dispatched as `gate.cat cloud <sub>`; also runnable as `python -m gatecat.cloud_cli <sub>`
    if argv and argv[0] == "cloud":
        argv = argv[1:]
    sub = argv[0] if argv else "help"
    if sub == "init":
        cmd_init()
    elif sub == "report":
        cmd_report()
    elif sub == "verify":
        cmd_verify()
    elif sub == "ledger":
        cmd_ledger(argv[1:])
    elif sub == "key" and len(argv) >= 2 and argv[1] == "export":
        from gatecat import cloud_crypto
        print(cloud_crypto.export_key())
    elif sub == "key" and len(argv) >= 3 and argv[1] == "import":
        from gatecat import cloud_crypto
        cloud_crypto.import_key(argv[2])
        print("key installed.")
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
