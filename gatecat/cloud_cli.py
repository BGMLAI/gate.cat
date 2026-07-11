"""gate.cat Cloud — the client CLI: init, report, verify, key.

  gate.cat cloud init            create the local encryption key (once)
  gate.cat cloud report          fetch your off-machine history, decrypt it
                                 locally, and summarize — the server never sees
                                 any of this in the clear
  gate.cat cloud verify          compare the off-machine copy against the local
                                 log: entries the agent deleted/rewrote locally
                                 but that already left the machine show up here
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
import urllib.request

from gatecat.cloud_reporter import DEFAULT_ENDPOINT, _log_paths, _redact


def _endpoint() -> str:
    return os.environ.get("GATECAT_CLOUD_ENDPOINT", DEFAULT_ENDPOINT)


def _api_key() -> str:
    k = os.environ.get("GATECAT_CLOUD_API_KEY")
    if not k:
        sys.exit("cloud is off: set GATECAT_CLOUD_API_KEY (Solo/Team subscription)")
    return k


def _fetch(since: int = 0) -> list:
    """GET the account's encrypted events from the server."""
    url = _endpoint().rsplit("/events", 1)[0] + f"/events?since={since}"
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + _api_key()})
    return json.load(urllib.request.urlopen(req, timeout=15)).get("events", [])


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
    if only_remote:
        print(f"\n⚠ {len(only_remote)} event(s) exist off-machine but NOT in the local "
              "log — something rewrote your local history after it shipped.")
        sys.exit(3)
    print("\n✓ local log matches the off-machine copy — no tampering detected.")


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
