"""COMPONENT 3 — tamper-evident cloud ledger (ship + verify + export).

The free-core writes hash-chained toggle/override records locally. The reporter
must ALSO ship them (E2EE) tagged as a ledger, and the client must fetch,
decrypt locally, and VERIFY the hash-chain — detecting tamper / gap / reorder.
These pin: ledger records get tagged, the chain verifies when intact, and any
break is detected; plus the portable JSON export.
"""
import json
import os

import pytest

pytest.importorskip("cryptography")   # [cloud] extra; ledger is E2EE

from gatecat import cloud_cli, cloud_crypto, cloud_reporter
from gatecat.integrations import protection as P


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("GATECAT_VETO_LOG", str(tmp_path / "veto.jsonl"))
    monkeypatch.setenv("GATECAT_PROTECTION_FILE", str(tmp_path / "protection.json"))
    monkeypatch.setenv("GATECAT_OVERRIDES_FILE", str(tmp_path / "overrides.json"))
    monkeypatch.setenv("GATECAT_CLOUD_KEY_FILE", str(tmp_path / "cloud.key"))
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def _make_ledger_records():
    """Generate a few chained toggle/override records in the local veto log."""
    P.set_protection("off")
    P.set_protection("on")
    P.add_override("git " + "push --" + "force origin main", ttl_s=60)


def _ship_to_rows(veto_log, key):
    """Emulate the reporter: redact + encrypt each veto-log line, tagging ledger
    events, then assign server seqs. Returns cloud-style rows [{seq, ct, kind}]."""
    rows = []
    seq = 0
    for line in open(veto_log):
        ev = cloud_reporter._redact(json.loads(line), False)
        seq += 1
        row = {"seq": seq, "ct": cloud_crypto.encrypt_event(key, ev)}
        if ev.get("ledger"):
            row["kind"] = "ledger"
        rows.append(row)
    return rows


def test_ledger_records_are_tagged_and_carry_chain(isolated):
    _make_ledger_records()
    key = cloud_crypto.load_or_create_key()
    rows = _ship_to_rows(isolated / "veto.jsonl", key)
    ledger_rows = [r for r in rows if r.get("kind") == "ledger"]
    # off + on + override_grant = 3 chained ledger records
    assert len(ledger_rows) == 3
    # decrypt and confirm chain fields are present
    dec = cloud_cli._decrypt_all(ledger_rows)
    assert all(r.get("chain_self") for r in dec)


def test_intact_chain_verifies(isolated):
    _make_ledger_records()
    key = cloud_crypto.load_or_create_key()
    rows = [r for r in _ship_to_rows(isolated / "veto.jsonl", key) if r.get("kind") == "ledger"]
    dec = [r for r in cloud_cli._decrypt_all(rows) if r.get("ledger")]
    chk = cloud_cli.verify_chain(dec)
    assert chk["ok"] is True
    assert chk["n"] == 3
    assert chk["breaks"] == []


def test_reordered_chain_detected(isolated):
    """(e) a tampered/reordered ledger breaks the hash-chain."""
    _make_ledger_records()
    key = cloud_crypto.load_or_create_key()
    rows = [r for r in _ship_to_rows(isolated / "veto.jsonl", key) if r.get("kind") == "ledger"]
    # swap the first two records (their seq order now disagrees with the chain)
    swapped = [
        {"seq": 1, "ct": rows[1]["ct"]},
        {"seq": 2, "ct": rows[0]["ct"]},
        {"seq": 3, "ct": rows[2]["ct"]},
    ]
    dec = [r for r in cloud_cli._decrypt_all(swapped) if r.get("ledger")]
    chk = cloud_cli.verify_chain(dec)
    assert chk["ok"] is False
    assert chk["breaks"]


def test_dropped_record_detected(isolated):
    """A missing (deleted) ledger record breaks the chain (gap detection)."""
    _make_ledger_records()
    key = cloud_crypto.load_or_create_key()
    rows = [r for r in _ship_to_rows(isolated / "veto.jsonl", key) if r.get("kind") == "ledger"]
    dropped = [{"seq": 1, "ct": rows[0]["ct"]}, {"seq": 3, "ct": rows[2]["ct"]}]
    dec = [r for r in cloud_cli._decrypt_all(dropped) if r.get("ledger")]
    chk = cloud_cli.verify_chain(dec)
    assert chk["ok"] is False


def test_tampered_ciphertext_is_undecryptable(isolated):
    """A rewritten ciphertext fails AES-GCM auth -> flagged undecryptable, so it
    cannot silently masquerade as a valid ledger record."""
    _make_ledger_records()
    key = cloud_crypto.load_or_create_key()
    rows = [r for r in _ship_to_rows(isolated / "veto.jsonl", key) if r.get("kind") == "ledger"]
    import base64
    raw = bytearray(base64.b64decode(rows[1]["ct"]))
    raw[-1] ^= 0x01                       # flip a tag bit
    rows[1]["ct"] = base64.b64encode(bytes(raw)).decode()
    dec = cloud_cli._decrypt_all(rows)
    assert any(r.get("_undecryptable") for r in dec)


def test_empty_ledger_verifies_trivially(isolated):
    assert cloud_cli.verify_chain([]) == {"ok": True, "n": 0, "breaks": []}


# ---- CLI verbs (ledger / ledger export) over a mocked server ----------------

def test_cmd_ledger_export_writes_json(isolated, monkeypatch, capsys):
    _make_ledger_records()
    key = cloud_crypto.load_or_create_key()
    rows = [r for r in _ship_to_rows(isolated / "veto.jsonl", key) if r.get("kind") == "ledger"]
    monkeypatch.setenv("GATECAT_CLOUD_API_KEY", "gck_test")

    def fake_get_json(path):
        assert path == "/ledger"
        return {"ledger": rows, "tier": "team"}

    monkeypatch.setattr(cloud_cli, "_get_json", fake_get_json)
    out_file = str(isolated / "export.json")
    cloud_cli.cmd_ledger(["export", out_file])
    data = json.loads(open(out_file).read())
    assert data["chain_verified"] is True
    assert data["count"] == 3
    assert len(data["ledger"]) == 3


def test_cmd_ledger_upgrade_message_on_402(isolated, monkeypatch):
    monkeypatch.setenv("GATECAT_CLOUD_API_KEY", "gck_solo")

    def fake_get_json(path):
        raise cloud_cli._UpgradeRequired("ledger export requires Team")

    monkeypatch.setattr(cloud_cli, "_get_json", fake_get_json)
    with pytest.raises(SystemExit) as e:
        cloud_cli.cmd_ledger([])
    assert "Team" in str(e.value)


def test_cmd_ledger_detects_tamper_and_exits_3(isolated, monkeypatch):
    _make_ledger_records()
    key = cloud_crypto.load_or_create_key()
    rows = [r for r in _ship_to_rows(isolated / "veto.jsonl", key) if r.get("kind") == "ledger"]
    tampered = [
        {"seq": 1, "ct": rows[1]["ct"]},
        {"seq": 2, "ct": rows[0]["ct"]},
        {"seq": 3, "ct": rows[2]["ct"]},
    ]
    monkeypatch.setenv("GATECAT_CLOUD_API_KEY", "gck_team")
    monkeypatch.setattr(cloud_cli, "_get_json", lambda p: {"ledger": tampered})
    with pytest.raises(SystemExit) as e:
        cloud_cli.cmd_ledger([])
    assert e.value.code == 3
