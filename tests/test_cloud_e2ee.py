"""gate.cat Cloud — end-to-end encryption + zero-knowledge server (council red line).

The load-bearing guarantee: events are encrypted on the client with a key the
server never sees; the server stores ciphertext + timestamp only.
"""
import importlib.util
import json
import os
import tempfile

import pytest

from gatecat import cloud_crypto as cc

pytest.importorskip("cryptography")


@pytest.fixture()
def keyfile(monkeypatch):
    p = tempfile.mktemp()
    monkeypatch.setenv("GATECAT_CLOUD_KEY_FILE", p)
    monkeypatch.delenv("GATECAT_CLOUD_PASSPHRASE", raising=False)
    return p


def test_key_is_32_bytes_and_stable(keyfile):
    k1 = cc.load_or_create_key()
    k2 = cc.load_or_create_key()
    assert len(k1) == 32 and k1 == k2
    assert oct(os.stat(cc.key_path()).st_mode)[-3:] == "600"


def test_ciphertext_is_opaque_and_roundtrips(keyfile):
    key = cc.load_or_create_key()
    ev = {"ts": 1, "policy": "RM_RF", "decision": "block", "reason": "rm -rf /"}
    blob = cc.encrypt_event(key, ev)
    assert "RM_RF" not in blob and "rm -rf" not in blob
    assert cc.decrypt_event(key, blob) == ev


def test_tamper_and_wrong_key_rejected(keyfile):
    key = cc.load_or_create_key()
    blob = cc.encrypt_event(key, {"policy": "X"})
    bad = blob[:-4] + ("AAAA" if blob[-4:] != "AAAA" else "BBBB")
    with pytest.raises(Exception):
        cc.decrypt_event(key, bad)
    with pytest.raises(Exception):
        cc.decrypt_event(os.urandom(32), blob)


def test_export_import_roundtrip(keyfile):
    key = cc.load_or_create_key()
    exported = cc.export_key()
    p2 = tempfile.mktemp()
    cc.import_key(exported, p2)
    assert cc.load_or_create_key(p2) == key


def test_passphrase_key_is_deterministic(monkeypatch):
    monkeypatch.setenv("GATECAT_CLOUD_PASSPHRASE", "team-secret")
    a = cc.load_or_create_key()
    b = cc.load_or_create_key()
    assert a == b and len(a) == 32


def _load_server():
    path = os.path.join(os.path.dirname(__file__), "..", "products", "cloud", "cloud_server.py")
    spec = importlib.util.spec_from_file_location("cloud_server", os.path.abspath(path))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_server_is_zero_knowledge(keyfile, monkeypatch, tmp_path):
    monkeypatch.setenv("CLOUD_DATA_DIR", str(tmp_path))
    srv = _load_server()
    srv._ensure()
    api_key = srv.issue_key("acct1", "solo")
    assert srv._account_for(api_key)["account"] == "acct1"
    assert srv._account_for("gck_wrong") is None

    key = cc.load_or_create_key()
    events = [{"ts": 1, "policy": "DB_DESTRUCTIVE", "reason": "DROP TABLE users"},
              {"ts": 2, "policy": "TERRAFORM_PROD", "reason": "terraform destroy"}]
    batch = [{"ts": e["ts"], "ct": cc.encrypt_event(key, e)} for e in events]
    assert srv._store("acct1", batch) == 2

    raw = open(os.path.join(str(tmp_path), "events", "acct1.jsonl")).read()
    assert "DB_DESTRUCTIVE" not in raw and "terraform" not in raw and "DROP TABLE" not in raw
    stored = [json.loads(l) for l in raw.splitlines()]
    assert set(stored[0].keys()) == {"seq", "ts", "ct"}

    back = srv._read("acct1", since=0)
    assert [cc.decrypt_event(key, r["ct"]) for r in back] == events
    assert srv._read("acct1", since=1) == back[1:]
