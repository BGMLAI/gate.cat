"""gate.cat cloud CLI — network/auth failures must degrade to ONE clear line,
never a Python traceback on a paying user's terminal. These pin exactly the
three shapes a first-5-minutes subscriber hits (wrong key, server down, and the
happy round-trip), with NO real network: urllib.request.urlopen is stubbed.
"""
from __future__ import annotations

import io
import json
import urllib.error

import pytest

from gatecat import cloud_cli


@pytest.fixture()
def cloud_env(tmp_path, monkeypatch):
    """A logged-in cloud client with an isolated local key file and no network."""
    monkeypatch.setenv("GATECAT_CLOUD_API_KEY", "k")
    monkeypatch.setenv("GATECAT_CLOUD_KEY_FILE", str(tmp_path / "cloud.key"))
    monkeypatch.delenv("GATECAT_CLOUD_PASSPHRASE", raising=False)
    monkeypatch.delenv("GATECAT_CLOUD_ENDPOINT", raising=False)
    return tmp_path


def _stub_urlopen(monkeypatch, handler):
    monkeypatch.setattr(cloud_cli.urllib.request, "urlopen", handler)


def test_wrong_key_401_is_one_clear_line_not_a_traceback(cloud_env, monkeypatch):
    """A wrong/expired key (server 401) used to raise HTTPError straight through
    _fetch -> raw stack trace. Now it exits with a single actionable line."""
    def raise_401(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)
    _stub_urlopen(monkeypatch, raise_401)

    with pytest.raises(SystemExit) as exc:
        cloud_cli.cmd_report()
    msg = str(exc.value)
    assert exc.value.code not in (0, None)      # error exit, not success
    assert "401" in msg
    assert "GATECAT_CLOUD_API_KEY" in msg       # names the thing to fix
    assert "Traceback" not in msg               # a message, not a stack


def test_unreachable_host_is_one_clear_line_not_a_traceback(cloud_env, monkeypatch):
    """Server down / offline (URLError) must be a plain line, never a stack."""
    def refuse(req, timeout=None):
        raise urllib.error.URLError("connection refused")
    _stub_urlopen(monkeypatch, refuse)

    with pytest.raises(SystemExit) as exc:
        cloud_cli.cmd_report()
    msg = str(exc.value)
    assert exc.value.code not in (0, None)
    assert "unreachable" in msg.lower()
    assert "Traceback" not in msg


def test_happy_path_round_trip_decrypts_and_reports(cloud_env, monkeypatch, capsys):
    """Correct key + reachable server: the encrypted event round-trips, decrypts
    locally, and cmd_report prints its summary without raising."""
    pytest.importorskip("cryptography")         # decryption path needs the extra
    from gatecat import cloud_crypto
    key = cloud_crypto.load_or_create_key()
    ev = {"ts": "2026-07-24T10:00:00Z", "policy": "RM_RF", "decision": "block",
          "ctx_sha256": "abc"}
    blob = cloud_crypto.encrypt_event(key, ev)

    def serve(req, timeout=None):
        assert req.headers.get("Authorization") == "Bearer k"   # key strip()ed + sent
        return io.BytesIO(json.dumps({"events": [{"ct": blob, "seq": 1}]}).encode())
    _stub_urlopen(monkeypatch, serve)

    cloud_cli.cmd_report()                        # must NOT raise
    out = capsys.readouterr().out
    assert "1 events" in out
    assert "RM_RF" in out
