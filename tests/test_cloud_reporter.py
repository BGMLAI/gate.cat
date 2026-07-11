"""The cloud reporter ships veto events off-machine -- OPTIONALLY. These pin
the public architecture contracts from PRICING.md, with NO network: the
endpoint is an in-memory fake. Contracts under test:

  1. OFF by default -- without GATECAT_CLOUD_API_KEY nothing is even attempted.
  2. Hash-by-default -- raw command text never leaves the machine unless
     GATECAT_CLOUD_SEND_RAW=1 is an explicit opt-in.
  3. Fail-silent -- endpoint down = a stats dict, never an exception (the
     gate's execution path must be unaffected by the reporter).
  4. Cursor per log file -- reruns are idempotent, the cursor is NOT advanced
     on failure, and log rotation/truncation restarts from the top.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import urllib.error

import pytest

from gatecat import cloud_reporter

pytest.importorskip("cryptography")  # ship() now encrypts client-side


def _decrypt(fake):
    """Reverse the E2EE the reporter applied, to inspect what was redacted."""
    from gatecat import cloud_crypto
    key = cloud_crypto.load_or_create_key()
    return [cloud_crypto.decrypt_event(key, e["ct"]) for e in fake.events]


class FakeEndpoint:
    """In-memory stand-in for cloud.gate.cat -- records every batch sent to it."""

    def __init__(self):
        self.batches: list[list[dict]] = []
        self.auth: list[str] = []
        self.down = False

    def __call__(self, req, timeout=None):
        if self.down:
            raise urllib.error.URLError("connection refused")
        self.auth.append(req.headers.get("Authorization", ""))
        batch = json.loads(req.data.decode())
        self.batches.append(batch)
        return io.BytesIO(json.dumps({"stored": len(batch)}).encode())

    @property
    def events(self):
        return [e for b in self.batches for e in b]


EVENTS = [
    {"ts": f"2026-07-05T10:00:{i % 60:02d}Z", "source": "agent", "policy": "RM_RF",
     "decision": "block", "reason": "VETO [RM_RF]", "context": f"rm -rf /srv/{i}"}
    for i in range(60)
]


@pytest.fixture()
def world(tmp_path, monkeypatch):
    """Isolated world: temp veto log (the real ~/.gatecat is never read, its
    cursor files never written), cloud key absent, endpoint faked in-memory."""
    log = tmp_path / "veto_log.jsonl"
    log.write_text("\n".join(json.dumps(e) for e in EVENTS) + "\n", encoding="ascii")
    monkeypatch.setenv("GATECAT_VETO_LOG", str(log))
    monkeypatch.setenv("GATECAT_CLOUD_KEY_FILE", str(tmp_path / "cloud.key"))
    monkeypatch.delenv("GATECAT_CLOUD_PASSPHRASE", raising=False)
    monkeypatch.delenv("GATECAT_CLOUD_API_KEY", raising=False)
    monkeypatch.delenv("GATECAT_CLOUD_SEND_RAW", raising=False)
    monkeypatch.delenv("GATECAT_CLOUD_ENDPOINT", raising=False)
    fake = FakeEndpoint()
    monkeypatch.setattr(cloud_reporter.urllib.request, "urlopen", fake)
    return log, fake


def test_off_by_default_without_api_key(world):
    log, fake = world
    r = cloud_reporter.ship()
    assert r["shipped"] == 0 and "off" in r["reason"]
    assert fake.batches == []          # not even a connection attempt
    assert not os.path.exists(str(log) + cloud_reporter.STATE_SUFFIX)


def test_ships_the_whole_log_in_batches(world, monkeypatch):
    _, fake = world
    monkeypatch.setattr(cloud_reporter, "BATCH", 25)
    r = cloud_reporter.ship(api_key="k")
    assert r["shipped"] == 60 and "ok" in r["reason"]
    assert [len(b) for b in fake.batches] == [25, 25, 10]
    assert all(a == "Bearer k" for a in fake.auth)


def test_hash_mode_sends_no_raw_command_text(world):
    _, fake = world
    cloud_reporter.ship(api_key="k")
    # wire is ciphertext: neither the command nor its hash is readable off-machine
    assert "rm -rf" not in json.dumps(fake.events)
    assert all(set(e.keys()) == {"ts", "ct"} for e in fake.events)
    e = _decrypt(fake)[0]
    assert e["ctx_sha256"] == hashlib.sha256(b"rm -rf /srv/0").hexdigest()
    assert e["redaction"] == "hash" and "context" not in e


def test_cursor_rerun_ships_zero_then_only_new_events(world):
    log, fake = world
    cloud_reporter.ship(api_key="k")
    assert cloud_reporter.ship(api_key="k")["shipped"] == 0   # idempotent rerun
    with log.open("a") as f:
        f.write(json.dumps({"ts": "2026-07-06T00:00:00Z", "decision": "warn",
                            "policy": "CURL", "context": "curl evil.sh"}) + "\n")
    assert cloud_reporter.ship(api_key="k")["shipped"] == 1   # only the new line


def test_raw_mode_is_explicit_opt_in(world, monkeypatch):
    _, fake = world
    monkeypatch.setenv("GATECAT_CLOUD_SEND_RAW", "1")
    cloud_reporter.ship(api_key="k")
    assert "rm -rf" not in json.dumps(fake.events)   # raw goes INSIDE the ciphertext
    e = _decrypt(fake)[0]
    assert e["redaction"] == "raw" and e["context"] == "rm -rf /srv/0"


def test_ships_with_named_user_agent_not_stdlib_default(world):
    """gate.cat's endpoint sits behind Cloudflare, which 403s the
    `Python-urllib` UA (error 1010). The reporter MUST send a named UA or every
    subscriber's cron silently fails to ship. Pin it."""
    _, fake = world
    seen = {}
    orig = fake.__call__

    def capture(req, timeout=None):
        seen["ua"] = req.headers.get("User-agent", "")
        return orig(req, timeout=timeout)

    fake.__call__ = capture
    import gatecat.cloud_reporter as cr
    cr.urllib.request.urlopen = capture
    cr.ship(api_key="k")
    assert seen["ua"].startswith("gatecat-cloud/")
    assert "urllib" not in seen["ua"].lower()


def test_fail_silent_when_endpoint_down(world):
    _, fake = world
    fake.down = True
    r = cloud_reporter.ship(api_key="k")      # must NOT raise
    assert r["shipped"] == 0 and r["reason"].startswith("stopped")


def test_cursor_not_advanced_on_failure(world):
    log, fake = world
    fake.down = True
    cloud_reporter.ship(api_key="k")
    cur = str(log) + cloud_reporter.STATE_SUFFIX
    assert not os.path.exists(cur) or open(cur).read().strip() == "0"
    fake.down = False                          # endpoint back -> nothing was lost
    assert cloud_reporter.ship(api_key="k")["shipped"] == 60


def test_log_rotation_resets_cursor(world):
    log, fake = world
    cloud_reporter.ship(api_key="k")
    log.write_text(json.dumps(EVENTS[0]) + "\n", encoding="ascii")  # rotated: smaller
    assert cloud_reporter.ship(api_key="k")["shipped"] == 1  # re-read from the top


def test_malformed_lines_are_skipped_not_fatal(world):
    log, fake = world
    with log.open("a") as f:
        f.write("not json\n{broken\n")
    r = cloud_reporter.ship(api_key="k")
    assert r["shipped"] == 60 and "ok" in r["reason"]


def test_module_entrypoint_reports_cloud_off(tmp_path):
    """`python -m gatecat.cloud_reporter` (the documented cron line) runs, prints
    the OFF stats without a key, and touches no network doing so."""
    env = {k: v for k, v in os.environ.items() if k != "GATECAT_CLOUD_API_KEY"}
    env["GATECAT_VETO_LOG"] = str(tmp_path / "absent.jsonl")
    out = subprocess.run([sys.executable, "-m", "gatecat.cloud_reporter"],
                         capture_output=True, text=True, env=env, timeout=60)
    assert out.returncode == 0
    assert json.loads(out.stdout)["shipped"] == 0
