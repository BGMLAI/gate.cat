"""FEATURE 4 - gate-watch the FREE-CORE state files.

An agent WRITING/EDITING ~/.gatecat/protection.json or overrides.json via a shell
(>, >>, tee, sed -i, cp/mv, dd of=, python open('w')/write_text) is BLOCKED, and
this is a NEVER_DISARM class (still blocks with protection OFF). The agent must not
be able to flip its own guard or self-approve. The human's `gate.cat on/off/allow`
CLI writes the file through the TOOL (stdlib, not a shell redirect), so that path
still works. Reads are allowed. 0 false positives on other config paths.
"""
import pytest

from gatecat import ActionVetoed, check_action
from gatecat.integrations import protection as P

_PROD = dict(cwd="/srv/app",
             env={"HOME": "/home/deploy", "PATH": "/usr/bin", "USER": "deploy"},
             home="/home/deploy")


def _verdict(cmd):
    try:
        d = check_action("agent", cmd, **_PROD)
    except ActionVetoed:
        return "block"
    if getattr(d, "blocked", False):
        return "block"
    return "warn" if getattr(d, "level", "") == "warn" else "allow"


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("GATECAT_PROTECTION_FILE", str(tmp_path / "protection.json"))
    monkeypatch.setenv("GATECAT_OVERRIDES_FILE", str(tmp_path / "overrides.json"))
    monkeypatch.setenv("GATECAT_VETO_LOG", str(tmp_path / "veto.jsonl"))
    return tmp_path


@pytest.mark.parametrize("cmd", [
    "echo off > ~/.gatecat/protection.json",
    "echo off >> ~/.gatecat/protection.json",
    "echo '{}' > $HOME/.gatecat/overrides.json",
    "sed -i s/on/off/ ~/.gatecat/protection.json",
    "perl -i -pe s/on/off/ /home/deploy/.gatecat/protection.json",
    "tee ~/.gatecat/protection.json",
    "sudo tee -a /home/deploy/.gatecat/overrides.json",
    "cp /tmp/evil.json ~/.gatecat/protection.json",
    "mv /tmp/evil.json ~/.gatecat/overrides.json",
    "dd if=/tmp/x of=/home/deploy/.gatecat/protection.json",
    ": > ~/.gatecat/protection.json",
    "python3 -c \"open('/home/deploy/.gatecat/protection.json','w').write('off')\"",
    "python3 -c \"open('/home/deploy/.gatecat/overrides.json','a').write('x')\"",
])
def test_shell_write_to_state_file_blocked(cmd):
    assert _verdict(cmd) == "block"


@pytest.mark.parametrize("cmd", [
    "cat ~/.gatecat/protection.json",
    "less ~/.gatecat/overrides.json",
    "python3 -c \"open('/home/deploy/.gatecat/protection.json','r').read()\"",
    "cp ~/.gatecat/protection.json /tmp/backup.json",   # reading FROM state -> backup
    "echo hi > ~/.config/myapp/config.json",            # unrelated config
    "sed -i s/a/b/ ./notes.txt",
    "ls -la ~/.gatecat/",
])
def test_benign_reads_and_other_paths_pass(cmd):
    assert _verdict(cmd) == "allow"


def test_state_write_still_blocked_when_protection_off(isolated):
    P.set_protection("off")           # ordinary rules disarmed...
    # ...but the state files are NEVER_DISARM: still blocked.
    assert _verdict("echo off > ~/.gatecat/protection.json") == "block"
    assert _verdict("sed -i s/x/y/ ~/.gatecat/overrides.json") == "block"


def test_state_write_cannot_be_overridden(isolated):
    P.add_override("echo off > ~/.gatecat/protection.json", ttl_s=300)
    assert _verdict("echo off > ~/.gatecat/protection.json") == "block"


def test_cli_writer_path_still_works(isolated):
    # the human's CLI writes the file through the tool (not a gated shell), so it
    # succeeds even though a shell write to the same file is blocked.
    P.set_protection("off")
    assert P.is_protection_off()
    P.set_protection("on")
    assert not P.is_protection_off()
    P.add_override("some blocked cmd", ttl_s=60)
    assert P.has_valid_override("some blocked cmd")
