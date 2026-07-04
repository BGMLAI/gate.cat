"""B5: pin the autogen#7770 repro so the $106k demo can't silently rot.

If TERRAFORM_PROD stops catching the incident action, this fails - the story
in the pitch must always be backed by a real `block` (rada#2: our own honest
line applies to our own marketing).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPRO = Path(__file__).resolve().parents[1] / "examples" / "repro_autogen_7770.py"


def test_repro_runs_and_blocks_the_incident_action(tmp_path):
    """The repro exits 0 (its own PASS check) and its output shows the exact
    incident Terraform action BLOCKED by TERRAFORM_PROD."""
    # inherit the full env (USERPROFILE/SYSTEMROOT etc. are needed on Windows for
    # Path.home()); only redirect the audit log so the test writes to tmp.
    env = dict(os.environ)
    env["CACHEBACK_VETO_LOG"] = str(tmp_path / "log.jsonl")
    proc = subprocess.run(
        [sys.executable, str(REPRO)],
        capture_output=True, text=True, env=env, timeout=30,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = proc.stdout
    assert "BLOCK  terraform apply -auto-approve" in out
    assert "TERRAFORM_PROD" in out
    assert "[PASS]" in out
    # honest edge is present, not hidden
    assert "does NOT catch" in out and "UNCHECKED" in out
