"""Shared fixtures: a fake ``cacheback.veto`` engine for contract tests.

The real engine (TruthPipeline/VetoGate, 457 tests) lives in the cacheback
SDK and is NOT a dependency of these tests. The fake below implements the
exact seam contract documented in ``cacheback.integrations/_engine.py``:
``VetoGate(policies=[dict])`` + ``before_action(action, source=...)`` ->
object with ``blocked``/``reason``/``policy``. Its policy wall is a plain
regex match - enough to pin OUR side of the contract; the engine's own
behavior is pinned by its own suite.
"""

from __future__ import annotations

import os
import sys
import textwrap
from pathlib import Path

import pytest

PKG_ROOT = Path(__file__).resolve().parents[1]

FAKE_VETO = textwrap.dedent(
    '''
    """Fake cacheback.veto implementing the seam contract (tests only)."""
    import re


    class ActionVetoed(RuntimeError):
        pass


    class _Decision:
        def __init__(self, blocked, reason, policy=None):
            self.blocked = blocked
            self.reason = reason
            self.policy = policy


    class VetoGate:
        def __init__(self, policies):
            self._policies = policies

        def before_action(self, action, source=""):
            for pol in self._policies:
                for pattern in pol["patterns"]:
                    if re.search(pattern, action, re.IGNORECASE):
                        return _Decision(True, pol["reason"], pol["name"])
            return _Decision(False, "allowed", None)
    '''
)


@pytest.fixture()
def fake_engine(tmp_path: Path) -> Path:
    """Materialize a fake ``cacheback.veto`` package; return its sys.path root."""
    root = tmp_path / "fake_engine"
    pkg = root / "cacheback"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "veto.py").write_text(FAKE_VETO)
    return root


@pytest.fixture()
def hook_env(fake_engine: Path, tmp_path: Path) -> dict[str, str]:
    """Subprocess env: fake engine + this package on PYTHONPATH, tmp audit log."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(fake_engine), str(PKG_ROOT)])
    env["CACHEBACK_VETO_LOG"] = str(tmp_path / "veto_log.jsonl")
    return env


@pytest.fixture()
def engine_on_path(fake_engine: Path, tmp_path: Path, monkeypatch):
    """In-process variant for adapter tests: import fake engine directly."""
    monkeypatch.setenv("CACHEBACK_VETO_LOG", str(tmp_path / "veto_log.jsonl"))
    monkeypatch.syspath_prepend(str(fake_engine))
    # The seam imports cacheback.veto lazily inside evaluate() and memoizes the
    # constructed gate; make sure neither a previously-imported fake module nor
    # a cached gate from another test leaks in.
    from cacheback.integrations import _engine

    for mod in ("cacheback", "cacheback.veto"):
        sys.modules.pop(mod, None)
    _engine._GATE_CACHE.clear()
    yield
    _engine._GATE_CACHE.clear()
    for mod in ("cacheback", "cacheback.veto"):
        sys.modules.pop(mod, None)
