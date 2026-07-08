"""Shared fixtures: a fake ``gatecat.veto`` engine for contract tests.

The real engine (TruthPipeline/VetoGate, 457 tests) lives in the gatecat
SDK and is NOT a dependency of these tests. The fake below implements the
exact seam contract documented in ``gatecat.integrations/_engine.py``:
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

PKG_ROOT = Path(__file__).resolve().parents[2]  # .../packages/gatecat (dir holding the gatecat/ package)

FAKE_VETO = textwrap.dedent(
    '''
    """Fake gatecat.veto implementing the seam contract (tests only)."""
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


# The fake ``gatecat`` package root must satisfy two constraints at once:
#   1. ``gatecat.veto`` resolves to the FAKE above (contract tests drive it).
#   2. ``gatecat.integrations`` (hook/adapters under test) is still importable
#      from the REAL package tree - the fake does not (and must not) reimplement it.
# So the fake ``__init__`` extends its own ``__path__`` with the real package dir:
# fake dir first (veto wins), real dir second (integrations reachable).
FAKE_INIT = textwrap.dedent(
    '''
    """Fake gatecat root (tests only): fake veto wins, real integrations reachable."""
    import os as _os
    __path__ = [_os.path.dirname(__file__), {real_pkg!r}]
    '''
)

# In a dev env the real gatecat is often installed editable (a ``.pth`` adds it
# to ``sys.path`` at startup), which outranks a plain regular-package on PYTHONPATH
# - so ``import gatecat`` would pick up the REAL root and never run the fake
# ``__init__`` above. ``sitecustomize`` runs automatically at interpreter startup
# (the fake root is on PYTHONPATH), before any import, and forces the fake root to
# the front of ``sys.path`` so the fake wins deterministically in dev AND on a clean
# CI where gatecat is not installed at all.
SITECUSTOMIZE = textwrap.dedent(
    '''
    import os, sys
    _fake = os.path.dirname(os.path.abspath(__file__))
    if _fake in sys.path:
        sys.path.remove(_fake)
    sys.path.insert(0, _fake)
    sys.modules.pop("gatecat", None)  # drop any real gatecat imported earlier
    '''
)


@pytest.fixture()
def fake_engine(tmp_path: Path) -> Path:
    """Materialize a fake ``gatecat`` package; return its sys.path root.

    Fake ``gatecat.veto`` implements the seam contract; ``gatecat.integrations``
    is served from the real package tree via the fake ``__init__``'s ``__path__``.
    """
    root = tmp_path / "fake_engine"
    pkg = root / "gatecat"
    pkg.mkdir(parents=True)
    real_pkg = str(PKG_ROOT / "gatecat")
    (pkg / "__init__.py").write_text(FAKE_INIT.format(real_pkg=real_pkg))
    (pkg / "veto.py").write_text(FAKE_VETO)
    (root / "sitecustomize.py").write_text(SITECUSTOMIZE)
    return root


@pytest.fixture()
def hook_env(fake_engine: Path, tmp_path: Path) -> dict[str, str]:
    """Subprocess env: fake engine + this package on PYTHONPATH, tmp audit log."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(fake_engine), str(PKG_ROOT)])
    env["GATECAT_VETO_LOG"] = str(tmp_path / "veto_log.jsonl")
    return env


@pytest.fixture()
def engine_absent_env(tmp_path: Path) -> dict[str, str]:
    """Subprocess env where ``gatecat.integrations`` is importable but the veto
    ENGINE is not - i.e. ``gatecat.veto`` raises on import.

    This is the deterministic way to exercise fail-closed: simply dropping the fake
    from PYTHONPATH is NOT enough, because in a dev env the real gatecat is often
    installed editable (a ``.pth`` puts it on ``sys.path``), so ``gatecat.veto``
    would still import and the hook would (correctly) evaluate instead of blocking.
    Here the fake veto module raises ImportError, so the seam's ``_load_veto_module``
    hits ``EngineUnavailable`` regardless of what is installed.
    """
    root = tmp_path / "engine_absent"
    pkg = root / "gatecat"
    pkg.mkdir(parents=True)
    real_pkg = str(PKG_ROOT / "gatecat")
    (pkg / "__init__.py").write_text(FAKE_INIT.format(real_pkg=real_pkg))
    (pkg / "veto.py").write_text(
        "raise ImportError('veto engine intentionally absent (test)')\n"
    )
    (root / "sitecustomize.py").write_text(SITECUSTOMIZE)
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(root), str(PKG_ROOT)])
    env["GATECAT_VETO_LOG"] = str(tmp_path / "veto_log.jsonl")
    return env


@pytest.fixture()
def engine_on_path(fake_engine: Path, tmp_path: Path, monkeypatch):
    """In-process variant for adapter tests: import fake engine directly."""
    monkeypatch.setenv("GATECAT_VETO_LOG", str(tmp_path / "veto_log.jsonl"))
    monkeypatch.syspath_prepend(str(fake_engine))
    # The seam imports gatecat.veto lazily inside evaluate() and memoizes the
    # constructed gate; make sure neither a previously-imported fake module nor
    # a cached gate from another test leaks in.
    from gatecat.integrations import _engine

    for mod in ("gatecat", "gatecat.veto"):
        sys.modules.pop(mod, None)
    _engine._GATE_CACHE.clear()
    yield
    _engine._GATE_CACHE.clear()
    for mod in ("gatecat", "gatecat.veto"):
        sys.modules.pop(mod, None)


# --------------------------------------------------------------------------
# F16 (council 2026-07-06): onnxruntime can HANG on import inside a WMI probe on
# some Windows / CPython 3.13 hosts, which would wedge the whole suite when a
# test lazily imports it (test_ml_guard -> MiniLM .encode). Probe `import
# onnxruntime` ONCE in a short-lived subprocess; if it does not return quickly,
# auto-skip the ML tests instead of letting the main process hang. This makes the
# ML skip-guard actually effective (available() alone cannot help - the hang is
# in the import itself). Override with GATECAT_FORCE_ML_TESTS=1.
# --------------------------------------------------------------------------
_ONNX_SAFE: "bool | None" = None


def _onnx_import_is_safe() -> bool:
    global _ONNX_SAFE
    if _ONNX_SAFE is not None:
        return _ONNX_SAFE
    if os.environ.get("GATECAT_FORCE_ML_TESTS") == "1":
        _ONNX_SAFE = True
        return True
    import subprocess
    try:
        r = subprocess.run(
            [sys.executable, "-c", "import onnxruntime"],
            capture_output=True, timeout=20,
        )
        _ONNX_SAFE = (r.returncode == 0)
    except (subprocess.TimeoutExpired, OSError):
        _ONNX_SAFE = False
    return _ONNX_SAFE


def pytest_collection_modifyitems(config, items):
    """Skip ML-dependent tests when `import onnxruntime` is unsafe on this host."""
    if _onnx_import_is_safe():
        return
    skip = pytest.mark.skip(
        reason="onnxruntime import unsafe on this host (WMI-probe hang); "
        "set GATECAT_FORCE_ML_TESTS=1 to force"
    )
    for item in items:
        if "test_ml_guard" in str(item.fspath):
            item.add_marker(skip)
