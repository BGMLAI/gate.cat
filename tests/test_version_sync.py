"""The runtime version string must track pyproject — regression for the
0.4.18 wheel, which shipped with distribution metadata 0.4.18 but
``gatecat.__version__ == "0.4.17"`` (caught 2026-07-23 during the F9 re-pin;
cosmetic, but it makes support and bug reports lie about the installed
version). A bare literal comparison keeps this deterministic in dev checkouts
where importlib.metadata may see no installed distribution.
"""
from pathlib import Path

import tomllib

import gatecat


def test_runtime_version_matches_pyproject():
    pyproject = tomllib.loads(
        (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())

    assert gatecat.__version__ == pyproject["project"]["version"]
