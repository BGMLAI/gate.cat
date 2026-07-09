"""Cache-path entry points must honor the zero-dep-core contract: a missing
optional dep yields a clear "install the extra" message, never a raw traceback.

We can't uninstall numpy in CI (the [dev] extra pulls it), so we simulate the
missing dep by forcing the underlying import to raise, and assert the rewritten
message names the RIGHT extra.
"""
import builtins
import importlib

import pytest


def _force_import_error(monkeypatch, target_substr, missing_name):
    """Make importlib.import_module raise ImportError('No module named X') for the
    target submodule, as if the optional dep were absent."""
    real = importlib.import_module

    def fake(module_name, *a, **k):
        if target_substr in module_name:
            raise ImportError(f"No module named '{missing_name}'")
        return real(module_name, *a, **k)

    monkeypatch.setattr(importlib, "import_module", fake)


def test_cache_symbol_points_at_cache_extra(monkeypatch):
    import gatecat
    _force_import_error(monkeypatch, "gatecat.cache", "numpy")
    with pytest.raises(ImportError) as exc:
        _ = gatecat.SemanticCache
    assert "gate.cat[cache]" in str(exc.value)
    assert "No module named 'numpy'" not in str(exc.value)  # not the raw one


def test_openai_wrapper_missing_numpy_points_at_cache(monkeypatch):
    import gatecat
    # CachedOpenAI lives in gatecat.openai; simulate its numpy import failing
    _force_import_error(monkeypatch, "gatecat.openai", "numpy")
    with pytest.raises(ImportError) as exc:
        _ = gatecat.CachedOpenAI
    assert "gate.cat[cache]" in str(exc.value)


def test_openai_wrapper_missing_openai_points_at_openai(monkeypatch):
    import gatecat
    _force_import_error(monkeypatch, "gatecat.openai", "openai")
    with pytest.raises(ImportError) as exc:
        _ = gatecat.CachedOpenAI
    # the discriminating assertion: names [openai], NOT [cache]
    assert "gate.cat[openai]" in str(exc.value)


def test_anthropic_wrapper_missing_anthropic_points_at_anthropic(monkeypatch):
    import gatecat
    _force_import_error(monkeypatch, "gatecat.anthropic", "anthropic")
    with pytest.raises(ImportError) as exc:
        _ = gatecat.CachedAnthropic
    assert "gate.cat[anthropic]" in str(exc.value)


def test_cli_without_cache_prints_clean_message(monkeypatch, capsys):
    """gatecat-cli cache command with SemanticCache unavailable -> clean stderr,
    non-zero return, no traceback."""
    from gatecat import cli
    monkeypatch.setattr(cli, "SemanticCache", None)
    monkeypatch.setattr("sys.argv", ["gatecat-cli", "stats"])
    rc = cli.main()
    err = capsys.readouterr().err
    assert rc == 1
    assert "gate-cat[cache]" in err
    assert "Traceback" not in err


def test_cli_audit_does_not_need_cache(monkeypatch):
    """The audit subcommand must remain reachable even with SemanticCache=None
    (it runs against the user's endpoint, not the cache)."""
    from gatecat import cli
    monkeypatch.setattr(cli, "SemanticCache", None)
    called = {}
    monkeypatch.setattr(cli, "cmd_audit", lambda args: called.setdefault("ran", True))
    monkeypatch.setattr("sys.argv", ["gatecat-cli", "audit", "data.jsonl"])
    cli.main()
    assert called.get("ran") is True  # audit ran despite no cache stack
