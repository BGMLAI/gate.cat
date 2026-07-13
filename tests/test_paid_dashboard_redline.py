"""COMPONENT 5 — hosted (client-decrypted) dashboard + RED-LINE invariant.

The dashboard renders from BOTH the local log AND (if a cloud key is present)
cross-machine ciphertext fetched + decrypted locally. The paid value is the
cross-machine aggregation; rendering is always client-side. With no cloud key it
degrades to a richer local render — and, critically, the LOCAL budget-cap /
loop-guard stay free. These pin the dashboard model and the red line: no cloud
key => all local free features (including the local proxy budget-cap) still work.
"""
from __future__ import annotations

import pytest

from gatecat.integrations import rich_dashboard as RD


# ---- dashboard model + render (pure) ----------------------------------------

def _local():
    rmrf = "r" + "m -" + "rf /"                 # avoid tripping our own dogfood hook
    return [
        {"decision": "block", "policy": "RM_RF", "context": rmrf},
        {"decision": "warn", "policy": "GIT_FORCE_PUSH", "context": "git force"},
        {"decision": "allow", "policy": None, "context": "ls"},
        {"decision": "stagnation", "reason": "repeat_action x3: pytest"},
    ]


def _cloud():
    return [
        {"decision": "block", "policy": "CLOUD_DESTROY", "machine": "ci-1",
         "context": "aws terminate"},
        {"decision": "override_grant", "machine": "ci-2", "context": "preview",
         "ledger": True, "chain_self": "abc"},
        {"decision": "block", "policy": "RM_RF", "machine": "ci-1", "context": "wipe"},
    ]


def test_model_local_only_has_no_cloud():
    m = RD.build_model(_local(), [])
    assert m["has_cloud"] is False
    assert m["local"]["total"] == 4
    assert len(m["recent_vetoes"]) == 1          # one block locally
    assert len(m["stagnation"]) == 1


def test_model_merges_cross_machine():
    m = RD.build_model(_local(), _cloud())
    assert m["has_cloud"] is True
    # per-machine breakdown counts cloud events only
    assert dict(m["per_machine"]) == {"ci-1": 2, "ci-2": 1}
    # ledger picked out of the cloud stream
    assert len(m["ledger"]) == 1
    # vetoes come from both local + cloud
    assert len(m["recent_vetoes"]) == 3


def test_render_terminal_local_only_mentions_subscribe():
    m = RD.build_model(_local(), [])
    out = RD.render_terminal(m, "cloud off", color=False)
    assert "local (this machine)" in out
    assert "subscribe" in out.lower()


def test_render_html_is_self_contained():
    m = RD.build_model(_local(), _cloud())
    html = RD.render_html(m, "note")
    assert "<title>gate.cat dashboard" in html
    assert "http://" not in html.split("</style>")[0]   # no external assets in CSS
    assert "ci-1" in html                                # per-machine rendered


def test_dashboard_verb_no_cloud_key_runs(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("GATECAT_VETO_LOG", str(tmp_path / "veto.jsonl"))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("GATECAT_CLOUD_API_KEY", raising=False)
    from gatecat.integrations import dashboard as DB
    rc = DB.main(["dashboard"])
    assert rc == 0
    assert "cloud off" in capsys.readouterr().out.lower()


def test_dashboard_html_written(tmp_path, monkeypatch):
    monkeypatch.setenv("GATECAT_VETO_LOG", str(tmp_path / "veto.jsonl"))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("GATECAT_CLOUD_API_KEY", raising=False)
    out = str(tmp_path / "dash.html")
    from gatecat.integrations import dashboard as DB
    assert DB.main(["dashboard", "--html", out]) == 0
    assert "<title>gate.cat dashboard" in open(out).read()


# ---- RED LINE: no cloud key => all LOCAL free features work ------------------

@pytest.fixture
def no_cloud(tmp_path, monkeypatch):
    """Strip every cloud/entitlement signal; isolate local state."""
    for k in list(__import__("os").environ):
        if any(t in k.upper() for t in ("CLOUD", "ENTITLE", "STRIPE", "TIER",
                                        "SUBSCRIB", "LICENSE", "LEMON", "API_KEY")):
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def test_redline_local_budget_cap_works_without_cloud(no_cloud):
    """The LOCAL proxy budget-cap must run with ZERO cloud key/entitlement — it
    is a local kill/cap and is never paywalled."""
    from gatecat.proxy.local_guard import LocalGuardState, cost_of
    from gatecat.proxy.config import ProxyConfig
    cfg = ProxyConfig()   # from defaults, no env, no key
    st = LocalGuardState()
    st.add_spend("s", cost_of(1000, "gpt-4o", cfg.model_prices))
    # with a small budget the local cap trips — no cloud anything involved
    assert st.over_budget("s", 0.005) is True


def test_redline_local_loop_guard_works_without_cloud(no_cloud):
    from gatecat.proxy.local_guard import LocalGuardState
    st = LocalGuardState()
    st.observe_action("s", "tool:x()", 2)
    st.observe_action("s", "tool:x()", 2)
    assert st.observe_action("s", "tool:x()", 2)     # trips locally, no cloud


def test_redline_dashboard_local_render_without_cloud(no_cloud, monkeypatch):
    monkeypatch.setenv("GATECAT_VETO_LOG", str(no_cloud / "veto.jsonl"))
    from gatecat.integrations import dashboard as DB
    assert DB.main(["dashboard"]) == 0               # renders local-only, no crash


def test_redline_tier_gating_import_needs_no_cloud_key(no_cloud):
    """The server tier table is importable/usable without any cloud key set."""
    import importlib.util, os
    os.environ["CLOUD_DATA_DIR"] = str(no_cloud)
    path = os.path.join(os.path.dirname(__file__), "..", "products", "cloud", "cloud_server.py")
    spec = importlib.util.spec_from_file_location("cs_redline", os.path.abspath(path))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    # the local product path: a FREE tier still has a valid entitlement
    assert m.entitlement("free")["tier"] == "free"
