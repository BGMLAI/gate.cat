"""COMPONENT 4 — proxy LOCAL budget-cap + loop-guard (stagnation).

Both run in-process on the proxy and are FREE (never tier-gated): they halt by
DENYING the next action routed through the proxy (no external process kill).
These pin: over-budget halts, under-budget allows, and repeated no-progress
actions trip the loop-guard. Plus the pure cost/price helpers.
"""
from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")
import httpx
from httpx import ASGITransport, AsyncClient
from unittest.mock import patch

from gatecat.proxy.app import create_app
from gatecat.proxy.config import ProxyConfig
from gatecat.proxy.local_guard import (
    LocalGuardState,
    cost_of,
    estimate_completion_tokens,
    price_for_model,
    session_action_signature,
)


# ---- pure pricing / cost ----------------------------------------------------

def test_price_exact_and_prefix_and_default():
    prices = {"default": 0.0, "gpt-4o": 0.010}
    assert price_for_model("gpt-4o", prices) == 0.010
    assert price_for_model("gpt-4o-2024-08-06", prices) == 0.010   # prefix match
    assert price_for_model("mystery-model", prices) == 0.0         # default


def test_cost_of_scales_with_tokens():
    prices = {"default": 0.0, "m": 0.002}      # $0.002 / 1k
    assert cost_of(1000, "m", prices) == pytest.approx(0.002)
    assert cost_of(500, "m", prices) == pytest.approx(0.001)


def test_estimate_tokens_is_chars_over_four():
    assert estimate_completion_tokens("a" * 40) == 10
    assert estimate_completion_tokens("") == 1     # never zero


def test_over_budget_semantics():
    st = LocalGuardState()
    st.add_spend("s", 0.05)
    assert st.over_budget("s", 0.04) is True
    assert st.over_budget("s", 0.06) is False
    assert st.over_budget("s", 0) is False         # 0 disables the cap


def test_loop_guard_trips_on_third_identical_action():
    st = LocalGuardState()
    assert st.observe_action("s", "tool:run(x)", 2) is None
    assert st.observe_action("s", "tool:run(x)", 2) is None
    assert st.observe_action("s", "tool:run(x)", 2)          # 3rd trips


def test_action_signature_tool_vs_text():
    sig_tool = session_action_signature(
        {"choices": [{"message": {"tool_calls": [
            {"function": {"name": "sh", "arguments": '{"c":"ls"}'}}]}}]})
    assert sig_tool.startswith("tool:sh(")
    sig_text = session_action_signature(
        {"choices": [{"message": {"content": "hello"}}]})
    assert sig_text.startswith("text:")


# ---- endpoint integration ---------------------------------------------------

async def _post(app, body, upstream_json, headers=None):
    orig_post = httpx.AsyncClient.post

    async def fake_post(self, url, *a, **kw):
        if str(url).startswith("http"):
            return httpx.Response(200, json=upstream_json)
        return await orig_post(self, url, *a, **kw)

    async with app.router.lifespan_context(app):
        with patch("httpx.AsyncClient.post", fake_post):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                return await c.post("/v1/chat/completions", json=body,
                                    headers=headers or {})


def _plain_completion(text="ok", ctoks=1000):
    return {"id": "c1", "object": "chat.completion", "model": "gpt-4o",
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": text}}],
            "usage": {"completion_tokens": ctoks}}


def _tool_completion(cmd="ls -la", ctoks=10):
    return {"id": "c1", "object": "chat.completion", "model": "gpt-4o",
            "choices": [{"index": 0, "finish_reason": "tool_calls",
                         "message": {"role": "assistant", "tool_calls": [
                             {"id": "t1", "type": "function", "function": {
                                 "name": "bash", "arguments": json.dumps({"command": cmd})}}]}}],
            "usage": {"completion_tokens": ctoks}}


def _cfg(tmp_path, **kw):
    base = dict(openai_api_key="sk-test", cache_dir=str(tmp_path / "c"),
                synthesis_mode="off", tool_veto="off")
    base.update(kw)
    return ProxyConfig(**base)


def _req(text="do it", tools=False):
    body = {"model": "gpt-4o", "messages": [{"role": "user", "content": text}]}
    if tools:
        body["tools"] = [{"type": "function", "function": {"name": "bash"}}]
    return body


class TestBudgetCap:
    async def test_under_budget_allows(self, tmp_path):
        """(d) under-budget -> the request is served normally."""
        app = create_app(_cfg(tmp_path, budget_usd=1.00))  # $1 cap, one call = $0.01
        resp = await _post(app, _req(), _plain_completion(ctoks=1000))
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("gatecat", {}).get("vetoed") is not True

    async def test_over_budget_halts_next_call(self, tmp_path):
        """(d) once the session blows the budget, the NEXT call is halted."""
        app = create_app(_cfg(tmp_path, budget_usd=0.005))  # $0.005 cap
        headers = {"X-Gatecat-Session": "sess-A"}
        # first call: 1000 gpt-4o tokens = $0.01 > $0.005 -> spend recorded
        r1 = await _post(app, _req(), _plain_completion(ctoks=1000), headers)
        assert r1.status_code == 200               # first call still served
        # second call: session already over budget -> halted
        r2 = await _post(app, _req(), _plain_completion(ctoks=1000), headers)
        d2 = r2.json()
        assert d2.get("gatecat", {}).get("vetoed") is True
        assert "budget cap reached" in d2["choices"][0]["message"]["content"]
        assert "tool_calls" not in d2["choices"][0]["message"]

    async def test_budget_isolated_per_session(self, tmp_path):
        app = create_app(_cfg(tmp_path, budget_usd=0.005))
        # burn session A over budget
        await _post(app, _req(), _plain_completion(ctoks=1000),
                    {"X-Gatecat-Session": "A"})
        await _post(app, _req(), _plain_completion(ctoks=1000),
                    {"X-Gatecat-Session": "A"})
        # session B is fresh -> still served
        rb = await _post(app, _req(), _plain_completion(ctoks=1000),
                         {"X-Gatecat-Session": "B"})
        assert rb.json().get("gatecat", {}).get("vetoed") is not True

    async def test_zero_budget_never_caps(self, tmp_path):
        app = create_app(_cfg(tmp_path, budget_usd=0.0))
        for _ in range(3):
            r = await _post(app, _req(), _plain_completion(ctoks=100000),
                            {"X-Gatecat-Session": "S"})
            assert r.json().get("gatecat", {}).get("vetoed") is not True


class TestLoopGuard:
    async def test_repeated_no_progress_trips_stagnation(self, tmp_path):
        """(d) repeated identical no-progress tool calls -> loop-guard veto."""
        app = create_app(_cfg(tmp_path, tool_veto="block",
                              stagnation_local="block", stagnation_local_repeat=2))
        headers = {"X-Gatecat-Session": "loop"}
        same = _tool_completion(cmd="pytest -q")   # a SAFE call, repeated
        r1 = await _post(app, _req(tools=True), same, headers)
        r2 = await _post(app, _req(tools=True), same, headers)
        r3 = await _post(app, _req(tools=True), same, headers)
        # first two pass (safe tool call preserved), the 3rd trips the loop-guard
        assert r1.json()["choices"][0]["message"].get("tool_calls")
        d3 = r3.json()
        assert d3.get("gatecat", {}).get("vetoed") is True
        assert "loop-guard" in d3["choices"][0]["message"]["content"]

    async def test_warn_mode_annotates_but_keeps_call(self, tmp_path):
        app = create_app(_cfg(tmp_path, tool_veto="block",
                              stagnation_local="warn", stagnation_local_repeat=2))
        headers = {"X-Gatecat-Session": "loopw"}
        same = _tool_completion(cmd="pytest -q")
        await _post(app, _req(tools=True), same, headers)
        await _post(app, _req(tools=True), same, headers)
        r3 = await _post(app, _req(tools=True), same, headers)
        d3 = r3.json()
        # warn mode: NOT vetoed, but the stagnation reason is surfaced
        assert d3.get("gatecat", {}).get("vetoed") is not True
        assert d3["choices"][0]["message"].get("tool_calls")
        assert "gatecat" in d3 and d3["gatecat"].get("stagnation")


class TestHealthSurface:
    async def test_health_reports_local_guard(self, tmp_path):
        app = create_app(_cfg(tmp_path, budget_usd=0.5, stagnation_local="block"))
        async with app.router.lifespan_context(app):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                h = (await c.get("/health")).json()
        assert h["local_budget_cap"]["enabled"] is True
        assert h["local_budget_cap"]["budget_usd"] == 0.5
        assert h["loop_guard"]["enabled"] is True
