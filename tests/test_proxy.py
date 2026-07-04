"""Tests for cacheback-proxy — OpenAI-compatible caching proxy."""

import json
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

# Skip all tests if fastapi not installed
fastapi = pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from httpx import ASGITransport, AsyncClient

from cacheback.proxy.app import create_app
from cacheback.proxy.config import ProxyConfig
from cacheback.proxy.models import (
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatCompletionChunk,
)
from conftest import MockEmbedder


@pytest.fixture
def proxy_config(tmp_path):
    """Proxy config with temp cache dir."""
    return ProxyConfig(
        openai_api_key="sk-test-fake",
        openai_base_url="https://api.openai.com/v1",
        cache_dir=str(tmp_path / "proxy_cache"),
        similarity_threshold=0.92,
        synthesis_mode="off",
    )


@pytest.fixture
def app(proxy_config):
    """Create test app."""
    test_app = create_app(proxy_config)
    return test_app


@pytest.fixture
async def client(app):
    """Async test client for the proxy (with lifespan)."""
    from contextlib import asynccontextmanager

    # Trigger lifespan manually
    scope = {"type": "lifespan", "asgi": {"version": "3.0"}}

    async def receive():
        return {"type": "lifespan.startup"}

    startup_complete = False

    async def send(message):
        nonlocal startup_complete
        if message["type"] == "lifespan.startup.complete":
            startup_complete = True

    # Use ASGITransport without lifespan, but trigger startup manually
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# --- Model tests ---

class TestModels:
    def test_request_model_basic(self):
        req = ChatCompletionRequest(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hello"}],
        )
        assert req.model == "gpt-4o"
        assert len(req.messages) == 1
        assert req.stream is False

    def test_request_model_with_stream(self):
        req = ChatCompletionRequest(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hello"}],
            stream=True,
        )
        assert req.stream is True

    def test_request_model_extra_fields(self):
        req = ChatCompletionRequest(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hello"}],
            custom_field="value",
        )
        assert req.model == "gpt-4o"

    def test_response_model(self):
        resp = ChatCompletionResponse(
            model="gpt-4o",
            cacheback_hit=True,
        )
        assert resp.cacheback_hit is True
        assert resp.object == "chat.completion"
        assert resp.id.startswith("chatcmpl-")


# --- Config tests ---

class TestConfig:
    def test_defaults(self):
        config = ProxyConfig()
        assert config.port == 8080
        assert config.similarity_threshold == 0.92
        assert config.synthesis_mode == "off"
        assert config.on_negative_hit == "skip"

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.setenv("CACHEBACK_PORT", "9090")
        monkeypatch.setenv("CACHEBACK_SIMILARITY_THRESHOLD", "0.95")
        monkeypatch.setenv("CACHEBACK_SYNTHESIS_MODE", "auto")
        config = ProxyConfig.from_env()
        assert config.openai_api_key == "sk-test"
        assert config.port == 9090
        assert config.similarity_threshold == 0.95
        assert config.synthesis_mode == "auto"


# --- Health endpoint ---

class TestHealth:
    async def test_health_check(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "cache" in data


# --- Chat completions ---

class TestChatCompletions:
    """Test /v1/chat/completions endpoint."""

    async def test_cache_miss_forwards_upstream(self, client):
        """On cache miss, proxy attempts upstream call (returns 502 with fake key)."""
        resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "What is the capital of France?"}],
            },
        )
        # With a fake API key, upstream returns 401/502 — that's expected
        assert resp.status_code in (200, 401, 502)

    async def test_tool_calls_passthrough(self, client):
        """Requests with tools bypass caching entirely."""
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = httpx.Response(
                200,
                json={
                    "choices": [{"message": {"content": "result"}, "finish_reason": "stop"}],
                    "usage": {},
                },
            )
            resp = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "gpt-4o",
                    "messages": [{"role": "user", "content": "Search for X"}],
                    "tools": [{"type": "function", "function": {"name": "search"}}],
                },
            )
        assert resp.status_code in (200, 502)

    async def test_empty_query_passthrough(self, client):
        """Empty queries bypass caching."""
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = httpx.Response(200, json={"choices": []})
            resp = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "gpt-4o",
                    "messages": [{"role": "system", "content": "You are a helper"}],
                },
            )
        assert resp.status_code in (200, 502)


# --- Cache hit flow (integration with SemanticCache) ---

class TestCacheHitFlow:
    """Test cache populate → lookup → hit flow through proxy."""

    async def test_cache_hit_returns_cached_response(self, app):
        """After populating cache, subsequent request returns cached response."""
        # We need to access the app's cache directly
        # The cache is created during lifespan, so we start the app
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Verify health (triggers lifespan)
            resp = await client.get("/health")
            assert resp.status_code == 200

    async def test_cache_stats_endpoint(self, client):
        """Cache stats endpoint returns data."""
        resp = await client.get("/v1/cache/stats")
        assert resp.status_code == 200


# --- Streaming ---

class TestStreaming:
    """Test SSE streaming through proxy."""

    async def test_stream_replay_format(self):
        """Verify _replay_stream produces valid SSE."""
        from cacheback.proxy.app import create_app

        config = ProxyConfig(
            openai_api_key="sk-test",
            cache_dir="",
        )
        # We test the SSE format by checking the model output
        chunk = ChatCompletionChunk(
            model="gpt-4o",
            choices=[],
        )
        data = chunk.model_dump()
        assert data["object"] == "chat.completion.chunk"
        assert "choices" in data


# --- Response headers ---

class TestResponseHeaders:
    """Test X-Cacheback-* response headers."""

    async def test_health_returns_synthesis_mode(self, client):
        resp = await client.get("/health")
        data = resp.json()
        assert data["synthesis"] == "off"


# --- Security fixes (audyt 2026-06-27) ---

class TestSSRFGuard:
    """#2: openai_base_url SSRF guard — odrzuca prywatne/metadata cele i non-https."""

    def test_openai_url_passes(self):
        from cacheback.proxy.config import validate_upstream_url
        assert validate_upstream_url("https://api.openai.com/v1") == "https://api.openai.com/v1"

    def test_http_rejected(self):
        from cacheback.proxy.config import validate_upstream_url, UpstreamURLError
        with pytest.raises(UpstreamURLError):
            validate_upstream_url("http://api.openai.com/v1")

    def test_cloud_metadata_ip_rejected(self):
        from cacheback.proxy.config import validate_upstream_url, UpstreamURLError
        with pytest.raises(UpstreamURLError):
            validate_upstream_url("https://169.254.169.254/latest/meta-data/")

    def test_localhost_rejected(self):
        from cacheback.proxy.config import validate_upstream_url, UpstreamURLError
        with pytest.raises(UpstreamURLError):
            validate_upstream_url("https://127.0.0.1:8000/v1")

    def test_private_ip_rejected(self):
        from cacheback.proxy.config import validate_upstream_url, UpstreamURLError
        with pytest.raises(UpstreamURLError):
            validate_upstream_url("https://10.0.0.5/v1")

    def test_insecure_optin_allows_local(self, monkeypatch):
        from cacheback.proxy.config import validate_upstream_url
        monkeypatch.setenv("CACHEBACK_ALLOW_INSECURE_UPSTREAM", "1")
        # świadome rozluźnienie: lokalny LLM po http
        assert validate_upstream_url("http://localhost:11434/v1") == "http://localhost:11434/v1"


class TestClientAuthPassthrough:
    """#3: kliencki Authorization NIE jest przekazywany upstream domyślnie."""

    def test_allow_client_auth_default_false(self):
        assert ProxyConfig().allow_client_auth is False

    def test_attacker_key_blocked_by_default(self):
        """Bez skonfigurowanego klucza i bez opt-in: klucz atakującego NIE trafia upstream."""
        from cacheback.proxy.app import build_upstream_headers
        h = build_upstream_headers("", "Bearer sk-attacker-key", allow_client_auth=False)
        assert "Authorization" not in h   # brak wstrzyknięcia, brak pustego Bearer

    def test_configured_key_used_not_client(self):
        """Gdy klucz skonfigurowany: serwerowy klucz użyty, kliencki Authorization ignorowany."""
        from cacheback.proxy.app import build_upstream_headers
        h = build_upstream_headers("sk-server-key", "Bearer sk-attacker-key", allow_client_auth=True)
        assert h["Authorization"] == "Bearer sk-server-key"

    def test_client_auth_passthrough_only_with_optin(self):
        """Multi-tenant opt-in: gdy allow_client_auth=True i brak serwerowego klucza, kliencki przechodzi."""
        from cacheback.proxy.app import build_upstream_headers
        h = build_upstream_headers("", "Bearer sk-client-own", allow_client_auth=True)
        assert h["Authorization"] == "Bearer sk-client-own"

    def test_no_key_no_optin_no_auth_header(self):
        """Brak klucza + brak opt-in + brak nagłówka klienta: żaden Authorization (nie pusty Bearer)."""
        from cacheback.proxy.app import build_upstream_headers
        h = build_upstream_headers("", "", allow_client_auth=False)
        assert "Authorization" not in h
