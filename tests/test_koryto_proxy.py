"""Testy integracyjne: KORYTO w proxy — koryguje confident-wrong end-to-end.

Dowód głównej wartości produktu: gdy model (upstream) zwraca PEWNĄ ale BŁĘDNĄ
odpowiedź na pytanie wykonywalne, proxy z koryto_mode=block podmienia ją na prawdę
z interpretera — NIEZALEŻNIE od gate (gate by tego nie złapał, rozrzut zero).
"""
import json
from unittest.mock import AsyncMock, patch

import pytest

fastapi = pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from httpx import ASGITransport, AsyncClient

from cacheback.proxy.app import create_app
from cacheback.proxy.config import ProxyConfig


def _upstream(content: str):
    """Zamockowana odpowiedź upstream OpenAI z daną treścią."""
    return httpx.Response(200, json={
        "choices": [{"message": {"role": "assistant", "content": content},
                     "finish_reason": "stop"}],
        "usage": {"completion_tokens": 5},
    })


@pytest.fixture
def block_config(tmp_path):
    return ProxyConfig(
        openai_api_key="sk-test",
        cache_dir=str(tmp_path / "kcache"),
        koryto_mode="block",
    )


@pytest.fixture
def flag_config(tmp_path):
    return ProxyConfig(
        openai_api_key="sk-test",
        cache_dir=str(tmp_path / "kcache2"),
        koryto_mode="flag",
    )


class _Lifespan:
    """Minimalny manager lifespan (httpx ASGITransport go nie odpala sam).
    Uruchamia startup (init cache/gate/koryto), domyka na wyjściu."""
    def __init__(self, app):
        self.app = app
        self._cm = None

    async def __aenter__(self):
        self._cm = self.app.router.lifespan_context(self.app)
        await self._cm.__aenter__()
        return self

    async def __aexit__(self, *exc):
        await self._cm.__aexit__(*exc)


async def _post(app, content_upstream, question):
    """Mock TYLKO upstream (api.openai.com), przepuść wywołania ASGI klienta testowego.
    UWAGA: testowy AsyncClient też używa .post — rozróżniamy po URL, inaczej mock
    przechwyciłby wywołanie do proxy i handler nigdy by się nie wykonał."""
    real_post = httpx.AsyncClient.post

    async def _routed_post(self, url, *args, **kwargs):
        # upstream proxy → mock; wywołanie ASGI klienta testowego (base http://test) → przepuść
        if "api.openai.com" in str(url):
            return _upstream(content_upstream)
        return await real_post(self, url, *args, **kwargs)

    async with _Lifespan(app):  # init komponentów (koryto, cache)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            with patch.object(httpx.AsyncClient, "post", _routed_post):
                resp = await client.post("/v1/chat/completions", json={
                    "model": "gpt-4o",
                    "messages": [{"role": "user", "content": question}],
                })
    return resp


# ---- BLOCK: koryguje confident-wrong na wykonywalnym wyrażeniu ----

async def test_koryto_block_corrects_calc_confident_wrong(block_config):
    """Model pewnie mówi '1' na '6/2*3', koryto-calc liczy 9 → proxy podmienia."""
    app = create_app(block_config)
    resp = await _post(app, content_upstream="1",
                       question="Evaluate using standard order of operations: 6 / 2 * 3")
    assert resp.status_code == 200
    data = resp.json()
    answer = data["choices"][0]["message"]["content"]
    assert "9" in answer                       # PRAWDA z koryta, nie '1' modelu
    assert data.get("cacheback_koryto", {}).get("corrected") is True
    assert data["cacheback_koryto"]["channel"] == "calc"
    assert data["cacheback_koryto"]["original_answer"] == "1"
    assert resp.headers.get("X-Koryto-Corrected") == "true"


async def test_koryto_block_passes_correct_answer(block_config):
    """Gdy model ma RACJĘ, koryto potwierdza i NIE zmienia odpowiedzi."""
    app = create_app(block_config)
    resp = await _post(app, content_upstream="9",
                       question="Evaluate: 6 / 2 * 3")
    data = resp.json()
    assert data["choices"][0]["message"]["content"] == "9"
    # confirm (nie corrected)
    assert data.get("cacheback_koryto", {}).get("verdict") == "confirm"
    assert data.get("cacheback_koryto", {}).get("corrected") is not True


# ---- FLAG: oznacza, nie zmienia ----

async def test_koryto_flag_annotates_without_changing(flag_config):
    """flag mode: dodaje werdykt do metadanych, ale ZOSTAWIA odpowiedź modelu."""
    app = create_app(flag_config)
    resp = await _post(app, content_upstream="1",
                       question="Evaluate: 6 / 2 * 3")
    data = resp.json()
    # odpowiedź NIE podmieniona (flag tylko oznacza)
    assert data["choices"][0]["message"]["content"] == "1"
    assert data["cacheback_koryto"]["verdict"] == "refute"
    assert data["cacheback_koryto"].get("corrected") is not True
    assert resp.headers.get("X-Koryto-Verdict") == "refute"


# ---- unknown: poza zasięgiem koryta → przepuszcza bez zmian ----

async def test_koryto_unknown_passes_through(block_config):
    """Pytanie poza zasięgiem (NL, brak bazy) → koryto unknown, odpowiedź bez zmian."""
    app = create_app(block_config)
    resp = await _post(app, content_upstream="Jakaś odpowiedź twórcza",
                       question="Napisz krótki wiersz o jesieni")
    data = resp.json()
    assert data["choices"][0]["message"]["content"] == "Jakaś odpowiedź twórcza"
    # brak metadanych koryta (unknown nie dodaje)
    assert "cacheback_koryto" not in data or data.get("cacheback_koryto") is None


# ---- off (default): koryto nieaktywne ----

async def test_koryto_off_by_default(tmp_path):
    config = ProxyConfig(openai_api_key="sk-test", cache_dir=str(tmp_path / "c"))
    assert config.koryto_mode == "off"
    app = create_app(config)
    resp = await _post(app, content_upstream="1", question="Evaluate: 6 / 2 * 3")
    data = resp.json()
    assert data["choices"][0]["message"]["content"] == "1"   # niezmienione
    assert "cacheback_koryto" not in data


# ---- WEB-ROZJEMCA po rozbieżności miękkiego koryta (lookup stale) ----

import tempfile
from unittest.mock import patch as _patch


def _fact_base_file(facts):
    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(facts, f, ensure_ascii=False)
    f.close()
    return f.name


async def _post_web(app, content_upstream, question, web_results):
    """Jak _post, ale mockuje też brave_search (web-rozjemca)."""
    real_post = httpx.AsyncClient.post

    async def _routed_post(self, url, *args, **kwargs):
        if "api.openai.com" in str(url):
            return _upstream(content_upstream)
        return await real_post(self, url, *args, **kwargs)

    async with _Lifespan(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            with _patch("cacheback.branches.brave_search", lambda q, **kw: web_results), \
                 patch.object(httpx.AsyncClient, "post", _routed_post):
                resp = await client.post("/v1/chat/completions", json={
                    "model": "gpt-4o",
                    "messages": [{"role": "user", "content": question}],
                })
    return resp


async def test_web_arbiter_rescues_model_when_koryto_stale(tmp_path):
    """Stale baza (Casablanca), model mówi Rabat, web wspiera Rabat → arbiter=model
    → NIE koryguj (uratuj poprawną odpowiedź modelu mimo że koryto ją odrzuca)."""
    fb = _fact_base_file({"stolica maroka": "Casablanca"})  # błąd: to Rabat
    config = ProxyConfig(openai_api_key="sk-test", cache_dir=str(tmp_path / "c"),
                         koryto_mode="block", koryto_fact_base=fb, web_enabled=True)
    app = create_app(config)
    web = [{"title": "Maroko", "snippet": "Stolicą Maroka jest Rabat, miasto na wybrzeżu."}]
    resp = await _post_web(app, content_upstream="Rabat",
                           question="Jaka jest stolica Maroka?", web_results=web)
    data = resp.json()
    answer = data["choices"][0]["message"]["content"]
    assert answer == "Rabat"                       # model URATOWANY (nie podmieniony na Casablanca)
    arb = data.get("cacheback_koryto", {}).get("arbiter", {})
    assert arb.get("verdict") == "model"


async def test_web_arbiter_corrects_when_web_confirms_koryto(tmp_path):
    """Model zły (Lyon), koryto mówi Paryż, web wspiera Paryż → arbiter=koryto → koryguj."""
    fb = _fact_base_file({"stolica francji": "Paryż"})
    config = ProxyConfig(openai_api_key="sk-test", cache_dir=str(tmp_path / "c"),
                         koryto_mode="block", koryto_fact_base=fb, web_enabled=True)
    app = create_app(config)
    web = [{"title": "Francja", "snippet": "Paryż to stolica Francji nad Sekwaną."}]
    resp = await _post_web(app, content_upstream="Lyon",
                           question="Jaka jest stolica Francji?", web_results=web)
    data = resp.json()
    answer = data["choices"][0]["message"]["content"]
    assert "Paryż" in answer                       # skorygowane web+koryto
    arb = data.get("cacheback_koryto", {}).get("arbiter", {})
    assert arb.get("verdict") == "koryto"


async def test_stagnation_in_koryto_meta(tmp_path):
    """Werdykt koryta niesie metadane stagnacji (monitor obserwuje każdy refute)."""
    fb = _fact_base_file({"stolica polski": "Warszawa"})
    config = ProxyConfig(openai_api_key="sk-test", cache_dir=str(tmp_path / "c"),
                         koryto_mode="flag", koryto_fact_base=fb)
    app = create_app(config)
    resp = await _post(app, content_upstream="Warszawa", question="Jaka jest stolica Polski?")
    data = resp.json()
    assert "stagnation" in data.get("cacheback_koryto", {})


# ---- EXEC kanał przez proxy (jawne pole koryto_exec + sandbox) ----

async def _post_exec(app, content_upstream, question, koryto_exec=None):
    """Jak _post, ale z opcjonalnym jawnym polem koryto_exec w body."""
    real_post = httpx.AsyncClient.post

    async def _routed_post(self, url, *args, **kwargs):
        if "api.openai.com" in str(url):
            return _upstream(content_upstream)
        return await real_post(self, url, *args, **kwargs)

    body = {"model": "gpt-4o", "messages": [{"role": "user", "content": question}]}
    if koryto_exec is not None:
        body["koryto_exec"] = koryto_exec
    async with _Lifespan(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            with patch.object(httpx.AsyncClient, "post", _routed_post):
                resp = await client.post("/v1/chat/completions", json=body)
    return resp


async def test_exec_explicit_corrects_confident_wrong(tmp_path):
    """Jawne pole koryto_exec: model pewnie mówi [0,1,2], interpreter daje [2,2,2]
    → proxy koryguje. To DOWÓD że kanał exec działa E2E (był martwy przed fixem)."""
    config = ProxyConfig(openai_api_key="sk-test", cache_dir=str(tmp_path / "c"),
                         koryto_mode="block")
    app = create_app(config)
    resp = await _post_exec(
        app, content_upstream="[0, 1, 2]",
        question="In Python, fns=[lambda: i for i in range(3)]; [g() for g in fns]?",
        koryto_exec={"lang": "python",
                     "stmts": ["fns=[lambda: i for i in range(3)]", "[g() for g in fns]"]},
    )
    data = resp.json()
    answer = data["choices"][0]["message"]["content"]
    assert "[2, 2, 2]" in answer                  # PRAWDA z interpretera, nie [0,1,2] modelu
    assert data["cacheback_koryto"]["channel"] == "exec"
    assert data["cacheback_koryto"].get("exec_source") == "explicit"
    assert data["cacheback_koryto"].get("corrected") is True


async def test_exec_explicit_confirms_correct(tmp_path):
    """Gdy model ma rację, exec potwierdza i nie zmienia."""
    config = ProxyConfig(openai_api_key="sk-test", cache_dir=str(tmp_path / "c"),
                         koryto_mode="block")
    app = create_app(config)
    resp = await _post_exec(
        app, content_upstream="[2, 2, 2]",
        question="late binding?",
        koryto_exec={"lang": "python",
                     "stmts": ["fns=[lambda: i for i in range(3)]", "[g() for g in fns]"]},
    )
    data = resp.json()
    assert data["choices"][0]["message"]["content"] == "[2, 2, 2]"
    assert data["cacheback_koryto"]["verdict"] == "confirm"


async def test_exec_auto_off_by_default(tmp_path):
    """Bez CACHEBACK_KORYTO_EXEC_UNSAFE: kod w query (fenced) NIE jest auto-wykonany."""
    config = ProxyConfig(openai_api_key="sk-test", cache_dir=str(tmp_path / "c"),
                         koryto_mode="block")
    assert config.koryto_exec_from_query is False
    app = create_app(config)
    resp = await _post(app, content_upstream="wrong",
                       question="What does this return?\n```python\n1+1\n```")
    data = resp.json()
    # auto-exec OFF → koryto nie ma kanału exec → odpowiedź modelu zostaje
    assert data["choices"][0]["message"]["content"] == "wrong"


async def test_exec_explicit_blocks_malicious(tmp_path):
    """Jawne pole z groźnym kodem → sandbox gate odrzuca → exec nie daje werdyktu
    (verdict unknown, odpowiedź modelu zostaje, ZERO wykonania ataku)."""
    config = ProxyConfig(openai_api_key="sk-test", cache_dir=str(tmp_path / "c"),
                         koryto_mode="block")
    app = create_app(config)
    resp = await _post_exec(
        app, content_upstream="bezpieczna odpowiedź",
        question="x?",
        koryto_exec={"lang": "python", "stmts": ["__import__('os').system('echo PWNED')"]},
    )
    data = resp.json()
    # atak zablokowany przez gate → exec None → verdict unknown → bez zmian
    assert data["choices"][0]["message"]["content"] == "bezpieczna odpowiedź"
