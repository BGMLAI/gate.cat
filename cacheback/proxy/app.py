"""cacheback-proxy — OpenAI-compatible caching proxy server.

Receives standard OpenAI API requests, routes through SemanticCache,
forwards misses to the upstream provider. Zero code change for users.

Usage:
    uvicorn cacheback.proxy.app:app --host 0.0.0.0 --port 8080

Or via Docker:
    docker run -e OPENAI_API_KEY=sk-... -p 8080:8080 cacheback/proxy
"""

import json
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Optional

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from cacheback.cache import SemanticCache, DEFAULT_CACHE_DIR
from cacheback.proxy.config import ProxyConfig
from cacheback.proxy.models import (
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatCompletionChoice,
    ChatCompletionMessage,
    CompletionUsage,
    ChatCompletionChunk,
    StreamChoice,
    DeltaContent,
)

logger = logging.getLogger("cacheback.proxy")


def _extract_query(messages: list) -> str:
    """Extract last user message as cache key."""
    for msg in reversed(messages):
        role = msg.role if hasattr(msg, "role") else msg.get("role", "")
        content = msg.content if hasattr(msg, "content") else msg.get("content", "")
        if role == "user":
            if isinstance(content, str):
                return content.strip()
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        return block.get("text", "").strip()
            break
    return ""


def build_upstream_headers(api_key: str, client_auth_header: str,
                           allow_client_auth: bool) -> dict:
    """Zbuduj nagłówki upstream (audyt 2026-06-27 #3 — testowalna, czysta funkcja).

    Domyślnie używaj WYŁĄCZNIE skonfigurowanego klucza. Kliencki Authorization
    przekazywany TYLKO gdy allow_client_auth=True i brak skonfigurowanego klucza
    (proxy multi-tenant) — inaczej atakujący wstrzyknąłby własny/obcy klucz.
    Bez klucza: NIE wysyłaj pustego Bearer.
    """
    key = api_key
    if not key and allow_client_auth and client_auth_header.startswith("Bearer "):
        key = client_auth_header[7:]
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    return headers


def create_app(config: Optional[ProxyConfig] = None) -> FastAPI:
    """Create the cacheback proxy FastAPI app."""

    if config is None:
        config = ProxyConfig.from_env()

    cache: Optional[SemanticCache] = None
    synthesis_engine = None
    http_client: Optional[httpx.AsyncClient] = None
    gate = None  # TruthGate (cacheback.Gate), init in lifespan if gate_mode != off
    web_branch = None   # 3rd cascade branch (cacheback.WebBranch)
    tool_branch = None  # 4th cascade branch (cacheback.ToolBranch)
    koryto = None       # deterministyczny weryfikator atomu (cacheback.Koryto)
    stagnation = None   # stagnation-by-state: pilnuje czy koryto nie zgniło

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        nonlocal cache, synthesis_engine, http_client, gate, web_branch, tool_branch, koryto, stagnation

        # Initialize cache
        cache = SemanticCache(
            cache_dir=config.cache_dir or DEFAULT_CACHE_DIR,
            similarity_threshold=config.similarity_threshold,
            negative_threshold=config.negative_threshold,
            max_entries=config.cache_max_entries,
            ttl_seconds=config.cache_ttl,
            on_negative_hit=config.on_negative_hit,
        )

        # Initialize CAS synthesis engine
        if config.synthesis_mode in ("auto", "always"):
            try:
                from cacheback.synthesis import SynthesisEngine
                synthesis_engine = SynthesisEngine(
                    model=config.synthesis_model,
                    base_url=config.synthesis_model_base_url or None,
                    api_key=config.synthesis_model_api_key or None,
                )
                synthesis_engine._threshold = config.synthesis_threshold
                synthesis_engine._top_k = config.synthesis_top_k
                logger.info("CAS synthesis enabled: model=%s", config.synthesis_model)
            except Exception as e:
                logger.warning("CAS synthesis init failed: %s", e)

        # HTTP client for upstream API calls
        http_client = httpx.AsyncClient(timeout=120.0)

        # Initialize TruthGate (disagreement gate over upstream model)
        if config.gate_mode in ("flag", "block"):
            try:
                from cacheback.gate import Gate
                embedder = None
                if config.gate_semantic:
                    try:
                        from cacheback.embedders import get_embedder
                        embedder = get_embedder("minilm")
                    except Exception as e:
                        logger.warning("gate semantic embedder unavailable (%s); lexical", e)
                # sample_fn set per-request (needs the request's model); Gate holds config
                gate = Gate(n_samples=config.gate_n_samples,
                            threshold=config.gate_threshold, embedder=embedder)
                logger.info("TruthGate enabled: mode=%s n=%d threshold=%.2f",
                            config.gate_mode, config.gate_n_samples, config.gate_threshold)
            except Exception as e:
                logger.warning("TruthGate init failed: %s", e)

        # Repair branches: web (3rd) + tools (4th).
        # Włączane gdy gate LUB koryto aktywne — web-rozjemca obsługuje też rozbieżność koryta.
        if config.gate_mode in ("flag", "block") or config.koryto_mode in ("flag", "block"):
            try:
                if config.web_enabled:
                    from cacheback.branches import WebBranch
                    web_branch = WebBranch(api_key=config.brave_api_key or None)
                    logger.info("Web branch enabled (Brave)")
                if config.tools_enabled:
                    from cacheback.branches import ToolBranch
                    tool_branch = ToolBranch()
                    logger.info("Tool branch enabled (builtin: calculate)")
            except Exception as e:
                logger.warning("Repair branches init failed: %s", e)

        # KORYTO — deterministyczny weryfikator atomu (działa NIEZALEŻNIE od gate)
        if config.koryto_mode in ("flag", "block"):
            try:
                from cacheback.koryto import Koryto, FactBase
                from cacheback.stagnation import StagnationMonitor
                from cacheback.koryto_sources import (
                    http_cache_source, chroma_source, multi_source,
                )
                # plik JSON (mały, walidacyjny)
                facts = {}
                if config.koryto_fact_base:
                    try:
                        facts = json.loads(open(config.koryto_fact_base, encoding="utf-8").read())
                        logger.info("Koryto fact-base (JSON): %d entries", len(facts))
                    except Exception as e:
                        logger.warning("Koryto fact-base JSON load failed (%s)", e)
                # REALNE BAZY (multi-source z bramką jakości; REJESTR 2026-06-27).
                # Lookup pyta WSZYSTKIE dobrej jakości: 4M cache + ChromaDB (po filtrze MCQ).
                sources = []
                if config.koryto_cache_url:
                    sources.append(http_cache_source(
                        config.koryto_cache_url, api_key=config.koryto_cache_key,
                        min_sim=config.koryto_lookup_min_sim))
                    logger.info("Koryto lookup źródło: cache %s", config.koryto_cache_url)
                if config.koryto_chroma_url and config.koryto_chroma_collection:
                    sources.append(chroma_source(
                        config.koryto_chroma_url, config.koryto_chroma_collection,
                        min_sim=config.koryto_lookup_min_sim))
                    logger.info("Koryto lookup źródło: chroma %s/%s (filtr MCQ)",
                                config.koryto_chroma_url, config.koryto_chroma_collection)
                lookup_fn = multi_source(sources) if sources else None
                fb = None
                if facts or lookup_fn is not None:
                    fb = FactBase(facts or None, lookup_fn=lookup_fn)
                koryto = Koryto(fact_base=fb)
                # stagnation-by-state pilnuje koryta (czy seria miękkich odrzuceń = stale baza)
                stagnation = StagnationMonitor(
                    window=config.stagnation_window,
                    soft_streak_trigger=config.stagnation_soft_streak,
                )
                logger.info("Koryto enabled: mode=%s (exec+calc%s) + stagnation-monitor",
                            config.koryto_mode, "+lookup" if fb else "")
            except Exception as e:
                logger.warning("Koryto init failed: %s", e)

        logger.info(
            "cacheback-proxy started: threshold=%.2f, synthesis=%s, gate=%s",
            config.similarity_threshold,
            config.synthesis_mode,
            config.gate_mode,
        )

        yield

        # Cleanup
        if cache:
            cache.close()
        if http_client:
            await http_client.aclose()

    app = FastAPI(
        title="cacheback-proxy",
        description="OpenAI-compatible caching proxy with semantic similarity",
        version="0.2.0",
        lifespan=lifespan,
    )

    # --- Health endpoint ---

    @app.get("/health")
    async def health():
        stats = cache.stats if cache else {}
        return {
            "status": "ok",
            "cache": stats,
            "synthesis": config.synthesis_mode,
        }

    # --- Cache stats ---

    @app.get("/v1/cache/stats")
    async def cache_stats():
        if not cache:
            return {"error": "cache not initialized"}
        return cache.stats

    # --- Main chat completions endpoint ---

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request):
        body = await request.json()
        req = ChatCompletionRequest(**body)

        messages = req.messages
        model = req.model
        stream = req.stream or False
        query = _extract_query(messages)

        # Passthrough: tool calls or empty queries bypass cache
        if req.tools or not query:
            return await _forward_upstream(body, stream, request)

        # --- Tier 1: Verbatim cache lookup ---
        cached_text = cache.lookup(query) if cache else None

        if stream:
            return await _handle_stream(
                body, request, query, model, cached_text
            )

        # Non-streaming path
        if cached_text is not None:
            logger.debug("[proxy] HIT: %s", query[:80])
            return _build_response(cached_text, model, cache_hit=True)

        # --- Tier 2: CAS synthesis ---
        synth_text = _try_synthesis(query, model)
        if synth_text is not None:
            logger.debug("[proxy] SYNTHESIS: %s", query[:80])
            return _build_response(synth_text, model, synthesized=True)

        # --- Tier 2.5: TruthGate (disagreement over upstream model) ---
        # Cache nie naprawiło → zmierz czy mały model jest pewny. Niepewny =
        # próbuj naprawy (tools/web), potem oznacz (flag) lub odmów (block).
        gate_meta = None
        if gate is not None:
            gate_meta = await _gate_probe(body, model)
            if gate_meta and gate_meta.get("uncertain"):
                # gałąź 4 (tools): deterministyczne, gdy pasuje (np. obliczenie)
                if tool_branch is not None:
                    hit = tool_branch.maybe_run(query)
                    if hit:
                        tool_name, observation = hit
                        logger.debug("[proxy] TOOL %s: %s", tool_name, query[:60])
                        return _build_response(
                            observation, model,
                            gate={**gate_meta, "repaired_by": f"tool:{tool_name}"},
                        )
                # gałąź 3 (web): świeży kontekst TYLKO gdy snippet ma odpowiedź
                if web_branch is not None:
                    wr = web_branch.fetch(query)
                    if wr.used:
                        logger.debug("[proxy] WEB (score=%.2f): %s", wr.score, query[:60])
                        # wstrzyknij kontekst web do promptu i wymuś odpowiedź upstream
                        body = dict(body)
                        body["messages"] = [
                            {"role": "system", "content": "Use ONLY this context to answer. "
                             "If it does not contain the answer, say you don't know.\n\n" + wr.context},
                            *body.get("messages", []),
                        ]
                        gate_meta = {**gate_meta, "repaired_by": "web", "web_score": round(wr.score, 3)}
                        # spadnij do Tier 3 z wzbogaconym promptem (nie block)
                    elif config.gate_mode == "block":
                        return _build_response(
                            "Nie mam wystarczającej pewności, by odpowiedzieć wiarygodnie. "
                            "(disagreement=%.2f) — zalecana weryfikacja przez człowieka."
                            % gate_meta.get("disagreement", 0.0),
                            model, gate=gate_meta, abstained=True,
                        )
                elif config.gate_mode == "block":
                    return _build_response(
                        "Nie mam wystarczającej pewności, by odpowiedzieć wiarygodnie. "
                        "(disagreement=%.2f) — zalecana weryfikacja przez człowieka."
                        % gate_meta.get("disagreement", 0.0),
                        model, gate=gate_meta, abstained=True,
                    )

        # --- Tier 3: Upstream API call ---
        upstream_resp = await _forward_upstream(body, False, request)

        # --- Tier 3.5: KORYTO — zweryfikuj odpowiedź modelu deterministycznie ---
        # Działa NIEZALEŻNIE od gate: łapie confident-wrong (rozrzut zero) którego
        # gate nie widzi. Twarde koryto (exec/calc) odrzuca → zwróć prawdę z koryta.
        koryto_meta = None
        original_text = None
        if koryto is not None and isinstance(upstream_resp, JSONResponse):
            try:
                resp_data = json.loads(upstream_resp.body.decode())
                model_answer = _extract_response_text(resp_data) or ""
                exec_payload, exec_source = _koryto_exec_payload(req, query)
                kv = koryto.verify(query, model_answer, **exec_payload)
                if exec_source:
                    pass  # exec_source dodane do meta niżej
                if kv.verdict != "unknown":
                    # TRUTH-FORGERY GUARD: exec z source='auto' = kod z query usera.
                    # Atakujący kontroluje query → kontroluje exec-"prawdę". NIE koryguj
                    # twardo na samym auto-exec; tylko jawne pole ('explicit') lub calc/lookup.
                    forgeable = (kv.channel == "exec" and exec_source == "auto")

                    koryto_meta = kv.to_dict()
                    if exec_source:
                        koryto_meta["exec_source"] = exec_source
                    # NIE leakuj sfałszowanej "prawdy" do metadanych (audyt 2026-06-27 should-fix):
                    # gdy forgeable, atakujący-kontrolowany output nie może udawać 'truth'.
                    if forgeable:
                        koryto_meta["truth"] = None
                        koryto_meta["forgeable"] = True

                    # stagnacja: śledź czy koryto nie zgniło (seria miękkich odrzuceń)
                    if stagnation is not None:
                        st = stagnation.observe(kv)
                        koryto_meta["stagnation"] = st.to_dict()

                    if config.koryto_mode == "block" and kv.verdict == "refute" and kv.truth:
                        if kv.hard and not kv.needs_arbiter and not forgeable:
                            # TWARDE koryto (exec/calc): interpreter się nie myli → koryguj od razu.
                            original_text = model_answer
                            corrected = _apply_koryto_correction(resp_data, kv.truth)
                            koryto_meta["corrected"] = True
                            koryto_meta["repaired_by"] = "koryto:" + kv.channel
                            koryto_meta["original_answer"] = (original_text or "")[:200]
                            corrected["cacheback_koryto"] = koryto_meta
                            if gate_meta is not None:
                                corrected["cacheback_gate"] = gate_meta
                            return JSONResponse(content=corrected, headers={
                                "X-Koryto-Verdict": "refute", "X-Koryto-Channel": kv.channel,
                                "X-Koryto-Corrected": "true"})
                        elif kv.needs_arbiter and web_branch is not None:
                            # MIĘKKIE koryto (lookup): baza bywa stale → web-ROZJEMCA rozsądza
                            # KTO ma rację (model czy koryto). NIE blokuj ślepo na bazie.
                            arb = _web_arbiter(query, model_answer, kv.truth)
                            koryto_meta["arbiter"] = arb
                            if arb["verdict"] == "koryto":
                                # web potwierdza koryto → model faktycznie zły → koryguj
                                corrected = _apply_koryto_correction(resp_data, kv.truth)
                                corrected["cacheback_koryto"] = {**koryto_meta, "corrected": True,
                                    "repaired_by": "koryto:lookup+web", "original_answer": model_answer[:200]}
                                return JSONResponse(content=corrected, headers={
                                    "X-Koryto-Verdict": "refute", "X-Koryto-Channel": "lookup+web",
                                    "X-Koryto-Corrected": "true"})
                            # arb=="model" (koryto stale, uratuj model) lub "niejasne" → NIE koryguj,
                            # tylko oznacz (odpowiedź modelu zostaje).
            except Exception as e:
                logger.warning("[proxy] koryto check failed: %s", e)

        if (gate_meta is not None or koryto_meta is not None) and isinstance(upstream_resp, JSONResponse):
            try:
                data = json.loads(upstream_resp.body.decode())
                hdrs = dict(upstream_resp.headers)
                if gate_meta is not None:
                    data["cacheback_gate"] = gate_meta
                    hdrs["X-Truthgate-Uncertain"] = str(gate_meta.get("uncertain", False)).lower()
                    hdrs["X-Truthgate-Disagreement"] = str(round(gate_meta.get("disagreement", 0.0), 3))
                if koryto_meta is not None:
                    data["cacheback_koryto"] = koryto_meta
                    hdrs["X-Koryto-Verdict"] = koryto_meta.get("verdict", "")
                    hdrs["X-Koryto-Channel"] = koryto_meta.get("channel", "")
                upstream_resp = JSONResponse(content=data, headers=hdrs)
            except Exception:
                pass

        # Cache the response — NIE cache'uj odpowiedzi którą koryto odrzuciło jako błędną
        if isinstance(upstream_resp, JSONResponse) and not (koryto_meta and koryto_meta.get("verdict") == "refute"):
            try:
                resp_data = json.loads(upstream_resp.body.decode())
                text = _extract_response_text(resp_data)
                if text and cache:
                    tokens = resp_data.get("usage", {}).get("completion_tokens", 0)
                    cache.populate(query, text, model=model, tokens=tokens)
            except Exception:
                pass

        return upstream_resp

    # --- Internal helpers ---

    def _try_synthesis(query: str, model: str) -> Optional[str]:
        """Attempt CAS synthesis. Returns text or None."""
        if not synthesis_engine or not cache:
            return None
        try:
            from cacheback.synthesis import SynthesisCandidate
            candidates_raw = cache.lookup_for_synthesis(
                query,
                threshold=synthesis_engine._threshold,
                top_k=synthesis_engine._top_k,
            )
            if not candidates_raw:
                return None
            candidates = []
            for cache_id, similarity in candidates_raw:
                entry = cache.get_entry(cache_id)
                if entry:
                    candidates.append(SynthesisCandidate(
                        query=entry.query_text,
                        response=entry.response_text,
                        similarity=similarity,
                        cache_id=cache_id,
                    ))
            if not candidates:
                return None
            result = synthesis_engine.synthesize(query, candidates)
            return result.text if result.text else None
        except Exception as e:
            logger.warning("[proxy] synthesis error: %s", e)
            return None

    async def _gate_probe(body: dict, model: str) -> Optional[dict]:
        """Probe upstream model N times (temp>0), measure disagreement.
        Returns gate metadata dict, or None on failure (never breaks pipeline)."""
        if gate is None or http_client is None:
            return None
        try:
            url = f"{config.openai_base_url}/chat/completions"
            headers = {"Content-Type": "application/json"}
            if config.openai_api_key:
                headers["Authorization"] = f"Bearer {config.openai_api_key}"
            probe_body = {
                "model": model,
                "messages": body.get("messages", []),
                "temperature": 0.7,
                "max_tokens": 256,
            }

            # krótki timeout per-probe: gate to overhead na każdym zapytaniu,
            # nie może wisieć. Lepiej brak gate (None) niż zawieszony pipeline.
            probe_timeout = float(os.environ.get("CACHEBACK_GATE_TIMEOUT", "20"))

            async def one():
                r = await http_client.post(url, json=probe_body, headers=headers,
                                           timeout=probe_timeout)
                d = r.json()
                return (d.get("choices") or [{}])[0].get("message", {}).get("content", "") or ""

            import asyncio as _asyncio
            samples = await _asyncio.gather(
                *[one() for _ in range(gate.n_samples)], return_exceptions=True
            )
            samples = [s for s in samples if isinstance(s, str) and s.strip()]
            if len(samples) < 2:
                return None
            verdict = gate.check_samples(samples)
            return verdict.to_dict()
        except Exception as e:
            logger.warning("[proxy] gate probe failed: %s", e)
            return None

    def _build_response(
        text: str,
        model: str,
        cache_hit: bool = False,
        synthesized: bool = False,
        gate: Optional[dict] = None,
        abstained: bool = False,
    ) -> JSONResponse:
        """Build an OpenAI-format JSON response."""
        resp = ChatCompletionResponse(
            model=model,
            choices=[ChatCompletionChoice(
                message=ChatCompletionMessage(content=text),
            )],
            cacheback_hit=cache_hit,
            cacheback_synthesized=synthesized,
        )
        content = resp.model_dump()
        if gate is not None:
            content["cacheback_gate"] = gate
        if abstained:
            content["cacheback_abstained"] = True
        headers = {
            "X-Cacheback-Hit": str(cache_hit).lower(),
            "X-Cacheback-Synthesized": str(synthesized).lower(),
        }
        if gate is not None:
            headers["X-Truthgate-Uncertain"] = str(gate.get("uncertain", False)).lower()
        return JSONResponse(content=content, headers=headers)

    async def _handle_stream(
        body: dict,
        request: Request,
        query: str,
        model: str,
        cached_text: Optional[str],
    ) -> StreamingResponse:
        """Handle streaming requests with cache support."""

        if cached_text is not None:
            logger.debug("[proxy] STREAM HIT: %s", query[:80])
            return StreamingResponse(
                _replay_stream(cached_text, model),
                media_type="text/event-stream",
                headers={
                    "X-Cacheback-Hit": "true",
                    "X-Cacheback-Synthesized": "false",
                },
            )

        # Tier 2: Synthesis → replay as stream
        synth_text = _try_synthesis(query, model)
        if synth_text is not None:
            logger.debug("[proxy] STREAM SYNTHESIS: %s", query[:80])
            return StreamingResponse(
                _replay_stream(synth_text, model),
                media_type="text/event-stream",
                headers={
                    "X-Cacheback-Hit": "false",
                    "X-Cacheback-Synthesized": "true",
                },
            )

        # Tier 3: Forward upstream, buffer and cache
        return StreamingResponse(
            _proxy_stream(body, request, query, model),
            media_type="text/event-stream",
            headers={
                "X-Cacheback-Hit": "false",
                "X-Cacheback-Synthesized": "false",
            },
        )

    async def _replay_stream(text: str, model: str):
        """Replay cached text as SSE stream."""
        chunk_id = f"chatcmpl-cache-{int(time.time())}"
        created = int(time.time())

        # Content chunk
        data = {
            "id": chunk_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{"index": 0, "delta": {"role": "assistant", "content": text}, "finish_reason": None}],
        }
        yield f"data: {json.dumps(data)}\n\n"

        # Stop chunk
        data = {
            "id": chunk_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
        }
        yield f"data: {json.dumps(data)}\n\n"
        yield "data: [DONE]\n\n"

    async def _proxy_stream(
        body: dict,
        request: Request,
        query: str,
        model: str,
    ):
        """Forward streaming request upstream, buffer chunks, cache on completion."""
        body["stream"] = True
        headers = _upstream_headers(request)
        url = f"{config.openai_base_url}/chat/completions"
        buffer = []

        if http_client is None:
            error_data = {"error": {"message": "http_client not initialized", "type": "proxy_error"}}
            yield f"data: {json.dumps(error_data)}\n\n"
            yield "data: [DONE]\n\n"
            return

        try:
            async with http_client.stream(
                "POST", url, json=body, headers=headers
            ) as resp:
                async for line in resp.aiter_lines():
                    yield f"{line}\n"

                    # Parse SSE for buffering
                    if line.startswith("data: ") and line != "data: [DONE]":
                        try:
                            chunk_data = json.loads(line[6:])
                            choices = chunk_data.get("choices", [])
                            if choices:
                                delta = choices[0].get("delta", {})
                                content = delta.get("content")
                                if content:
                                    buffer.append(content)
                        except json.JSONDecodeError:
                            pass

                # After stream completes, cache the full response
                if buffer and cache:
                    full_text = "".join(buffer)
                    cache.populate(query, full_text, model=model)

        except httpx.HTTPError as e:
            # detal tylko do logu; klient dostaje generic (audyt 2026-06-27 #8:
            # surowy str(e) leakował DNS/SSL/ścieżki = recon dla atakującego)
            logger.error("[proxy] upstream stream error: %s", e)
            error_data = {
                "error": {"message": "Upstream service error", "type": "proxy_error"}
            }
            yield f"data: {json.dumps(error_data)}\n\n"
            yield "data: [DONE]\n\n"

    async def _forward_upstream(
        body: dict,
        stream: bool,
        request: Request,
    ) -> JSONResponse:
        """Forward request to upstream OpenAI API."""
        headers = _upstream_headers(request)
        url = f"{config.openai_base_url}/chat/completions"

        try:
            if http_client is None:
                raise httpx.HTTPError("http_client not initialized")
            resp = await http_client.post(url, json=body, headers=headers)
            return JSONResponse(
                content=resp.json(),
                status_code=resp.status_code,
            )
        except (httpx.HTTPError, AttributeError) as e:
            # detal tylko do logu; klient dostaje generic (audyt 2026-06-27 #8)
            logger.error("[proxy] upstream error: %s", e)
            return JSONResponse(
                content={"error": {"message": "Upstream service error", "type": "proxy_error"}},
                status_code=502,
            )

    def _upstream_headers(request: Request) -> dict:
        """Build headers for upstream API call (audyt 2026-06-27 #3 — patrz build_upstream_headers)."""
        return build_upstream_headers(
            config.openai_api_key,
            request.headers.get("authorization", ""),
            config.allow_client_auth,
        )

    def _extract_response_text(resp_data: dict) -> Optional[str]:
        """Extract text from OpenAI response dict."""
        choices = resp_data.get("choices", [])
        if choices:
            msg = choices[0].get("message", {})
            return msg.get("content")
        return None

    def _koryto_exec_payload(req, query: str):
        """Zwraca (payload_dict, source). payload do koryto.verify(**payload).
        Kolejność: (1) jawne pole req.koryto_exec (szczelne, klient świadomy),
        (2) auto-wyłuskanie z query TYLKO gdy config.koryto_exec_from_query (UNSAFE),
        (3) None. Kod ZAWSZE z query (nie z odpowiedzi modelu) — inaczej tautologia."""
        # (1) jawne pole
        ke = getattr(req, "koryto_exec", None)
        if isinstance(ke, dict):
            lang = (ke.get("lang") or "python").lower()
            if lang in ("node", "js", "javascript") and ke.get("code"):
                return ({"exec_js": str(ke["code"])}, "explicit")
            stmts = ke.get("stmts")
            if isinstance(stmts, list) and stmts:
                return ({"exec_stmts": [str(s) for s in stmts]}, "explicit")
        # (2) auto-wyłuskanie z query — TYLKO gdy operator świadomie włączył
        if config.koryto_exec_from_query:
            try:
                from cacheback.codeblocks import extract_code_blocks, to_exec_statements
                for blk in extract_code_blocks(query, source="question"):
                    if blk.lang == "python":
                        stmts = to_exec_statements(blk.code)
                        if stmts:
                            return ({"exec_stmts": stmts}, "auto")
            except Exception:
                pass
        return ({}, None)

    def _apply_koryto_correction(resp_data: dict, truth: str) -> dict:
        """Podmień treść odpowiedzi na prawdę z koryta, zachowując strukturę OpenAI.
        Zwraca KOPIĘ (nie mutuje oryginału)."""
        data = json.loads(json.dumps(resp_data))  # deep copy
        choices = data.get("choices") or [{}]
        msg = choices[0].setdefault("message", {})
        msg["content"] = str(truth)
        choices[0]["finish_reason"] = "stop"
        data["choices"] = choices
        return data

    def _web_arbiter(query: str, model_answer: str, koryto_truth: str) -> dict:
        """Web-ROZJEMCA: gdy miękkie koryto (lookup) odrzuca odpowiedź modelu, web
        rozsądza KTO ma rację. Zwraca {verdict: model|koryto|niejasne, ...}.

        Mechanizm (Badanie C, REJESTR): snippety wspierają model → koryto stale
        (uratuj model). Wspierają koryto → model zły (koryguj). Oba/żadne → niejasne.
        Próg jakości snippetu zapobiega truciu (web-szum)."""
        try:
            from cacheback.branches import _token_overlap
            wr = web_branch.fetch(query)
            text = wr.context or " ".join(
                str(r.get("title", "") + " " + r.get("snippet", "")) for r in (wr.results or []))
            if not text.strip():
                return {"verdict": "niejasne", "reason": "brak snippetów", "web_score": wr.score}
            sup_model = _token_overlap(model_answer, text)
            sup_koryto = _token_overlap(str(koryto_truth), text)
            # wsparcie = atom obecny w snippecie z marginesem nad drugim
            margin = 0.15
            if sup_model >= sup_koryto + margin:
                return {"verdict": "model", "reason": "web wspiera model (koryto stale)",
                        "sup_model": round(sup_model, 3), "sup_koryto": round(sup_koryto, 3)}
            if sup_koryto >= sup_model + margin:
                return {"verdict": "koryto", "reason": "web potwierdza koryto (model zły)",
                        "sup_model": round(sup_model, 3), "sup_koryto": round(sup_koryto, 3)}
            return {"verdict": "niejasne", "reason": "web nie rozstrzygnął",
                    "sup_model": round(sup_model, 3), "sup_koryto": round(sup_koryto, 3)}
        except Exception as e:
            # detal tylko do logu; metadane klienta dostają generic (audyt 2026-06-27 #8)
            logger.warning("[proxy] web arbiter failed: %s", e)
            return {"verdict": "niejasne", "reason": "web arbiter unavailable"}

    return app


# Default app instance (for `uvicorn cacheback.proxy.app:app`)
app = create_app()
