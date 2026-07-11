"""gatecat-proxy — OpenAI-compatible caching proxy server.

Receives standard OpenAI API requests, routes through SemanticCache,
forwards misses to the upstream provider. Zero code change for users.

Usage:
    uvicorn gatecat.proxy.app:app --host 0.0.0.0 --port 8080

Or via Docker:
    docker run -e OPENAI_API_KEY=sk-... -p 8080:8080 gatecat/proxy
"""

import json
import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from typing import Optional

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

# NOTE: gatecat.cache is imported LAZILY inside the lifespan, not here. It pulls
# numpy/onnxruntime (the [cache] extra); the ACTION-VETO is pure stdlib. So
# `pip install gate-cat[proxy]` must import and veto WITHOUT the heavy cache
# stack — a client who only wants "veto my agent" should not need onnxruntime.
from gatecat.integrations import (
    check_action,
    ActionVetoed,
    ExtraPolicyError,
    policies_with_extras,
)
from gatecat.proxy.config import ProxyConfig
from gatecat.proxy.models import (
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatCompletionChoice,
    ChatCompletionMessage,
    CompletionUsage,
    ChatCompletionChunk,
    StreamChoice,
    DeltaContent,
)

logger = logging.getLogger("gatecat.proxy")


def _resolve_veto_policies():
    """Resolve the effective veto policy list ONCE at import: DOGFOOD_DEFAULTS
    plus any operator-configured GATECAT_EXTRA_POLICIES packs.

    Fail-closed (security tool): if the env var names a pack that cannot be
    imported or contains a non-Policy object, we do NOT silently fall back to
    the defaults — the operator believes those policies are enforced. We log
    loudly (stderr + logger) and re-raise so the proxy REFUSES TO START rather
    than serve traffic with a gap the user thinks is covered. The import fails,
    so `uvicorn gatecat.proxy.app:app` aborts with the reason on stderr.
    """
    try:
        return policies_with_extras()
    except ExtraPolicyError as exc:
        msg = (
            f"gate.cat FATAL [EXTRA_POLICIES]: {exc} — refusing to start the "
            "proxy with a policy pack the operator configured but that could "
            "not be loaded (fail-closed)."
        )
        print(msg, file=sys.stderr, flush=True)
        logger.critical(msg)
        raise


# Effective deny-list for the proxy layer: built-ins + GATECAT_EXTRA_POLICIES.
# Resolved once at import (env is fixed for the server's lifetime); a broken
# extra-policy config aborts startup rather than degrading silently.
_VETO_POLICIES = _resolve_veto_policies()


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


# ---- ACTION-VETO on tool calls (proxy layer) --------------------------------
# A tool-calling agent on ANY OpenAI-compatible provider asks the model what to
# run; the model answers with `tool_calls`. We check each proposed call against
# the deny-list BEFORE it reaches the agent, so `rm -rf`, `terraform destroy`,
# `DROP TABLE`, `gh repo delete`, disk wipes, etc. never get executed. The agent
# needs zero code — it just points its base_url at the proxy.

def _flatten_tool_call(tc: dict) -> str:
    """Flatten one OpenAI tool_call into a single string the deny-policies scan.

    Shape: ``{"type":"function","function":{"name":..,"arguments":"<json str>"}}``.
    The policies are regexes over command-like text, so a dangerous command inside
    the arguments (e.g. a shell tool's ``command`` field) is caught wherever it
    sits. Non-string arguments are JSON-flattened (full payload, never truncated).
    """
    if not isinstance(tc, dict):
        return str(tc)
    fn = tc.get("function") or {}
    name = fn.get("name", "") or ""
    args = fn.get("arguments", "")
    if not isinstance(args, str):
        try:
            args = json.dumps(args, ensure_ascii=True)
        except Exception:
            args = str(args)
    return f"{name} {args}".strip()


def _veto_tool_calls(resp_data: dict):
    """Scan every tool_call in an upstream completion against the deny-list.

    Returns ``(blocked, reason, offending)``. Only ever blocks when a real
    tool_call is present AND it is dangerous, unparseable, or the engine errored
    on it (fail-closed on a real call). A plain text completion (no tool_calls)
    is never touched.
    """
    if not isinstance(resp_data, dict):
        return False, "", ""
    for ch in (resp_data.get("choices") or []):
        msg = (ch or {}).get("message") or {}
        for tc in (msg.get("tool_calls") or []):
            try:
                action = _flatten_tool_call(tc)
            except Exception:
                return True, "gate.cat: unparseable tool call (fail-closed)", ""
            if not action:
                continue
            try:
                check_action("proxy_tool_call", action, _VETO_POLICIES)
            except ActionVetoed as exc:
                return True, str(exc), action
            except Exception as exc:  # engine error on a REAL call -> fail-closed
                return True, f"gate.cat: veto engine error (fail-closed): {exc}", action
    return False, "", ""


def _build_veto_response(resp_data: dict, reason: str, offending: str) -> dict:
    """A completion telling the agent the action was vetoed, with NO tool_calls
    so the agent loop executes nothing. finish_reason='stop' ends the turn."""
    content = (
        "gate.cat VETO — this action was blocked before it ran.\n"
        f"Reason: {reason}\n"
        f"Blocked tool call: {offending[:400]}\n"
        "If this is legitimate, a human must run it manually."
    )
    return {
        "id": resp_data.get("id", "gatecat-veto"),
        "object": "chat.completion",
        "model": resp_data.get("model", ""),
        "choices": [{
            "index": 0,
            "finish_reason": "stop",
            "message": {"role": "assistant", "content": content},
        }],
        "gatecat": {"vetoed": True, "reason": reason},
    }


async def _sse_from_completion(resp_data: dict):
    """Re-emit a whole (non-streamed) completion as OpenAI SSE chunks, so a client
    that asked for stream=True still gets a stream after we gated the tool call."""
    choice = (resp_data.get("choices") or [{}])[0]
    msg = choice.get("message") or {}
    base = {
        "id": resp_data.get("id", "gatecat"),
        "object": "chat.completion.chunk",
        "model": resp_data.get("model", ""),
    }
    delta = {"role": "assistant"}
    if msg.get("content"):
        delta["content"] = msg["content"]
    if msg.get("tool_calls"):
        delta["tool_calls"] = msg["tool_calls"]
    first = {**base, "choices": [{"index": 0, "delta": delta, "finish_reason": None}]}
    yield f"data: {json.dumps(first)}\n\n"
    fin = {**base, "choices": [{"index": 0, "delta": {},
                                "finish_reason": choice.get("finish_reason") or "stop"}]}
    yield f"data: {json.dumps(fin)}\n\n"
    yield "data: [DONE]\n\n"


def build_upstream_headers(api_key: str, client_auth_header: str,
                           allow_client_auth: bool) -> dict:
    """Build upstream headers (audit 2026-06-27 #3 — testable, pure function).

    By default use ONLY the configured key. The client Authorization is
    forwarded ONLY when allow_client_auth=True and no key is configured
    (multi-tenant proxy) — otherwise an attacker could inject their own/foreign key.
    Without a key: do NOT send an empty Bearer.
    """
    key = api_key
    if not key and allow_client_auth and client_auth_header.startswith("Bearer "):
        key = client_auth_header[7:]
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    return headers


def create_app(config: Optional[ProxyConfig] = None) -> FastAPI:
    """Create the gatecat proxy FastAPI app."""

    if config is None:
        config = ProxyConfig.from_env()

    cache = None  # SemanticCache, lazily created in lifespan (needs [cache] extra)
    synthesis_engine = None
    http_client: Optional[httpx.AsyncClient] = None
    gate = None  # TruthGate (gatecat.Gate), init in lifespan if gate_mode != off
    web_branch = None   # 3rd cascade branch (gatecat.WebBranch)
    tool_branch = None  # 4th cascade branch (gatecat.ToolBranch)
    koryto = None       # deterministic atom verifier (gatecat.Koryto)
    stagnation = None   # stagnation-by-state: watches whether the koryto has gone stale

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        nonlocal cache, synthesis_engine, http_client, gate, web_branch, tool_branch, koryto, stagnation

        # Initialize cache — lazy import so a [proxy]-only install (no numpy/onnx)
        # still runs: the action-veto works cache-less, only the semantic-cache
        # tier is disabled. Install gate-cat[cache] (or [proxy] with [cache]) for it.
        try:
            from gatecat.cache import SemanticCache, DEFAULT_CACHE_DIR
            cache = SemanticCache(
                cache_dir=config.cache_dir or DEFAULT_CACHE_DIR,
                similarity_threshold=config.similarity_threshold,
                negative_threshold=config.negative_threshold,
                max_entries=config.cache_max_entries,
                ttl_seconds=config.cache_ttl,
                on_negative_hit=config.on_negative_hit,
            )
        except ImportError as e:
            cache = None
            logger.warning("[proxy] semantic cache disabled (%s) — action-veto still "
                           "active; install gate-cat[cache] to enable caching.", e)

        # Initialize CAS synthesis engine
        if config.synthesis_mode in ("auto", "always"):
            try:
                from gatecat.synthesis import SynthesisEngine
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
                from gatecat.gate import Gate
                embedder = None
                if config.gate_semantic:
                    try:
                        from gatecat.embedders import get_embedder
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
        # Enabled when gate OR koryto is active — the web arbiter also handles koryto disagreement.
        if config.gate_mode in ("flag", "block") or config.koryto_mode in ("flag", "block"):
            try:
                if config.web_enabled:
                    from gatecat.branches import WebBranch
                    web_branch = WebBranch(api_key=config.brave_api_key or None)
                    logger.info("Web branch enabled (Brave)")
                if config.tools_enabled:
                    from gatecat.branches import ToolBranch
                    tool_branch = ToolBranch()
                    logger.info("Tool branch enabled (builtin: calculate)")
            except Exception as e:
                logger.warning("Repair branches init failed: %s", e)

        # KORYTO — deterministic atom verifier (works INDEPENDENTLY of the gate)
        if config.koryto_mode in ("flag", "block"):
            try:
                from gatecat.koryto import Koryto, FactBase
                from gatecat.stagnation import StagnationMonitor
                from gatecat.koryto_sources import (
                    http_cache_source, chroma_source, multi_source,
                )
                # JSON file (small, for validation)
                facts = {}
                if config.koryto_fact_base:
                    try:
                        facts = json.loads(open(config.koryto_fact_base, encoding="utf-8").read())
                        logger.info("Koryto fact-base (JSON): %d entries", len(facts))
                    except Exception as e:
                        logger.warning("Koryto fact-base JSON load failed (%s)", e)
                # REAL DATABASES (multi-source with a quality gate; REGISTRY 2026-06-27).
                # Lookup queries ALL good-quality ones: 4M cache + ChromaDB (after the MCQ filter).
                sources = []
                if config.koryto_cache_url:
                    sources.append(http_cache_source(
                        config.koryto_cache_url, api_key=config.koryto_cache_key,
                        min_sim=config.koryto_lookup_min_sim))
                    logger.info("Koryto lookup source: cache %s", config.koryto_cache_url)
                if config.koryto_chroma_url and config.koryto_chroma_collection:
                    sources.append(chroma_source(
                        config.koryto_chroma_url, config.koryto_chroma_collection,
                        min_sim=config.koryto_lookup_min_sim))
                    logger.info("Koryto lookup source: chroma %s/%s (MCQ filter)",
                                config.koryto_chroma_url, config.koryto_chroma_collection)
                lookup_fn = multi_source(sources) if sources else None
                fb = None
                if facts or lookup_fn is not None:
                    fb = FactBase(facts or None, lookup_fn=lookup_fn)
                koryto = Koryto(fact_base=fb)
                # stagnation-by-state watches the koryto (whether a run of soft rejections = stale database)
                stagnation = StagnationMonitor(
                    window=config.stagnation_window,
                    soft_streak_trigger=config.stagnation_soft_streak,
                )
                logger.info("Koryto enabled: mode=%s (exec+calc%s) + stagnation-monitor",
                            config.koryto_mode, "+lookup" if fb else "")
            except Exception as e:
                logger.warning("Koryto init failed: %s", e)

        logger.info(
            "gatecat-proxy started: threshold=%.2f, synthesis=%s, gate=%s",
            config.similarity_threshold,
            config.synthesis_mode,
            config.gate_mode,
        )

        # ENFORCEMENT BANNER (0.4.10) — the proxy can only veto tool calls that
        # actually flow THROUGH it. The #1 proxy failure mode is silent: an agent
        # whose base_url points straight at the provider is never inspected, and
        # a proxy that never sees traffic looks identical to one that is working.
        # So we state the enforcement status loudly at startup, and if the veto is
        # OFF we warn — a misconfigured (veto-disabled) proxy must not look healthy.
        # Operators verify live via GET /health -> "action_veto".
        if config.tool_veto == "off":
            logger.warning(
                "[proxy] ACTION-VETO IS OFF (GATECAT_PROXY_TOOL_VETO=off) — tool "
                "calls are NOT inspected. The proxy is a passthrough. Point your "
                "agent's base_url here AND set tool_veto=block for enforcement."
            )
        else:
            logger.info(
                "[proxy] ACTION-VETO active: mode=%s, %d deny-policies. Enforcement "
                "only covers agents whose base_url actually points at this proxy "
                "(%s); verify at GET /health.",
                config.tool_veto, len(_VETO_POLICIES),
                config.openai_base_url,
            )

        yield

        # Cleanup
        if cache:
            cache.close()
        if http_client:
            await http_client.aclose()

    app = FastAPI(
        title="gatecat-proxy",
        description="OpenAI-compatible caching proxy with semantic similarity",
        version="0.2.1",
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
            # ENFORCEMENT STATUS (0.4.10) — lets an operator/agent confirm the veto
            # is really on. `enforcing` is False when tool_veto=off (passthrough),
            # so a health check can catch a misconfigured proxy instead of trusting
            # that "200 OK" means "protected". Does NOT prove the agent routes
            # through this proxy — that is the operator's base_url responsibility.
            "action_veto": {
                "mode": config.tool_veto,
                "enforcing": config.tool_veto == "block",
                "policies": len(_VETO_POLICIES),
            },
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

        # ACTION-VETO: a tool-calling request gets its proposed tool_calls checked
        # against the deny-list before they reach the agent. We force a
        # non-streaming upstream call so the gate always sees the COMPLETE tool
        # call (no partial-delta races), then re-emit in the client's shape.
        if req.tools and config.tool_veto != "off":
            probe_body = {**body, "stream": False}
            upstream = await _forward_upstream(probe_body, False, request)
            if not isinstance(upstream, JSONResponse):
                return upstream
            try:
                data = json.loads(upstream.body.decode())
            except Exception:
                return upstream  # unparseable upstream -> pass through unchanged
            blocked, reason, offending = _veto_tool_calls(data)
            if blocked and config.tool_veto == "block":
                logger.warning("[proxy] TOOL-VETO blocked: %s", offending[:120])
                out = _build_veto_response(data, reason, offending)
            elif blocked:  # flag mode: annotate, do not block
                logger.info("[proxy] TOOL-VETO flag: %s", offending[:120])
                data.setdefault("gatecat", {})["tool_veto_flag"] = {
                    "reason": reason, "call": offending[:400]}
                out = data
            else:
                out = data
            if stream:
                return StreamingResponse(_sse_from_completion(out),
                                         media_type="text/event-stream")
            return JSONResponse(content=out, status_code=upstream.status_code)

        # Passthrough: tool calls (veto off) or empty queries bypass cache
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
        # Cache did not repair it → measure whether the small model is confident. Uncertain =
        # try repair (tools/web), then flag it (flag) or refuse (block).
        gate_meta = None
        if gate is not None:
            gate_meta = await _gate_probe(body, model)
            if gate_meta and gate_meta.get("uncertain"):
                # branch 4 (tools): deterministic, when it applies (e.g. a calculation)
                if tool_branch is not None:
                    hit = tool_branch.maybe_run(query)
                    if hit:
                        tool_name, observation = hit
                        logger.debug("[proxy] TOOL %s: %s", tool_name, query[:60])
                        return _build_response(
                            observation, model,
                            gate={**gate_meta, "repaired_by": f"tool:{tool_name}"},
                        )
                # branch 3 (web): fresh context ONLY when the snippet has the answer
                if web_branch is not None:
                    wr = web_branch.fetch(query)
                    if wr.used:
                        logger.debug("[proxy] WEB (score=%.2f): %s", wr.score, query[:60])
                        # inject the web context into the prompt and force an upstream answer
                        body = dict(body)
                        body["messages"] = [
                            {"role": "system", "content": "Use ONLY this context to answer. "
                             "If it does not contain the answer, say you don't know.\n\n" + wr.context},
                            *body.get("messages", []),
                        ]
                        gate_meta = {**gate_meta, "repaired_by": "web", "web_score": round(wr.score, 3)}
                        # fall through to Tier 3 with the enriched prompt (do not block)
                    elif config.gate_mode == "block":
                        return _build_response(
                            "I am not confident enough to answer reliably. "
                            "(disagreement=%.2f) — human verification recommended."
                            % gate_meta.get("disagreement", 0.0),
                            model, gate=gate_meta, abstained=True,
                        )
                elif config.gate_mode == "block":
                    return _build_response(
                        "I am not confident enough to answer reliably. "
                        "(disagreement=%.2f) — human verification recommended."
                        % gate_meta.get("disagreement", 0.0),
                        model, gate=gate_meta, abstained=True,
                    )

        # --- Tier 3: Upstream API call ---
        upstream_resp = await _forward_upstream(body, False, request)

        # --- Tier 3.5: KORYTO — verify the model's answer deterministically ---
        # Works INDEPENDENTLY of the gate: catches confident-wrong (zero spread) that
        # the gate does not see. A hard koryto (exec/calc) rejects → return the truth from the koryto.
        koryto_meta = None
        original_text = None
        if koryto is not None and isinstance(upstream_resp, JSONResponse):
            try:
                resp_data = json.loads(upstream_resp.body.decode())
                model_answer = _extract_response_text(resp_data) or ""
                exec_payload, exec_source = _koryto_exec_payload(req, query)
                kv = koryto.verify(query, model_answer, **exec_payload)
                if exec_source:
                    pass  # exec_source added to meta below
                if kv.verdict != "unknown":
                    # TRUTH-FORGERY GUARD: exec with source='auto' = code from the user's query.
                    # The attacker controls the query → controls the exec-"truth". Do NOT correct
                    # hard on auto-exec alone; only an explicit field ('explicit') or calc/lookup.
                    forgeable = (kv.channel == "exec" and exec_source == "auto")

                    koryto_meta = kv.to_dict()
                    if exec_source:
                        koryto_meta["exec_source"] = exec_source
                    # Do NOT leak the forged "truth" into the metadata (audit 2026-06-27 should-fix):
                    # when forgeable, attacker-controlled output must not masquerade as 'truth'.
                    if forgeable:
                        koryto_meta["truth"] = None
                        koryto_meta["forgeable"] = True

                    # stagnation: track whether the koryto has gone stale (a run of soft rejections)
                    if stagnation is not None:
                        st = stagnation.observe(kv)
                        koryto_meta["stagnation"] = st.to_dict()

                    if config.koryto_mode == "block" and kv.verdict == "refute" and kv.truth:
                        if kv.hard and not kv.needs_arbiter and not forgeable:
                            # HARD koryto (exec/calc): the interpreter does not err → correct immediately.
                            original_text = model_answer
                            corrected = _apply_koryto_correction(resp_data, kv.truth)
                            koryto_meta["corrected"] = True
                            koryto_meta["repaired_by"] = "koryto:" + kv.channel
                            koryto_meta["original_answer"] = (original_text or "")[:200]
                            corrected["gatecat_koryto"] = koryto_meta
                            if gate_meta is not None:
                                corrected["gatecat_gate"] = gate_meta
                            return JSONResponse(content=corrected, headers={
                                "X-Koryto-Verdict": "refute", "X-Koryto-Channel": kv.channel,
                                "X-Koryto-Corrected": "true"})
                        elif kv.needs_arbiter and web_branch is not None:
                            # SOFT koryto (lookup): the database can be stale → the web ARBITER decides
                            # WHO is right (the model or the koryto). Do NOT block blindly on the database.
                            arb = _web_arbiter(query, model_answer, kv.truth)
                            koryto_meta["arbiter"] = arb
                            if arb["verdict"] == "koryto":
                                # web confirms the koryto → the model is genuinely wrong → correct
                                corrected = _apply_koryto_correction(resp_data, kv.truth)
                                corrected["gatecat_koryto"] = {**koryto_meta, "corrected": True,
                                    "repaired_by": "koryto:lookup+web", "original_answer": model_answer[:200]}
                                return JSONResponse(content=corrected, headers={
                                    "X-Koryto-Verdict": "refute", "X-Koryto-Channel": "lookup+web",
                                    "X-Koryto-Corrected": "true"})
                            # arb=="model" (koryto stale, rescue the model) or "niejasne" → do NOT correct,
                            # just flag it (the model's answer stays).
            except Exception as e:
                logger.warning("[proxy] koryto check failed: %s", e)

        if (gate_meta is not None or koryto_meta is not None) and isinstance(upstream_resp, JSONResponse):
            try:
                data = json.loads(upstream_resp.body.decode())
                hdrs = dict(upstream_resp.headers)
                if gate_meta is not None:
                    data["gatecat_gate"] = gate_meta
                    hdrs["X-Truthgate-Uncertain"] = str(gate_meta.get("uncertain", False)).lower()
                    hdrs["X-Truthgate-Disagreement"] = str(round(gate_meta.get("disagreement", 0.0), 3))
                if koryto_meta is not None:
                    data["gatecat_koryto"] = koryto_meta
                    hdrs["X-Koryto-Verdict"] = koryto_meta.get("verdict", "")
                    hdrs["X-Koryto-Channel"] = koryto_meta.get("channel", "")
                upstream_resp = JSONResponse(content=data, headers=hdrs)
            except Exception:
                pass

        # Cache the response — do NOT cache an answer the koryto rejected as wrong
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
            from gatecat.synthesis import SynthesisCandidate
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

            # short per-probe timeout: the gate is overhead on every request,
            # it must not hang. Better no gate (None) than a stalled pipeline.
            probe_timeout = float(os.environ.get("GATECAT_GATE_TIMEOUT", "20"))

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
            gatecat_hit=cache_hit,
            gatecat_synthesized=synthesized,
        )
        content = resp.model_dump()
        if gate is not None:
            content["gatecat_gate"] = gate
        if abstained:
            content["gatecat_abstained"] = True
        headers = {
            "X-Gatecat-Hit": str(cache_hit).lower(),
            "X-Gatecat-Synthesized": str(synthesized).lower(),
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
                    "X-Gatecat-Hit": "true",
                    "X-Gatecat-Synthesized": "false",
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
                    "X-Gatecat-Hit": "false",
                    "X-Gatecat-Synthesized": "true",
                },
            )

        # Tier 3: Forward upstream, buffer and cache
        return StreamingResponse(
            _proxy_stream(body, request, query, model),
            media_type="text/event-stream",
            headers={
                "X-Gatecat-Hit": "false",
                "X-Gatecat-Synthesized": "false",
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
            # detail only to the log; the client gets a generic message (audit 2026-06-27 #8:
            # raw str(e) leaked DNS/SSL/paths = recon for an attacker)
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
            # detail only to the log; the client gets a generic message (audit 2026-06-27 #8)
            logger.error("[proxy] upstream error: %s", e)
            return JSONResponse(
                content={"error": {"message": "Upstream service error", "type": "proxy_error"}},
                status_code=502,
            )

    def _upstream_headers(request: Request) -> dict:
        """Build headers for upstream API call (audit 2026-06-27 #3 — see build_upstream_headers)."""
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
        """Returns (payload_dict, source). payload for koryto.verify(**payload).
        Order: (1) the explicit field req.koryto_exec (airtight, client is aware),
        (2) auto-extraction from the query ONLY when config.koryto_exec_from_query (UNSAFE),
        (3) None. The code ALWAYS comes from the query (not the model's answer) — otherwise a tautology."""
        # (1) explicit field
        ke = getattr(req, "koryto_exec", None)
        if isinstance(ke, dict):
            lang = (ke.get("lang") or "python").lower()
            if lang in ("node", "js", "javascript") and ke.get("code"):
                return ({"exec_js": str(ke["code"])}, "explicit")
            stmts = ke.get("stmts")
            if isinstance(stmts, list) and stmts:
                return ({"exec_stmts": [str(s) for s in stmts]}, "explicit")
        # (2) auto-extraction from the query — ONLY when the operator has deliberately enabled it
        if config.koryto_exec_from_query:
            try:
                from gatecat.codeblocks import extract_code_blocks, to_exec_statements
                for blk in extract_code_blocks(query, source="question"):
                    if blk.lang == "python":
                        stmts = to_exec_statements(blk.code)
                        if stmts:
                            return ({"exec_stmts": stmts}, "auto")
            except Exception:
                pass
        return ({}, None)

    def _apply_koryto_correction(resp_data: dict, truth: str) -> dict:
        """Replace the response content with the truth from the koryto, preserving the OpenAI structure.
        Returns a COPY (does not mutate the original)."""
        data = json.loads(json.dumps(resp_data))  # deep copy
        choices = data.get("choices") or [{}]
        msg = choices[0].setdefault("message", {})
        msg["content"] = str(truth)
        choices[0]["finish_reason"] = "stop"
        data["choices"] = choices
        return data

    def _web_arbiter(query: str, model_answer: str, koryto_truth: str) -> dict:
        """Web ARBITER: when the soft koryto (lookup) rejects the model's answer, the web
        decides WHO is right. Returns {verdict: model|koryto|niejasne, ...}.

        Mechanism (Study C, REGISTRY): snippets support the model → koryto stale
        (rescue the model). They support the koryto → the model is wrong (correct). Both/neither → niejasne.
        The snippet-quality threshold prevents poisoning (web noise)."""
        try:
            from gatecat.branches import _token_overlap
            wr = web_branch.fetch(query)
            text = wr.context or " ".join(
                str(r.get("title", "") + " " + r.get("snippet", "")) for r in (wr.results or []))
            if not text.strip():
                return {"verdict": "niejasne", "reason": "no snippets", "web_score": wr.score}
            sup_model = _token_overlap(model_answer, text)
            sup_koryto = _token_overlap(str(koryto_truth), text)
            # support = the atom is present in the snippet with a margin over the other
            margin = 0.15
            if sup_model >= sup_koryto + margin:
                return {"verdict": "model", "reason": "web supports the model (koryto stale)",
                        "sup_model": round(sup_model, 3), "sup_koryto": round(sup_koryto, 3)}
            if sup_koryto >= sup_model + margin:
                return {"verdict": "koryto", "reason": "web confirms the koryto (model wrong)",
                        "sup_model": round(sup_model, 3), "sup_koryto": round(sup_koryto, 3)}
            return {"verdict": "niejasne", "reason": "web did not decide",
                    "sup_model": round(sup_model, 3), "sup_koryto": round(sup_koryto, 3)}
        except Exception as e:
            # detail only to the log; the client metadata gets a generic message (audit 2026-06-27 #8)
            logger.warning("[proxy] web arbiter failed: %s", e)
            return {"verdict": "niejasne", "reason": "web arbiter unavailable"}

    return app


# Default app instance (for `uvicorn gatecat.proxy.app:app`)
app = create_app()
