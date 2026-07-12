"""Proxy configuration via environment variables."""

import ipaddress
import json
import os
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse


class UpstreamURLError(ValueError):
    """openai_base_url points to an unsafe/private target (SSRF guard)."""


def _is_private_host(host: str) -> bool:
    """Whether the host resolves to a private/loopback/link-local IP (SSRF)."""
    # direct IP literal
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        pass
    # hostname → try to resolve (best-effort; no DNS = don't block blindly)
    try:
        for fam, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(sockaddr[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return True
    except (socket.gaierror, ValueError, OSError):
        return False
    return False


def validate_upstream_url(url: str) -> str:
    """SSRF guard (audit 2026-06-27 #2): reject non-https and private/metadata targets.

    The default api.openai.com passes. A custom URL must be https and must NOT point to
    a private IP / 169.254.169.254 (cloud metadata) — otherwise the proxy could exfiltrate
    the API key to an internal service. Deliberate relaxation (local LLM, http upstream):
    `GATECAT_ALLOW_INSECURE_UPSTREAM=1`.
    """
    if os.environ.get("GATECAT_ALLOW_INSECURE_UPSTREAM", "0").strip() in ("1", "true", "True"):
        return url
    p = urlparse(url)
    if p.scheme != "https":
        raise UpstreamURLError(
            f"openai_base_url must be https (it is {p.scheme!r}). "
            "For a local/http upstream set GATECAT_ALLOW_INSECURE_UPSTREAM=1."
        )
    host = p.hostname or ""
    if not host:
        raise UpstreamURLError(f"openai_base_url has no host: {url!r}")
    if _is_private_host(host):
        raise UpstreamURLError(
            f"openai_base_url points to a private/metadata target ({host}) — SSRF guard. "
            "Deliberate use: GATECAT_ALLOW_INSECURE_UPSTREAM=1."
        )
    return url


@dataclass
class ProxyConfig:
    """Proxy server configuration. All values from env vars with sensible defaults."""

    # Upstream provider
    openai_api_key: str = ""
    openai_base_url: str = "https://api.openai.com/v1"

    # Cache settings
    cache_dir: str = ""
    similarity_threshold: float = 0.92
    negative_threshold: float = 0.85
    cache_max_entries: int = 100_000
    cache_ttl: int = 24 * 3600
    on_negative_hit: str = "skip"  # proxy default: skip (don't block requests)

    # Synthesis (CAS)
    synthesis_mode: str = "off"
    synthesis_model: str = "google/gemini-2.0-flash-lite-001"
    synthesis_model_base_url: str = ""
    synthesis_model_api_key: str = ""
    synthesis_threshold: float = 0.80
    synthesis_top_k: int = 5

    # TruthGate (disagreement gate). off | flag | block
    #   off:   disabled (zero changes, default)
    #   flag:  measures uncertainty, adds metadata to the response (does not block)
    #   block: when uncertain and no cache repair -> returns abstention instead of guessing
    gate_mode: str = "off"
    gate_n_samples: int = 5
    gate_threshold: float = 0.30
    gate_semantic: bool = True  # MiniLM for semantic spread (vs lexical)

    # ACTION-VETO on tool-calls — an action gate AT THE PROXY LEVEL.
    # When the upstream (Ollama/NIM/OpenRouter/vLLM/...) returns tool_calls, each one is
    # checked against 20 DOGFOOD policies (recursive-force delete, prod infra
    # teardown, destructive SQL, repo/registry deletion, disk wipe, ...). A dangerous
    # tool-call is BLOCKED before the agent executes it — the client writes no
    # code at all, it just points base_url at the proxy.
    # block | flag | off  (default: block — this is the whole point of this proxy).
    #   block: dangerous tool-call -> return a refusal to the agent instead of the call
    #   flag:  don't block, just append the `gatecat.tool_veto_flag` metadata
    #   off:   let it through (old behavior)
    tool_veto: str = "block"

    # Repair branches (when gate uncertain + cache weak): web → tools → abstain
    web_enabled: bool = False        # 3rd branch: Brave web-search (requires BRAVE_API_KEY)
    brave_api_key: str = ""
    tools_enabled: bool = True       # 4th branch: built-in tools (calc)

    # KORYTO — a deterministic atom verifier. off | flag | block
    #   Works INDEPENDENTLY of the gate (on the question's structure, not on spread) → catches
    #   confident-wrong that the gate doesn't see (zero spread). This is the missing link:
    #   gate/audit DIAGNOSE confident-wrong, koryto REACTS to it.
    #   off:   disabled (default, zero changes).
    #   flag:  verifies exec/calc/lookup, adds a verdict to the metadata (does not block).
    #   block: when the HARD koryto (exec/calc) rejects the answer → returns the truth from koryto
    #          instead of the model's confident-wrong. Lookup (soft) NEVER blocks on its own
    #          (needs_arbiter) — it requires a web arbiter, because the base can be stale.
    koryto_mode: str = "off"
    koryto_fact_base: str = ""       # path to JSON {question-fragment: value} for the lookup channel
    # REAL BASES for the lookup channel (multi-source with a quality gate, REGISTER 2026-06-27).
    # Lookup queries ALL good-quality ones, not just the small JSON. Gate: sim≥threshold + MCQ filter.
    koryto_cache_url: str = ""       # semantic cache URL (e.g. 4M VPS) — http_cache_source
    koryto_cache_key: str = ""       # key for the cache (when required)
    koryto_chroma_url: str = ""      # ChromaDB v2 URL (e.g. GTX1070 :8775)
    koryto_chroma_collection: str = ""  # collection id in ChromaDB (after the MCQ filter)
    koryto_lookup_min_sim: float = 0.82  # retrieval quality threshold (on-target vs loose)
    # STAGNATION — watches whether koryto has rotted (a run of soft rejections = stale base)
    stagnation_window: int = 5
    stagnation_soft_streak: int = 3  # how many soft rejections in a row = koryto suspect
    # EXEC — interpreter channel. An explicit koryto_exec field in the body works (via sandbox).
    # AUTO-extraction of code from TRAFFIC is OFF by default (a plain pip-sandbox is not fully
    # airtight against hostile code — the env name has UNSAFE on purpose, the operator sees the risk).
    koryto_exec_from_query: bool = False    # set GATECAT_KORYTO_EXEC_UNSAFE=1 to enable
    koryto_exec_timeout: float = 5.0
    koryto_exec_mem_mb: int = 512

    # LOCAL BUDGET-CAP + LOCAL STAGNATION HALT (2026-07-12) — both FREE, both run
    # in-process on THIS proxy. Per session key (X-Gatecat-Session header, else the
    # client API key) we accumulate completion_tokens * per-model price into a
    # running USD cost; over `budget_usd` the proxy VETOES the next action (halts
    # by denying, it does NOT kill an external process). Stagnation feeds each
    # request's flattened tool-call / assistant-message hash to a per-session
    # StateStagnationDetector; a trip vetoes (or warns, per stagnation_action).
    #
    # RED LINE: these are the LOCAL kill/cap — never tier-gated. 0 disables each.
    budget_usd: float = 0.0                 # 0 == off (no local budget cap)
    budget_action: str = "block"            # block | warn
    # per-model USD price PER 1K completion tokens; "default" is the fallback.
    model_prices: dict = field(default_factory=lambda: {
        "default": 0.0,
        "gpt-4o": 0.010, "gpt-4o-mini": 0.0006, "gpt-4.1": 0.008,
        "o3": 0.040, "o4-mini": 0.0044,
        "claude-3-5-sonnet": 0.015, "claude-3-5-haiku": 0.004,
        "claude-sonnet-4": 0.015, "claude-opus-4": 0.075,
        "deepseek-chat": 0.0011, "deepseek-reasoner": 0.0022,
    })
    stagnation_local: str = "off"           # off | warn | block (local loop-guard)
    stagnation_local_repeat: int = 2        # identical actions before it trips (3rd)

    # Upstream security (audit 2026-06-27 #3): by default do NOT forward the
    # client's Authorization header upstream (an attacker could inject their own key).
    # Deliberate enablement (multi-tenant proxy where the client supplies their own key):
    # GATECAT_ALLOW_CLIENT_AUTH=1.
    allow_client_auth: bool = False

    # Server
    host: str = "0.0.0.0"
    port: int = 8080
    log_level: str = "info"

    @staticmethod
    def _model_prices_from_env(default_prices: dict) -> dict:
        """Merge the built-in per-model price table with an optional JSON override
        (GATECAT_PROXY_MODEL_PRICES = {"model": usd_per_1k, ...}). A broken value
        is ignored (the local cap must never fail to start on a typo)."""
        prices = dict(default_prices)
        raw = os.environ.get("GATECAT_PROXY_MODEL_PRICES", "").strip()
        if raw:
            try:
                override = json.loads(raw)
                if isinstance(override, dict):
                    for k, v in override.items():
                        prices[str(k)] = float(v)
            except (ValueError, TypeError):
                pass
        return prices

    @classmethod
    def from_env(cls) -> "ProxyConfig":
        """Load config from environment variables (GATECAT_ prefix)."""
        _default_prices = cls.__dataclass_fields__["model_prices"].default_factory()
        return cls(
            budget_usd=float(os.environ.get("GATECAT_PROXY_BUDGET_USD", "0") or 0),
            budget_action=os.environ.get("GATECAT_PROXY_BUDGET_ACTION", "block"),
            model_prices=cls._model_prices_from_env(_default_prices),
            stagnation_local=os.environ.get("GATECAT_PROXY_STAGNATION", "off"),
            stagnation_local_repeat=int(os.environ.get("GATECAT_PROXY_STAGNATION_REPEAT", "2")),
            gate_mode=os.environ.get("GATECAT_GATE_MODE", "off"),
            gate_n_samples=int(os.environ.get("GATECAT_GATE_N_SAMPLES", "5")),
            gate_threshold=float(os.environ.get("GATECAT_GATE_THRESHOLD", "0.30")),
            gate_semantic=os.environ.get("GATECAT_GATE_SEMANTIC", "1").strip() in ("1", "true", "True"),
            tool_veto=os.environ.get("GATECAT_PROXY_TOOL_VETO", "block"),
            web_enabled=os.environ.get("GATECAT_WEB_ENABLED", "0").strip() in ("1", "true", "True"),
            brave_api_key=os.environ.get("BRAVE_API_KEY", ""),
            tools_enabled=os.environ.get("GATECAT_TOOLS_ENABLED", "1").strip() in ("1", "true", "True"),
            koryto_mode=os.environ.get("GATECAT_KORYTO_MODE", "off"),
            koryto_fact_base=os.environ.get("GATECAT_KORYTO_FACT_BASE", ""),
            koryto_cache_url=os.environ.get("GATECAT_KORYTO_CACHE_URL", ""),
            koryto_cache_key=os.environ.get("GATECAT_KORYTO_CACHE_KEY", ""),
            koryto_chroma_url=os.environ.get("GATECAT_KORYTO_CHROMA_URL", ""),
            koryto_chroma_collection=os.environ.get("GATECAT_KORYTO_CHROMA_COLLECTION", ""),
            koryto_lookup_min_sim=float(os.environ.get("GATECAT_KORYTO_LOOKUP_MIN_SIM", "0.82")),
            stagnation_window=int(os.environ.get("GATECAT_STAGNATION_WINDOW", "5")),
            stagnation_soft_streak=int(os.environ.get("GATECAT_STAGNATION_SOFT_STREAK", "3")),
            koryto_exec_from_query=os.environ.get("GATECAT_KORYTO_EXEC_UNSAFE", "0").strip() in ("1", "true", "True"),
            koryto_exec_timeout=float(os.environ.get("GATECAT_KORYTO_EXEC_TIMEOUT", "5.0")),
            koryto_exec_mem_mb=int(os.environ.get("GATECAT_KORYTO_EXEC_MEM_MB", "512")),
            openai_api_key=os.environ.get("OPENAI_API_KEY", ""),
            openai_base_url=validate_upstream_url(
                os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")),
            cache_dir=os.environ.get("GATECAT_CACHE_DIR", ""),
            similarity_threshold=float(os.environ.get("GATECAT_SIMILARITY_THRESHOLD", "0.92")),
            negative_threshold=float(os.environ.get("GATECAT_NEGATIVE_THRESHOLD", "0.85")),
            cache_max_entries=int(os.environ.get("GATECAT_MAX_ENTRIES", "100000")),
            cache_ttl=int(os.environ.get("GATECAT_TTL", str(24 * 3600))),
            on_negative_hit=os.environ.get("GATECAT_ON_NEGATIVE_HIT", "skip"),
            synthesis_mode=os.environ.get("GATECAT_SYNTHESIS_MODE", "off"),
            synthesis_model=os.environ.get("GATECAT_SYNTHESIS_MODEL", "google/gemini-2.0-flash-lite-001"),
            synthesis_model_base_url=os.environ.get("GATECAT_SYNTHESIS_BASE_URL", ""),
            synthesis_model_api_key=os.environ.get("GATECAT_SYNTHESIS_API_KEY", ""),
            synthesis_threshold=float(os.environ.get("GATECAT_SYNTHESIS_THRESHOLD", "0.80")),
            synthesis_top_k=int(os.environ.get("GATECAT_SYNTHESIS_TOP_K", "5")),
            allow_client_auth=os.environ.get("GATECAT_ALLOW_CLIENT_AUTH", "0").strip() in ("1", "true", "True"),
            host=os.environ.get("GATECAT_HOST", "0.0.0.0"),
            port=int(os.environ.get("GATECAT_PORT", "8080")),
            log_level=os.environ.get("GATECAT_LOG_LEVEL", "info"),
        )
