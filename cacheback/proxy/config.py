"""Proxy configuration via environment variables."""

import ipaddress
import os
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse


class UpstreamURLError(ValueError):
    """openai_base_url wskazuje na niebezpieczny/prywatny cel (SSRF guard)."""


def _is_private_host(host: str) -> bool:
    """Czy host rozwiązuje się do prywatnego/loopback/link-local IP (SSRF)."""
    # bezpośredni literał IP
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        pass
    # nazwa hosta → spróbuj rozwiązać (best-effort; brak DNS = nie blokuj na ślepo)
    try:
        for fam, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(sockaddr[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return True
    except (socket.gaierror, ValueError, OSError):
        return False
    return False


def validate_upstream_url(url: str) -> str:
    """SSRF guard (audyt 2026-06-27 #2): odrzuć non-https i prywatne/metadata cele.

    Domyślny api.openai.com przechodzi. Custom URL musi być https i NIE prowadzić do
    prywatnego IP / 169.254.169.254 (cloud metadata) — inaczej proxy mógłby exfiltrować
    klucz API do wewnętrznej usługi. Świadome rozluźnienie (lokalny LLM, http upstream):
    `CACHEBACK_ALLOW_INSECURE_UPSTREAM=1`.
    """
    if os.environ.get("CACHEBACK_ALLOW_INSECURE_UPSTREAM", "0").strip() in ("1", "true", "True"):
        return url
    p = urlparse(url)
    if p.scheme != "https":
        raise UpstreamURLError(
            f"openai_base_url musi być https (jest {p.scheme!r}). "
            "Dla lokalnego/http upstreamu ustaw CACHEBACK_ALLOW_INSECURE_UPSTREAM=1."
        )
    host = p.hostname or ""
    if not host:
        raise UpstreamURLError(f"openai_base_url bez hosta: {url!r}")
    if _is_private_host(host):
        raise UpstreamURLError(
            f"openai_base_url wskazuje na prywatny/metadata cel ({host}) — SSRF guard. "
            "Świadome użycie: CACHEBACK_ALLOW_INSECURE_UPSTREAM=1."
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
    #   off:   wyłączony (zero zmian, default)
    #   flag:  mierzy niepewność, dodaje metadane do odpowiedzi (nie blokuje)
    #   block: gdy niepewny i brak naprawy z cache -> zwraca abstention zamiast zgadywać
    gate_mode: str = "off"
    gate_n_samples: int = 5
    gate_threshold: float = 0.30
    gate_semantic: bool = True  # MiniLM do rozrzutu semantycznego (vs lexical)

    # Gałęzie naprawy (gdy gate niepewny + cache słaby): web → tools → abstain
    web_enabled: bool = False        # 3. gałąź: Brave web-search (wymaga BRAVE_API_KEY)
    brave_api_key: str = ""
    tools_enabled: bool = True       # 4. gałąź: wbudowane narzędzia (calc)

    # KORYTO — deterministyczny weryfikator atomu. off | flag | block
    #   Działa NIEZALEŻNIE od gate (na strukturze pytania, nie na rozrzucie) → łapie
    #   confident-wrong, którego gate nie widzi (rozrzut zero). To brakujące ogniwo:
    #   gate/audit DIAGNOZUJĄ confident-wrong, koryto na niego REAGUJE.
    #   off:   wyłączony (default, zero zmian).
    #   flag:  weryfikuje exec/calc/lookup, dodaje werdykt do metadanych (nie blokuje).
    #   block: gdy TWARDE koryto (exec/calc) odrzuca odpowiedź → zwraca prawdę z koryta
    #          zamiast confident-wrong modelu. Lookup (miękki) NIGDY nie blokuje sam
    #          (needs_arbiter) — wymaga web-rozjemcy, bo baza bywa stale.
    koryto_mode: str = "off"
    koryto_fact_base: str = ""       # ścieżka do JSON {pytanie-fragment: wartość} dla kanału lookup
    # REALNE BAZY dla kanału lookup (multi-source z bramką jakości, REJESTR 2026-06-27).
    # Lookup pyta WSZYSTKIE dobrej jakości, nie tylko mały JSON. Bramka: sim≥próg + filtr-MCQ.
    koryto_cache_url: str = ""       # URL semantic cache (np. 4M VPS) — http_cache_source
    koryto_cache_key: str = ""       # klucz do cache (gdy wymaga)
    koryto_chroma_url: str = ""      # URL ChromaDB v2 (np. GTX1070 :8775)
    koryto_chroma_collection: str = ""  # collection id w ChromaDB (po filtrze MCQ)
    koryto_lookup_min_sim: float = 0.82  # próg jakości retrievalu (trafny vs luźny)
    # STAGNACJA — pilnuje czy koryto nie zgniło (seria miękkich odrzuceń = stale baza)
    stagnation_window: int = 5
    stagnation_soft_streak: int = 3  # ile miękkich odrzuceń z rzędu = koryto podejrzane
    # EXEC — kanał interpreter. Jawne pole koryto_exec w body działa (przez sandbox).
    # AUTO-wyłuskanie kodu z RUCHU domyślnie OFF (czysty pip-sandbox nie jest w pełni
    # szczelny dla wrogiego kodu — nazwa env z UNSAFE celowo, operator widzi ryzyko).
    koryto_exec_from_query: bool = False    # CACHEBACK_KORYTO_EXEC_UNSAFE=1 by włączyć
    koryto_exec_timeout: float = 5.0
    koryto_exec_mem_mb: int = 512

    # Bezpieczeństwo upstream (audyt 2026-06-27 #3): domyślnie NIE przekazuj
    # klienckiego Authorization header upstream (atakujący mógłby wstrzyknąć swój klucz).
    # Świadome włączenie (proxy multi-tenant gdzie klient podaje własny klucz):
    # CACHEBACK_ALLOW_CLIENT_AUTH=1.
    allow_client_auth: bool = False

    # Server
    host: str = "0.0.0.0"
    port: int = 8080
    log_level: str = "info"

    @classmethod
    def from_env(cls) -> "ProxyConfig":
        """Load config from environment variables (CACHEBACK_ prefix)."""
        return cls(
            gate_mode=os.environ.get("CACHEBACK_GATE_MODE", "off"),
            gate_n_samples=int(os.environ.get("CACHEBACK_GATE_N_SAMPLES", "5")),
            gate_threshold=float(os.environ.get("CACHEBACK_GATE_THRESHOLD", "0.30")),
            gate_semantic=os.environ.get("CACHEBACK_GATE_SEMANTIC", "1").strip() in ("1", "true", "True"),
            web_enabled=os.environ.get("CACHEBACK_WEB_ENABLED", "0").strip() in ("1", "true", "True"),
            brave_api_key=os.environ.get("BRAVE_API_KEY", ""),
            tools_enabled=os.environ.get("CACHEBACK_TOOLS_ENABLED", "1").strip() in ("1", "true", "True"),
            koryto_mode=os.environ.get("CACHEBACK_KORYTO_MODE", "off"),
            koryto_fact_base=os.environ.get("CACHEBACK_KORYTO_FACT_BASE", ""),
            koryto_cache_url=os.environ.get("CACHEBACK_KORYTO_CACHE_URL", ""),
            koryto_cache_key=os.environ.get("CACHEBACK_KORYTO_CACHE_KEY", ""),
            koryto_chroma_url=os.environ.get("CACHEBACK_KORYTO_CHROMA_URL", ""),
            koryto_chroma_collection=os.environ.get("CACHEBACK_KORYTO_CHROMA_COLLECTION", ""),
            koryto_lookup_min_sim=float(os.environ.get("CACHEBACK_KORYTO_LOOKUP_MIN_SIM", "0.82")),
            stagnation_window=int(os.environ.get("CACHEBACK_STAGNATION_WINDOW", "5")),
            stagnation_soft_streak=int(os.environ.get("CACHEBACK_STAGNATION_SOFT_STREAK", "3")),
            koryto_exec_from_query=os.environ.get("CACHEBACK_KORYTO_EXEC_UNSAFE", "0").strip() in ("1", "true", "True"),
            koryto_exec_timeout=float(os.environ.get("CACHEBACK_KORYTO_EXEC_TIMEOUT", "5.0")),
            koryto_exec_mem_mb=int(os.environ.get("CACHEBACK_KORYTO_EXEC_MEM_MB", "512")),
            openai_api_key=os.environ.get("OPENAI_API_KEY", ""),
            openai_base_url=validate_upstream_url(
                os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")),
            cache_dir=os.environ.get("CACHEBACK_CACHE_DIR", ""),
            similarity_threshold=float(os.environ.get("CACHEBACK_SIMILARITY_THRESHOLD", "0.92")),
            negative_threshold=float(os.environ.get("CACHEBACK_NEGATIVE_THRESHOLD", "0.85")),
            cache_max_entries=int(os.environ.get("CACHEBACK_MAX_ENTRIES", "100000")),
            cache_ttl=int(os.environ.get("CACHEBACK_TTL", str(24 * 3600))),
            on_negative_hit=os.environ.get("CACHEBACK_ON_NEGATIVE_HIT", "skip"),
            synthesis_mode=os.environ.get("CACHEBACK_SYNTHESIS_MODE", "off"),
            synthesis_model=os.environ.get("CACHEBACK_SYNTHESIS_MODEL", "google/gemini-2.0-flash-lite-001"),
            synthesis_model_base_url=os.environ.get("CACHEBACK_SYNTHESIS_BASE_URL", ""),
            synthesis_model_api_key=os.environ.get("CACHEBACK_SYNTHESIS_API_KEY", ""),
            synthesis_threshold=float(os.environ.get("CACHEBACK_SYNTHESIS_THRESHOLD", "0.80")),
            synthesis_top_k=int(os.environ.get("CACHEBACK_SYNTHESIS_TOP_K", "5")),
            allow_client_auth=os.environ.get("CACHEBACK_ALLOW_CLIENT_AUTH", "0").strip() in ("1", "true", "True"),
            host=os.environ.get("CACHEBACK_HOST", "0.0.0.0"),
            port=int(os.environ.get("CACHEBACK_PORT", "8080")),
            log_level=os.environ.get("CACHEBACK_LOG_LEVEL", "info"),
        )
