"""Entry point for: python -m cacheback.proxy"""

from cacheback.proxy.config import ProxyConfig


def main():
    # Pomocny komunikat zamiast cryptic ModuleNotFoundError (audyt 2026-06-27 should-fix):
    # proxy wymaga extra [proxy] (fastapi/uvicorn/httpx). Bez niego daj jasną instrukcję.
    try:
        import uvicorn
    except ModuleNotFoundError as e:
        raise SystemExit(
            "cacheback-proxy wymaga dodatkowych zależności. Zainstaluj:\n"
            "    pip install cacheback-ai[proxy]\n"
            f"(brakuje: {e.name})"
        )
    config = ProxyConfig.from_env()
    uvicorn.run(
        "cacheback.proxy.app:app",
        host=config.host,
        port=config.port,
        log_level=config.log_level,
    )


if __name__ == "__main__":
    main()
