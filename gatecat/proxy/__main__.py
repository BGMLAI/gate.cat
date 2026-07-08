"""Entry point for: python -m gatecat.proxy"""

from gatecat.proxy.config import ProxyConfig


def main():
    # Pomocny komunikat zamiast cryptic ModuleNotFoundError (audyt 2026-06-27 should-fix):
    # proxy wymaga extra [proxy] (fastapi/uvicorn/httpx). Bez niego daj jasną instrukcję.
    try:
        import uvicorn
    except ModuleNotFoundError as e:
        raise SystemExit(
            "gatecat-proxy wymaga dodatkowych zależności. Zainstaluj:\n"
            "    pip install gate.cat[proxy]\n"
            f"(brakuje: {e.name})"
        )
    config = ProxyConfig.from_env()
    uvicorn.run(
        "gatecat.proxy.app:app",
        host=config.host,
        port=config.port,
        log_level=config.log_level,
    )


if __name__ == "__main__":
    main()
