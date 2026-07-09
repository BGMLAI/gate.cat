"""Entry point for: python -m gatecat.proxy"""

from gatecat.proxy.config import ProxyConfig


def main():
    # Helpful message instead of a cryptic ModuleNotFoundError (audit 2026-06-27 should-fix):
    # the proxy requires the [proxy] extra (fastapi/uvicorn/httpx). Without it, give a clear instruction.
    try:
        import uvicorn
    except ModuleNotFoundError as e:
        raise SystemExit(
            "gatecat-proxy requires additional dependencies. Install them:\n"
            "    pip install gate.cat[proxy]\n"
            f"(missing: {e.name})"
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
