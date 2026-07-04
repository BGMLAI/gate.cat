"""cacheback-proxy — OpenAI-compatible caching proxy server.

Zero code change: just point base_url at the proxy.

    docker run -e OPENAI_API_KEY=sk-... -p 8080:8080 cacheback/proxy

Then in your code:
    client = OpenAI(base_url="http://localhost:8080/v1")
"""

from cacheback.proxy.app import create_app

__all__ = ["create_app"]
