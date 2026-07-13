"""gatecat CLI — manage the semantic cache.

Usage:
    gatecat stats              # Show cache statistics
    gatecat entries            # List cached entries
    gatecat evict              # Remove expired entries
    gatecat clear              # Clear all entries
    gatecat lookup "query"     # Test a cache lookup
    gatecat audit data.jsonl   # "how much does YOUR agent guess" — gate-audit against an endpoint
"""

# Annotations are lazy strings (PEP 563) so `cmd_stats(cache: SemanticCache, ...)`
# does not evaluate SemanticCache at import time — lets the cache import below be
# guarded without breaking every function signature in this module.
from __future__ import annotations

import argparse
import json
import os
import sys
import time

# The whole CLI (except `audit`, which runs against the user's endpoint) manages
# the semantic cache, which lives behind the optional [cache] extra. Guard the
# import so `gatecat-cli` prints a clear "install the extra" line instead of a
# raw `ModuleNotFoundError: numpy` traceback — the zero-dep-core contract the
# rest of the package already honors (see gatecat/__init__.py).
try:
    from gatecat.cache import SemanticCache, DEFAULT_CACHE_DIR
except ImportError:
    SemanticCache = None  # type: ignore[assignment, misc]
    DEFAULT_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".gatecat")


def cmd_stats(cache: SemanticCache, args):
    s = cache.stats
    print(f"Cache directory: {cache._cache_dir}")
    print(f"Embedder:        {s['embedder']} ({s['modality']})")
    print(f"Entries:         {s['entries']}")
    print(f"Hits:            {s['hits']}")
    print(f"Misses:          {s['misses']}")
    print(f"Hit rate:        {s['hit_rate']:.1%}")
    print(f"Populations:     {s['populations']}")


def cmd_entries(cache: SemanticCache, args):
    cache._lazy_init()
    store = cache._store
    store._ensure_db()

    rows = store._conn.execute(
        """SELECT id, query_text, model, tokens, hit_count, modality, created_at, expires_at
           FROM cache_entries WHERE expires_at > ?
           ORDER BY created_at DESC LIMIT ?""",
        (time.time(), args.limit),
    ).fetchall()

    if not rows:
        print("No cache entries.")
        return

    for r in rows:
        age_h = (time.time() - r[6]) / 3600
        ttl_h = (r[7] - time.time()) / 3600
        print(
            f"[{r[0]:>4}] {r[1][:55]:<55} "
            f"hits={r[4]} model={r[2][:15]} "
            f"mod={r[5]} age={age_h:.1f}h ttl={ttl_h:.0f}h"
        )


def cmd_evict(cache: SemanticCache, args):
    evicted = cache.evict_expired()
    print(f"Evicted {evicted} expired entries.")
    print(f"Remaining: {cache.stats['entries']}")


def cmd_clear(cache: SemanticCache, args):
    cache._lazy_init()
    cache._store._ensure_db()
    cursor = cache._store._conn.execute("DELETE FROM cache_entries")
    cache._store._conn.commit()
    print(f"Cleared {cursor.rowcount} entries.")


def cmd_lookup(cache: SemanticCache, args):
    query = " ".join(args.query)
    if not query:
        print("Usage: gatecat lookup 'your query here'")
        return

    start = time.time()
    result = cache.lookup(query)
    latency = (time.time() - start) * 1000

    if result:
        print(f"HIT ({latency:.1f}ms)")
        print(f"Response: {result[:500]}")
    else:
        print(f"MISS ({latency:.1f}ms)")


def cmd_audit(args):
    """'How much does YOUR agent guess' — gate-audit against an OpenAI-compatible endpoint.

    Trust proof-point: the dev points at their model + a Q&A set and gets a
    confident-wrong count (the model is CONFIDENTLY wrong) + gate AUC. This is
    concrete evidence that it's worth wiring in a veto/gate — not marketing,
    measured on THEIR agent.

    data.jsonl: one JSON per line: {"q": "...", "gold": "...", "aliases": [...]}.
    Endpoint: --base-url (OpenAI-compatible /chat/completions), --model, --api-key
    (or env OPENAI_API_KEY). The gate calls the model N times at temp>0 -> spread -> uncertainty.
    """
    from gatecat.audit import run_audit

    # 1. load the Q&A set
    rows = []
    with open(args.data, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    if not rows:
        print("No questions in the file.")
        return
    print(f"Auditing {len(rows)} questions on model '{args.model}' via {args.base_url} ...")

    # 2. client for the user's endpoint (httpx — already in the [proxy] extras)
    try:
        import httpx
    except ImportError:
        print("httpx not found. Install: pip install 'gate.cat[proxy]'")
        return
    key = args.api_key or os.environ.get("OPENAI_API_KEY", "")
    url = args.base_url.rstrip("/") + "/chat/completions"
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"

    def _call(prompt, temperature):
        body = {"model": args.model, "temperature": temperature,
                "messages": [{"role": "user", "content": prompt}], "max_tokens": 256}
        try:
            r = httpx.post(url, json=body, headers=headers, timeout=60.0)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"] or ""
        except Exception as e:  # network/model error -> empty sample (the gate handles it)
            return ""

    # sample_fn = high temp (spread for the gate); answer_fn = temp 0 (scoring)
    report = run_audit(
        sample_fn=lambda p: _call(p, 0.8),
        answer_fn=lambda p: _call(p, 0.0),
        data=rows,
        n_samples=args.samples,
        threshold=args.gate_threshold,
        progress=lambda i, n: print(f"  {i}/{n}", end="\r"),
    )
    print()
    print(report.render_text())
    if report.confident_wrong > 0:
        print(f"\n>> {report.confident_wrong} WRONG answers that the model gave CONFIDENTLY.")
        print(">> This is exactly where an agent can take a confident-wrong action. Wire in gate.cat:")
        print(">>   pip install gate.cat   |   https://bgmlai.github.io/gate-landing/")


def main():
    import sys
    # `gate.cat cloud <init|report|verify|key>` — the E2EE off-machine history CLI.
    # Dispatched before argparse so cloud_cli owns its own sub-arguments.
    if len(sys.argv) > 1 and sys.argv[1] == "cloud":
        from gatecat import cloud_cli
        cloud_cli.main(sys.argv[2:])
        return

    parser = argparse.ArgumentParser(
        prog="gatecat",
        description="Universal semantic cache for AI APIs",
    )
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR, help="Cache directory")
    parser.add_argument("--threshold", type=float, default=0.92, help="Similarity threshold")
    parser.add_argument("--embedder", default="minilm", help="Embedder name (minilm, clip, clap, whisper)")

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("stats", help="Show cache statistics")

    entries_p = sub.add_parser("entries", help="List cached entries")
    entries_p.add_argument("--limit", type=int, default=20, help="Max entries to show")

    sub.add_parser("evict", help="Remove expired entries")
    sub.add_parser("clear", help="Clear all entries")

    lookup_p = sub.add_parser("lookup", help="Test a cache lookup")
    lookup_p.add_argument("query", nargs="*", help="Query text")

    audit_p = sub.add_parser("audit", help="'How much does YOUR agent guess' — gate-audit against an endpoint")
    audit_p.add_argument("data", help="JSONL of questions: {q, gold, aliases?} per line")
    audit_p.add_argument("--base-url", default="https://openrouter.ai/api/v1",
                         help="OpenAI-compatible base URL (default: OpenRouter)")
    audit_p.add_argument("--model", default="openai/gpt-4o-mini", help="Model ID")
    audit_p.add_argument("--api-key", default="", help="API key (or env OPENAI_API_KEY)")
    audit_p.add_argument("--samples", type=int, default=5, help="Gate samples (spread)")
    audit_p.add_argument("--gate-threshold", type=float, default=0.30, help="Uncertainty threshold")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # audit does NOT need SemanticCache — it runs against the user's endpoint
    if args.command == "audit":
        cmd_audit(args)
        return

    # every other command manages the cache; without the [cache] extra, say so
    # cleanly instead of crashing on the numpy import above.
    if SemanticCache is None:
        print(
            "gatecat-cli's cache commands need the semantic-cache extra: "
            "`pip install gate-cat[cache]` (adds numpy/hnswlib/onnxruntime).\n"
            "The action-veto guardrail, its `gate.cat` dashboard, and "
            "`gatecat-cli audit` need none of it.",
            file=sys.stderr,
        )
        return 1

    cache = SemanticCache(
        cache_dir=args.cache_dir,
        similarity_threshold=args.threshold,
        embedder=args.embedder,
    )

    try:
        {
            "stats": cmd_stats,
            "entries": cmd_entries,
            "evict": cmd_evict,
            "clear": cmd_clear,
            "lookup": cmd_lookup,
        }[args.command](cache, args)
    finally:
        cache.close()


if __name__ == "__main__":
    main()
