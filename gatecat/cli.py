"""gatecat CLI — manage the semantic cache.

Usage:
    gatecat stats              # Show cache statistics
    gatecat entries            # List cached entries
    gatecat evict              # Remove expired entries
    gatecat clear              # Clear all entries
    gatecat lookup "query"     # Test a cache lookup
    gatecat audit data.jsonl   # "ile zgaduje TWOJ agent" — gate-audit na endpoincie
"""

import argparse
import json
import os
import time

from gatecat.cache import SemanticCache, DEFAULT_CACHE_DIR


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
    """'Ile zgaduje TWOJ agent' — gate-audit na endpoincie OpenAI-compatible.

    Trust proof-point: dev wskazuje swoj model + zestaw Q&A, dostaje liczbe
    confident-wrong (model myli sie PEWNIE) + AUC gate. To konkretny dowod, ze
    warto wpiac veto/gate — nie marketing, zmierzone na JEGO agencie.

    data.jsonl: po jednym JSON na linie: {"q": "...", "gold": "...", "aliases": [...]}.
    Endpoint: --base-url (OpenAI-compatible /chat/completions), --model, --api-key
    (lub env OPENAI_API_KEY). Gate woła model N razy przy temp>0 -> rozrzut -> uncertainty.
    """
    from gatecat.audit import run_audit

    # 1. wczytaj zbior Q&A
    rows = []
    with open(args.data, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    if not rows:
        print("Brak pytan w pliku.")
        return
    print(f"Audyt {len(rows)} pytan na modelu '{args.model}' przez {args.base_url} ...")

    # 2. klient endpointu usera (httpx — juz w extras [proxy])
    try:
        import httpx
    except ImportError:
        print("Brak httpx. Zainstaluj: pip install 'gate.cat[proxy]'")
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
        except Exception as e:  # blad sieci/modelu -> pusta probka (gate to zniesie)
            return ""

    # sample_fn = temp wysoka (rozrzut dla gate); answer_fn = temp 0 (scoring)
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
        print(f"\n>> {report.confident_wrong} odpowiedzi BLEDNYCH ktore model podal PEWNIE.")
        print(">> To wlasnie tu agent moze wykonac confident-wrong akcje. Wepnij gate.cat:")
        print(">>   pip install gate.cat   |   https://bgmlai.github.io/gate-landing/")


def main():
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

    audit_p = sub.add_parser("audit", help="'Ile zgaduje TWOJ agent' — gate-audit na endpoincie")
    audit_p.add_argument("data", help="JSONL z pytaniami: {q, gold, aliases?} per linia")
    audit_p.add_argument("--base-url", default="https://openrouter.ai/api/v1",
                         help="OpenAI-compatible base URL (default: OpenRouter)")
    audit_p.add_argument("--model", default="openai/gpt-4o-mini", help="Model ID")
    audit_p.add_argument("--api-key", default="", help="API key (lub env OPENAI_API_KEY)")
    audit_p.add_argument("--samples", type=int, default=5, help="Probki gate (rozrzut)")
    audit_p.add_argument("--gate-threshold", type=float, default=0.30, help="Prog uncertainty")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # audit NIE potrzebuje SemanticCache — dziala na endpoincie usera
    if args.command == "audit":
        cmd_audit(args)
        return

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
