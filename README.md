# gate.cat

> **Install:** `pip install gate-cat` — then a veto in three lines:
> ```python
> from gatecat.integrations import check_action        # deny-list gate
> from gatecat.integrations.policies import DOGFOOD_DEFAULTS
> check_action("agent", "terraform destroy -auto-approve", DOGFOOD_DEFAULTS)  # -> ActionVetoed
> ```
> The distribution is `gate.cat` (PyPI normalizes it, so `pip install gate-cat`);
> the import module is `gatecat`. 0.2.x used `import cacheback` — see `MIGRATION.md`.
> Honest line, up front: the gate is certain only about what it **blocks**. An
> action it does not match is *unchecked*, not *safe*.
>
> **Scope — persistent environments.** gate.cat guards places where a mistake is
> *irreversible*: a dev laptop with real data, a deploy pipeline, prod, paid
> infra. In a throwaway CI/sandbox container (a fresh git checkout that gets
> discarded) nothing is irreversible, so the gate **disarms itself** and logs a
> `disarmed` no-op rather than crying wolf. It auto-detects CI markers;
> `GATECAT_VETO_EPHEMERAL=0` forces it armed anyway. Measured on 14.7k real
> Claude Code commands *and* a public HF corpus of 8.6k SWE-agent commands, it
> intervenes on **~0.6% of commands on both** — the deny-list found something
> structural, not tuned to one user.

**Stop your AI agent before it takes an irreversible action.** `TruthPipeline` gives an honest
verdict on any answer (confirmed / refuted / uncertain / unchecked) using deterministic checks
(exec/calc/lookup) plus a sample-spread uncertainty signal — `veto.py` consumes that verdict to
block, pause, or ask a human before a tool call executes. Built for the cheap/local model stack
(7-30B via Ollama/vLLM) that frontier-first guardrails don't target.

One mechanism, not two products: the verification engine (`TruthPipeline`) and the action-gate
that consumes it (`before_action` / `VetoGate`) ship together — same package, same brand.
Semantic cache and Cache-Augmented Synthesis (below) are the supporting engine underneath both.

[![PyPI](https://img.shields.io/pypi/v/gate.cat)](https://pypi.org/project/gate.cat/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/gate.cat)](https://pypi.org/project/gate.cat/)

## Install

```bash
pip install gate-cat                  # core
pip install "gate-cat[openai]"      # + OpenAI wrapper
pip install "gate-cat[anthropic]"   # + Anthropic wrapper
pip install "gate-cat[proxy]"       # + proxy server (FastAPI)
pip install "gate-cat[all]"         # everything
```
> Quote the extras (`"gate-cat[openai]"`) — zsh treats bare `[...]` as a glob.

## Truth Pipeline (koryto → gate → veto)

One entry point that composes the SDK's verification blocks into a truth +
compliance pipeline for ANY model (a 3B SLM on a phone and a frontier LLM use
the same `sample_fn` callback).

```python
from gatecat import TruthPipeline, ActionPolicy, ActionVetoed

pipe = TruthPipeline(
    sample_fn=my_llm,                              # callback(prompt) -> str
    fact_base={"capital of france": "Paris"},      # lookup channel (optional)
    policy=ActionPolicy(deny=[r"terraform.*prod"], max_amount=100.0),
)

r = pipe.evaluate("Evaluate: 6 / 2 * 3", answer="1")
r.verdict   # "refuted" — caught confident-wrong, deterministically, $0
r.truth     # "9" — the correct value, so the caller can self-correct

@pipe.guard()                                      # compliance on ACTIONS
def deploy(target): ...
deploy(target="terraform apply prod")              # raises ActionVetoed BEFORE executing

pipe.compliance_report()                           # audit trail: verdicts + vetoes
```

**Honest verdicts** — the pipeline never claims more than it measured:

| Verdict | Meaning | `reliable` | `trusted` |
|---|---|---|---|
| `confirmed` | answer matches a verified atom (exec/calc/lookup) | ✅ | ✅ |
| `refuted` | answer contradicts a verified atom | ❌ | ❌ |
| `uncertain` | soft disagreement without arbiter, or high sample spread | ❌ | ❌ |
| `unchecked` | outside verification reach — **not** "true", just "couldn't check" | ❌ | ✅ |

For critical systems filter on `report.reliable` (confirmed only), not `trusted`.

> **Gate catches HESITATION, not LYING.** When the model is confidently wrong (same N probes,
> same wrong answer — zero spread), that's invisible to disagreement. The gate is an
> **uncertainty signal → pause/escalate**, NOT a correctness guarantee.

**Verdict precedence** (conflicts are resolved by construction):
1. `exec`/`calc` (hard, physically independent of the model) always win — the gate isn't even asked.
2. `lookup` disagreement goes to the optional `arbiter_fn`; without one → `uncertain`
   (set `lookup_hard_block=True` only if your fact base is fresh at query time).
3. `gate` (sample-spread) runs only when no verified atom exists.
4. `veto` is an orthogonal axis: it judges *actions*, is fail-closed, and `guard()`
   without a policy raises instead of silently allowing everything.

**Methods**: `evaluate(q, answer)` verifies an existing answer · `ask(q)` generates
with `sample_fn` then verifies · `guard()` decorates a tool function with pre-execution
veto · `check_action(repr)` evaluates an action without running it.

**`arbiter_fn` contract**: `(question, answer, KorytoVerdict) -> Optional[bool]` —
`True` = the fact base is right (refute stands), `False` = the model was right
(stale base, answer confirmed), `None`/exception = no ruling → `uncertain`.
Every stage that spoke is recorded in `report.stages` for debugging.

**Why small/cheap models**: agents increasingly run on cheap/local models (7-30B via Ollama/vLLM)
for cost and data-residency. That's where the gate's uncertainty signal is strongest
(AUC 0.77–0.90, measured N=4800) and where frontier-first guardrail vendors don't aim — on
frontier models the gate weakens (AUC 0.68–0.71).

*Naming note*: `koryto` (Polish: riverbed) is the project's canonical term for the
deterministic verification layer — the probabilistic "river" (model output) is held
by a deterministic "riverbed" (exec/calc/lookup). It is a deliberate brand term, not
an accident of translation.

## Cache / Cache-Augmented Synthesis (supporting engine)

The verification/veto layer above runs on top of a semantic cache. Used standalone, the cache
also works as a drop-in wrapper for OpenAI/Anthropic SDKs with a three-tier response: verbatim
cache, synthesis, upstream — cache semantically similar queries and return instant responses
(<10ms), or synthesize from cached knowledge (~300ms, ~$0.002) instead of a full upstream call.

## Quick Start

### OpenAI (drop-in, zero code change)

```python
from gatecat import CachedOpenAI

client = CachedOpenAI(api_key="sk-...")

# First call: ~500ms (API + cache populate)
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "What is the capital of France?"}],
)

# Second call with similar query: ~5ms (cache hit)
response2 = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "capital of France?"}],
)
print(response2.gatecat_hit)  # True
```

### Anthropic

```python
from gatecat import CachedAnthropic

client = CachedAnthropic(api_key="sk-ant-...")
message = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[{"role": "user", "content": "What is Python?"}],
)
print(message.gatecat_hit)  # True on cache hit
```

### Streaming

Streaming works transparently. Cache misses buffer and store the response; cache hits replay as a synthetic stream.

```python
stream = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Explain quantum computing"}],
    stream=True,
)
for chunk in stream:
    print(chunk.choices[0].delta.content or "", end="")
```

### Cache-Augmented Synthesis (CAS)

When a query is similar to cached entries but not an exact match, CAS synthesizes a fresh response from cached knowledge using a cheap LLM — instead of calling the expensive upstream API.

```python
from gatecat import CachedOpenAI

client = CachedOpenAI(
    synthesis_mode="auto",  # enable three-tier response
    # Uses Gemini Flash Lite via OpenRouter by default (~$0.002/synthesis)
    # Or point to local llama-cpp: synthesis_model="local/phi-4-mini"
)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Explain photosynthesis"}],
)

if response.gatecat_hit:
    print("Verbatim cache hit (<10ms, $0.00)")
elif response.gatecat_synthesized:
    print("Synthesized from cache (~300ms, ~$0.002)")
else:
    print("Upstream API call (~500ms, ~$0.03)")
```

```
Three-tier response:

  Query  -->  Embed  -->  HNSW search
                |
    sim >= 0.92 |  VERBATIM HIT   -->  Return cached response     <10ms   $0.00
    sim >= 0.80 |  SYNTHESIS       -->  Top-K cached Q&A + LLM    ~300ms  ~$0.002
    sim <  0.80 |  UPSTREAM MISS   -->  Call API, cache response   ~500ms  ~$0.03
```

Validated with 100-question benchmark across 5 domains: **0.892 mean quality ratio** vs direct API responses.

### Proxy Mode (zero code change)

Run gate.cat as a standalone proxy server. No SDK integration needed — just change `base_url`:

```bash
# Docker (recommended)
docker run -e OPENAI_API_KEY=sk-... -p 8080:8080 gatecat/proxy

# Or pip
pip install gate.cat[proxy]
gatecat-proxy  # starts on :8080
```

Then point your existing code at the proxy:

```python
from openai import OpenAI

client = OpenAI(base_url="http://localhost:8080/v1")  # that's it
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "What is Python?"}],
)
# Cache headers: X-Gatecat-Hit, X-Gatecat-Synthesized
```

Works with any OpenAI-compatible client (curl, LangChain, LiteLLM, etc). Configure via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | — | API key for upstream provider |
| `GATECAT_SIMILARITY_THRESHOLD` | `0.92` | Cache hit threshold |
| `GATECAT_SYNTHESIS_MODE` | `off` | `off` / `auto` / `always` |
| `GATECAT_TTL` | `86400` | Cache TTL in seconds |
| `GATECAT_PORT` | `8080` | Server port |

### Async

```python
from gatecat import AsyncCachedOpenAI, AsyncCachedAnthropic

async_client = AsyncCachedOpenAI()
response = await async_client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello"}],
)
```

### Standalone Cache

Use `SemanticCache` directly for any embedding-based caching:

```python
from gatecat import SemanticCache

cache = SemanticCache(
    similarity_threshold=0.92,
    cache_ttl=86400,  # 24 hours
)

cache.populate("What is Python?", "Python is a programming language...")
result = cache.lookup("Tell me about Python")  # cache hit
```

### Negative Cache (blocklist)

Block known-bad query patterns before they hit the API:

```python
# Block a query pattern
client.cache.negative.add(
    "What is the airspeed of an unladen swallow?",
    reason="hallucination",
)

# Similar queries are now blocked
client.cache.negative.check("airspeed of swallows")  # returns match info

# Manage the blocklist
client.cache.negative.list(limit=50)
client.cache.negative.remove(entry_id=42)
client.cache.negative.report_false_positive(entry_id=42)
```

## Configuration

```python
client = CachedOpenAI(
    # Cache settings
    cache_dir="~/.gatecat",        # where to store cache data
    similarity_threshold=0.92,        # cosine similarity for cache hit (0-1)
    negative_threshold=0.85,          # threshold for negative cache
    cache_ttl=86400,                  # TTL in seconds (24h default)
    cache_max_entries=100_000,        # max entries before LRU eviction
    cache_enabled=True,               # set False to disable
    on_negative_hit="raise",          # "raise" | "skip" | callable

    # Synthesis settings (CAS)
    synthesis_mode="off",             # "off" | "auto" | "always"
    synthesis_model="google/gemini-2.0-flash-lite-001",  # any OpenAI-compatible model
    synthesis_model_base_url=None,    # auto-detected from OPENROUTER_API_KEY
    synthesis_model_api_key=None,     # auto-detected from env
    synthesis_threshold=0.80,         # min similarity for synthesis candidates
    synthesis_top_k=5,                # number of cached Q&A pairs for synthesis

    # OpenAI settings (passthrough)
    api_key="sk-...",
)
```

## How It Works

```
Query --> Embed (MiniLM-L6, 384-dim) --> Search HNSW index
  |-- VERBATIM HIT  (sim >= 0.92) --> Return cached response (<10ms)
  |-- SYNTHESIS      (sim >= 0.80) --> Top-K cached Q&A + cheap LLM (~300ms)
  '-- MISS           (sim <  0.80) --> Call upstream API, cache response (~500ms)
```

- **Embedder**: ONNX MiniLM-L6-v2 (90MB, runs locally, no API calls)
- **Index**: hnswlib HNSW for fast approximate nearest neighbor search
- **Store**: SQLite with WAL mode for concurrent access
- **Fallback**: numpy brute-force if hnswlib is unavailable

## CLI

```bash
gatecat-cli stats          # Show cache statistics
gatecat-cli entries        # List cached entries
gatecat-cli evict          # Remove expired entries
gatecat-cli clear          # Clear all entries
gatecat-cli lookup "query" # Test a cache lookup
```

## Custom Embedders

Register your own embedder for any modality:

```python
from gatecat.embedders import BaseEmbedder, register_embedder
import numpy as np

class MyEmbedder(BaseEmbedder):
    dim = 256
    modality = "custom"

    def encode(self, input_data) -> np.ndarray:
        # Your embedding logic here
        ...

register_embedder("my-embedder", MyEmbedder)
cache = SemanticCache(embedder="my-embedder")
```

Built-in embedders: `minilm` (text), `clip` (image, coming soon), `clap` (voice, coming soon).

## Comparison

| Feature | gate.cat | GPTCache | LiteLLM | Redis LangCache |
|---------|-----------|----------|---------|-----------------|
| Semantic similarity | Yes | Yes | Exact only | Yes |
| Cache-Augmented Synthesis | Yes | No | No | No |
| OpenAI drop-in | Yes | Partial | Yes | No |
| Anthropic drop-in | Yes | No | Yes | No |
| Streaming support | Yes | No | No | No |
| Negative cache | Yes | No | No | No |
| Multimodal (planned) | Yes | No | No | No |
| Async | Yes | No | Yes | No |
| Zero config | Yes | No | No | No |
| Proxy mode (Docker) | Yes | No | Yes | No |
| Local (no server) | Yes | Yes | No | No |
| License | Apache 2.0 | MIT | MIT | Redis |

## License

Apache 2.0 — see [LICENSE](LICENSE).

Built by [BGML.ai](https://bgml.ai) / [Fundacja BLOOM](https://bloom.foundation).
