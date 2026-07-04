# Changelog

All notable changes to `cacheback-ai` will be documented in this file.

## [Unreleased] -- Action-veto + dowody jakosci (2026-06-27)

Pivot pozycjonowania: fail-closed **action-veto** (blokada nieodwracalnej akcji agenta
ZANIM sie wykona) jako rdzen produktu. Kaskada gate -> koryto -> veto -> abstain.

### Dodane

- **Side-effect tool gating (fail-closed przy rejestracji)** -- `Tool.side_effect: bool`.
  Narzedzie ze skutkiem ubocznym (`side_effect=True`) NIE moze byc zarejestrowane bez
  `VetoGate` -- `ToolRegistry.register` rzuca `ValueError` zamiast cicho przepuscic
  nieodwracalna akcje. Read-only (default `side_effect=False`) = zero zmian.
  (`src/tools/registry.py`)
- **Explicit abstain** -- jawny stan `branch="abstain"` w three-branch routerze (opt-in
  `allow_abstain=True`): gdy model nie wie (gate-on) i ani cache, ani web nie maja jakosci,
  router JAWNIE sie wstrzymuje zamiast zgadywac. Trust-sygnal. Nigdy nie kradnie galezi,
  gdzie jest dowod (model pewny / cache trafny / web dobry). (`src/ensemble/router_three_branch.py`)
- **Dowod: prog jakosci web-snippetu odcina szum** -- `tests/test_web_snippet_threshold.py`.
  Trafny snippet wstrzykiwany, szum ponizej progu odrzucony (Badanie C: web-szum psuje
  base-correct 2-3x mocniej niz zly cache).
- **`ARCHITECTURE.md`** -- pelny dokument techniczny SDK (warstwy, moduly, przeplywy,
  modele danych, rozszerzanie, testy). Rozroznia SDK cacheback (bez ReAct) vs aplikacja iors.
- **`plan_verifier` (nowy modul produktu) -- koryto POSTEPU PROJEKTU.** Agent deklaruje
  'etap zrobiony' (rzeka), verifier wymaga NIEZALEZNEGO dowodu (test pass / plik+token /
  HTTP 2xx / command z allow-listy) zanim oznaczy done. `PlanVerifier`, `PlanStep`,
  `StepVerdict`, `PlanReport` eksportowane z `cacheback`. Fail-closed: brak dowodu = unproven.
  Kluczowe (po adversarial review): evidence z immutable spec (nie z narracji agenta),
  `progress_pct` liczy TYLKO `proven AND hard` (url/benchmark = soft/stale), allow-list
  binarek zamiast deny-listy, file wymaga `must_contain` + zero repo-root fallback.
  Dogfood: `scripts/verify_session_plan.py` liczy realny postep TEJ sesji dowodem
  (6/12 twardo proven, reszta uczciwie unproven). `tests/test_plan_verifier.py` (13 testow,
  regresja na 7 zmierzonych bypassow).

### Trust-loop (GTM: jak dotrzec do ludzi ktorzy zaczna ufac AI)

- **`cacheback audit data.jsonl` (CLI)** -- proof-point 'ile zgaduje TWOJ agent'. Dev wskazuje
  swoj model (OpenAI-compatible endpoint) + zestaw Q&A, dostaje liczbe confident-wrong
  (model myli sie PEWNIE) + AUC gate -> CTA do gate.cat. Konkretny mechanizm konwersji
  odwiedzajacego w uzytkownika: zmierz na WLASNYM agencie, zobacz ryzyko, wepnij veto.
  `examples/audit_sample.jsonl` (10 Q&A startowych), `tests/test_cli_audit.py` (3 testy, mock).

### Dowody jakosci (metryka #1: false-positive rate)

- `scripts/audit_false_positive.py` + `tests/test_false_positive.py` -- **FPR=0** (0 legalnych
  akcji blednie zablokowanych / 24), **false-refute=0** na hard channels (exec/calc), 8/8
  akcji finansowych poprawnie wymaga czlowieka.
- `tests/test_veto_bypass_e2e.py` -- **0 przeciekow** na 22 adversarialnych bypassach
  (tab/newline/komentarz SQL/case-games/rm-rf/terraform/kubectl) + E2E gate+koryto.

### Testy

- Suita cacheback: **391 pass + 3 skip**, 0 regresji (+ side-effect gating i explicit-abstain
  w aplikacji iors: `tests/test_tools/`, `tests/test_ensemble/` 241 pass).

## [Unreleased] -- CAS SDK Implementation (Phase 1.5)

### Cache-Augmented Synthesis (CAS) -- SDK integration

**Three-tier response system**
- VERBATIM (sim >= 0.92): Direct cache return, <10ms, $0.00
- SYNTHESIS (sim >= 0.80): Top-K cached Q&A synthesized via LLM, ~300ms, ~$0.002
- UPSTREAM (sim < 0.80): Full API call, ~500ms, ~$0.03

**New files**
- `cacheback/synthesis.py` -- SynthesisEngine, SynthesisCandidate, SynthesisResult
- `tests/test_synthesis.py` -- 26 tests (engine, integration, response flags, cache lookup)

**Modified files**
- `cacheback/cache.py` -- `lookup_for_synthesis()` (top-K at lower threshold), `get_entry()`
- `cacheback/openai.py` -- synthesis tier in CachedOpenAI, AsyncCachedOpenAI
- `cacheback/anthropic.py` -- synthesis tier in CachedAnthropic, AsyncCachedAnthropic

**New constructor params** (all wrappers, backward-compatible):
- `synthesis_mode`: "off" (default) | "auto" | "always"
- `synthesis_model`: model ID (default: "google/gemini-2.0-flash-lite-001")
- `synthesis_model_base_url`: API base URL (auto-detected from env)
- `synthesis_model_api_key`: API key (auto-detected from env)
- `synthesis_threshold`: min similarity for candidates (default: 0.80)
- `synthesis_top_k`: number of cached responses for synthesis (default: 5)

**New response attributes**:
- `response.cacheback_synthesized` -- True when CAS synthesized the response

**Tests**: 112 passing (was 86)

### Streaming synthesis
- Synthesis results replayed as synthetic stream chunks (both OpenAI and Anthropic)
- Both sync and async paths supported
- Tests: 113 passing

### Proxy mode (`cacheback-proxy`)
- OpenAI-compatible proxy server via FastAPI + uvicorn
- Zero code change: `client = OpenAI(base_url="http://localhost:8080/v1")`
- Streaming SSE with buffer-and-cache on miss
- Cache hit/synthesis headers: `X-Cacheback-Hit`, `X-Cacheback-Synthesized`
- `/health` and `/v1/cache/stats` endpoints
- Docker support: `docker run -e OPENAI_API_KEY=sk-... -p 8080:8080 cacheback/proxy`
- `pip install cacheback-ai[proxy]` extras group
- `cacheback-proxy` CLI entry point
- Config via env vars (`CACHEBACK_*` prefix)
- Tests: 127 passing (14 proxy tests added)

### CLAP audio embedder
- Full CLAP HTSAT implementation via ONNX Runtime (Xenova/clap-htsat-unfused)
- Accepts bytes (WAV/FLAC), file paths, numpy arrays
- Mel spectrogram preprocessing: 48kHz, 64 mel bins, 10s fixed duration
- 512-dim L2-normalized vectors for audio similarity caching
- Thread-safe with lazy model download from HuggingFace (~300MB)
- Registered as `"clap"` in embedder registry
- Shared audio utilities module (`_audio.py`): mel filterbank, STFT, resampling, audio I/O

### Whisper + MiniLM compound voice embedder
- Compound pipeline: Whisper tiny transcribes → MiniLM embeds text
- Full Whisper ONNX inference: encoder + greedy decoder with special tokens
- Audio preprocessing: 16kHz, 80 mel bins, Whisper-format log10 normalization
- Handles merged decoder model with KV-cache inputs (zero-sized for first pass)
- 384-dim L2-normalized vectors (MiniLM text embedding dimension)
- `transcribe()` utility method for debugging/standalone use
- Thread-safe with lazy model download (~75MB Whisper + ~90MB MiniLM)
- Registered as `"whisper"` in embedder registry
- Tests: 164 passing (27 new: 13 audio utils, 7 CLAP, 7 Whisper)

### CLIP image embedder
- Full CLIP ViT-B/32 implementation via ONNX Runtime
- Accepts PIL.Image, bytes (JPEG/PNG), file paths, np.ndarray
- Center-crop resize to 224x224 with CLIP normalization (mean/std)
- 512-dim L2-normalized vectors for image similarity caching
- Thread-safe with lazy model download from HuggingFace (~150MB)
- Registered as `"clip"` in embedder registry
- Tests: 137 passing (10 CLIP preprocessing tests added)

### Landing page update (site/index.html)
- Updated hero messaging: three-tier response, 30-90% cost savings, CAS badge
- Added CAS section with tier diagram (verbatim/synthesis/upstream cost/latency bars)
- Added Proxy Mode section with Docker + pip setup, env vars, endpoints, features panel
- Added Synthesis and Proxy tabs in code examples section
- Updated comparison table: +CAS, +Proxy mode, +Multimodal (image) rows
- Updated metrics strip: verbatim hit, synthesis latency, cost savings, CAS benchmark score
- Updated feature grid: +CAS card, +Proxy Mode card, merged Streaming & Async, merged Local & Zero Config
- Added nav links for Synthesis and Proxy sections
- Added Proxy and Image to providers strip

### Cache-Augmented Synthesis (CAS) validation infrastructure

**Full Results (100-question benchmark) -- GO**
- Mean judge ratio: **0.892** (threshold: 0.80) -- **ALL DOMAINS PASS**
- Synthesis model: Gemini 2.0 Flash Lite (cloud, via OpenRouter)
- Judge model: Gemini 3.1 Flash Lite
- Per-domain: customer_support 0.89, programming 0.86, science 0.89, general 0.94, creative 0.88
- ROUGE-L 0.167 (expected low -- synthesis paraphrases by design)
- Mean latency: 2687ms (cloud API -- local synthesis ~300ms)
- BERTScore: skipped (segfault on Windows, secondary metric)

**Benchmark Script** (`scripts/benchmark_cas.py`)
- 100 questions across 5 domains (customer_support, programming, science, general, creative)
- 5 semantically similar variants per question = 600 cached Q&A pairs
- Multi-metric evaluation: LLM-as-Judge (primary), BERTScore (secondary), ROUGE-L (tertiary)
- Fleet device integration via BGML orchestrator API (`force_device_id` + `skip_cache`)
- OpenRouter backend for dataset generation and judge scoring
- Quality gate: mean ratio >= 0.80, per-domain thresholds, latency < 2000ms
- ROUGE-L: hard floor 0.10, soft warning 0.30 (synthesis paraphrases, not copies)
- CLI: `--generate-dataset`, `--quick`, `--reference-model`, `--synthesis-model`, `--judge-model`
- Fixed Windows cp1252 Unicode encoding (ASCII-only print output)
- Answer truncation in synthesis context (500 chars max per cached answer)

**Dataset Generation**
- Quick dataset (10 questions): `benchmarks/cas_dataset_quick.json` (Gemini 3.1 Flash Lite)
- Full dataset (100 questions): `benchmarks/cas_dataset_gemini31.json` (in progress)

**Known Issues**
- Fleet synthesis (POS-B2 Phi-4-mini) times out on synthesis prompts (even truncated)
- Orchestrator retry flooding: visible as attempt #49-50 in logs
- BERTScore not installed (secondary metric, skipped in quick benchmark)
- customer_support domain borderline (0.80 vs 0.85 threshold, needs more samples)

## [0.1.1] — 2026-03-23

### Hardening release — CEO review fixes

**Thread Safety**
- Added `threading.RLock` to `CacheStore` — all write operations (store, record_hit, evict) are now thread-safe
- Double-check locking pattern in `_ensure_db()` prevents race conditions during lazy initialization
- Added `PRAGMA busy_timeout=5000` to SQLite connections (5s retry on concurrent writes)
- `VectorIndex.add()` already thread-safe via hnswlib internal locking

**Schema Migration System**
- New `cacheback_meta` table tracks schema version
- `MIGRATIONS` list supports incremental schema upgrades (from_ver → to_ver → SQL)
- `_run_migrations()` auto-upgrades on DB open — safe for rolling deploys
- Legacy DBs (no meta table) auto-detected and upgraded

**Error Recovery**
- Corrupt SQLite DB: detected via `sqlite3.DatabaseError`, auto-deleted and recreated
- Corrupt hnswlib index: detected on `load_index()`, auto-deleted and rebuilt fresh
- OpenAI wrapper: `response.choices[0].message.content = None` no longer crashes (tool_calls, empty responses)
- Negative cache: embedder failures during index rebuild now logged with warning (not silent `pass`)

**Tests**
- Added `tests/test_robustness.py` — 15 new tests covering:
  - Corrupt DB/index recovery (4 tests)
  - OpenAI null content handling (2 tests)
  - Schema migration versioning (4 tests)
  - Thread safety under concurrent load (3 tests)
  - Graceful degradation: flaky embedder, post-eviction store (2 tests)
- Total: 86 tests passing

**Deferred**
- Gemini Embedding 2 evaluation → `TODOS.md` (Phase 1.5, P2)

## [0.1.0] — 2026-03-22

### Initial release

- `SemanticCache` kernel: lookup, populate, evict, stats
- `CachedOpenAI` + `AsyncCachedOpenAI` — drop-in OpenAI wrapper with transparent caching
- `CachedAnthropic` + `AsyncCachedAnthropic` — Anthropic wrapper
- Streaming support: buffer-and-replay for both sync and async
- Negative cache: `cache.negative.add/check/list/remove` API
- `CachebackBlocked` exception for negative cache hits
- ONNX MiniLM-L6-v2 embedder (384-dim, ~90MB, lazy download)
- hnswlib HNSW vector index with cosine similarity
- SQLite WAL backend with TTL and LRU eviction
- CLI: `cacheback stats`, `cacheback clear`, `cacheback lookup`
- Apache 2.0 license
- PyPI: `pip install cacheback-ai`
