# gatecat — Architecture

> **Pakiet:** `gate.cat` v0.2.0 · Apache-2.0 · Python ≥3.10
> **Root:** `packages/gatecat/gatecat/`
> **Dla:** deweloperów chcących zrozumieć budowę i rozszerzyć kod.
> Cytaty `file:line` względem `packages/gatecat/gatecat/` (chyba że podano `src/` = aplikacja iors).

---

## 1. Przegląd

gatecat to **model-agnostyczny pip-package** łączący dwa rozłączne stosy:

1. **Stos cache** — semantyczny cache Q&A (embedder ONNX → HNSW index → SQLite store) z opcjonalną
   syntezą odpowiedzi z sąsiadów (CAS).
2. **Stos weryfikacji** — „koryto pilnuje rzeki": deterministyczny weryfikator faktu (`koryto`),
   disagreement-gate (`gate`), action-veto przed nieodwracalną akcją (`veto`), gałęzie naprawy
   (`branches`) i monitor stagnacji (`stagnation`).

Oba stosy są niezależne; model jest wstrzykiwany przez callback (`sample_fn`/`run`) albo HTTP
(opcjonalny proxy). **Pakiet NIE zawiera agent-frameworka ani pętli ReAct** — to należy do aplikacji
iors (patrz §9). Core (`numpy`/`hnswlib`/`onnxruntime`/`huggingface-hub`/`tokenizers`) jest zawsze
obecny; wszystko inne to opcjonalne `extras` (`pyproject.toml:30-37`).

Punkty wejścia użytkownika:
- **In-process wrappery** — `CachedOpenAI` / `CachedAnthropic` (drop-in dla SDK dostawcy).
- **Proxy** — FastAPI serwer OpenAI-compatible (`python -m gatecat.proxy`), spina oba stosy.
- **Biblioteka** — `SemanticCache`, `Koryto`, `Gate`, `VetoGate`, `GatedLoop` używane bezpośrednio.

---

## 2. Warstwy

```
                    WRAPPERY / PROXY  (openai.py · anthropic.py · proxy/app.py)
 ── STOS CACHE ─────────────────────────────┐   ┌──────── STOS WERYFIKACJI ──────────────
  synthesis.py  CAS — synteza z sąsiadów     │   │  gate.py        rozrzut N próbek (disagree)
  cache.py      SemanticCache — KERNEL        │   │  koryto.py      exec / calc / lookup
  embedders/*   ONNX, modality → wektor       │   │   └ koryto_sandbox.py  AST allow-list + Job/rlimit
  index.py      VectorIndex — hnswlib HNSW    │   │   └ koryto_sources.py  lookup_fn + bramka jakości
  store.py      CacheStore — SQLite WAL       │   │  branches.py     web (gałąź 3) / tools (gałąź 4)
  negative.py   blocklist — osobny store      │   │  stagnation.py   czy koryto „zgniło"
 ────────────────────────────────────────────┘   │  veto.py         action-veto PRZED akcją
                                                  │  agent.py        GatedLoop — gating pętli agenta
                                                  │  audit.py        Gate Report (offline)
```

Zależności jednokierunkowe:
`embedders → index → store` montowane w `cache.py`; `cache → synthesis`;
`gate → agent/audit/branches`; `koryto → koryto_sandbox/koryto_sources/veto/stagnation`.
**`proxy/app.py` to jedyne miejsce łączące oba stosy.**

---

## 3. Moduły

### 3a. Stos cache

| Plik | Rola | Publiczne API | Zależności |
|---|---|---|---|
| `store.py` | `CacheStore` — SQLite WAL, tabela `cache_entries` | `store/get/record_hit/evict_expired/evict_lru/get_total_entries/get_all_embeddings` | stdlib `sqlite3`, `numpy` |
| `index.py` | `VectorIndex` — HNSW dim-aware, label==cache_id | `add_items/search/save/load/resize` | `hnswlib` (fallback brute-force numpy) |
| `embedders/__init__.py` | registry + `BaseEmbedder(ABC)` | `get_embedder/register_embedder` | — |
| `embedders/minilm.py` | `MiniLMEmbedder` dim=384 text | `encode()` | `onnxruntime`,`tokenizers`,`huggingface-hub` |
| `embedders/{clip,clap,whisper}.py` | CLIP 512 / CLAP 512 / Whisper 384 | `encode()` | `Pillow`(image)/`soundfile`(voice) |
| `cache.py` | `SemanticCache` — KERNEL (embedder+index+store) | `lookup/lookup_for_synthesis/populate/negative/stats/save/close` | powyższe |
| `negative.py` | `NegativeCacheAPI` — osobny SQLite+index, blocklist | `add/check/check_embedding/list/remove/report_false_positive` | `index`,`store` |
| `synthesis.py` | `SynthesisEngine` (CAS) — synteza z top-k sąsiadów | `synthesize()` | extra `[openai]` |

**`store.py` — CacheStore.** Schemat `cache_entries` (`store.py:25-42`):
`id PK AUTOINCREMENT, query_text, response_text, embedding BLOB, model, tokens, modality,
created_at, expires_at, hit_count, last_hit_at, metadata`. Indeksy na `expires_at`, `modality`.
`embedding` = `np.float32.tobytes()` (`store.py:177`), odczyt `np.frombuffer(...,dtype=float32)` z
guardem wymiaru (`store.py:251-264`). PRAGMA: `journal_mode=WAL, synchronous=NORMAL,
busy_timeout=5000` (`store.py:94-96`). Migracje wersjonowane przez `gatecat_meta`
(`SCHEMA_VERSION=1`, lista `MIGRATIONS` pusta). **Fail-safe:** korupcja DB → log + `os.remove` +
recreate (`store.py:100-120`). `evict_lru` sortuje `last_hit_at ASC, created_at ASC`. Thread-safe
przez `RLock`, `check_same_thread=False`.

**`index.py` — VectorIndex.** HNSW: `space="ip"`, `M=16`, `ef_construction=200`, `ef_search=50`,
`max_elements=500_000` z auto-resize ×2. **label == cache_id** (db.id) — `add_items(vec,[cache_id])`.
Similarity = `1.0 - distance`. Lazy-load `_ensure_index`; load z pliku autorytatywny, korupcja →
remove + rebuild fresh. **Fallback:** brak `hnswlib` → `_BruteForceIndex` (numpy matmul) — działa,
ale `save()` jest no-op. Thread-safe przez `Lock`.

**`embedders/` — registry.** `BaseEmbedder(ABC)` z `dim/modality/encode()`. `get_embedder(name,
cache_dir)` zwraca **singleton per (name, cache_dir)**. Auto-rejestracja przy imporcie
(`_register_builtins`): `minilm` zawsze; `clip/clap/whisper` tylko gdy deps dostępne (try/except
ImportError). `MiniLMEmbedder`: model `sentence-transformers/all-MiniLM-L6-v2`, plik `onnx/model.onnx`
(~90MB) z HF Hub, BEZ torch. Lazy-load z double-check lock; ONNX session NIE thread-safe → inference
serializowane pod `Lock`. Mean-pooling + L2-normalize → cosine = dot. `embedders/_audio.py` =
współdzielony mel/STFT/resample pure-numpy.

**`cache.py` — SemanticCache (KERNEL).** Domyślne: `threshold=0.92, negative_threshold=0.85,
max_entries=100k, ttl=24h` (konstruktor `cache.py:45-48`). Publiczne:
- `lookup(query) → Optional[str]`: embed → **negative-check first** → positive search k=1 →
  `store.get` → `record_hit`. Krótkie query (<5 zn.) pominięte. **Fail-closed bezpieczeństwo /
  fail-open dostępność**: `GatecatBlocked` propaguje (negative hit z policy `raise`), każdy inny
  wyjątek → passthrough `None`.
- `lookup_for_synthesis(query, threshold=0.80, top_k=5) → list[(cache_id, sim)]` — dla CAS.
- `populate(query, response, model, tokens) → bool`: skip jeśli `len<20` (`MIN_RESPONSE_LENGTH`);
  skip near-dup (sim≥0.98); store+index.add; LRU eviction + ręczna resync `_count`
  (HNSW nie ma delete — gotcha).
- `negative` (property, lazy), `stats`, `save`, `close`, context-manager.

**`negative.py` — NegativeCacheAPI.** **Osobny** SQLite (`negative/negative.db`) + osobny
`VectorIndex` (`negative/neg_index.bin`), próg 0.85, TTL 30 dni. Schemat `negative_entries`: +
`category, severity, false_positives`. Auto-remove po `MAX_FALSE_POSITIVES=5`. `_safe_json` chroni
przed korupcją kolumny metadata.

### 3b. Stos weryfikacji

| Plik | Rola | Publiczne API | Fail-mode |
|---|---|---|---|
| `gate.py` | `Gate` — disagreement z rozrzutu N próbek | `check/check_samples/check_scores` | fail-CLOSED (uncertain) |
| `agent.py` | `GatedLoop` — gating pętli agenta | `run()` + callbacki | fail-safe (rescued=False) |
| `koryto.py` | `Koryto` — exec/calc/lookup atomu | `verify()` | confirm/refute/unknown |
| `koryto_sandbox.py` | szczelne wykonanie kodu | `run_context_guard/run_sandboxed` | fail-CLOSED (mury) |
| `koryto_sources.py` | budowanie `lookup_fn` + bramka jakości | `http_cache_source/chroma_source/multi_source` | fail-safe → None |
| `stagnation.py` | `StagnationMonitor` — czy koryto zgniło | `observe()` → state | — |
| `branches.py` | `WebBranch` / `ToolBranch` — gałęzie naprawy | `maybe_run/add` | gated progiem |
| `veto.py` | action-veto przed akcją | `before_action/VetoGate/ActionPolicy` | fail-CLOSED |
| `audit.py` | Gate Report offline | `run_audit/make_backend` | — |

**`gate.py` — Gate / GateVerdict.** Mierzy ROZRZUT N próbek (`n_samples=5`, `threshold=0.30`).
`check(prompt)` woła `sample_fn` N razy; `check_samples/check_scores` na gotowych danych. Rozrzut:
semantyczny (embedder) lub lexical fallback. **Fail-closed:** wszystkie próbki padły / <2 ważne →
`disagreement=1.0, uncertain=True`. Łapie WAHANIE, nie confident-wrong (uczciwe ograniczenie z
docstringu).

**`agent.py` — GatedLoop.** Owija pętlę agenta; probe na NASTĘPNY krok; `max_uncertain_steps` z rzędu
→ stop `runaway_guessing`. `on_uncertain` callback (eskalacja); wyjątek w nim → `rescued=False`
fail-safe. Backstopy: `max_steps`, `max_cost`.

**`koryto.py` — Koryto / KorytoVerdict / FactBase.** Deterministyczny weryfikator atomu, 3 kanały
kolejno: **exec** (interpreter przez `koryto_sandbox`, hard), **calc** (jawne wyrażenia AST, hard),
**lookup** (FactBase, soft → `needs_arbiter`). Werdykt: `confirm|refute|unknown`, pola
`hard/needs_arbiter/channel/truth`. `atoms_match` = word-boundary + substring fallback.
**`enable_exec=True` domyślnie** w SDK (`koryto.py:270`); node-exec osobno OFF
(`GATECAT_KORYTO_EXEC_NODE_UNSAFE`). (W iors-wpięciu exec wyłączony — patrz §9.)

**`koryto_sandbox.py` — szczelne wykonanie.** Mury (fail-closed): (A) `ast_gate` allow-list
`_ALLOWED_NODES`, `Attribute` zakazany bezwarunkowo, `Call` tylko do `SAFE_BUILTINS`+lokalne,
statyczne capy anty-DoS (int>7 cyfr, `Pow` exp≤20, seq-mult≤1000, range≤10⁶); (B)
`__builtins__=SAFE_DICT`; (C) `python -I -S -E`; (D) `_clean_env` bez sekretów; (E) Linux
`setrlimit+setsid` / Windows **Job Object** kill-on-close. Wejścia: `run_context_guard(stmts)`
(setup + eval ostatniego), `run_sandboxed(code)`. Gate na WEJŚCIU usera, harness zaufany.

**`koryto_sources.py` — budowanie lookup_fn.** `http_cache_source` (4M cache VPS),
`chroma_source` (ChromaDB v2 cosine), `multi_source` (pierwszy przechodzący). **Bramka jakości**
`_quality_ok`: `sim≥0.82` + filtr MCQ (`is_mcq`) + min długość. Wszystko fail-safe → None.

**`stagnation.py` — StagnationMonitor / StagnationState.** Okno werdyktów koryta; `soft_streak≥3`
(param `soft_streak_trigger`) LUB `refute_ratio≥0.8` z miękkimi → `koryto_suspect=True` (eskaluj do
web-rozjemcy). **Klucz:** czyste TWARDE odrzucenia (exec/calc) NIGDY nie czynią koryta podejrzanym.
Domyślne okno: **5** w SDK (`stagnation.py:15`); w iors-wpięciu **20** (patrz §9).

**`branches.py` — WebBranch / ToolBranch.** Gałąź 3 (web, Brave domyślny, pluggable `search_fn`):
wstrzyk TYLKO gdy `snippet_score≥próg` (0.55 retrieval / 0.25 overlap). Gałąź 4 (tools): bezpieczny
`calculate` (AST, bez `eval`), `looks_like_math` routing. Pluggable: `ToolBranch.add(name,desc,run)`.

**`veto.py` — action-veto.** Blokada akcji agenta PRZED wykonaniem. `before_action` dekorator
(sync+async), `VetoGate`, `ActionPolicy`, `ActionVetoed`, `VetoDecision`. Trzy mury fail-closed:
**POLICY** (`deny`>`max_amount`>`require_human`, regex; NaN/inf amount → veto, zły regex → veto),
**KORYTO** (`exec_check` → interpreter), **HUMAN** (`human_approve` callback). `strict=True` wymaga
≥1 muru.

**`audit.py` — Gate Report.** `run_audit(sample_fn, answer_fn, data)` → `AuditReport`:
`base_accuracy, gate_flag_rate, AUC` (Mann-Whitney, tylko gdy `n_wrong≥10` — winner's curse guard),
rozdział `uncertain_wrong` vs `confident_wrong`. `make_backend` (ollama / openai-compatible). CLI
`truthgate-audit`.

### 3c. Wrappery / proxy / streaming

| Plik | Rola | Publiczne API |
|---|---|---|
| `openai.py` | `CachedOpenAI` / `AsyncCachedOpenAI` drop-in | `chat.completions.create` (3-tier in-process) |
| `anthropic.py` | `CachedAnthropic` / `AsyncCachedAnthropic` | `messages.create/.stream` |
| `_async_cache.py` | `AsyncSemanticCache` — blokujące ops w executor | te same args co sync |
| `_streaming.py` | `StreamBuffer` (OBA formaty), replay/buffer | `buffer_and_cache_*/replay_cached_*` |
| `codeblocks.py` | `extract_code_blocks/to_exec_statements` | (sam nic nie wykonuje) |
| `proxy/app.py` | FastAPI serwer — kaskada wielostopniowa | `POST /v1/chat/completions`, `/health` |
| `proxy/config.py` | `ProxyConfig.from_env` + SSRF-guard | `validate_upstream_url/build_upstream_headers` |
| `proxy/models.py` | pydantic OpenAI-compatible | `ChatCompletion{Request,Response,...}` |

`openai.py`: `__getattr__` deleguje do oryginalnego klienta; podmieniony tylko
`chat.completions.create`. `_CachedResponse` udaje strukturę OpenAI z `gatecat_hit /
gatecat_synthesized`. Import `openai` lazy → `ImportError` z instrukcją `[openai]`.
`_streaming.StreamBuffer.feed` rozumie OBA formaty (OpenAI `delta.content` / Anthropic
`content_block_delta`).

---

## 4. Przepływy

### 4a. Cache lookup / populate (`cache.py`)

```
lookup(query):
  len<5 ──────────────────────────────► None (skip)
  embed(query)
  negative.check_embedding(vec) ──hit──► policy: skip→None | raise→GatecatBlocked
  index.search(vec, k=1)
  sim ≥ threshold(0.92) ──tak──► store.get(cache_id) → record_hit → response_text
                        ──nie──► None
  (każdy inny wyjątek ──────────► None  # fail-open dostępność)

populate(query, response, model, tokens):
  len(response) < 20 ────────────► False (MIN_RESPONSE_LENGTH)
  embed → index.search k=1, sim ≥ 0.98 ──► False (near-dup)
  store.store(...) → index.add_items(vec, [cache_id])
  _count > max_entries ──► store.evict_lru → resync _count   # HNSW bez delete
```

### 4b. Proxy request — kaskada (`proxy/app.py`)

Wejście `POST /v1/chat/completions`. `_extract_query` = ostatnia wiadomość `role=user`.
**Passthrough** gdy `req.tools` lub puste query (`proxy/app.py:254`) — patrz §9 (proxy NIE robi
tool-callingu).

```
Tier 1  Verbatim cache    cache.lookup(query) sim≥0.92         → HIT: zwróć
Tier 2  CAS synthesis     lookup_for_synthesis 0.80≤sim<0.92   → syntetyzuj
Tier 2.5 TruthGate        _gate_probe: N próbek upstream temp=0.7, mierz rozrzut
         └ uncertain → gałąź 4 (tools/calc), potem gałąź 3 (web; snippet≥próg → wstrzyknij kontekst),
            potem block-mode → abstention
Tier 3  Upstream API      _forward_upstream
Tier 3.5 KORYTO           koryto.verify(query, model_answer)
         ├ exec/calc (hard) refute → _apply_koryto_correction → zwróć prawdę koryta
         ├ lookup (soft, needs_arbiter) → _web_arbiter rozsądza model vs koryto
         └ stagnation.observe(kv): seria miękkich odrzuceń = koryto stale
Cache populate            tylko gdy koryto NIE odrzuciło
```

Tryby z `ProxyConfig`:
- `gate_mode` — `off|flag|block` (`config.py:88`)
- `koryto_mode` — `off|flag|block` (`config.py:107`)
- `synthesis_mode` — **`off|auto|always`** (NIE flag/block; `config.py:77`, `app.py:104`)

Wszystkie domyślnie `off`/`off`/`off` → zero zmian zachowania. Gate i koryto inicjalizowane w
`lifespan`. Streaming `_handle_stream` (HIT replay / synteza replay / miss = `_proxy_stream`
buffer+cache). Metadane: `gatecat_hit/synthesized/gate/koryto/abstained` + nagłówki
`X-Gatecat-* / X-Truthgate-* / X-Koryto-*`.

**Bezpieczeństwo proxy:** SSRF-guard `validate_upstream_url` (https-only + blok prywatnych/metadata
IP, `config.py:33-57`); `build_upstream_headers` domyślnie NIE przekazuje klienckiego `Authorization`
(wymaga `GATECAT_ALLOW_CLIENT_AUTH=1`); generyczne błędy do klienta (detal tylko do logu).
Truth-forgery guard: exec z `source="auto"` (kod z query usera) NIE koryguje twardo, `truth`
wymazany z meta (`app.py:342`).

### 4c. Verification stack: gate → koryto → veto → abstain

```
              ┌────────────────────────────────────────────────┐
  prompt ───► │ GATE  (gate.py)  N próbek → disagreement        │
              │        uncertain? ──nie──► (zaufaj odpowiedzi)   │
              └──────────────│ tak ────────────────────────────┘
                             ▼
              ┌────────────────────────────────────────────────┐
  answer ───► │ KORYTO (koryto.py) exec | calc | lookup         │
              │   refute & hard ──────► korekta / abstain        │
              │   refute & soft ──────► needs_arbiter → web      │
              │   confirm/unknown ────► przepuść                  │
              └──────────────│──────────────────────────────────┘
                             ▼
              ┌────────────────────────────────────────────────┐
  action ───► │ VETO  (veto.py)  POLICY → KORYTO → HUMAN         │
              │   not allowed ────────► ActionVetoed (block)     │
              └────────────────────────────────────────────────┘
                             ▼
              stagnation.observe(verdicts): koryto_suspect? → eskaluj
```

Gate łapie WAHANIE (model nie wie); koryto łapie CONFIDENT-WRONG na fizycznie niezależnym kanale
(exec/calc twardo, lookup miękko); veto blokuje NIEODWRACALNĄ akcję zanim się wykona; stagnation
pilnuje, czy samo koryto nie zgniło (przeszkadza zamiast pomagać).

---

## 5. Modele danych

### 5a. SQLite — `cache_entries` (`store.py:25-42`)

```sql
CREATE TABLE cache_entries (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,   -- == label w VectorIndex
  query_text   TEXT NOT NULL,
  response_text TEXT NOT NULL,
  embedding    BLOB NOT NULL,        -- np.float32.tobytes(), dim wg embeddera
  model        TEXT,
  tokens       INTEGER,
  modality     TEXT DEFAULT 'text',
  created_at   REAL,
  expires_at   REAL,                 -- index
  hit_count    INTEGER DEFAULT 0,
  last_hit_at  REAL,
  metadata     TEXT                  -- JSON
);
-- + negative_entries (negative.py): te same kolumny + reason/category/severity/false_positives
-- + gatecat_meta (schema_version)
```

PRAGMA: `WAL`, `synchronous=NORMAL`, `busy_timeout=5000`. Migracje przez `gatecat_meta`
(`SCHEMA_VERSION=1`).

### 5b. VectorIndex (`index.py`)

`hnswlib.Index(space="ip", dim=embedder.dim)`, `M=16`, `ef_construction=200`, `ef_search=50`,
`max_elements=500_000` (auto-resize ×2). **label == cache_id (db.id)** — to spina index ze store
1:1. Brak `hnswlib` → `_BruteForceIndex` (numpy, `save()` no-op). `embedding` BLOB = float32 → cosine
działa bo embeddery L2-normalizują (ip == cosine).

### 5c. Embedder registry (`embedders/__init__.py`)

Moduł-globalne `_registry` (name→klasa) i `_instances` (singleton per (name, cache_dir)).
`BaseEmbedder.encode()` MUSI zwracać `np.float32` znormalizowany. `VectorIndex(dim=embedder.dim)` —
index jest dim-agnostyczny, więc nowy embedder o innym wymiarze działa bez zmian w index/store.

### 5d. Publiczne dataclasses

| Dataclass | Plik | Kluczowe pola |
|---|---|---|
| `CacheEntry` | `store.py` | id, query_text, response_text, model, tokens, modality, hit_count, metadata |
| `NegativeEntry` | `negative.py` | + reason, category, severity, false_positives |
| `SynthesisCandidate` / `SynthesisResult` | `synthesis.py` | query/response/similarity/cache_id ; text/source/latency/mean_similarity |
| `GateVerdict` | `gate.py` | disagreement, uncertain, samples, threshold, method, n |
| `StepResult` / `LoopResult` | `agent.py` | output/done/prompt/cost ; stopped_reason/steps/uncertain_steps |
| `KorytoVerdict` | `koryto.py` | verdict, channel, truth, hard, needs_arbiter; `.caught` |
| `StagnationState` | `stagnation.py` | koryto_suspect, refute_streak, soft_refute_streak, window_refute_ratio |
| `VetoDecision` | `veto.py` | allowed, mur, reason, verdict |
| `CodeBlock` | `codeblocks.py` | lang, code, source |
| `AuditReport` | `audit.py` | base_accuracy, auc, uncertain_wrong, confident_wrong, recall_on_errors |
| pydantic `ChatCompletion{Request,Response,...}` | `proxy/models.py` | OpenAI-compatible; + `koryto_exec`, + `gatecat_hit/synthesized` |

> `DeviceEntry` NIE istnieje w tym pakiecie — to byłby orchestrator floty (aplikacja iors), nie SDK.

---

## 6. Rozszerzanie

### 6a. Nowy embedder

```python
import numpy as np
from gatecat.embedders import BaseEmbedder, register_embedder

class MyEmbedder(BaseEmbedder):
    dim = 256
    modality = "text"
    def encode(self, inputs: list[str]) -> np.ndarray:
        vecs = my_model(inputs)                       # (n, 256)
        return (vecs / np.linalg.norm(vecs, axis=1, keepdims=True)).astype(np.float32)

register_embedder("myembed", MyEmbedder)              # albo w _register_builtins
# get_embedder("myembed") zwróci singleton; VectorIndex(dim=256) dim-agnostyczny
```

### 6b. Nowy tool (gałąź 4)

```python
from gatecat.branches import ToolBranch
tb = ToolBranch()
tb.add("currency", "Konwersja walut", lambda q: convert(q))   # branches.py:208
# routing przez heurystykę maybe_run — rozszerz jeśli nie-matematyczny
```

### 6c. Nowy lookup-source (kanał lookup koryta)

```python
from gatecat.koryto_sources import multi_source
from gatecat.koryto import FactBase, Koryto

def my_source(question: str) -> str | None:
    hit = my_kb.search(question)
    if hit and hit.sim >= 0.82 and not is_mcq(hit.text):   # wzór _quality_ok
        return hit.text
    return None

fb = FactBase(lookup_fn=multi_source([my_source, http_cache_source(url)]))
koryto = Koryto(fact_base=fb)
# proxy: GATECAT_KORYTO_CACHE_URL / GATECAT_KORYTO_CHROMA_URL
```

### 6d. Nowy kanał koryta (poza exec/calc/lookup)

Rozszerz `Koryto.verify`: zwróć `KorytoVerdict(hard=True)` dla fizycznie niezależnego źródła
prawdy, `needs_arbiter=True` dla miękkiego (idzie do web-rozjemcy, nie blokuje twardo).

---

## 7. Konfiguracja

### 7a. Extras (`pyproject.toml:30-37`)

**Core (zawsze):** `numpy, hnswlib, onnxruntime, huggingface-hub, tokenizers`. Brak `hnswlib` →
brute-force (działa, wolniej).

| Extra | Pakiety | Aktywuje |
|---|---|---|
| `openai` | openai≥1.0 | `CachedOpenAI`, `SynthesisEngine` (CAS) |
| `anthropic` | anthropic≥0.20 | `CachedAnthropic` |
| `image` | Pillow≥10 | CLIP preprocessing |
| `voice` | soundfile≥0.12 | CLAP/Whisper audio I/O |
| `proxy` | fastapi, uvicorn, httpx, pydantic | serwer proxy + `WebBranch`/`koryto_sources`/`audit` (httpx) |
| `all` / `dev` | wszystko / pytest+httpx | — |

Wzorzec: import lazy w środku funkcji/property + `try/except ImportError` → czytelny błąd z
instrukcją extra. Brak extras NIE psuje importu `gatecat` (`__init__.py` używa `__getattr__`).

**Entry-points (`pyproject.toml:39-42`):** `gatecat` (CLI stats/clear/lookup), `gatecat-proxy`
(serwer), `truthgate-audit` (Gate Report).

### 7b. Zmienne środowiskowe — proxy (`proxy/config.py`, `from_env()`)

Upstream/serwer: `OPENAI_API_KEY`(""), `OPENAI_BASE_URL`(api.openai.com/v1; SSRF-guard),
`GATECAT_ALLOW_INSECURE_UPSTREAM`(0), `GATECAT_ALLOW_CLIENT_AUTH`(0),
`GATECAT_HOST`(0.0.0.0), `GATECAT_PORT`(8080), `GATECAT_LOG_LEVEL`(info).
Cache: `GATECAT_CACHE_DIR`(""), `GATECAT_SIMILARITY_THRESHOLD`(0.92),
`GATECAT_NEGATIVE_THRESHOLD`(0.85), `GATECAT_MAX_ENTRIES`(100000), `GATECAT_TTL`(86400),
`GATECAT_ON_NEGATIVE_HIT`(skip).
Synthesis (CAS): `GATECAT_SYNTHESIS_MODE`(off; **off|auto|always**),
`GATECAT_SYNTHESIS_MODEL`(google/gemini-2.0-flash-lite-001), `..._BASE_URL`(""), `..._API_KEY`(""),
`GATECAT_SYNTHESIS_THRESHOLD`(0.80), `GATECAT_SYNTHESIS_TOP_K`(5).
TruthGate (off|flag|block): `GATECAT_GATE_MODE`(off), `..._N_SAMPLES`(5), `..._THRESHOLD`(0.30),
`..._SEMANTIC`(1).
Gałęzie: `GATECAT_WEB_ENABLED`(0), `BRAVE_API_KEY`(""), `GATECAT_TOOLS_ENABLED`(1).
KORYTO (off|flag|block): `GATECAT_KORYTO_MODE`(off), `..._FACT_BASE`(""), `..._CACHE_URL`(""),
`..._CACHE_KEY`(""), `..._CHROMA_URL`(""), `..._CHROMA_COLLECTION`(""), `..._LOOKUP_MIN_SIM`(0.82).
Stagnacja: `GATECAT_STAGNATION_WINDOW`(**5**), `..._SOFT_STREAK`(3).
Exec sandbox: `GATECAT_KORYTO_EXEC_UNSAFE`(0; auto-wyłuskanie kodu z ruchu OFF),
`..._EXEC_TIMEOUT`(5.0), `..._EXEC_MEM_MB`(512).

---

## 8. Testy

`tools.pytest.ini_options`: `asyncio_mode="auto"`, `testpaths=["tests"]`. `conftest.py` daje
`tmp_cache_dir` + `MockEmbedder` (deterministyczny hash-embed 384-dim, BEZ ONNX) — testy nie dotykają
realnych API/modeli.

**Uruchomienie:**
```bash
pip install -e ".[dev]"
pytest tests/                 # Windows: --basetemp=F:/tmp gdy C: pełny
gatecat stats               # CLI
gatecat-proxy               # = python -m gatecat.proxy (0.0.0.0:8080)
```

**20 plików, 372 testy** (`pytest --collect-only`; 369 pass + 3 skip). Rozszerzono o warstwę
action-veto i dowody jakości (2026-06-27): `test_veto_bypass_e2e.py` (22 adversarialne bypassy
+ E2E gate+koryto), `test_false_positive.py` (FPR=0 / false-refute=0 — metryka #1 produktu),
`test_web_snippet_threshold.py` (dowód, że próg jakości snippetu odcina web-szum). Rdzeń:

| Plik | # | Plik | # |
|---|---|---|---|
| test_embedders.py | 53 | test_negative.py | 13 |
| test_veto.py | 30 | test_koryto_sources.py | 13 |
| test_synthesis.py | 27 | test_codeblocks.py | 13 |
| test_veto_bypass_e2e.py | 27 | test_openai.py | 12 |
| test_proxy.py | 25 | test_koryto_proxy.py | 12 |
| test_koryto.py | 21 | test_anthropic.py | 12 |
| test_truthgate.py | 15 | test_cache.py | 10 |
| test_robustness.py | 15 | test_stagnation.py | 7 |
| test_koryto_sandbox.py | 14 | test_false_positive.py | 5 |
| test_streaming.py | 13 | **+ web-threshold, …** | **→ 372** |

**CI (`.github/workflows/`):** `ci.yml` — push/PR na `main`, matrix 3 OS × Py 3.10/3.11/3.12,
`pip install -e ".[dev]" → pytest`; job `lint` = `ruff check`. `publish.yml` — tag `v*`, PyPI
trusted-publish (OIDC).

**Deployment (proxy):** `Dockerfile` python:3.12-slim, `pip install ".[proxy]"`,
`GATECAT_CACHE_DIR=/data/gatecat`, EXPOSE 8080, HEALTHCHECK `/health`,
`CMD python -m gatecat.proxy`. `docker-compose.yml` — port 8080, wolumen `gatecat-data`,
`restart: unless-stopped`.

---

## 9. Rozróżnienie: SDK gatecat vs aplikacja iors/bgml

**To są dwie różne rzeczy. Nie mieszaj.**

- **SDK `gatecat`** (ten pakiet, `pip install gate.cat`): silnik veto/koryto/cache,
  model-agnostyczny, **BEZ agent-frameworka i pętli ReAct**. Proxy robi **passthrough** gdy w żądaniu
  są `tools` (`proxy/app.py:254` → `if req.tools or not query: return _forward_upstream(...)`) —
  czyli proxy NIE wykonuje tool-callingu, działa tylko jako warstwa veto wokół TWOICH narzędzi.
  Jedyne wbudowane „narzędzie" to `calculate` (AST) w `branches.py`.

- **Aplikacja iors** (`src/`, serwis FastAPI na VPS `204.168.129.200`): **importuje gatecat lazy**
  jako veto-engine i osobno ma **własny, pełny ReAct stack** w `src/tools/`
  (`agent_entry.py → router.py → grammars.py(GBNF) → react_agent.py`, `strategy=tool_calling_react`,
  aktywowany przez `settings.bgml_react_tool_agent_enabled`). **ReAct należy do iors, nie do SDK.**

Jak iors wpina gatecat (dwa niezależne punkty):

| Aspekt | SDK `gatecat` (pip) | Aplikacja iors (VPS, `src/`) |
|---|---|---|
| Tool-calling / ReAct | ❌ pass-through na `req.tools`; tylko `calculate` | ✅ pełny ReAct+GBNF (`src/tools/`) |
| Veto w czacie | proxy Tier 3.5 (`koryto.verify` w kaskadzie) | `_veto_finalize` w fleet/orch synthesis (`src/api/iors_chat.py:2951`), **fail-OPEN** |
| Veto w akcji | `@before_action` / `VetoGate` | `VetoGate` w `ToolRegistry.execute` (`src/tools/registry.py`), **fail-CLOSED** |
| `VetoGate` mury w iors | POLICY+KORYTO+HUMAN | tylko **POLICY** (`koryto=None, human_approve=None` w `src/tools/builtin.py`) |
| `synthesis_mode` | `off/auto/always` | n/d |
| Stagnation window | default **5** | default **20** (`iors_veto_stagnation_window`) |
| Exec channel | `enable_exec=True` | `iors_veto_koryto_exec=False` |
| Tryb veto | `GATECAT_KORYTO_MODE` / `_GATE_MODE` | `IORS_VETO_MODE` (env > settings; off\|flag\|block) |
| Orchestrator timeout | n/d | stała `IORS_ORCHESTRATOR_TIMEOUT_S=60.0` (`src/api/iors_chat.py:77`) ⚠️ komentarz w kodzie mówi „120s" — **rozbieżność do rozstrzygnięcia** (60s < p95~90s = możliwy przedwczesny cancel) |

**Kluczowa różnica fail-mode:** w iors **czat = veto fail-OPEN** (nie zatrzymuje żywego serwisu;
`block` blokuje TYLKO `hard_refute` exec/calc; soft/lookup daje wyłącznie `veto_flag` w
`bgml_metadata` — shadow). **Tool-agent = action-veto fail-CLOSED** (`registry.execute` blokuje akcję
ze skutkiem ubocznym zanim się wykona; błąd bramki → veto). Oba czerpią mode z
`IORS_VETO_MODE`/`iors_veto_mode`, ale to niezależne punkty wpięcia.

iors importuje moduły punktowo (`importlib.import_module("gatecat.koryto")`, nie `from gatecat
import *` — top-level `__init__` ciągnąłby embedder na hot-path). `mode=="off"` → zero importu
gatecat. ImportError/crash → trwale off (fail-OPEN, bez retry-storm).
