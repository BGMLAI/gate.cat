# Licensing map

**Short version: the thing you install is Apache-2.0 and always will be. The
evaluation corpus is licensed separately, and you can still re-run it to check
our numbers for free.**

Pinned 2026-07-31.

| What | Licence | Why |
|---|---|---|
| `gatecat/` — the whole pip package: veto engine, 71 default policy walls, the reproducible bypass suite, Claude Code hook, framework adapters, CLI dashboard, local reports | **Apache-2.0** ([LICENSE](LICENSE)) | This is the product and the distribution. Free forever, complete, nothing held back. Changing this would trade the only channel we have for revenue we do not have yet. |
| `scripts/recall_danger_axis.py`, `scripts/corpus_recall.py` — the 43-class danger catalog and runner | **Apache-2.0** | These are how you reproduce our headline recall claim with `pip install gate-cat` and no datasets. A claim nobody can re-run is a rumour. |
| `scripts/corpus_million*.py`, `scripts/corpus_eval.py`, `results/million_recall_*.json` — the large-corpus harness and its adjudicated outputs | **Corpus & Benchmark Licence** ([LICENSE-CORPUS](LICENSE-CORPUS)) | Somebody can rebuild the engine in a weekend. Nobody rebuilds 826,644 adjudicated real agent commands in a weekend. |
| `products/`, `ops/`, `docs/legal/`, `docs/sales/` — Cloud service code, internal operations, commercial templates | Not distributed; all rights reserved | Never shipped in the package. Public in the repo for transparency, not as a grant. |

## What changed on 2026-07-31, and what did not

**Did not change:** anything you can `pip install`. The free gate is exactly as
free and exactly as complete as it was yesterday. If you use gate.cat, this
change is invisible to you and is meant to be.

**Changed:** the adjudicated corpus artifacts moved out from under Apache-2.0
going forward, so they can be licensed to the people who actually want them —
agent-platform and sandbox vendors who need an evaluation corpus to show their
own safety numbers.

**Explicitly preserved:** you may still read, run, re-run and *publish results
that contradict ours*, for free, without asking. That grant is section 3 of
[LICENSE-CORPUS](LICENSE-CORPUS) and it is not a courtesy — a security vendor
whose numbers cannot be checked has nothing to sell. We would rather read that
we are wrong than not know.

**Not retroactive, and we say so in the licence itself.** Versions published
before 2026-07-31 went out under Apache-2.0 and keep Apache-2.0 rights. Git
history is not being rewritten. See section 5 of [LICENSE-CORPUS](LICENSE-CORPUS)
for why we wrote that down rather than leaving it ambiguous.

## Commercial corpus licence

Redistribution, inclusion in another benchmark, model training, publishing your
*own* product's safety figures measured against it, or reselling evaluation
services on top of it — those need a licence: **bogumil@bgml.ai**, subject
"corpus licence". Academic and non-commercial research use is granted on
request.
