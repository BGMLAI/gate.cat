# FACTS.md — claims & measurement register

Every number gate.cat uses publicly, with its source and allowed wording.
**Rule: no public claim without a row here. Copy is regenerated FROM this page — never the other way.**
(Council review 2026-07-08, finding C08.)

| # | Claim | Number | Source artifact | Pinned at | Allowed wording | Forbidden wording |
|---|---|---|---|---|---|---|
| F1a | Recall on known danger classes (FULL 6-stage gate) | 43/43 neutralized (30 block, 13 warn), 0 allowed; 0/13 benign false-blocked | `scripts/recall_danger_axis.py` vs `ActionPipeline` (all 6 stages), catalog = `scripts/corpus_recall.py`. Deterministic, complete, reproducible with `pip install gate-cat` + no datasets. See [RECALL.md](RECALL.md). | master, 2026-07-08 (verified this session) | "100% recall on all 43 known danger classes through the full gate, 0 false-blocks on benign twins — reproduce with scripts/recall_danger_axis.py" | claiming it covers UNKNOWN shapes (that's axis 2); "100% safe" |
| F1b | Recall on real agent traffic at scale (FULL gate) | 1,085,159 unique real commands; 447 catalog dangers; 443 neutralized; 4 allowed → **0 real misses** after adjudication | `scripts/corpus_million.py` vs full `ActionPipeline`, 5 public datasets (Nemotron, SWE-Zero, SWE-Hero, Kwai SWE-smith-mini, nebius); independent 43-class catalog. The 4 allows = 2 unique disposable-artifact cleanups (`proven-disposable`; same shape blocks 5/5 on a real target) = catalog false alarm. Artifact: [`results/million_recall_2026-07-08.json`](results/million_recall_2026-07-08.json); method in [RECALL.md](RECALL.md). | master 2026-07-08 (verified this session) | "0 real recall misses across 1.085M unique real agent commands through the full gate (the 4 catalog-flagged allows are disposable-artifact cleanups the gate correctly permits — same shape blocks on a real target)" | "100% safe"; quoting the raw 4-passed as misses; conflating the 11.7% full-pipeline warn rate with the 0.6% check_action figure |
| F2 | Intervention rate on real traffic | ~0.6% | 14.7k-command Claude Code dogfood log + public 8.6k SWE-agent HF corpus | measured pre-0.3; Bash-engine metric, valid on 0.3.x and 0.4.x | "intervenes on ~0.6% of real commands (two independent logs)" | any implication it was measured on YOUR traffic |
| F3 | Test suite | green in CI on py3.11+3.12+3.13 (≈892 passed / 28 skipped / 0 failed) | `.github/workflows/ci.yml` on tag v0.4.3 = `8469248` (2026-07-08); latest run linked from the CI badge | tag v0.4.3 (2026-07-08) | "tests green in CI as of v0.4.3 (ubuntu, py3.11–3.13)" — link the badge for the exact count | unversioned "900+ tests"; the pre-CI local count 907 (superseded — skips differ per env, CI number is the checkable one) |
| F4 | Bypass suite | 65/65 caught + named gaps printed | `gatecat/integrations/bypass_suite.py` | v0.4.0 | "bypass suite catches 65/65 of what it claims and prints the gaps it doesn't (base64, deletes via a language runtime, curl\|sh obfuscation)" | "no known bypasses" |
| F5 | Hard-channel false positives | 0/39 exec, 0/4 calc | internal eval | TODO: pin artifact | "measured false-positive rate of 0 on exec (0/39) and calc (0/4) channels" | "zero false positives" (unscoped) |
| F6 | Uncertainty signal strength (small models) | AUC 0.77–0.90 | N=4800 measurement | TODO: pin artifact/paper section | "AUC 0.77–0.90 on 7–30B models (N=4800)" | universal-coverage claims |
| F7 | Uncertainty signal strength (frontier) | AUC 0.68–0.71 | same run as F6 | TODO | state it plainly as the wedge's honest limit | hiding it |
| F8 | Write/Edit content false-block class | ~11% of dogfood false blocks (fixed in 0.4.0) | dogfood log analysis | 0.4.0 CHANGELOG | "0.4.0 stops scanning file content — content is data, not action" | pretending 0.3.x didn't have it |
| F9 | Installable version |   0.4.7 | https://pypi.org/project/gate.cat/ · tag `v0.4.7` = `23c0ed1`; hero snippet clean-venv-verified against the PyPI wheel; Beta + Topic::Security classifiers live | 2026-07-08 | "0.4.7 on PyPI; tag v0.4.7 is the installable version" | citing GitHub-only versions as installable |
| F10 | Default policy walls | 21 in `DOGFOOD_DEFAULTS` (23 presets incl. opt-in) | `gatecat/integrations/policies.py`; measure: `python -c "from gatecat.integrations import DOGFOOD_DEFAULTS; print(len(DOGFOOD_DEFAULTS))"` | v0.4.1 | "21 default policies" | the stale "20 default policies" (pre-0.4.0 count; AUTOEXEC_WRITE landed in 0.4.0) |
| F11 | Demo recordings | Demo A + B, ~5 s each, raw single take | [`docs/demos/`](docs/demos/) — the `.cast` files ARE the recordings; made against 0.4.1 installed from PyPI | commit `142e75c` (2026-07-08) | "raw asciinema, no montage, recorded against the PyPI package" | "real production traffic" (it's a scripted scenario, honestly labeled) |
| F12 | Line coverage | 73% (6339 statements) in CI; 74% locally with the armed-gate-only tests included | CI run [28942984519](https://github.com/BGMLAI/gate.cat/actions/runs/28942984519) — pytest `--cov=gatecat`, printed in every CI job | 2026-07-08 (master `b9a75c0`) | "73% statement coverage, printed by CI on every run" | rounding up to "3/4 of the code is tested"; hiding that proxy/CLI paths are the least covered |

## Honest-limits block (must accompany capability claims)

- The gate is certain only about what it **blocks**. An unmatched action is *unchecked*, not *safe*.
- Lookup/fact-check channel is **empty by default** (bring your own fact base). Not a hallucination detector.
- Prompt-injection defense is experimental and off-headline.
- Framework adapters are in-process convention; **only the Claude Code hook is enforcement outside the agent's control flow**.
- Signal is strongest on 7–30B local models; weaker on frontier (F6/F7).

## Process

1. New number → new row (with source + pin) BEFORE it appears in any copy.
2. Version-scoped numbers (tests, bypass count) get re-pinned at each release; old numbers stay valid only in version-scoped contexts (e.g. CHANGELOG).
3. TODO rows must be resolved (artifact pinned) before the number is used in NEW copy.
