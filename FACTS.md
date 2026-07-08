# FACTS.md — claims & measurement register

Every number gate.cat uses publicly, with its source and allowed wording.
**Rule: no public claim without a row here. Copy is regenerated FROM this page — never the other way.**
(Council review 2026-07-08, finding C08.)

| # | Claim | Number | Source artifact | Pinned at | Allowed wording | Forbidden wording |
|---|---|---|---|---|---|---|
| F1 | Recall on dangerous-command corpus | 100% | `scripts/corpus_million.py` + `scripts/corpus_recall.py` (1M-command corpus) | TODO: pin commit/tag of the run | "100% recall on a 1M-command corpus for the dangerous set" + link to scripts | "catches everything", "100% safe" |
| F2 | Intervention rate on real traffic | ~0.6% | 14.7k-command Claude Code dogfood log + public 8.6k SWE-agent HF corpus | measured pre-0.3; Bash-engine metric, valid on 0.3.x and 0.4.x | "intervenes on ~0.6% of real commands (two independent logs)" | any implication it was measured on YOUR traffic |
| F3 | Test suite | 892 passed / 28 skipped / 0 failed, on py3.11+3.12+3.13 | CI run [28941307405](https://github.com/BGMLAI/gate.cat/actions/runs/28941307405) (`.github/workflows/ci.yml`) | tag v0.4.2 = `9a55712` (2026-07-08) | "892 tests green in CI as of v0.4.2 (ubuntu, py3.11–3.13)" | unversioned "900+ tests"; the pre-CI local count 907 (superseded — skips differ per env, CI number is the checkable one) |
| F4 | Bypass suite | 65/65 caught + named gaps printed | `gatecat/integrations/bypass_suite.py` | v0.4.0 | "bypass suite catches 65/65 of what it claims and prints the gaps it doesn't (base64, deletes via a language runtime, curl\|sh obfuscation)" | "no known bypasses" |
| F5 | Hard-channel false positives | 0/39 exec, 0/4 calc | internal eval | TODO: pin artifact | "measured false-positive rate of 0 on exec (0/39) and calc (0/4) channels" | "zero false positives" (unscoped) |
| F6 | Uncertainty signal strength (small models) | AUC 0.77–0.90 | N=4800 measurement | TODO: pin artifact/paper section | "AUC 0.77–0.90 on 7–30B models (N=4800)" | universal-coverage claims |
| F7 | Uncertainty signal strength (frontier) | AUC 0.68–0.71 | same run as F6 | TODO | state it plainly as the wedge's honest limit | hiding it |
| F8 | Write/Edit content false-block class | ~11% of dogfood false blocks (fixed in 0.4.0) | dogfood log analysis | 0.4.0 CHANGELOG | "0.4.0 stops scanning file content — content is data, not action" | pretending 0.3.x didn't have it |
| F9 | Installable version | 0.4.2 | https://pypi.org/project/gate.cat/ · tag `v0.4.2` = `9a55712`; hero snippet + the `-F` fix clean-venv-verified against the PyPI wheel | 2026-07-08 | "0.4.2 on PyPI; tag v0.4.2 is the installable version" | citing GitHub-only versions as installable |
| F10 | Default policy walls | 21 in `DOGFOOD_DEFAULTS` (23 presets incl. opt-in) | `gatecat/integrations/policies.py`; measure: `python -c "from gatecat.integrations import DOGFOOD_DEFAULTS; print(len(DOGFOOD_DEFAULTS))"` | v0.4.1 | "21 default policies" | the stale "20 default policies" (pre-0.4.0 count; AUTOEXEC_WRITE landed in 0.4.0) |
| F11 | Demo recordings | Demo A + B, ~5 s each, raw single take | [`docs/demos/`](docs/demos/) — the `.cast` files ARE the recordings; made against 0.4.1 installed from PyPI | commit `142e75c` (2026-07-08) | "raw asciinema, no montage, recorded against the PyPI package" | "real production traffic" (it's a scripted scenario, honestly labeled) |

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
