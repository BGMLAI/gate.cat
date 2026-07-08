# Reproducibility scripts

These are the scripts behind the headline numbers. See [`../FACTS.md`](../FACTS.md) for
which claim each one backs.

## Verify the recall number (F1: 100% recall on the dangerous set)

The recall claim is measured against public command corpora — you can reproduce it.

```bash
pip install "gate-cat" datasets      # `datasets` = HuggingFace loader, not a gate.cat dep
python scripts/corpus_recall.py <corpus_dir>     # danger detection recall on a labeled set
python scripts/corpus_million.py                 # streams a 1M-command corpus, reports catches
python scripts/corpus_eval.py --source nemotron <corpus>   # eval against the Nemotron command set
```

- No HuggingFace token is needed for public datasets. If you have one, drop it in
  `~/.env.hugging` as `HF_TOKEN=...` and the scripts pick it up automatically (optional).
- `corpus_recall.py` defines the danger regex (`DANGER_RX`) and the labeling used for recall;
  read it to see exactly what counts as "dangerous" — the number is only as honest as that label,
  and the label is right here in the open.

## What these are NOT

Not the test suite (`pytest`; 892 green in CI as of v0.4.1 — see FACTS.md F3) and not the bypass suite
(`python -m gatecat.integrations.bypass_suite`, which prints its own known gaps). Those run with
zero extra dependencies. These corpus scripts exist purely so the recall claim is checkable by a
skeptic, not taken on faith.
