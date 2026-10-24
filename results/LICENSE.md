# Licence for the artifacts in `results/`

The `million_recall_*.json` artifacts in this directory are **Corpus Materials**
under the [gate.cat Corpus & Benchmark Licence v1.0](../LICENSE-CORPUS), in
effect from 2026-07-31. They are **not** Apache-2.0.

You may read them, re-run the harness that produced them, and publish results
that contradict ours — free, no registration, no notice to us required
(licence §3). You need a commercial licence to redistribute them, include them
in another benchmark, train a model on them, or publish your own product's
safety figures measured against them (licence §4): bogumil@bgml.ai.

Versions of these files published before 2026-07-31 went out under Apache-2.0
and keep those rights (licence §5).

**Not covered by that licence:** the underlying third-party datasets these
artifacts were derived from, each of which carries its own upstream licence.
Provenance — dataset repo ids, split names, measurement dates — is in
[RECALL.md](../RECALL.md) and in each artifact header.

`million_recall_2026-07-08.json` is retained as the **historical record** and is
superseded: its 1,085,159 header double-counted a dataset and overstated the
corpus by 23.8%. The current figure is 826,644 (range 826,644–835,128) from
`million_recall_2026-07-28.json`. See FACTS.md F1b. Do not quote the old number
outside a dated historical context.
