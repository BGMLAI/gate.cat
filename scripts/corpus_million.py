"""Million-command recall run. Streams MANY datasets, dedups to a target of
~1,000,000 UNIQUE real agent commands, runs each through the gate, and reports
the ONE metric that matters (REJESTR_PRAWD): % of dangers NEUTRALIZED.

Design for scale + safety of the run itself:
  - streaming (no big files on disk; VPS has ~24GB free)
  - checkpoint every N commands to a JSON so an ssh drop never loses progress
  - the danger catalog is INDEPENDENT of the gate's policies (a match that the
    gate ALLOWs is a recall MISS - the fatal error we hunt)
  - every danger that PASSES is recorded in full (with per-stage trace) so each
    one can be read and either fixed (real miss) or dismissed (catalog false hit)
"""
from __future__ import annotations
import json, os, re, sys, glob
from collections import Counter

os.environ.setdefault("GATECAT_VETO_EPHEMERAL", "0")
# FULL GATE: the 6-mechanism ActionPipeline (allow-list -> koryto[deny-walls +
# delete-analyzer] -> gate -> stagnation -> arbiter -> human), NOT the flat
# check_action (which only runs 3 of the layers). This is what the product
# actually is; the run must measure it.
from gatecat.action_pipeline import ActionPipeline
from gatecat.integrations.action_analysis import DeletePolicy

_PIPE = ActionPipeline(policy=DeletePolicy(), home="/root", cwd="/workspace/repo")

# Optional: read an HF token from ~/.env.hugging if present (public datasets need none).
_env_hf = os.path.expanduser("~/.env.hugging")
if os.path.exists(_env_hf):
    for line in open(_env_hf):
        line = line.strip()
        if line.startswith(("HF_TOKEN=", "HUGGING_FACE_HUB_TOKEN=")):
            os.environ["HF_TOKEN"] = line.split("=", 1)[1].strip().strip('"').strip("'")
from datasets import load_dataset

# reuse the catalog + extractor from corpus_recall (same dir on the VPS)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from corpus_recall import DANGER_RX, danger_hits, walk  # noqa: E402

TARGET = int(os.environ.get("MILLION_TARGET", "1000000"))
CKPT = "/opt/gatecat-test/million_checkpoint.json"

# datasets to stream, in order, until we hit TARGET unique commands. Ordered by
# richness (commands/record) so we reach a million fastest.
DATASETS = [
    ("nvidia/SWE-Zero-openhands-trajectories", None, "train"),
    ("nvidia/Nemotron-RL-Agentic-SWE-Pivot-v1", None, "train"),
    ("SWE-bench/SWE-smith-trajectories", None, "ticks"),
    ("nebius/SWE-agent-trajectories", None, "train"),
]


def evaluate_cmd(cmd, cwd="/workspace/repo", home="/root"):
    try:
        v = _PIPE.check(cmd)                 # runs ALL six mechanisms
        return v.level, v.stages
    except Exception as e:
        # fail-closed: an error in the pipeline is a block, never a silent allow
        return "block", [{"stage": "error", "error": f"{type(e).__name__}: {e}"}]
    except Exception as e:
        return "error", [["error", "error", str(e)[:120]]]


def main():
    seen = set()
    levels = Counter()
    danger_levels = Counter()
    passed = []          # dangers the gate ALLOWED (recall misses to inspect)
    errors = []
    n_eval = 0

    passed_by_class = Counter()   # every passed danger, counted per class

    def checkpoint():
        dangers = sum(danger_levels.values())
        neut = danger_levels["block"] + danger_levels["warn"]
        pct = (100.0 * neut / dangers) if dangers else 100.0
        json.dump({
            "evaluated": n_eval, "unique": len(seen),
            "levels": dict(levels), "danger_levels": dict(danger_levels),
            "dangers": dangers, "neutralized": neut, "passed": len(passed),
            "neutralized_pct": round(pct, 3),
            "passed_by_class": dict(passed_by_class),   # full breakdown, no cap
            "passed_samples": passed[:400], "errors": errors[:100],
        }, open(CKPT, "w"), indent=2)

    for repo, config, split in DATASETS:
        if len(seen) >= TARGET:
            break
        print(f"\n### streaming {repo} (have {len(seen)}/{TARGET})", flush=True)
        try:
            ds = load_dataset(repo, config, split=split, streaming=True,
                              token=os.environ.get("HF_TOKEN"))
        except Exception as e:
            print(f"  LOAD ERR: {str(e)[:100]}")
            continue
        for rec in ds:
            for c in walk(rec):
                c = c.strip()
                if not c or len(c) >= 20000 or c in seen:
                    continue
                seen.add(c)
                lvl, stages = evaluate_cmd(c)
                n_eval += 1
                levels[lvl] += 1
                hits = danger_hits(c)
                if hits:
                    danger_levels[lvl] += 1
                    if lvl == "allow":
                        for h in hits:
                            passed_by_class[h] += 1
                        if len(passed) < 400:
                            passed.append({"cmd": c[:400], "danger": hits, "stages": stages})
                if lvl == "error":
                    errors.append({"cmd": c[:200]})
                if n_eval % 20000 == 0:
                    checkpoint()
                    d = sum(danger_levels.values())
                    nt = danger_levels["block"] + danger_levels["warn"]
                    pc = (100.0 * nt / d) if d else 100.0
                    print(f"  {n_eval} eval | dangers {d} neutralized {nt} "
                          f"({pc:.2f}%) passed {len(passed)} err {levels['error']}",
                          flush=True)
                if len(seen) >= TARGET:
                    break
            if len(seen) >= TARGET:
                break

    checkpoint()
    dangers = sum(danger_levels.values())
    neut = danger_levels["block"] + danger_levels["warn"]
    pct = (100.0 * neut / dangers) if dangers else 100.0
    print("\n" + "#" * 64)
    print(f"#  UNIESZKODLIWILISMY {pct:.3f}% ZAGROZEN")
    print(f"#  ({neut} z {dangers} zagrozen | PRZEPUSZCZONYCH: {len(passed)})")
    print(f"#  na {len(seen)} unikalnych komendach | crashy: {levels['error']}")
    print("#" * 64, flush=True)
    if passed:
        print(f"\nPRZEPUSZCZONE (do weryfikacji - real miss vs falszywy alarm katalogu):")
        for p in passed[:20]:
            print(f"  {p['danger']} :: {p['cmd'][:90]}")


if __name__ == "__main__":
    main()
