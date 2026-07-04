#!/usr/bin/env python3
"""Read ~/.cacheback/veto_log.jsonl and report the false-block rate.

This is the headline dogfooding metric (VETO_PIPELINE_PLAN.md B2): of everything
the gate BLOCKED, how many were false alarms you'd have wanted to run? A guardrail
that cries wolf gets uninstalled after the first bad block, so this number gates
any outreach — collect N>=30 blocks, adjudicate, publish honestly.

Usage:
    python false_block_rate.py                 # summarize the log
    python false_block_rate.py --adjudicate    # interactively mark each block real/false

Adjudication writes a sibling file veto_log.adjudicated.jsonl so you never lose
your rulings and can re-run the summary any time.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

LOG = Path(os.environ.get("CACHEBACK_VETO_LOG", str(Path.home() / ".cacheback" / "veto_log.jsonl")))
ADJ = LOG.with_suffix(".adjudicated.jsonl")


def load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def summarize() -> None:
    records = load(LOG)
    blocks = [r for r in records if r.get("decision") == "block"]
    allows = [r for r in records if r.get("decision") == "allow"]
    shadow = [r for r in records if r.get("decision") == "shadow_block"]
    adj = {(_key(r)): r.get("verdict") for r in load(ADJ)}

    ruled = [r for r in blocks if _key(r) in adj]
    false_blocks = [r for r in ruled if adj[_key(r)] == "false"]
    real_blocks = [r for r in ruled if adj[_key(r)] == "real"]

    print(f"log: {LOG}")
    print(f"  decisions total : {len(records)}")
    print(f"  allows          : {len(allows)}")
    print(f"  blocks          : {len(blocks)}")
    print(f"  shadow_blocks   : {len(shadow)}")
    print(f"  blocks adjudicated: {len(ruled)}  (real={len(real_blocks)} false={len(false_blocks)})")
    if ruled:
        rate = len(false_blocks) / len(ruled)
        print(f"  FALSE-BLOCK RATE : {rate:.1%}  (N={len(ruled)})")
        if len(ruled) < 30:
            print(f"  -> collect {30 - len(ruled)} more adjudicated blocks before publishing (plan: N>=30).")
    else:
        print("  FALSE-BLOCK RATE : n/a — run with --adjudicate to rule on each block.")
    # which policies fire most (where to tune)
    by_policy: dict[str, int] = {}
    for r in blocks:
        by_policy[r.get("policy") or "?"] = by_policy.get(r.get("policy") or "?", 0) + 1
    if by_policy:
        print("  blocks by policy:", ", ".join(f"{k}={v}" for k, v in sorted(by_policy.items(), key=lambda x: -x[1])))


def _key(r: dict) -> str:
    return f"{r.get('ts')}|{r.get('context','')[:80]}"


def adjudicate() -> None:
    blocks = [r for r in load(LOG) if r.get("decision") == "block"]
    already = {_key(r) for r in load(ADJ)}
    todo = [r for r in blocks if _key(r) not in already]
    if not todo:
        print("Nothing new to adjudicate. Run without --adjudicate for the summary.")
        return
    print(f"{len(todo)} un-ruled block(s). For each: [r]eal (should block), [f]alse (wrongly blocked), [s]kip, [q]uit.\n")
    with ADJ.open("a", encoding="utf-8") as fh:
        for r in todo:
            print(f"  policy={r.get('policy')}  context={r.get('context','')[:100]}")
            ans = input("  real/false/skip/quit [r/f/s/q]: ").strip().lower()
            if ans in ("q", "quit"):
                break
            if ans in ("s", "skip", ""):
                continue
            verdict = "real" if ans in ("r", "real") else "false"
            fh.write(json.dumps({**r, "verdict": verdict}) + "\n")
            fh.flush()
    print("\nDone. Re-run without --adjudicate for the updated false-block rate.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--adjudicate", action="store_true", help="interactively rule on each block")
    args = ap.parse_args()
    if args.adjudicate:
        adjudicate()
    else:
        summarize()
