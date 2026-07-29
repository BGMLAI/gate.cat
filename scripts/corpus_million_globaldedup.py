"""Przeliczenie korpusu recall z GLOBALNA deduplikacja.

Powod: results/million_recall_2026-07-08.json sumuje `unique` PER DATASET,
a repo nvidia/SWE-Hero-openhands-trajectories wystepuje w tej liscie DWA RAZY
(250000 + 300000 = 550000 z naglowkowych 1 085 159). Do tego dedup byl robiony
wewnatrz zbioru, wiec powtorzenia MIEDZY zbiorami tez nie sa odjete.

Ten skrypt: jeden wspolny set() na wszystkie zbiory, kazde repo raz.
Budzet unikalnych per repo = ten sam co w oryginale (zeby porownanie bylo
apples-to-apples), SWE-Hero dostaje jeden budzet (wiekszy z dwoch: 300000).

Wynik: ile NAPRAWDE jest unikalnych komend + ile z nich to zagrozenia wg
niezaleznego katalogu + ile bramka neutralizuje.
"""
from __future__ import annotations
import json, os, sys, time, signal

OUT = "/tmp/claude-1000/-home-bgml-bgml-ai/177e4a39-282a-40cd-9b63-9b3f60311764/scratchpad/recalc_result.json"
CKPT = "/tmp/claude-1000/-home-bgml-bgml-ai/177e4a39-282a-40cd-9b63-9b3f60311764/scratchpad/recalc_ckpt.json"

sys.path.insert(0, "/home/bgml/gate.cat/scripts")
sys.path.insert(0, "/home/bgml/gate.cat")

from corpus_recall import danger_hits, walk  # noqa: E402
from gatecat.action_pipeline import ActionPipeline  # noqa: E402
from gatecat.integrations.action_analysis import DeletePolicy  # noqa: E402
from datasets import load_dataset  # noqa: E402

_PIPE = ActionPipeline(policy=DeletePolicy(), home="/root", cwd="/workspace/repo")

# (repo, split, budzet unikalnych) — DOKLADNIE te repo co w oryginalnym JSON,
# ale SWE-Hero RAZ (budzet = wiekszy z dwoch wpisow: 300000)
DATASETS = [
    ("nvidia/Nemotron-RL-Agentic-SWE-Pivot-v1", "train", 20000),
    ("nvidia/SWE-Zero-openhands-trajectories", "train", 300000),
    ("nvidia/SWE-Hero-openhands-trajectories", "train", 300000),
    ("Kwai-Klear/SWE-smith-mini_swe_agent_plus-trajectories-66k", "train", 200000),
    ("SWE-Gym/OpenHands-Sampled-Trajectories", "train", 8476),
    ("SWE-Gym/OpenHands-SFT-Trajectories", "train", 8),
    ("nebius/SWE-agent-trajectories", "train", 6675),
]

seen: set[str] = set()          # GLOBALNY dedup
per_repo_new: dict[str, int] = {}   # ile NOWYCH unikalnych wniosl kazdy repo
per_repo_seen_before: dict[str, int] = {}  # ile juz bylo (overlap miedzy zbiorami)
dangers: dict[str, str] = {}    # cmd -> klasa
neutralized = 0
passed_cmds: list[dict] = []
errors = 0
t0 = time.time()
_stop = False


def _sig(*_a):
    global _stop
    _stop = True


signal.signal(signal.SIGTERM, _sig)
signal.signal(signal.SIGINT, _sig)


def evaluate(cmd: str):
    try:
        v = _PIPE.check(cmd)
        return v.level
    except Exception:
        return "block"  # fail-closed, jak w oryginale


def snapshot(done_repos):
    return {
        "unique_global": len(seen),
        "per_repo_new": per_repo_new,
        "per_repo_overlap_skipped": per_repo_seen_before,
        "dangers": len(dangers),
        "neutralized": neutralized,
        "passed": len(passed_cmds),
        "errors": errors,
        "repos_done": done_repos,
        "elapsed_s": round(time.time() - t0, 1),
    }


done = []
for repo, split, budget in DATASETS:
    if _stop:
        break
    print(f"\n### {repo} (budzet {budget} nowych unikalnych; globalnie mam {len(seen)})", flush=True)
    added = 0
    dup_skipped = 0
    try:
        ds = load_dataset(repo, split=split, streaming=True)
        for rec in ds:
            if _stop or added >= budget:
                break
            for cmd in walk(rec):
                if not cmd:
                    continue
                c = cmd.strip()
                if not c:
                    continue
                if c in seen:
                    dup_skipped += 1
                    continue
                seen.add(c)
                added += 1
                hits = danger_hits(c)
                if hits:
                    dangers[c] = hits[0] if isinstance(hits, (list, tuple)) else str(hits)
                    lvl = evaluate(c)
                    if lvl in ("block", "warn"):
                        globals()['neutralized'] = neutralized + 1
                    else:
                        passed_cmds.append({"cmd": c[:400], "class": dangers[c], "level": lvl})
                if added % 20000 == 0:
                    print(f"  +{added} nowych | globalnie {len(seen)} | pominietych duplikatow {dup_skipped} "
                          f"| dangers {len(dangers)} | passed {len(passed_cmds)} | {round(time.time()-t0)}s", flush=True)
                    json.dump(snapshot(done), open(CKPT, "w"), indent=1)
                if added >= budget:
                    break
    except Exception as e:
        print(f"  BLAD na {repo}: {type(e).__name__}: {str(e)[:200]}", flush=True)
        errors += 1
    per_repo_new[repo] = added
    per_repo_seen_before[repo] = dup_skipped
    done.append(repo)
    print(f"  KONIEC {repo}: +{added} nowych, {dup_skipped} duplikatow pominietych, globalnie {len(seen)}", flush=True)
    json.dump(snapshot(done), open(CKPT, "w"), indent=1)

res = snapshot(done)
res["passed_samples"] = passed_cmds[:50]
res["naglowek_stary"] = 1085159
res["roznica_vs_stary"] = 1085159 - len(seen)
res["uwaga"] = ("Stary naglowek sumowal `unique` per dataset i liczyl "
                "nvidia/SWE-Hero-openhands-trajectories DWA RAZY (250000+300000). "
                "Tutaj: jeden globalny set, kazde repo raz.")
json.dump(res, open(OUT, "w"), indent=1)
print("\n=== WYNIK ===")
print(json.dumps({k: v for k, v in res.items() if k != "passed_samples"}, indent=1))
