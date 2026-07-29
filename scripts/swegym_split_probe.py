import sys, json
sys.path.insert(0,"/home/bgml/gate.cat/scripts"); sys.path.insert(0,"/home/bgml/gate.cat")
from corpus_recall import danger_hits, walk
from datasets import load_dataset
out={}
for repo, split in [("SWE-Gym/OpenHands-Sampled-Trajectories","train.raw"),
                    ("SWE-Gym/OpenHands-SFT-Trajectories","train.success.oss")]:
    s=set(); dup=0; dang=0; recs=0
    try:
        ds=load_dataset(repo, split=split, streaming=True)
        for rec in ds:
            recs+=1
            for c in walk(rec):
                c=(c or "").strip()
                if not c: continue
                if c in s: dup+=1; continue
                s.add(c)
                if danger_hits(c): dang+=1
            if recs>=20000: break
    except Exception as e:
        out[repo]={"blad":f"{type(e).__name__}: {str(e)[:150]}"}; continue
    out[repo]={"split":split,"rekordow":recs,"unikalnych_komend":len(s),"duplikatow":dup,"dangers":dang}
    print(repo, "->", out[repo], flush=True)
json.dump(out, open("/tmp/claude-1000/-home-bgml-bgml-ai/177e4a39-282a-40cd-9b63-9b3f60311764/scratchpad/swegym_probe.json","w"), indent=1)
print("GOTOWE")
