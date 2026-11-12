"""Verify completion and common input hashes for all final held-out pairs."""
from pathlib import Path
import hashlib, json
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "results/post_seminar_phase2/baseline_regenerated/traces/urban_roundabout"
OUT = ROOT / "results/post_seminar_phase6_final"
PILOTS = [ROOT / "results/post_seminar_phase6/pilot",
          ROOT / "results/post_seminar_phase6_holdout/pilot", OUT / "pilot"]
def sha(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024), b""): h.update(chunk)
    return h.hexdigest()
def candidate(d,s):
    for root in PILOTS:
        p=root/f"vehicles_{d}/seed_{s}"
        if (p/"C1_placement_B0_decisions.csv").is_file(): return p
    raise FileNotFoundError((d,s))
rows=[]
for d in (20,40,60,80,100):
  for s in (1007,1008,1009,1010):
    b=BASE/f"vehicles_{d}/seed_{s}"; c=candidate(d,s)
    run=json.loads((c/"run_summary.json").read_text(encoding="utf-8"))
    assert run.get("completed") is True, (d,s,"incomplete")
    hashes={name:{"baseline":sha(b/name),"candidate":sha(c/name)} for name in
            ("mobility_trace.csv","generated_messages.csv","attack_ground_truth.csv")}
    assert all(x["baseline"]==x["candidate"] for x in hashes.values()), (d,s,hashes)
    m=json.loads((c/"scenario_manifest.json").read_text(encoding="utf-8"))
    assert m["seed"]==s, (d,s,m.get("seed"))
    assert int(run["case_count"])>0
    rows.append({"density":d,"seed":s,"baseline_dir":str(b.relative_to(ROOT)),"candidate_dir":str(c.relative_to(ROOT)),
      "completed":True,"case_count":run["case_count"],"hashes":hashes,
      "candidate_scenario_manifest_sha256":sha(c/"scenario_manifest.json")})
comparison=pd.read_csv(OUT/"final_paired_comparison.csv")
assert len(comparison)==20 and set(zip(comparison.density,comparison.seed))=={(d,s) for d in (20,40,60,80,100) for s in (1007,1008,1009,1010)}
assert comparison.ground_truth_opportunities.gt(0).all()
(OUT/"paired_input_manifest.json").write_text(json.dumps({"cell_count":len(rows),"same_mobility_messages_and_attack_truth":True,"cells":rows},indent=2),encoding="utf-8")
print(f"verified {len(rows)} paired cells; completion markers and mobility/message/ground-truth hashes match")
