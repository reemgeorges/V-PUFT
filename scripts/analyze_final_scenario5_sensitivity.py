from __future__ import annotations

import hashlib, json, math, shutil, sys
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from scripts.sensitivity_opportunities import build_base_emission_times, evaluate_attack_opportunities

PILOT = ROOT / "results/final_scenario5_sensitivity/pilot_2026-11-16"
RESULTS = ROOT / "results/final_scenario5_sensitivity"
DOCS = ROOT / "docs/final_scenario5_sensitivity"
WINDOW = 15.0
FROZEN = json.loads((PILOT / "FROZEN_INPUT_HASHES.json").read_text(encoding="utf-8"))

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def div(a, b):
    return float(a / b) if b else 0.0

def confusion(tp, fp, tn, fn):
    p, r, frr = div(tp,tp+fp), div(tp,tp+fn), div(fp,fp+tn)
    f1 = div(2*p*r,p+r)
    den = math.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
    return p,r,frr,f1,div(tp*tn-fp*fn,den)

def main():
    DOCS.mkdir(parents=True, exist_ok=True)
    figdir = DOCS / "figures"
    figdir.mkdir(parents=True, exist_ok=True)
    m = pd.read_csv(PILOT / "SENSITIVITY_METRICS_BY_SEED.csv")
    d = pd.read_csv(PILOT / "SENSITIVITY_CASE_DECISIONS.csv")
    manifest = pd.read_csv(PILOT / "SENSITIVITY_RUN_MANIFEST.csv")
    if len(m) != 64 or len(manifest) != 64 or not manifest.status.eq("completed").all():
        raise RuntimeError("Pilot is not 64/64 successful")
    if m.duplicated(["variant_id","density","seed","architecture"]).any():
        raise RuntimeError("Duplicate metrics cells")
    if d.duplicated(["variant_id","density","seed","architecture","case_id"]).any():
        raise RuntimeError("Duplicate case decisions")
    if set(m.trace_sha256) != set(manifest.trace_sha256):
        raise RuntimeError("Metric and manifest trace hashes differ")

    from vpuft.state_aware_evaluation import state_aware_first_revocation_metrics
    for key, g in d.groupby(["variant_id","density","seed","architecture"], dropna=False):
        inp = g[["case_id","vehicle_id","seed","architecture","ground_truth_malicious",
                 "committed","new_state"]].copy()
        mb = state_aware_first_revocation_metrics(inp, window_seconds=WINDOW)
        mm = m[(m.variant_id==key[0])&(m.density==key[1])&(m.seed==key[2])&(m.architecture==key[3])]
        if len(mb)!=1 or len(mm)!=1:
            raise RuntimeError(f"Method B grouping mismatch: {key}")
        for col in ["TP","FP","TN","FN"]:
            if int(mb.iloc[0][col]) != int(mm.iloc[0][col]):
                raise RuntimeError(f"Method B mismatch {key} {col}")
        if int(mb.iloc[0].excluded_post_revocation_windows) != int(mm.iloc[0].excluded_post_revocation_cases):
            raise RuntimeError(f"Method B exclusions mismatch {key}")

    # Verify case universes do not change across QE/transport configurations.
    universe = d.groupby(["density","seed","architecture","variant_id"]).case_id.apply(set)
    for density in [20,100]:
        for seed in [7001,7002]:
            for arch in ["C100","Distributed"]:
                sets = universe.loc[(density,seed,arch)]
                ref = sets.iloc[0]
                if any(x != ref for x in sets):
                    raise RuntimeError(f"Case universe changed: {density}/{seed}/{arch}")

    # Fixed denominator: one unique malicious message emitted by the SUMO attack injector.
    opportunities = []
    trace_manifest = json.loads((PILOT / "SENSITIVITY_TRACE_MANIFEST.json").read_text(encoding="utf-8"))
    for tr in trace_manifest["traces"]:
        density, seed = int(tr["density"]), int(tr["seed"])
        td = PILOT / "shared_inputs/traces" / f"density_{density}" / f"seed_{seed}"
        generated = pd.read_csv(td / "generated_messages.csv")
        attacks = generated[generated.ground_truth_malicious.astype(str).str.lower().isin(["true","1"])]
        mobility = pd.read_csv(td / "mobility_trace.csv")
        base_emission_time = build_base_emission_times(
            mobility.to_dict("records"), seed=seed)
        events = pd.read_json(td / "shared_detection_trace.jsonl", lines=True)
        dm = d[(d.density==density)&(d.seed==seed)]
        for (variant,arch), g in dm.groupby(["variant_id","architecture"]):
            summary = evaluate_attack_opportunities(
                attacks.to_dict("records"), events.to_dict("records"),
                g.to_dict("records"), base_emission_time, seed=seed,
                window_seconds=WINDOW)
            opportunities.append({
                "variant_id":variant,"factor":str(g.iloc[0].factor),"level":str(g.iloc[0].level),
                "density":density,"seed":seed,"architecture":arch,
                **summary,"trace_sha256":tr["trace_sha256"],
                "definition":"Unique emitted malicious V2X message ID; observed if any detection event contains the ID; detected if observed and its mapped 15-second case commits revocation; protected if first vehicle revocation finalized strictly before message emission."
            })
    op=pd.DataFrame(opportunities)
    if op.duplicated(["variant_id","density","seed","architecture"]).any():
        raise RuntimeError("Duplicate opportunity summary")
    for key,g in op.groupby(["density","seed"]):
        if g.attack_message_opportunities.nunique()!=1:
            raise RuntimeError(f"Fixed denominator changed: {key}")

    # Preserve, but do not use, the first zero-result table produced by a case-prefix mismatch.
    old=PILOT/"SENSITIVITY_FIXED_OPPORTUNITIES.csv"
    audit=PILOT/"SENSITIVITY_FIXED_OPPORTUNITIES_INITIAL_ZERO_BUG.csv"
    if old.exists() and not audit.exists():
        shutil.copy2(old,audit)
    op.to_csv(PILOT/"SENSITIVITY_FIXED_OPPORTUNITIES_CORRECTED.csv",index=False)

    m=m.merge(op[["variant_id","density","seed","architecture","attack_message_opportunities",
                  "observed_attack_messages","unobserved_attack_messages",
                  "successfully_detected_attack_messages","opportunity_detection_recall",
                  "protected_attack_messages","protected_opportunity_fraction"]],
              on=["variant_id","density","seed","architecture"],validate="one_to_one")
    m.to_csv(RESULTS/"SENSITIVITY_METRICS_BY_SEED.csv",index=False)
    op.to_csv(RESULTS/"SENSITIVITY_FIXED_OPPORTUNITIES.csv",index=False)
    manifest.to_csv(RESULTS/"SENSITIVITY_RUN_MANIFEST.csv",index=False)
    shutil.copy2(PILOT/"SENSITIVITY_EFFECTIVE_CONFIGS.json",RESULTS/"SENSITIVITY_EFFECTIVE_CONFIGS.json")
    shutil.copy2(PILOT/"FROZEN_INPUT_HASHES.json",RESULTS/"SENSITIVITY_FROZEN_INPUT_HASHES.json")

    for rel, expected in FROZEN["sha256"].items():
        if sha(ROOT/rel)!=expected:
            raise RuntimeError(f"Frozen hash changed: {rel}")

    base=m[m.variant_id=="baseline"].set_index(["architecture","density","seed"])
    drec=[]; drows=[]
    for x in m.to_dict("records"):
        b=base.loc[(x["architecture"],x["density"],x["seed"])]
        y=dict(x)
        for col in ["malicious_revocation_recall","TP","FP","FN","false_revocation_rate",
                    "cpu_time_seconds","latency_p95_ms","messages_per_decision",
                    "packet_delivery_ratio","ledger_consistency_delay_p95_ms",
                    "opportunity_detection_recall","protected_opportunity_fraction"]:
            y["delta_"+col]=float(x[col])-float(b[col])
        drows.append(y)
    paired=pd.DataFrame(drows)

    rows=[]
    grp=["factor","level","variant_id","density","architecture"]
    for key,g in paired.groupby(grp,dropna=False):
        tp,fp,tn,fn=(int(g[c].sum()) for c in ["TP","FP","TN","FN"])
        p,r,frr,f1,mcc=confusion(tp,fp,tn,fn)
        dr=g.delta_malicious_revocation_recall.astype(float)
        dcpu=100*g.delta_cpu_time_seconds.astype(float)/g.cpu_time_seconds.astype(float).replace(0,np.nan)
        de2e=100*g.delta_latency_p95_ms.astype(float)/g.latency_p95_ms.astype(float).replace(0,np.nan)
        dmsg=100*g.delta_messages_per_decision.astype(float)/g.messages_per_decision.astype(float).replace(0,np.nan)
        rows.append({
            **dict(zip(grp,key)),"seed_n":g.seed.nunique(),
            "pooled_TP":tp,"pooled_FP":fp,"pooled_TN":tn,"pooled_FN":fn,
            "precision_pooled":p,"recall_pooled":r,"FRR_pooled":frr,"F1_pooled":f1,"MCC_pooled":mcc,
            "recall_macro_seed_mean":g.malicious_revocation_recall.mean(),
            "precision_seed_mean":g.trust_precision.mean(),"FRR_seed_mean":g.false_revocation_rate.mean(),
            "F1_seed_mean":g.trust_f1.mean(),"MCC_seed_mean":g.mcc.mean(),
            "excluded_terminal_mean":g.excluded_post_revocation_cases.mean(),
            "opportunity_recall_mean":g.opportunity_detection_recall.mean(),
            "protected_fraction_mean":g.protected_opportunity_fraction.mean(),
            "attack_messages_per_seed_mean":g.attack_message_opportunities.mean(),
            "observed_attack_messages_mean":g.observed_attack_messages.mean(),
            "cpu_mean_seconds":g.cpu_time_seconds.mean(),"cpu_delta_seconds_mean":g.delta_cpu_time_seconds.mean(),
            "cpu_delta_percent_mean":dcpu.mean(),"p95_e2e_mean_ms":g.latency_p95_ms.mean(),
            "p95_e2e_delta_ms_mean":g.delta_latency_p95_ms.mean(),"p95_e2e_delta_percent_mean":de2e.mean(),
            "messages_per_case_mean":g.messages_per_decision.mean(),
            "messages_delta_mean":g.delta_messages_per_decision.mean(),"messages_delta_percent_mean":dmsg.mean(),
            "PDR_mean":g.packet_delivery_ratio.mean(),
            "ledger_delay_p95_mean_ms":g.ledger_consistency_delay_p95_ms.mean(),
            "ledger_delay_delta_mean_ms":g.delta_ledger_consistency_delay_p95_ms.mean(),
            "paired_delta_recall_mean":dr.mean(),"paired_delta_recall_median":dr.median(),
            "paired_delta_recall_min":dr.min(),"paired_delta_recall_max":dr.max(),
            "recall_improved":int((dr>1e-12).sum()),"recall_unchanged":int((dr.abs()<=1e-12).sum()),
            "recall_worsened":int((dr< -1e-12).sum()),
            "paired_delta_TP_sum":int(g.delta_TP.sum()),"paired_delta_FP_sum":int(g.delta_FP.sum()),
            "paired_delta_FN_sum":int(g.delta_FN.sum()),
            "paired_delta_FRR_mean":g.delta_false_revocation_rate.mean()
        })
    agg=pd.DataFrame(rows)
    agg.to_csv(RESULTS/"SENSITIVITY_AGGREGATED_RESULTS.csv",index=False)

    factors=[
        ("freshness_window_seconds",["baseline","freshness_12s","freshness_30s"],["baseline","12s","30s"]),
        ("position_offset.required_sources",["baseline","position_sources_1","position_sources_3"],["baseline","1 source","3 sources"]),
        ("packet_delivery_ratio",["baseline","pdr_0.95","pdr_1.00"],["baseline","0.95","1.00"]),
        ("C100_backhaul_ms",["baseline","c100_backhaul_20ms","c100_backhaul_200ms"],["baseline","20ms","200ms"]),
    ]
    for metric, name, title, ylabel in [
        ("malicious_revocation_recall","SENSITIVITY_STATE_AWARE_RECALL.png","Scenario 5 pilot: state-aware Method B Recall","Recall"),
        ("false_revocation_rate","SENSITIVITY_FRR.png","Scenario 5 pilot: state-aware FRR","FRR"),
        ("latency_p95_ms","SENSITIVITY_P95_E2E.png","Scenario 5 pilot: P95 E2E latency","P95 E2E (ms)"),
        ("messages_per_decision","SENSITIVITY_MESSAGES_PER_CASE.png","Scenario 5 pilot: messages per case","Messages per case"),
        ("cpu_time_seconds","SENSITIVITY_CPU_TIME.png","Scenario 5 pilot: host CPU per architecture run","CPU seconds"),
    ]:
        fig,axes=plt.subplots(2,4,figsize=(18,8),sharey="row")
        for ri,density in enumerate([20,100]):
            for ci,(factor,ids,labs) in enumerate(factors):
                ax=axes[ri,ci]
                archs=["C100"] if factor=="C100_backhaul_ms" else ["C100","Distributed"]
                for arch in archs:
                    vals=[]
                    for vid in ids:
                        g=m[(m.variant_id==vid)&(m.density==density)&(m.architecture==arch)]
                        vals.append(float(g[metric].mean()) if len(g) else np.nan)
                    ax.plot(range(len(ids)),vals,marker="o",label=arch)
                ax.set_xticks(range(len(ids)),labs,rotation=20)
                ax.set_title(f"{factor}\\ndensity {density}")
                ax.grid(alpha=.25)
                if ci==0: ax.set_ylabel(ylabel)
                if ri==0 and ci==0: ax.legend()
        fig.suptitle(title+" (mean of two seeds; descriptive)",fontsize=14)
        fig.tight_layout(rect=(0,0,1,.94))
        fig.savefig(figdir/name,dpi=300,bbox_inches="tight")
        plt.close(fig)

    stat=[
        "# Sensitivity pilot statistical analysis","",
        "Seed-level runs are the units of replication. Each density has two paired seeds; the values below are descriptive paired differences, not significance tests. No confidence interval or p-value is claimed from n=2 per density.","",
        "| Factor | Level | Architecture | Density | n | Mean dRecall | Median | Improved/same/worse | Seed deltas | Range |",
        "|---|---|---|---:|---:|---:|---:|---|---|---|"
    ]
    for _,x in agg.iterrows():
        g=paired[(paired.variant_id==x.variant_id)&(paired.density==x.density)&(paired.architecture==x.architecture)]
        ds=", ".join(f"{z:+.4f}" for z in g.delta_malicious_revocation_recall.tolist())
        stat.append(f"| {x.factor} | {x.level} | {x.architecture} | {int(x.density)} | {int(x.seed_n)} | {x.paired_delta_recall_mean:+.4f} | {x.paired_delta_recall_median:+.4f} | {int(x.recall_improved)}/{int(x.recall_unchanged)}/{int(x.recall_worsened)} | {ds} | [{x.paired_delta_recall_min:+.4f}, {x.paired_delta_recall_max:+.4f}] |")
    (DOCS/"SENSITIVITY_STATISTICAL_ANALYSIS.md").write_text("\n".join(stat)+"\n",encoding="utf-8")

    # Arabic narrative documents are maintained as separately verified UTF-8 files.

    print(json.dumps({
        "runs":len(m),"decisions":len(d),"opportunity_rows":len(op),
        "aggregate_rows":len(agg),"frozen_hashes_verified":len(FROZEN["sha256"]),
        "zero_detection_baseline_rows":int((op[op.variant_id=="baseline"].successfully_detected_attack_messages==0).sum()),
        "opportunity_baseline":[
            {"architecture": str(k[0]), "density": int(k[1]), **v}
            for k,v in op[op.variant_id=="baseline"].groupby(["architecture","density"])[["attack_message_opportunities","observed_attack_messages","successfully_detected_attack_messages","protected_attack_messages"]].mean().round(3).to_dict(orient="index").items()
        ],
    },indent=2))

if __name__=="__main__":
    main()
