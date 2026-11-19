#!/usr/bin/env python3
"""Independent semantic checks for the corrected-final Scenario 5 Method B chapter."""
from __future__ import annotations
import csv, hashlib, json, math, re, zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "docs/final_chapter5/corrected_final_dataset_b"
DATA = ROOT / "results/urban_roundabout_campaign_corrected_final"
PKG = ROOT / "docs/final_scenario5_evidence_package/METHOD_B_CORRECTED_FINAL"
ARCHS = {
    "centralized_remote_0ms_control": "C0",
    "centralized_remote_100ms": "C100",
    "distributed_density_honest": "Distributed",
}
DENSITIES = [20, 40, 60, 80, 100]
SEEDS = list(range(1001, 1011))

def ival(value):
    return int(float(value))

def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def read_csv(path: Path):
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))

def calc(rows):
    e=[r for r in rows if r["reason"]!="already_revoked_terminal_state"]
    y=[ival(r["ground_truth_malicious"])==1 for r in e]
    pred=[ival(r["committed"])==1 and r["new_state"]=="revoked" for r in e]
    tp=sum(a and b for a,b in zip(y,pred)); fp=sum((not a) and b for a,b in zip(y,pred))
    tn=sum((not a) and (not b) for a,b in zip(y,pred)); fn=sum(a and (not b) for a,b in zip(y,pred))
    div=lambda a,b:a/b if b else 0.0
    precision=div(tp,tp+fp); recall=div(tp,tp+fn); frr=div(fp,fp+tn)
    f1=div(2*precision*recall,precision+recall)
    den=(tp+fp)*(tp+fn)*(tn+fp)*(tn+fn)
    mcc=(tp*tn-fp*fn)/math.sqrt(den) if den else 0.0
    return {"TP":tp,"FP":fp,"TN":tn,"FN":fn,"eligible":len(e),"excluded":len(rows)-len(e),
            "precision":precision,"recall":recall,"FRR":frr,"F1":f1,"MCC":mcc}

def md_tables(text):
    tables=[]
    lines=text.splitlines()
    i=0
    while i<len(lines):
        if lines[i].lstrip().startswith("|"):
            rows=[]
            while i<len(lines) and lines[i].lstrip().startswith("|"):
                row=[x.strip() for x in lines[i].strip().strip("|").split("|")]
                if not all(re.fullmatch(r":?-{3,}:?",x or "") for x in row):
                    rows.append(row)
                i+=1
            if rows: tables.append(rows)
        else:
            i+=1
    return tables

def verify() -> dict:
    checks = []
    def check(name, condition, detail):
        checks.append({"name": name, "passed": bool(condition), "detail": detail})
        if not condition:
            raise AssertionError(f"{name}: {detail}")

    manifest = json.loads((DATA/"combined/density_campaign_manifest.json").read_text(encoding="utf-8"))
    config = json.loads((DATA/"effective_config.json").read_text(encoding="utf-8"))
    prov_path = OUT/"SCENARIO5_METHOD_B_PROVENANCE.json"
    prov = json.loads(prov_path.read_text(encoding="utf-8"))
    decisions = read_csv(DATA/"combined/density_decisions.csv")
    seed_metrics = read_csv(DATA/"combined/density_metrics_by_seed.csv")
    official = read_csv(PKG/"SCENARIO5_METHOD_B_VERIFIED_METRICS.csv")
    recomputed = read_csv(OUT/"SCENARIO5_METHOD_B_RECOMPUTED_METRICS.csv")
    performance = read_csv(OUT/"SCENARIO5_METHOD_B_PERFORMANCE_SUMMARY.csv")
    check("dataset_rows", len(decisions)==52254, "52,254 case-window rows")
    check("architecture_density_seed_coverage",
          {r["architecture"] for r in decisions}==set(ARCHS)
          and {ival(r["vehicle_count"]) for r in decisions}==set(DENSITIES)
          and {ival(r["seed"]) for r in decisions}==set(SEEDS),
          "three architectures, five densities, ten seeds")
    check("paired_manifest", manifest.get("expected_shared_traces")==50
          and manifest.get("architecture_evaluations_per_trace")==3
          and bool(manifest.get("shared_trace_pairing")),
          "50 shared cells, three architecture evaluations each")
    check("historical_v4_roles", config["pbft"]["validators"]==["rsu-1","rsu-2","rsu-3","rsu-4"]
          and ival(config["pbft"]["max_byzantine"])==1,
          "Dataset B is original four-validator configuration, f=1")
    by_arch = {}
    for arch in ARCHS:
        rows=[r for r in decisions if r["architecture"]==arch]
        eligible=[r for r in rows if r["reason"]!="already_revoked_terminal_state"]
        tp=sum(ival(r["ground_truth_malicious"])==1 and ival(r["committed"])==1 and r["new_state"]=="revoked" for r in eligible)
        fp=sum(ival(r["ground_truth_malicious"])==0 and ival(r["committed"])==1 and r["new_state"]=="revoked" for r in eligible)
        tn=sum(ival(r["ground_truth_malicious"])==0 and not (ival(r["committed"])==1 and r["new_state"]=="revoked") for r in eligible)
        fn=sum(ival(r["ground_truth_malicious"])==1 and not (ival(r["committed"])==1 and r["new_state"]=="revoked") for r in eligible)
        by_arch[arch]=(tp,fp,tn,fn,len(eligible),len(rows)-len(eligible))
    expected={
      "centralized_remote_0ms_control":(639,9,12981,964,14593,2825),
      "centralized_remote_100ms":(639,9,12981,964,14593,2825),
      "distributed_density_honest":(641,9,12974,961,14585,2833),
    }
    check("confusion_and_terminal_counts",by_arch==expected,str(by_arch))
    # Independently rebuild every seed, pooled-density and macro-density row from case records.
    metric_rows = {(r["level"],r["architecture"],ival(r["density"]),ival(r["seed"]) if r["seed"] else None):r for r in recomputed}
    for arch in ARCHS:
      for density in DENSITIES:
        seed_values=[]
        density_rows=[r for r in decisions if r["architecture"]==arch and ival(r["vehicle_count"])==density]
        for seed in SEEDS:
            c=calc([r for r in density_rows if ival(r["seed"])==seed])
            row=metric_rows[("seed",arch,density,seed)]
            check(f"seed_recompute_{ARCHS[arch]}_{density}_{seed}",
                  tuple(ival(row[k]) for k in ("TP","FP","TN","FN","eligible","excluded"))==
                  tuple(c[k] for k in ("TP","FP","TN","FN","eligible","excluded")),
                  "seed confusion matrix independently matches records")
            for metric in ("precision","recall","FRR","F1","MCC"):
                check(f"seed_metric_{ARCHS[arch]}_{density}_{seed}_{metric}",
                      math.isclose(float(row[metric]),c[metric],rel_tol=0,abs_tol=1e-10),
                      "seed metric independently recomputed")
            seed_values.append(c)
            source=[r for r in seed_metrics if r["architecture"]==arch and ival(r["vehicle_count"])==density and ival(r["seed"])==seed]
            check(f"saved_seed_metric_{ARCHS[arch]}_{density}_{seed}",len(source)==1 and all(
                math.isclose(c[k],float(source[0][v]),rel_tol=0,abs_tol=1e-10)
                for k,v in (("precision","trust_precision"),("recall","malicious_revocation_recall"),
                            ("FRR","false_revocation_rate"),("F1","trust_f1"),("MCC","mcc"))),
                "recomputed seed metrics match frozen seed metrics")
        pooled=calc(density_rows)
        pr=metric_rows[("density_pooled",arch,density,None)]
        check(f"pooled_counts_{ARCHS[arch]}_{density}",
              tuple(ival(pr[k]) for k in ("TP","FP","TN","FN","eligible","excluded"))==
              tuple(pooled[k] for k in ("TP","FP","TN","FN","eligible","excluded")),
              "pooled counts independently match records")
        for metric in ("precision","recall","FRR","F1","MCC"):
            check(f"pooled_metric_{ARCHS[arch]}_{density}_{metric}",
                  math.isclose(float(pr[metric]),pooled[metric],rel_tol=0,abs_tol=1e-10),
                  "pooled metric independently recomputed")
        mr=metric_rows[("density_macro",arch,density,None)]
        for metric in ("precision","recall","FRR","F1","MCC"):
            macro=sum(c[metric] for c in seed_values)/len(seed_values)
            check(f"macro_metric_{ARCHS[arch]}_{density}_{metric}",
                  math.isclose(float(mr[metric]),macro,rel_tol=0,abs_tol=1e-10),
                  "macro metric independently recomputed from ten seeds")
    case_key=("topology","vehicle_count","seed","case_id")
    compare_cols=("ground_truth_malicious","predicted_revoked","committed","previous_state","new_state","reason")
    maps={}
    for arch in ARCHS:
        maps[arch]={tuple(r[k] for k in case_key):tuple(r[k] for k in compare_cols)
                    for r in decisions if r["architecture"]==arch}
    check("canonical_case_identity_sets",len(set.intersection(*(set(v) for v in maps.values())))==17418
          and all(set(v)==set(next(iter(maps.values()))) for v in maps.values()),
          "17,418 identities in all architectures; no unmatched cases")
    check("C0_C100_decision_identity",maps["centralized_remote_0ms_control"]==maps["centralized_remote_100ms"],
          "all decision/state/reason fields identical")
    primary_diffs=[]
    for k,v in maps["centralized_remote_100ms"].items():
        d=maps["distributed_density_honest"][k]
        if v[1]!=d[1]:
            primary_diffs.append((k,v,d))
    expected_ids={
      ("urban_roundabout", "60","1002","case-urban_roundabout-1002-veh_044-w0002"),
      ("urban_roundabout", "100","1004","case-urban_roundabout-1004-veh_020-w0001"),
    }
    check("primary_C100_Distributed_differences",len(primary_diffs)==2
          and {x[0] for x in primary_diffs}==expected_ids,
          "two primary malicious revocation differences")
    fpids={}
    for arch in ARCHS:
        fpids[arch]=sorted(r["case_id"] for r in decisions
          if r["architecture"]==arch and r["reason"]!="already_revoked_terminal_state"
          and ival(r["ground_truth_malicious"])==0 and ival(r["committed"])==1 and r["new_state"]=="revoked")
    check("false_positive_ids",len(fpids["distributed_density_honest"])==9
          and fpids["centralized_remote_100ms"]==fpids["distributed_density_honest"],
          "nine FP identities match between C100 and Distributed")
    check("seed_metric_rows",len(seed_metrics)==150, "150 architecture-density-seed rows")
    check("source_comparison_bundle",len(official)>0, "frozen Method B validation CSV exists")
    check("recomputed_metric_rows",len(recomputed)==180, "180 rows: seed, pooled density, macro density")
    check("performance_summary_rows",len(performance)==15,"15 architecture-density performance means")
    for arch in ARCHS:
      for density in DENSITIES:
        summary=[r for r in performance if r["architecture"]==arch and ival(r["density"])==density]
        source=[r for r in seed_metrics if r["architecture"]==arch and ival(r["vehicle_count"])==density]
        valid=len(summary)==1 and len(source)==10
        if valid:
            valid = ival(summary[0]["seed_count"])==10
            pairs=(("P95_E2E_ms_mean","latency_p95_ms"),("CPU_seconds_mean","cpu_time_seconds"),
                   ("messages_per_decision_mean","messages_per_decision"),("PDR_mean","packet_delivery_ratio"),
                   ("P95_ledger_consistency_delay_ms_mean","ledger_consistency_delay_p95_ms"))
            valid = valid and all(math.isclose(float(summary[0][out]),sum(float(x[col]) for x in source)/10,
                                               rel_tol=0,abs_tol=1e-10) for out,col in pairs)
        check(f"performance_summary_{ARCHS[arch]}_{density}",valid,
              "performance means independently match ten frozen seed rows")
    # Every pooled and macro number for C100 and Distributed must match the frozen official validation table.
    for arch in ("centralized_remote_100ms","distributed_density_honest"):
      for density in DENSITIES:
       for lev,offlev in (("density_pooled","density_pooled"),("density_macro","density_macro_seed_mean")):
        local=[r for r in recomputed if r["level"]==lev and r["architecture"]==arch and ival(r["density"])==density]
        source=[r for r in official if r["level"]==offlev and r["architecture"]==arch and ival(r["density"])==density]
        check(f"official_{ARCHS[arch]}_{density}_{lev}",len(local)==len(source)==1,"one comparable summary row")
        for metric in ("precision","recall","FRR","F1","MCC"):
            check(f"metric_{ARCHS[arch]}_{density}_{lev}_{metric}",
                  math.isclose(float(local[0][metric]),float(source[0][metric]),rel_tol=0,abs_tol=1e-10),
                  f"{metric} matches official Method B source")
    md=(OUT/"VPUFT_Chapter5_MethodB_Corrected_Final_AR.md").read_text(encoding="utf-8")
    html=(OUT/"VPUFT_Scenario5_Dataset_B_Method_B_Corrected_Final.html").read_text(encoding="utf-8")
    claims=(ROOT/"docs/final_scenario5_evidence_package/FINAL_THESIS_CLAIMS_AR.md").read_text(encoding="utf-8")
    check("Arabic_UTF8", "الفصل الخامس" in md and "الادعاءات العلمية" in claims, "Arabic text decodes from UTF-8")
    check("three_architectures_in_chapter", all(f"| {x} |" in md for x in ("C0","C100","Distributed")),
          "C0, C100 and Distributed are shown")
    check("metric_semantics", all(s in md for s in ("state-aware Recall","pooled","macro","already_revoked_terminal_state","fixed-denominator")),
          "pooled/macro, terminal exclusion and unavailable fixed-opportunity metrics stated")
    check("no_stale_unresolved_claim", not re.search(r"(المصدر.*غير محسوم|source unresolved)",claims,re.I),
          "Dataset B is the authoritative Method B dataset")
    check("security_limits", all(s in md for s in ("حجب الأدلة المعارضة","VIEW-CHANGE/NEW-VIEW","لا تثبت المحاكاة")),
          "evidence omission and incomplete PBFT recovery limitations retained")
    check("ablation_c_tradeoff", all(s in md for s in ("بوابات تنوع الجذر والمصدر والمنطقة والوسيط",
          "من 15 إلى 28","402/74 إلى 342/134","من 79 إلى 137","2,179/1,106 إلى 3,298/2,828")),
          "variant C TP and changing Method B denominators are explicitly reported as a weakened-policy counterfactual")
    check("HTML_numeric_direction", bool(re.search(r'<td dir="ltr">(?:\d|%|[A-Za-z])',html)),
          "numeric/Latin table cells use left-to-right direction")
    check("HTML_single_captions", "<figcaption>" not in html and html.count('width="620"')==4,
          "four bounded figures, no duplicate HTML captions")
    check("HTML_no_literal_title_marker", "<h1>الفصل الخامس" in html and "<h1># " not in html,
          "UTF-8 BOM does not render as a literal hash")
    check("performance_break", 'page-break-before:always' in html and "الأداء المسجل" in html,
          "performance section begins on a new page")
    check("supplementary_section_break", '<h2 style="page-break-before:always">الدراسات التكميلية وحدود الأمن</h2>' in html,
          "supplementary studies begin with their heading on a new page")
    check("no_sources_orphan", "## مصادر الأرقام" not in md,
          "source provenance moved into the limitations section")
    tables=md_tables(md)
    def find_table(header_part):
        return next((t for t in tables if any(header_part in h for h in t[0])),None)
    conf=find_table("TP")
    check("chapter_confusion_table",conf is not None and len(conf)==16,"one header plus 15 density-architecture rows")
    if conf:
      for row in conf[1:]:
        density=ival(row[0]); arch=next(a for a,label in ARCHS.items() if label==row[1])
        expected_row=metric_rows[("density_pooled",arch,density,None)]
        check(f"chapter_confusion_{row[1]}_{density}",
          tuple(ival(x) for x in row[2:])==tuple(ival(expected_row[k]) for k in ("TP","FP","TN","FN","eligible","excluded")),
          "chapter pooled confusion row matches recomputed source")
    perf_tables=[t for t in tables if "P95 E2E (ms)" in t[0] and "CPU (s)" in t[0]]
    comm_tables=[t for t in tables if "رسائل/قرار" in t[0] and "PDR" in t[0]]
    check("chapter_performance_tables",len(perf_tables)==1 and len(comm_tables)==1,
          "P95/CPU and messages/PDR/ledger tables are present")
    if perf_tables and comm_tables:
      for table, fields in ((perf_tables[0],("P95_E2E_ms_mean","CPU_seconds_mean")),
                            (comm_tables[0],("messages_per_decision_mean","PDR_mean","P95_ledger_consistency_delay_ms_mean"))):
        check("chapter_performance_row_count_"+fields[0],len(table)==16,"15 architecture-density rows")
        for row in table[1:]:
          density=ival(row[0]); arch=next(a for a,label in ARCHS.items() if label==row[1])
          summary=next(x for x in performance if x["architecture"]==arch and ival(x["density"])==density)
          actual=[float(x) for x in row[2:]]
          expected_values=[float(summary[f]) for f in fields]
          places=(1,3) if table is perf_tables[0] else (3,5,3)
          check(f"chapter_performance_values_{ARCHS[arch]}_{density}",
             len(actual)==len(expected_values) and all(round(a,p)==round(e,p) for a,e,p in zip(actual,expected_values,places)),
             "printed performance values match saved seed-level means at displayed precision")
    # Verify source hashes of historical inputs and frozen Dataset B.
    for rel, expected_hash in prov["source_sha256"].items():
        p=ROOT/Path(rel)
        check("source_hash_"+rel, p.exists() and sha(p)==expected_hash, "unchanged source SHA-256")
    for rel, expected_hash in prov.get("supplementary_sources",{}).items():
        p=ROOT/Path(rel)
        check("supplementary_hash_"+rel,p.is_file() and sha(p)==expected_hash,
              "supplementary ablation source SHA-256 matches")
    check("supplementary_source_inventory",len(prov.get("supplementary_sources",{}))==2,
          "Ablation findings and aggregated metrics are traced")
    # Verify deliverables structurally and hash inventory.
    for name in ("VPUFT_Chapter5_MethodB_Corrected_Final_AR.docx","VPUFT_Chapter5_MethodB_Corrected_Final_AR.pdf"):
        p=OUT/name
        check("artifact_"+name,p.exists() and p.stat().st_size>10000,"generated final artifact exists")
    docx=OUT/"VPUFT_Chapter5_MethodB_Corrected_Final_AR.docx"
    if docx.exists():
        with zipfile.ZipFile(docx) as z:
            xml=z.read("word/document.xml")
            check("docx_OOXML",b"w:document" in xml and len(xml)>50000,"Word document XML exists")
        dx=ET.fromstring(xml)
        w="{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
        docx_text="".join(t.text or "" for t in dx.iter(w+"t"))
        check("docx_ablation_c_numbers",all(x in docx_text for x in ("C_no_diversity_gates","342/134","341/135","1,700","781/546","774/561","1,923/357","1,657/623","7,612","2,179/1,106","3,298/2,828")),
              "DOCX records Variant C security caveat and verified density-specific numerators/denominators")
    pdf=OUT/"VPUFT_Chapter5_MethodB_Corrected_Final_AR.pdf"
    if pdf.exists():
        b=pdf.read_bytes()
        check("pdf_signature",b.startswith(b"%PDF-") and b"%%EOF" in b[-2048:],"PDF file structure")
    for rel, expected_hash in prov.get("generated_artifact_sha256",{}).items():
        p=ROOT/Path(rel)
        check("generated_hash_"+rel,p.is_file() and sha(p)==expected_hash,"generated output SHA-256 matches provenance")
    check("generated_hash_inventory",len(prov.get("generated_artifact_sha256",{}))>=15,
          "provenance records chapter, metrics, figures, scripts and claims hashes")
    for name in ("01_state_aware_recall.png","02_p95_e2e_latency.png","03_messages_per_decision.png","04_cpu_time.png"):
        p=OUT/"figures"/name
        check("figure_"+name,p.exists() and p.stat().st_size>10000,"source-derived figure exists")
    failed=[x for x in checks if not x["passed"]]
    return {"passed":len(checks)-len(failed),"failed":len(failed),"checks":checks,"counts":by_arch,
            "primary_case_differences":len(primary_diffs),"terminal_exclusions":{ARCHS[a]:v[5] for a,v in by_arch.items()}}
if __name__=="__main__":
    result=verify()
    (OUT/"SEMANTIC_VALIDATION_REPORT.json").write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps({k:v for k,v in result.items() if k!="checks"},ensure_ascii=True,indent=2))
