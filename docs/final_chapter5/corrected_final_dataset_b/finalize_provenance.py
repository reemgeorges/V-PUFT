from pathlib import Path
import hashlib,json
ROOT=Path(__file__).resolve().parents[3]
OUT=ROOT/"docs/final_chapter5/corrected_final_dataset_b"
manifest=OUT/"SCENARIO5_METHOD_B_PROVENANCE.json"
data=json.loads(manifest.read_text(encoding="utf-8"))
paths=[
"docs/final_chapter5/corrected_final_dataset_b/VPUFT_Chapter5_MethodB_Corrected_Final_AR.md",
"docs/final_chapter5/corrected_final_dataset_b/VPUFT_Scenario5_Dataset_B_Method_B_Corrected_Final.html",
"docs/final_chapter5/corrected_final_dataset_b/VPUFT_Chapter5_MethodB_Corrected_Final_AR.docx",
"docs/final_chapter5/corrected_final_dataset_b/VPUFT_Chapter5_MethodB_Corrected_Final_AR.pdf",
"docs/final_chapter5/corrected_final_dataset_b/SCENARIO5_METHOD_B_RECOMPUTED_METRICS.csv",
"docs/final_chapter5/corrected_final_dataset_b/SCENARIO5_METHOD_B_PERFORMANCE_SUMMARY.csv",
"docs/final_chapter5/corrected_final_dataset_b/FINAL_CHAPTER5_RECONCILIATION_AUDIT_AR.md",
"docs/final_chapter5/corrected_final_dataset_b/build_and_validate_method_b_chapter.py",
"docs/final_chapter5/corrected_final_dataset_b/export_word.ps1",
"docs/final_chapter5/corrected_final_dataset_b/validate_method_b_chapter.py",
"docs/final_chapter5/corrected_final_dataset_b/test_method_b_chapter.py",
"docs/final_scenario5_evidence_package/FINAL_THESIS_CLAIMS_AR.md",
]
paths += [f"docs/final_chapter5/corrected_final_dataset_b/figures/{name}" for name in (
"01_state_aware_recall.png","02_p95_e2e_latency.png","03_messages_per_decision.png","04_cpu_time.png")]
hashes={}
for rel in paths:
    p=ROOT/rel
    if not p.is_file(): raise FileNotFoundError(rel)
    hashes[rel]=hashlib.sha256(p.read_bytes()).hexdigest()
data["generated_artifact_sha256"]=hashes
data["hash_scope_note"]="Generated artifact hashes exclude this provenance manifest itself and SEMANTIC_VALIDATION_REPORT.json to avoid circular hashing; all frozen input hashes remain under source_sha256."
manifest.write_text(json.dumps(data,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
print(f"Recorded {len(hashes)} generated artifact hashes")
