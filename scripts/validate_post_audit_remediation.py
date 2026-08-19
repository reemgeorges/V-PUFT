from pathlib import Path
import subprocess
import json
import hashlib

BASELINE = "10b7ab507351818a7d8a1685d13a6c6b5cfd867b"
errors = []

def run(*args):
    return subprocess.check_output(args, text=True, encoding="utf-8", errors="replace").strip()

def fail(x):
    errors.append(x)

try:
    subprocess.check_call(["git", "merge-base", "--is-ancestor", BASELINE, "HEAD"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[PASS] baseline is ancestor of HEAD")
except Exception:
    fail("baseline is not ancestor of HEAD")

chapter = Path("results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html")
index = Path("results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/index.html")
if not chapter.exists() or not index.exists():
    fail("chapter files missing")
else:
    if chapter.read_bytes() != index.read_bytes():
        fail("chapter HTML and index differ")
    text = chapter.read_text(encoding="utf-8")
    for bad in ["5.16.1 ?????", "5.19.1 ?????", "5.20.7 ????", "\ufffd"]:
        if bad in text:
            fail(f"encoding corruption remains: {bad!r}")
    for marker in ['comparison-scope','without-smoke','5.16.1','5.19.1','5.20.7','5.20.8','5.20.9']:
        if f'data-post-audit="{marker}"' not in text:
            fail(f"missing Chapter marker {marker}")
    if "<b>32 / 32</b>اختبارات ناجحة" in text or "ونجحت جميع الاختبارات البالغ عددها" in text:
        fail("Chapter still overstates test status as 32/32 passed")
    for required_test_text in ["جُمِع <strong>32 اختباراً</strong>", "<strong>31</strong>", "SUMO/TraCI"]:
        if required_test_text not in text:
            fail("Chapter missing corrected test-status wording: " + required_test_text)

# V5 final-review checks
legacy_chapter = [
    'Liveness Failure</span> أو <span class="ltr">View Change</span>',
    "Centralized↔Distributed RSU هي المقارنة المعزولة",
    "<strong>مسار الشهود يرفع Recall مع كلفة FRR:</strong>",
]
if chapter.exists():
    ctext = chapter.read_text(encoding="utf-8")
    for phrase in legacy_chapter:
        if phrase in ctext:
            fail("V5 legacy Chapter wording remains: " + phrase)

threat = Path("docs/THREAT_MODEL.md").read_text(encoding="utf-8")
if "configured behavior (for example accept-invalid/equivocation) can be a no-op" not in threat:
    fail("THREAT_MODEL missing configured-vs-activated fault caveat")

runbook = Path("docs/reproducibility/FINAL_REPRODUCTION_RUNBOOK.md").read_text(encoding="utf-8")
if "exact package versions" not in runbook or "not reconstructible" not in runbook:
    fail("runbook missing exact-environment limitation")

try:
    eff = json.loads(Path("docs/reproducibility/effective_final_configuration.json").read_text(encoding="utf-8"))
    selected = json.loads(Path("results/full_campaign_v7/sensitivity_shared_views_mixedfix/selected_weights.json").read_text(encoding="utf-8"))
    cfg = json.loads(Path("configs/full_experiment.json").read_text(encoding="utf-8"))
    expected = json.loads(json.dumps(cfg))
    expected["weights"] = selected["weights"]
    if eff.get("effective_runtime_config") != expected:
        fail("effective_final_configuration runtime snapshot does not match base-config + selected weights")
    elif eff.get("selection_feasible") is not False:
        fail("effective_final_configuration lost selection_feasible=false")
    else:
        print("[PASS] self-contained effective final configuration")
except Exception as e:
    fail("effective final configuration check failed: " + str(e))

readme = Path("README.md").read_text(encoding="utf-8")
for bad in ["Byzantine/offline behavior", "  - view change\n", "حملة موحدة تشغل النماذج الثلاثة على الـTrace نفسه"]:
    if bad in readme:
        fail("README legacy wording remains: " + bad)
for req in ["git lfs pull", "sensitivity_shared_views_mixedfix/selected_weights.json", "integrated evidence-path"]:
    if req not in readme:
        fail("README missing: " + req)

replay = Path("replay_final_v7.py").read_text(encoding="utf-8")
if 'default="results/full_campaign_v7/sensitivity_shared_views_mixedfix/selected_weights.json"' not in replay:
    fail("weights path not fixed")
else:
    print("[PASS] final weights path")
if 'parser.add_argument("--output", default="reproduction_check/final_architectures")' not in replay:
    fail("replay default output is not safely outside frozen results")
else:
    print("[PASS] safe replay default output")

ahmed = Path("src/vpuft/architectures/ahmed_witness.py").read_text(encoding="utf-8")
if ahmed.count('"independent_roots": result.independent_roots') < 2:
    fail("Ahmed independent_roots missing")
else:
    print("[PASS] Ahmed independent_roots instrumentation")

required = [
    "docs/reproducibility/FINAL_REPRODUCTION_RUNBOOK.md",
    "docs/reproducibility/effective_final_configuration.json",
    "docs/remediation/CLAUDE_RECONCILIATION.md",
    "docs/remediation/CLAIM_AUDIT.md",
    "docs/remediation/STATISTICAL_ROBUSTNESS_ADDENDUM.md",
    "docs/remediation/FINAL_CONSISTENCY_AUDIT.md",
]
for p in required:
    if not Path(p).exists():
        fail("missing doc " + p)

protected_scopes = [
    "results/full_campaign_v7",
    "FINAL_FREEZE_v7_20260809",
    "configs",
    "sumo",
]
changed = [x.replace("\\","/") for x in run(
    "git","diff","--name-only",BASELINE,"--",*protected_scopes
).splitlines() if x]
prefix = "results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/"
allowed = {
    prefix+"chapter_5_results_discussion_ar.html",
    prefix+"index.html",
    prefix+"FINAL_MANIFEST.json",
    prefix+"chapter_metadata.json",
    "results/full_campaign_v7/statistical_inference/SUMMARY.md",
    "results/full_campaign_v7/case_agreement/SUMMARY.md",
    "results/full_campaign_v7/latency_decomposition/SUMMARY.md",
}
bad_changed = [x for x in changed if x not in allowed]
if bad_changed:
    fail("unexpected frozen result changes: " + ", ".join(bad_changed))
else:
    print("[PASS] frozen numeric/scientific result files untouched")

def canonical_text_bytes(path):
    b = Path(path).read_bytes()
    return b.replace(b"\r\n", b"\n").replace(b"\r", b"\n")

try:
    manifest_path = Path("results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/FINAL_MANIFEST.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    policy = manifest.get("hash_policy", {})
    if policy.get("algorithm") != "SHA-256" or policy.get("text_line_endings") != "canonical LF":
        fail("FINAL_MANIFEST missing canonical-LF SHA-256 policy")
    for item in manifest.get("inputs_and_outputs", []):
        p = Path(item["path"])
        if not p.exists():
            fail("manifest entry missing: " + item["path"])
            continue
        cb = canonical_text_bytes(p)
        got = hashlib.sha256(cb).hexdigest().upper()
        if got != item.get("sha256"):
            fail("manifest hash mismatch: " + item["path"])
        if len(cb) != item.get("size_bytes"):
            fail("manifest canonical size mismatch: " + item["path"])
    chapter_hash = hashlib.sha256(canonical_text_bytes(chapter)).hexdigest().upper()
    if manifest.get("chapter_sha256") != chapter_hash:
        fail("manifest top-level chapter_sha256 mismatch")
    meta = json.loads(Path("results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_metadata.json").read_text(encoding="utf-8"))
    if meta.get("chapter_sha256") != chapter_hash:
        fail("chapter_metadata chapter_sha256 mismatch")
    if not any(e.startswith("manifest ") or e.startswith("FINAL_MANIFEST") or e.startswith("chapter_metadata") for e in errors):
        print("[PASS] canonical-LF manifest verification")
except Exception as e:
    fail("manifest verification failed: " + str(e))

active_doc_checks = {
    "docs/ARCHITECTURE.md": [
        "PBFT simulation includes recipient certificates, vote locks, loss/retries, leader failure, view change, and recovery.",
        "All architectures replay the same trace.",
    ],
    "docs/EXPERIMENT_PROTOCOL.md": [
        "consensus success, view changes, liveness and safety",
    ],
    "docs/TEST_REPORT.md": [
        "PBFT quorum and view change",
    ],
}
for doc, forbidden in active_doc_checks.items():
    text = Path(doc).read_text(encoding="utf-8")
    for phrase in forbidden:
        if phrase in text:
            fail(f"active documentation legacy wording remains in {doc}: {phrase}")
if not any(e.startswith("active documentation legacy wording") for e in errors):
    print("[PASS] active documentation scope wording")

needles = ["Byzantine","safety_violation","Safety","view change","VIEW-CHANGE","MCC","same trace","تفوق","أفضل","authentication","Ring Signature","كثافة الجذور"]
scan = Path("docs/remediation/REMAINING_RISKY_CLAIMS_SCAN.md")
hits = []
bases = [
    Path("README.md"),
    Path("docs"),
    Path("defense_v8"),
    Path("results/full_campaign_v7/statistical_inference/SUMMARY.md"),
    Path("results/full_campaign_v7/case_agreement/SUMMARY.md"),
    Path("results/full_campaign_v7/latency_decomposition/SUMMARY.md"),
    chapter,
]
for base in bases:
    files = [base] if base.is_file() else sorted((p for p in base.rglob("*") if p.is_file()), key=lambda p: p.as_posix())
    for p in files:
        posix = p.as_posix()
        if p == scan:
            continue
        if posix.startswith("docs/archive/"):
            continue
        if p.suffix.lower() not in {".md",".txt",".html",".py",".json"}:
            continue
        try:
            lines = p.read_text(encoding="utf-8").splitlines()
        except Exception:
            continue
        for no,line in enumerate(lines,1):
            for n in needles:
                if n.lower() in line.lower():
                    hits.append((posix, no, n, line.strip()[:200]))
                    break

hits.sort(key=lambda x: (x[0], x[1], x[2], x[3]))
parts = [
    "# Remaining risky-claim lexical scan\n\n",
    "Lexical inventory of active/non-archive material for contextual review; hits are not automatically errors.\n",
    "The generated scan file itself is excluded to prevent recursive hit inflation.\n\n",
    "| file | line | trigger | excerpt |\n|---|---:|---|---|\n",
]
for p,no,n,line in hits:
    line = line.replace("|","\\|")
    parts.append(f"| `{p}` | {no} | `{n}` | {line} |\n")
rendered_scan = "".join(parts)
existing_scan = scan.read_text(encoding="utf-8") if scan.exists() else None
if existing_scan != rendered_scan:
    scan.write_text(rendered_scan, encoding="utf-8", newline="\n")
print(f"[INFO] active claim scan: {len(hits)} hits -> {scan}")

if errors:
    print("\nVALIDATION FAILED")
    for e in errors:
        print(" -", e)
    raise SystemExit(1)

print("\nVALIDATION PASSED")
print("Now run:")
print("pytest -q")
print("git diff --check")
print("git diff --stat")
print("git status")
