"""Build a compact, provenance-linked Scenario 5 sensitivity closure package."""
from __future__ import annotations

import csv
import hashlib
import json
import math
import shutil
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results/final_scenario5_sensitivity"
PILOT = RESULTS / "pilot_2026-11-16"
REPL = RESULTS / "replication_2026-11-16"
DOCS = ROOT / "docs/final_scenario5_sensitivity"
VARIANTS = ("baseline", "freshness_12s", "freshness_30s", "position_sources_1", "position_sources_3")
ARCHITECTURES = ("C100", "Distributed")


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def number(row: dict[str, str], key: str) -> float:
    value = row.get(key, "")
    if value == "":
        return math.nan
    return float(value)


def rate(a: float, b: float) -> float:
    return a / b if b else math.nan


def metric_row(dataset: str, density: int, variant: str, architecture: str,
               metrics: list[dict[str, str]], opportunities: list[dict[str, str]]) -> dict[str, object]:
    mrows = [r for r in metrics if r["variant_id"] == variant and int(r["density"]) == density
             and r["architecture"] == architecture]
    orows = [r for r in opportunities if r["variant_id"] == variant and int(r["density"]) == density
             and r["architecture"] == architecture]
    if dataset == "replication" and density == 100:
        # The preregistered all-factor comparison has four complete high-density seeds.
        mrows = [r for r in mrows if int(r["seed"]) <= 7006]
        orows = [r for r in orows if int(r["seed"]) <= 7006]
    if len(mrows) != len(orows) or not mrows:
        raise ValueError(f"Unpaired/empty data: {dataset}/{density}/{variant}/{architecture}")
    sums = {key: sum(number(r, key) for r in mrows) for key in ("TP", "FP", "TN", "FN", "excluded_post_revocation_cases")}
    tp, fp, tn, fn = (sums[k] for k in ("TP", "FP", "TN", "FN"))
    precision = rate(tp, tp + fp)
    recall = rate(tp, tp + fn)
    frr = rate(fp, fp + tn)
    f1 = rate(2 * tp, 2 * tp + fp + fn)
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = rate(tp * tn - fp * fn, denom)
    osums = {key: sum(number(r, key) for r in orows) for key in
             ("attack_message_opportunities", "observed_attack_messages", "unobserved_attack_messages",
              "successfully_detected_attack_messages", "protected_attack_messages")}
    opportunity_recall = rate(osums["successfully_detected_attack_messages"], osums["attack_message_opportunities"])
    protected = rate(osums["protected_attack_messages"], osums["attack_message_opportunities"])
    def mean(key: str) -> float:
        return sum(number(r, key) for r in mrows) / len(mrows)
    return {
        "dataset": dataset, "density": density, "variant_id": variant, "architecture": architecture,
        "paired_seed_n": len(mrows), "seeds": ";".join(sorted(r["seed"] for r in mrows)),
        "TP": int(tp), "FP": int(fp), "TN": int(tn), "FN": int(fn),
        "excluded_post_revocation_cases": int(sums["excluded_post_revocation_cases"]),
        "pooled_precision": precision, "pooled_state_aware_recall": recall,
        "macro_seed_state_aware_recall": mean("malicious_revocation_recall"),
        "pooled_FRR": frr, "pooled_F1": f1, "pooled_MCC": mcc,
        **{key: int(value) for key, value in osums.items()},
        "fixed_denominator_opportunity_recall": opportunity_recall,
        "fixed_denominator_protected_fraction": protected,
        "mean_cpu_time_seconds": mean("cpu_time_seconds"),
        "mean_p95_e2e_ms": mean("latency_p95_ms"),
        "mean_messages_per_case": mean("messages_per_decision"),
        "mean_bytes_per_case": mean("bytes_per_decision"),
        "mean_pdr": mean("packet_delivery_ratio"),
        "mean_p95_ledger_consistency_delay_ms": mean("ledger_consistency_delay_p95_ms"),
    }


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def build() -> None:
    DOCS.mkdir(parents=True, exist_ok=True)
    metrics_pilot = read_csv(PILOT / "SENSITIVITY_METRICS_BY_SEED.csv")
    opportunities_pilot = read_csv(PILOT / "SENSITIVITY_FIXED_OPPORTUNITIES_CORRECTED.csv")
    metrics_repl = read_csv(REPL / "SENSITIVITY_METRICS_BY_SEED.csv")
    opportunities_repl = read_csv(REPL / "SENSITIVITY_FIXED_OPPORTUNITIES.csv")
    rows = []
    for dataset, metrics, opportunities in (
        ("pilot", metrics_pilot, opportunities_pilot),
        ("replication", metrics_repl, opportunities_repl),
    ):
        for density in (20, 100):
            for variant in VARIANTS:
                for architecture in ARCHITECTURES:
                    rows.append(metric_row(dataset, density, variant, architecture, metrics, opportunities))
    write_csv(REPL / "SENSITIVITY_PILOT_VS_REPLICATION.csv", rows)
    shutil.copyfile(REPL / "SENSITIVITY_STATISTICAL_ANALYSIS.md", DOCS / "SENSITIVITY_STATISTICAL_ANALYSIS.md")
    figure_path = REPL / "figures/SENSITIVITY_PILOT_VS_REPLICATION_300dpi.png"
    fig, axes = plt.subplots(2, 2, figsize=(12, 8), sharex=True)
    names = ["baseline", "freshness_12s", "freshness_30s", "position_sources_1", "position_sources_3"]
    labels = ["Baseline", "Fresh 12 s", "Fresh 30 s", "Sources 1*", "Sources 3"]
    for row_index, density in enumerate((20, 100)):
        for col_index, (metric, title) in enumerate((("macro_seed_state_aware_recall", "State-aware Recall"),
                                                     ("fixed_denominator_opportunity_recall", "Opportunity detection Recall"))):
            ax = axes[row_index, col_index]
            for arch, marker in (("C100", "o"), ("Distributed", "s")):
                for dataset, linestyle in (("pilot", "--"), ("replication", "-")):
                    subset = [r for r in rows if r["density"] == density and r["variant_id"] in names
                              and r["architecture"] == arch and r["dataset"] == dataset]
                    lookup = {r["variant_id"]: r for r in subset}
                    values = [lookup[name][metric] for name in names]
                    ax.plot(range(len(names)), values, marker=marker, linestyle=linestyle,
                            label=f"{arch} / {dataset} (n={lookup[names[0]]['paired_seed_n']})")
            ax.set_title(f"{title} — density {density}")
            ax.set_ylabel("Fraction")
            ax.set_xticks(range(len(names)), labels, rotation=20, ha="right")
            ax.grid(True, alpha=0.25)
    axes[0, 0].legend(fontsize=7)
    fig.suptitle("Scenario 5 sensitivity: pilot vs independent replication\n"
                 "Seed-level macro; pilot n=2, replication density 20 n=6, density 100 n=4")
    fig.tight_layout()
    figure_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(figure_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    findings = """# نتائج تحليل الحساسية — خلاصة عربية\n\n## النطاق والاكتمال\n\nهذه خلاصة للحملة الاستكشافية الأصلية (بذرتان لكل كثافة) وللتكرار المستقل المسجل مسبقاً. اكتملت 103 من 120 خلية؛ الخلايا الـ17 الباقية لم تبدأ بسبب حد الساعة، ولا تُعامل كإخفاقات أو تُستكمل بعد تجاوز الميزانية. اكتملت جميع خلايا الكثافة 20 (6 بذور لكل إعداد ومعمارية)، بينما اكتملت المقارنة العاملية المزدوجة عند الكثافة 100 لأربع بذور فقط (7003–7006).\n\n## النتائج الأساسية في التكرار\n\nفي كثافة 20 (n=6)، خط الأساس pooled: TP=23, FP=1, TN=535, FN=43؛ Recall الحالة 34.85%، Precision 95.83%، FRR 0.187%، F1=0.511، MCC=0.554. استُبعدت 111 نافذة بعد الإلغاء النهائي. بلغ مقام فرص الرسائل الضارة الثابت 2550؛ رُصد/صُنّف مكتشفاً 339 (13.29%)، وحُميت 209 (8.20%).\n\nفي كثافة 100 (n=4، البذور 7003–7006)، خط الأساس pooled: TP=79, FP=2, TN=1719, FN=123؛ Recall الحالة 39.11% (متوسط seed=39.09%)، Precision 97.53%، FRR 0.116%، F1=0.558، MCC=0.595. استُبعدت 357 نافذة بعد الإلغاء. مقام الفرص الثابت 7612؛ اكتُشفت 2179 (28.63%) وحُميت 1106 (14.53%).\n\nخفض حد freshness إلى 12 ثانية قلل Recall الحالة وفرص الكشف في الكثافتين. عند الكثافة 20: 22 TP و0 FP، Recall=33.33%، opportunity Recall=11.92% (304/2550)، حماية 202/2550=7.92%. عند الكثافة 100: 71 TP و0 FP، Recall=34.63%، opportunity Recall=21.02% (1600/7612)، حماية 976/7612=12.82%. انخفضت حالات FP القائمة (واحدة عند 20 واثنتان عند 100) ولم تظهر FP جديدة، لكن خسر الإعداد TP حقيقية وفرص كشف؛ فهو مقايضة تشدد freshness وليس تحسناً أمنياً صافياً.\n\nرفع required_sources إلى 3 خفض TP من 23 إلى 17 عند كثافة 20، ومن 79 إلى 68 عند كثافة 100، دون تغيير FP. انخفض opportunity Recall من 13.29% إلى 9.76% عند 20، ومن 28.63% إلى 26.46% عند 100. تغيير required_sources إلى 1، وهو اختبار ضغط لسياسة أضعف، لم يغيّر القرارات في هذه العينة ولا يبرر تخفيف السياسة. freshness=30 ثانية لم يغير القرارات أو فرص الكشف في الخلايا المكتملة.\n\n## المعماريتان والموارد\n\nفي المقارنة العاملية المكتملة، قرارات C100 وDistributed متطابقة في البذور المتوازنة عند الكثافة 20 (6) والكثافة 100 (4). انخفض متوسط الرسائل لكل حالة في Distributed بحوالي 11.00 عند كثافة 20 و10.27 عند كثافة 100، وتحسن P95 E2E بنحو 88 ms و216 ms على الترتيب، مع CPU أعلى بنحو 0.023 s و0.188 s. زاد تأخر اتساق السجل P95 بنحو 13.45 ms و14.15 ms. هذه خصائص لهذا المحاكي وهذه المدخلات، ولا تثبت تحسناً أمنياً.\n\nتوجد مقارنة إضافية مكتملة للأساس عند الكثافة 100/baseline/seed 7007 خارج العينة العاملية ذات n=4: قرار واحد مختلف عند `case-urban_roundabout-7007-veh_000-w0001`، حيث فشلت C100 بسبب `central_server_unavailable` بينما التوزيع ثبّت الإلغاء. السجلات الخمس التالية حالات بعد الإلغاء النهائي في Distributed. لا نخلط هذه البذرة الإضافية مع المقارنات العاملية لجميع المتغيرات.\n\n## مقارنة الاتجاه مع الطيار\n\nاتجاهات التكرار تؤيد وصف الطيار لا التعميم: freshness=12 وrequired_sources=3 خفضا الاسترجاع في كل من الكثافتين في مجموعتي البيانات؛ freshness=30 وrequired_sources=1 لم يغيرا القرارات. حجم العينة صغير (n=2 في الطيار، n=4 أو 6 في التكرار)، لذا فواصل t وصفية فقط ولا تُستخدم لإثبات الدلالة أو السببية.\n\nلا يثبت هذا التكرار إمكان الوصول إلى 70% من Recall فرص الهجوم الثابتة، ولا يقيس ضماناً كاملاً لتحمل Byzantine. الاختبار محصور بكثافتين وسيناريو واحد، ولم تُنفذ 17 خلية مسجلة.\n"""
    (DOCS / "SENSITIVITY_FINDINGS_AR.md").write_text(findings, encoding="utf-8")
    limitations = """# حدود تحليل الحساسية وإقفال النطاق\n\n- التكرار المسجل لم يكتمل: 103/120 خلية؛ 17 خلية لم تبدأ بعد بلوغ حد الجدار الزمني. اكتملت 12/12 آثار SUMO المشتركة، ولا توجد خلايا فاشلة بين الخلايا التي بدأت.\n- سجل التشغيل 3651.813 ثانية مقابل سقف 3600، أي تجاوز 51.813 ثانية لأن خلية بدأت قبل الحد واكتملت نقطة حفظها بعده؛ أوقف المشغل قبل بدء خلية أخرى. لا نبرر التجاوز ولا نوسع الميزانية بأثر رجعي.\n- الحجم الخام 2,007,798,978 بايت ضمن حد 3GB، لكنه محفوظ محلياً خارج المستودع في `C:\\Users\\reemg\\AppData\\Local\\VPUFT-Preservation-2026-11-15\\sensitivity_replication_2026-11-16`. يبقى خطر فقدان النسخة المحلية قائماً؛ يجب نسخها إلى وسيط مستقل وفق سياسة النسخ الاحتياطي قبل حذف البيئة أو الجهاز.\n- ملفات pilot الخام داخل `results/final_scenario5_sensitivity/pilot_2026-11-16/` غير مضافة إلى Git؛ حجمها المسجل قرابة 669MB. لا تُحذف. بيانات التكرار الخام غير ملتزمة أيضاً؛ الملفات الملتزمة هي التحليل والملخصات المحدودة فقط.\n- التكرار يغطي كثافتي 20 و100 فقط؛ بذور المقارنة العاملية المكتملة 6 عند 20 و4 عند 100. لا استدلال على الكثافات 40/60/80 أو تعميم شامل لسيناريوهات حركة أخرى.\n- مؤشرات P95، CPU، PDR، الرسائل، والاتساق مأخوذة من المحاكي. لا يوجد قياس لبيئة نشر فعلية ولا تفكيك شامل لتكلفة كل مرحلة.\n- `position_sources=1` اختبار ضغط لسياسة أضعف، لا توصية تشغيلية. عدم تغير النتائج لا يثبت أمان خفض عتبة المصادر.\n- مؤشرات الفرص: المقام هو هويات رسائل CAM/DENM الضارة الفريدة المولدة في جدول الهجوم؛ Opportunity detection تعني رسالة ضارة رُصدت وربطت بحالة نافذة أُلغيت، وProtected تعني أن أول إلغاء ملتزم سبق وقت إرسال الرسالة. هذان مقياسان مختلفان عن Recall الحالة.\n- لا تثبت النتائج سلامة PBFT الكاملة عبر تغيّر المناظر، أو توافر الأدلة ضد منسق Byzantine، أو تحمل Byzantine من طرف إلى طرف. تبقى النتائج ضمن افتراضات المحاكاة المثبتة في التقارير الأمنية السابقة.\n- لا تُخلط هذه النتائج مع Dataset B المصحح، أو حملة v7، أو Phase 6، أو تجارب C3/V5 الأمنية. لم تُعدّل النتائج المجمدة ولم تُعد تشغيل SUMO في التحليل.\n\n## القرار\n\nيُقفل نطاق الحساسية المحدود بوصفه نتيجة صحيحة منهجياً لكنها جزئية ومحدودة القدرة الإحصائية. لا توجد مبررات لحملة حساسية مفتوحة إضافية؛ يمكن الانتقال إلى Ablation محدود بشرط إبقاء هذه القيود والـ17 خلية الناقصة واضحة، وعدم وصف التكرار بأنه 120/120.\n"""
    (DOCS / "SENSITIVITY_LIMITATIONS_AR.md").write_text(limitations, encoding="utf-8")
    source_files = [PILOT / "SENSITIVITY_METRICS_BY_SEED.csv", PILOT / "SENSITIVITY_FIXED_OPPORTUNITIES_CORRECTED.csv",
                    REPL / "SENSITIVITY_METRICS_BY_SEED.csv", REPL / "SENSITIVITY_FIXED_OPPORTUNITIES.csv",
                    REPL / "SENSITIVITY_RUN_CONTEXT.json", REPL / "SENSITIVITY_TRACE_MANIFEST.json",
                    REPL / "SENSITIVITY_EFFECTIVE_CONFIGS.json", REPL / "SENSITIVITY_VALIDATION_SUMMARY.json"]
    output_files = [
        REPL / "SENSITIVITY_PILOT_VS_REPLICATION.csv",
        REPL / "SENSITIVITY_OUTPUT_HASHES.json",
        REPL / "SENSITIVITY_AGGREGATED_RESULTS.csv",
        REPL / "SENSITIVITY_ARCHITECTURE_PAIRED.csv",
        REPL / "SENSITIVITY_ARCHITECTURE_CASE_DIFFERENCES.csv",
        REPL / "SENSITIVITY_CASE_DIFFERENCES.csv",
        REPL / "SENSITIVITY_EFFECTIVE_CONFIGS.json",
        REPL / "SENSITIVITY_FIXED_OPPORTUNITIES.csv",
        REPL / "SENSITIVITY_METRICS_BY_SEED.csv",
        REPL / "SENSITIVITY_RUN_CONTEXT.json",
        REPL / "SENSITIVITY_RUN_MANIFEST.csv",
        REPL / "SENSITIVITY_STATISTICAL_ANALYSIS.md",
        REPL / "SENSITIVITY_TRACE_MANIFEST.json",
        REPL / "SENSITIVITY_VALIDATION_SUMMARY.json",
        REPL / "figures/RECALL_SENSITIVITY_300dpi.png",
        REPL / "figures/RESOURCE_SENSITIVITY_300dpi.png",
        REPL / "figures/SENSITIVITY_PILOT_VS_REPLICATION_300dpi.png",
        DOCS / "SENSITIVITY_EXPERIMENT_PLAN.md",
        DOCS / "SENSITIVITY_STATISTICAL_ANALYSIS.md",
        DOCS / "SENSITIVITY_FINDINGS_AR.md",
        DOCS / "SENSITIVITY_LIMITATIONS_AR.md",
    ]
    (REPL / "SENSITIVITY_CLOSURE_HASHES.json").write_text(json.dumps({
        "baseline_commit": "19fafe5ae71dc570c0809dabbdfc7483863d9cc7",
        "analysis_scripts": {p.relative_to(ROOT).as_posix(): sha256(p) for p in
                             (ROOT / "scripts/sensitivity_replication_analysis.py", Path(__file__))},
        "source_artifacts": {str(p): sha256(p) for p in source_files},
        "output_artifacts": {p.relative_to(ROOT).as_posix(): sha256(p) for p in output_files},
        "pilot_trace_manifest_sha256": sha256(PILOT / "SENSITIVITY_TRACE_MANIFEST.json"),
        "replication_trace_manifest_sha256": sha256(REPL / "SENSITIVITY_TRACE_MANIFEST.json"),
        "raw_replication_location": "C:/Users/reemg/AppData/Local/VPUFT-Preservation-2026-11-15/sensitivity_replication_2026-11-16",
        "raw_replication_is_local_uncommitted_data": True,
        "completed_architecture_runs": 103, "planned_architecture_runs": 120,
        "not_run_cells": 17, "failed_cells": 0,
        "runtime_cap_seconds": 3600, "runtime_seconds_observed": 3651.813,
        "raw_size_cap_bytes": 3000000000, "raw_size_bytes_observed": 2007798978,
        "committed_raw_traces": False,
    }, indent=2, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    build()
