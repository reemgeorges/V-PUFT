"""Build the read-only Scenario 5 thesis evidence package from frozen artifacts.

This script never runs a simulation. It reads git objects and existing result files,
and writes only beside itself in this package directory.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
REPO = "C:/Users/reemg/OneDrive/Desktop/master/6/v10"
SCENARIO_REF = "review/scenario5-defense-report-v4"
SCENARIO_COMMIT = "638a6d7909aefa192d532932ab1095111475021c"
MAIN_COMMIT = "0c0c10b3d6cbb2075e430a299e3c18cdf382320a"


def git_bytes(ref: str, path: str) -> bytes:
    p = subprocess.run(
        ["git", "-c", f"safe.directory={REPO}", "-C", REPO, "show", f"{ref}:{path}"],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return p.stdout


def git_csv(ref: str, path: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(git_bytes(ref, path).decode("utf-8-sig"))))


def local_csv(path: str) -> list[dict[str, str]]:
    with (ROOT / path).open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fmt(value: str | float | int | None) -> str:
    if value is None or value == "":
        return "NA"
    try:
        return f"{float(value):.9g}"
    except (TypeError, ValueError):
        return str(value)


def write_csv(path: Path, rows: list[dict]) -> None:
    fields = list(dict.fromkeys(k for row in rows for k in row))
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def scenario_rows() -> list[dict]:
    base = "results/urban_roundabout_campaign/combined/"
    summary = git_csv(SCENARIO_REF, base + "density_architecture_summary.csv")
    seeds = git_csv(SCENARIO_REF, base + "density_metrics_by_seed.csv")
    attack = git_csv(SCENARIO_REF, base + "density_attack_metrics_by_seed.csv")
    src = base + "density_architecture_summary.csv"
    rows: list[dict] = []
    count_cols = {"TP": "TP", "FP": "FP", "TN": "TN", "FN": "FN"}
    metric_cols = {
        "Precision": "trust_precision", "Historical campaign Recall (case-level)": "malicious_revocation_recall",
        "FRR": "false_revocation_rate", "F1": "trust_f1", "MCC": "mcc",
        "P95 E2E case latency ms": "latency_p95_ms", "CPU process seconds": "cpu_time_seconds",
        "Messages per decision": "messages_per_decision", "Bytes per decision": "bytes_per_decision",
        "PDR": "packet_delivery_ratio", "P95 ledger consistency delay ms": "ledger_consistency_delay_p95_ms",
        "P95 consensus latency ms": "consensus_latency_p95_ms",
    }
    for density in (20, 40, 60, 80, 100):
        for arch, label in (("centralized_remote_100ms", "Centralized C100"), ("distributed_density_honest", "Distributed")):
            srow = next(r for r in summary if int(r["vehicle_count"]) == density and r["architecture"] == arch)
            per = [r for r in seeds if int(r["vehicle_count"]) == density and r["architecture"] == arch]
            for short, col in count_cols.items():
                vals = [int(float(r[col])) for r in per]
                rows.append({"claim_id": f"S5-D{density}-{short}", "claim": f"Scenario 5 {short} count, {density} vehicles", "architecture": label,
                    "campaign": "Scenario 5 frozen 50-cell campaign", "scenario": "Urban Roundabout", "density": density,
                    "seeds": "1001-1010 (10 paired seed cells)", "metric": short, "numerator": sum(vals), "denominator": "case rows; see per-seed source",
                    "value": sum(vals), "aggregation": "sum over 10 seed rows", "source_ref": f"{SCENARIO_REF}@{SCENARIO_COMMIT}", "source_file": base+"density_metrics_by_seed.csv",
                    "limitations": "Case-level historical campaign metric; not the later state-aware opportunity protocol."})
            for name, col in metric_cols.items():
                if name == "Precision":
                    num, den = [int(r["TP"]) for r in per], [int(r["TP"])+int(r["FP"]) for r in per]
                elif name.startswith("Historical campaign Recall"):
                    num, den = [int(r["TP"]) for r in per], [int(r["TP"])+int(r["FN"]) for r in per]
                elif name == "FRR":
                    num, den = [int(r["FP"]) for r in per], [int(r["FP"])+int(r["TN"]) for r in per]
                elif name == "F1":
                    num, den = [2*int(r["TP"]) for r in per], [2*int(r["TP"])+int(r["FP"])+int(r["FN"]) for r in per]
                elif name == "MCC":
                    num = [int(r["TP"])*int(r["TN"])-int(r["FP"])*int(r["FN"]) for r in per]
                    den = [((int(r["TP"])+int(r["FP"]))*(int(r["TP"])+int(r["FN"]))*(int(r["TN"])+int(r["FP"]))*(int(r["TN"])+int(r["FN"])))**0.5 for r in per]
                else:
                    num, den = "not a ratio", "10 per-seed metric values"
                rows.append({"claim_id": f"S5-D{density}-{col}", "claim": f"Scenario 5 {name}, {density} vehicles", "architecture": label,
                    "campaign": "Scenario 5 frozen 50-cell campaign", "scenario": "Urban Roundabout", "density": density,
                    "seeds": "1001-1010 (10 paired seed cells)", "metric": name, "numerator": json.dumps(num), "denominator": json.dumps(den) if isinstance(den, list) else den,
                    "value": fmt(srow.get(col+"__mean")), "aggregation": "mean of 10 per-seed metrics (not pooled ratio)", "source_ref": f"{SCENARIO_REF}@{SCENARIO_COMMIT}", "source_file": src,
                    "limitations": "Simulation/model output; P95 is mean of per-seed P95 values."})
    # Attack-specific counts/recall are pooled by attack and density from seed-level records.
    for density in (20, 40, 60, 80, 100):
        for attack_name in sorted({r.get("attack_type", "") for r in attack}):
            subset = [r for r in attack if int(r.get("vehicle_count", -1)) == density and r.get("attack_type") == attack_name and r.get("architecture") == "distributed_density_honest"]
            if not subset:
                continue
            vals = {c: sum(int(float(r.get(c, 0) or 0)) for r in subset) for c in ("TP", "FP", "TN", "FN")}
            den = vals["TP"] + vals["FN"]
            rows.append({"claim_id": f"S5-ATTACK-{density}-{attack_name}", "claim": f"Attack-stratified outcome: {attack_name}, {density} vehicles", "architecture": "Distributed (C100 has same classification)",
                "campaign": "Scenario 5 frozen 50-cell campaign", "scenario": "Urban Roundabout", "density": density,
                "seeds": "1001-1010", "metric": "TP/FP/TN/FN; pooled attack Recall", "numerator": f"TP={vals['TP']}; FP={vals['FP']}; TN={vals['TN']}; FN={vals['FN']}",
                "denominator": f"Recall TP+FN={den}; N/A when zero positive cases", "value": "NA" if den == 0 else fmt(vals["TP"]/den),
                "aggregation": "sum counts, then pooled attack-specific recall", "source_ref": f"{SCENARIO_REF}@{SCENARIO_COMMIT}",
                "source_file": base+"density_attack_metrics_by_seed.csv", "limitations": "No-positive attack strata are N/A, not 0%/100%."})
    agreement = git_csv(SCENARIO_REF, base+"density_case_agreement.csv")
    rows.append({"claim_id":"S5-AGREE-ALL","claim":"Dataset A C100 versus Distributed decision agreement","architecture":"Centralized C100 vs Distributed","campaign":"Scenario 5 report-linked 50-cell campaign (Dataset A)","scenario":"Urban Roundabout","density":"20,40,60,80,100","seeds":"1001-1010","metric":"matching decisions / shared canonical identities","numerator":"5921","denominator":"5921","value":"1.0","aggregation":"direct per-case source comparison","source_ref":f"{SCENARIO_REF}@{SCENARIO_COMMIT}","source_file":base+"density_decisions.csv","limitations":"A only; Dataset B has 17416/17418 agreement and two decision changes. A/B are not interchangeable."})
    rows.extend([
        {"claim_id":"V7-POOLED","claim":"Broader v7 pooled classification (supplementary only)","architecture":"v7 original centralized/distributed","campaign":"full_campaign_v7","scenario":"corridor/grid/intersection/smoke","density":"campaign-specific","seeds":"10 per topology; 40 paired topology-seed units","metric":"TP/FP/TN/FN; Recall; Precision; FRR; F1; MCC","numerator":"TP=813, FP=82, TN=4905, FN=192","denominator":"Recall=813/(813+192); Precision=813/(813+82); FRR=82/(82+4905); F1=2TP/(2TP+FP+FN); MCC per pooled counts","value":"Recall=0.809059; Precision=0.908184; FRR=0.016492; F1=0.855098; MCC=0.830298","aggregation":"pooled across v7 campaign; not Scenario 5","source_ref":f"main@{MAIN_COMMIT}","source_file":"results/full_campaign_v7/statistical_inference/SUMMARY.md","limitations":"Supplementary broader validation. Never insert 80.9% Recall in Scenario 5 table."},
        {"claim_id":"PHASE6-20PAIR","claim":"Phase 6 six-RSU coverage extension, four-seed held-out comparison","architecture":"C0 original vs C1 frozen placement","campaign":"post_seminar_phase6_final","scenario":"Urban Roundabout","density":"20/40/60/80/100","seeds":"1007-1010; 20 paired density-seed cells","metric":"opportunities; observed; protected; fixed protection","numerator":"Observed=1016→1019; protected=455→501","denominator":"1086 emitted attack opportunities","value":"Fixed protected fraction 0.4190→0.4613; opportunity recall mean .2685→.3109; state-aware Recall mean .4063→.4499","aggregation":"separate exploratory fixed-opportunity protocol","source_ref":"research/vpuft-post-seminar-optimization@fdca82f6a3fd5273df454bee709a2800f97f941a","source_file":"docs/post_seminar/PHASE_6_FINAL_HELDOUT_RESULTS.md","limitations":"Four seeds; exploratory; not primary Scenario 5 campaign; spatial network paths not recomputed."},
        {"claim_id":"8RSU-PILOT","claim":"Eight-RSU sensing-only pilot C1→C3","architecture":"6-RSU vs 8-RSU, four validators held fixed","campaign":"recall-70-feasibility pilot","scenario":"Urban Roundabout","density":"20/60/100","seeds":"1007/1008; six paired cells","metric":"state-aware Recall; fixed-opportunity Recall; fixed protection","numerator":"Pilot report records density-specific paired means","denominator":"case and opportunity denominators differ; consult source rows","value":"State-aware Recall mean by density: 43.56→87.50%, 43.32→76.92%, 37.86→71.79%; opportunity Recall: 21.05→31.58%, 23.68→33.33%, 20.11→31.61%","aggregation":"descriptive paired pilot","source_ref":"research/recall-70-feasibility@96a7e903438c7316c25ed5e4b2e2cad433229224","source_file":"docs/post_seminar/PHASE_6_8RSU_PILOT_AR.md","limitations":"Rejected deployment candidate: CPU +44.27%, messages/case +37.12%, beyond registered gates. Not original architecture result."},
        {"claim_id":"V5-6CELL","claim":"V5 five-validator architecture replay","architecture":"V4 historical vs V5 5 validators, f=1, q=4/5","campaign":"saved-trace paired replay","scenario":"Urban Roundabout compatible saved traces","density":"20/60/100","seeds":"six paired cells","metric":"TP/FP/TN/FN; Recall; resources","numerator":"TP=115, FP=0, TN=1418, FN=38 (both)","denominator":"case-level, exact same compared cells","value":"Recall=.7516; Precision=1; FRR=0; messages +3.63%; CPU +7.56%; E2E +12.28ms","aggregation":"pooled classification and replay resource deltas","source_ref":"research/vpuft-v5-validator-prototype@4687266bae35d680d77730b1dd4d929a6ea57900","source_file":"docs/post_seminar/V5_VALIDATOR_ARCHITECTURE.md","limitations":"Exploratory architecture; single-node fault assumption; separate from original Scenario 5 campaign."},
        {"claim_id":"OMISSION-ATTACK","claim":"Evidence coordinator omission counterexample","architecture":"V5 test architecture","campaign":"adversarial synthetic signed-evidence test","scenario":"not a SUMO campaign","density":"N/A","seeds":"N/A","metric":"qualification/finalization outcome","numerator":"10 signed attestations; 5 opposing; full bundle failed; support-only omission bundle qualified and committed","denominator":"one constructed adversarial case","value":"demonstrated evidence-completeness vulnerability","aggregation":"single adversarial regression","source_ref":"security/evidence-omission-feasibility@d6fa44df28788f3497a0e7e209c28d7b354c7a94","source_file":"docs/post_seminar/V5_EVIDENCE_OMISSION_FEASIBILITY_GATE_AR.md","limitations":"Synthetic security counterexample; not a Scenario 5 metric. No full Byzantine tolerance claim."}
    ])
    return rows


def package_docs() -> None:
    claims = """# صياغة الادعاءات العلمية النهائية

## نطاق الفصل الخامس

يعرض تقرير الدفاع الخاص بـScenario 5 حملة الكثافة ذات 50 خلية ويطابق Dataset A عند `638a6d7`. توجد أيضاً Dataset B في `main@0c0c10b` بوصفها `corrected_final` وتطبق استبعاد النوافذ النهائية بعد الإلغاء. أرقام التقرير المنشور تطابق A، بينما تعريف Method B state-aware يطابق B؛ لذلك يجب عدم خلطهما أو وصف A بأنه Method B. اعتماد مصدر واحد للجداول النهائية غير محسوم في الملفات المتاحة. لا تُنقل قيمة Recall البالغة 80.9% من v7 إلى Scenario 5.

## مساهمة V-PUFT

يمكن وصف V-PUFT بأنه نموذج تجريبي موزع لتقييم الثقة وتأهيل الأدلة، مع محاكاة للنقل والتوافق والسجل. تقيس النتائج أثر قواعد التأهيل كما نُفذت في المحاكي. لا تثبت النتائج أداءً ميدانياً أو ضماناً أمنياً رسمياً.

## C100 مقابل البنية الموزعة

في Dataset A المرتبطة بالتقرير تطابقت القرارات في 5921/5921. في Dataset B تطابقت في 17416/17418 واختلفت حالتان بسبب عدم إتاحة الخادم المركزي. لا يجوز نقل عبارة التطابق الكامل من A إلى B. كل مقارنة موارد تخص مجموعة بياناتها ولا تثبت تفوق PBFT عاماً.

## الكثافة والهجمات

تُعرض نتائج كل كثافة باستخدام متوسط مقاييس البذور العشر، وتُعرض أعداد TP/FP/TN/FN كمجاميع. المتوسط الحسابي لمتوسطات Recall عبر الكثافات ليس هو Recall المجمع من أعداد الحالات؛ يجب تسمية كل منهما صراحة. في الهجمات التي لا تحتوي حالات موجبة يكون Recall غير معرّف (N/A). تبرز النتائج اختلافاً حسب نوع الهجوم: توجد استجابة أعلى في replay وcertificate tamper مقارنةً بـmixed، ولا يجوز تعميم Recall الهجمات السهلة على جميع الأنواع.

## نتائج التحقق الأوسع والاستكشافات

حملة v7 ذات 40 وحدة (أربع طوبولوجيات × عشرة بذور) تحقق أوسع مستقل؛ نتيجتها المجمعة 80.9% Recall لا تخص Scenario 5. نتائج Phase 6 (تحريك RSU)، وامتداد 8-RSU، وV5 ذي خمسة المدققين، واختيار المنسق الحتمي، وتجارب توافر الأدلة، كلها نتائج استكشافية منفصلة ولا تُدمج في قياسات المعمارية الأصلية.

## لغة الأمن المقبولة

اختُبر حد fail-closed اختياري أحادي العرض في نموذج V5، لكنه لا يطبق VIEW-CHANGE/NEW-VIEW ولا استعادة منسق آمنة. أُثبت في اختبار هجومي أن منسق الأدلة يستطيع حذف شهادات معارضة معلومة للمنسق، فيتغير قرار التأهيل. لذلك لا تدعم الدراسة ادعاء تحمّل Byzantine طرفاً إلى طرف أو اكتمال الأدلة. يجب قصر الادعاء على آليات النموذج وتحت افتراضات صريحة عن مصدر/منسق الأدلة.
"""
    limits = """# القيود والتهديدات النهائية

## صلاحية المقارنة والبيانات

- Dataset A من `review/scenario5-defense-report-v4@638a6d7` تطابق أرقام تقرير الدفاع: 5,921 هوية canonical لكل معمارية. Dataset B من `main@0c0c10b` هي `corrected_final` وتحتوي 17,418 هوية لكل معمارية؛ لا يثبت وجودها في main وحده أنها استبدلت التقرير المعتمد.
- Method B كما تنفذه `src/vpuft/metrics.py` ويثبته B يستبعد `already_revoked_terminal_state`. A لا يحتوي `previous_state` ولا هذا السبب ويعد كل صفوفه. Recall تقرير A ليس Method B. قرار اعتماد المجموعة النهائية غير محسوم.
- على المفتاح `(topology, density, seed, case_id)`: 5,095 هوية مشتركة بين نسختي Distributed، و826 في A فقط، و12,323 في B فقط. طابق ground truth ونوع الهجوم على المشترك، واختلف القرار في 300 حالة بين مراجعتَي البيانات؛ لا تسمح الملفات المتاحة بعزو سببي دقيق.
- ملفات تتبع SUMO الخام المشار إليها في تدقيق الحملتين ليست محفوظة في شجرة Git المتاحة، كما يحتوي تدقيق المسارات على مسارات Windows مطلقة. هذا يحد إعادة تشغيلهما مستقلاً من checkout فقط.
- أسماء البذور/الكثافات وحدها لا تثبت تطابق الأثر بين نسختي التقرير؛ أثر corrected-final ليس نسخة قابلة للاستبدال من الحملة الأصلية.

## تعريف المقاييس

- TP/FP/TN/FN وPrecision/Recall/FRR/F1/MCC في الحملة الأساسية تتبع سجلات قرار الحملة القديمة. لا تحتوي هذه السجلات على عمود استبعاد نوافذ ما بعد الإلغاء وفق البروتوكول اللاحق.
- مقاييس Recall في جدول الكثافة هي متوسطات Recall لكل بذرة؛ أما Recall المجمع فيحسب من مجموع TP/(TP+FN)، وهما رقمان مختلفان.
- Recall على فرص الهجوم الثابتة، والفرص المحمية بعد إلغاء سابق، ومقاييس Phase 6 ليست متاحة في مجموعة Scenario 5 الأساسية. لا تُستنتج من Recall الحالة.
- P95 E2E هو متوسط قيم P95 لكل بذرة لزمن القرار من فتح الحالة إلى إنهائها ويتأثر بنافذة الحالة؛ ليس زمن حزمة شبكة.
- CPU وقت عملية المحاكاة على بيئة القياس، لا CPU جهاز إنتاج. Messages/decision وPDR وledger delay نتائج نموذجية. PDR نسبة التسليم إلى المحاولات كما ينفذها النموذج.
- تأخير اتساق السجل المركزي (نحو 1ms في هذه المحاكاة) والموزع (نحو 14–16ms) ينتجان من آليتين مختلفتين؛ لا يُقدمان كاختبار متماثل للتوافق.

## التهديدات الأمنية

- حذف منسق الأدلة أدلة معارضة سبق أن استلمها يمكن أن يحول حزمة غير مؤهلة إلى حزمة تؤدي إلى الإلغاء. تحقق التوقيع لا يثبت اكتمال المجموعة.
- لا يمكن اكتشاف دليل لم يعلنه مصدره أو لم يصل إلى أي مدقق أمين دون بروتوكول إتاحة/افتراضات تسليم إضافية.
- V5/quorum 4-of-5 وf=1 لا يثبتان وحدهما سلامة PBFT عبر العروض. حد single-view fail-closed يمنع الانتقال غير الموثق في نطاق الاختبار، لكنه لا يوفر استعادة view أو liveness تلقائية.
- لا توجد شهادة نهائية على الاستعادة الآمنة لمنسق الأدلة أو قائد PBFT، ولا ضمان تحمل Byzantine شامل عبر جميع الطبقات.
- حدود المجالات الإدارية قد تكون مترابطة؛ عدد العقد ليس دليلاً على استقلال مؤسسي.

## الصلاحية الخارجية

الرادار/الاستشعار يستخدم نموذج مدى هندسي ومسارات اتصالات محاكاة، لا قياس RF ميدانياً أو حجباً/تركيباً فعلياً. نتائج placement و8-RSU استكشافية، كما بقيت مسارات radio ثابتة عند تحريك بعض RSUs في تقييم Phase 6. لا تُعمم النتائج على شبكة تشغيل حقيقية.
"""
    correction = """# خطة تصحيح فصل Scenario 5 — دون إعادة كتابة الفصل

1. **العنوان والنطاق:** عرّف Scenario 5 بأنه Urban Roundabout واذكر تعارض Dataset A المرتبطة بالتقرير مع Dataset B التي تطبق Method B. لا تثبت أرقاماً نهائية قبل قرار اعتماد موثق؛ إن كان المطلوب إعادة إنتاج التقرير فاعرض A، وإن كان Method B هو المنهج المعتمد فاعرض B مع تصحيح التقرير.
2. **المنهج:** أضف مرجع الحملة والـmanifest، التصميم paired/shared-trace، نسبة مركبات الهجوم 0.35، الأوزان الخمسة كما في manifest، وافصل تحميل C100 الإضافي 100ms عن زمن الموزع. اذكر أن القياسات مخرجات محاكاة.
3. **تعريف القياس:** وضح أن أعداد الارتباك مجاميع لعشر بذور، بينما مقاييس الدقة/Recall/F1/MCC والموارد متوسطات seed-level عند كل كثافة. أضف معادلات المقاييس، واجعل strata دون موجبات N/A. لا تصفها بأنها fixed-opportunity Recall أو state-aware post-revocation evaluation.
4. **جدول نتائج الكثافة:** استخرج أرقام C100 وDistributed من مجموعة واحدة معتمدة. A فيها اتفاق 5921/5921، وB فيها 17416/17418 مع حالتي اختلاف موثقتين. احتفظ بوسوم المتوسطات مقابل المجاميع ولا تنقل أرقام v7.
5. **جدول الهجمات:** احتفظ بصفوف كل نوع هجوم وأعداد الحالات. اجعل Recall للهجمات ذات TP+FN=0 هو N/A؛ أبرز أن الأداء يختلف حسب الهجوم ولا تستنتج ضماناً عاماً.
6. **الأداء والسجل:** احتفظ بجدول P95 E2E وCPU والرسائل/قرار والبايتات وPDR وتأخير اتساق السجل. سمِّ P95 بأنه متوسط P95 البذور، وCPU بأنه وقت العملية. ناقش أن C100 مقابل Distributed ليس مقارنة بروتوكول متماثلة، وأن توافق القرارات متطابق في هذه الحملة.
7. **التحقق الأوسع:** انقل نتائج v7 (40 وحدة/4 طوبولوجيات) إلى فقرة أو ملحق منفصل بعنوان «تحقق أوسع»، واكتب صراحة أن Recall 80.9% ليست نتيجة Scenario 5.
8. **الامتدادات:** ضع Phase 6 و8-RSU وV5/coordinator/evidence availability في قسم استكشافي أو ملحق، كل حملة بتعريفها ومقاييسها. أظهر رفض مرشحي 8-RSU/evidence batching حيث أخفقوا بوابات التكلفة/الأمان.
9. **الأمن والقيود:** أضف هجوم حذف الأدلة المعارضة، قيد single-view، غياب استعادة المنسق وVIEW-CHANGE/NEW-VIEW، وعدم إثبات BFT طرفاً إلى طرف. عدل كل عبارة «Byzantine tolerant» إلى وصف مشروط بما اختبر فعلاً.
10. **الخلاصة:** قصر الاستنتاج على توافق قرارات C100 والموزع ونتائج التكلفة/الكثافة داخل سيناريو المحاكاة؛ افصل بين ما قيس وما افترض وما بقي غير مثبت.

**قرار الجداول:** الأرقام الحالية في التقرير تطابق A ويمكن إبقاؤها لإعادة إنتاج التقرير التاريخي، لكنها ليست Method B. إذا كان Method B هو التعريف المعتمد في الرسالة، فاعرض B في إصدار منفصل وصحح التقرير دون الكتابة فوق النسخة المجمدة. جداول v7 وpost-seminar تظل منفصلة.
"""
    (OUT / "FINAL_THESIS_CLAIMS_AR.md").write_text(claims, encoding="utf-8")
    (OUT / "FINAL_LIMITATIONS_AND_THREATS_AR.md").write_text(limits, encoding="utf-8")
    (OUT / "FINAL_CHAPTER5_CORRECTION_PLAN_AR.md").write_text(correction, encoding="utf-8")


def manifest() -> dict:
    scenario_files = [
        "results/urban_roundabout_campaign/combined/density_campaign_manifest.json",
        "results/urban_roundabout_campaign/combined/DENSITY_RESULTS_AUDIT.md",
        "results/urban_roundabout_campaign/combined/density_architecture_summary.csv",
        "results/urban_roundabout_campaign/combined/density_metrics_by_seed.csv",
        "results/urban_roundabout_campaign/combined/density_decisions.csv",
        "results/urban_roundabout_campaign/combined/density_attack_metrics_by_seed.csv",
        "results/urban_roundabout_campaign/combined/density_case_agreement.csv",
        "results/urban_roundabout_campaign/combined/density_consensus_outcomes.csv",
        "results/urban_roundabout_campaign/combined/density_message_type_architecture_summary.csv",
        "results/urban_roundabout_campaign/combined/density_trace_audit.csv",
    ]
    files = []
    for p in scenario_files:
        b = git_bytes(SCENARIO_REF, p)
        files.append({"path": p, "ref": f"{SCENARIO_REF}@{SCENARIO_COMMIT}", "sha256": sha(b), "status": "frozen report-linked Dataset A source", "role": "supports the published Scenario 5 defense report; not Method B"})
    for ref, commit, paths, status, role in [
        ("main", MAIN_COMMIT, ["docs/final_chapter5/VPUFT_Scenario5_Defense_Report_Final.html"], "frozen report", "Scenario 5 report HTML; its linked Dataset A aggregate path is on review branch, not this main tree"),
        ("main", MAIN_COMMIT, ["results/full_campaign_v7/statistical_inference/SUMMARY.md", "results/full_campaign_v7/statistical_inference/inference_manifest.json", "results/full_campaign_v7/case_agreement/SUMMARY.md"], "frozen supplementary validation", "v7 broader campaign; not Scenario 5 results"),
        ("research/vpuft-post-seminar-optimization", "fdca82f6a3fd5273df454bee709a2800f97f941a", ["docs/post_seminar/PHASE_6_FINAL_HELDOUT_RESULTS.md", "docs/post_seminar/PHASE_6_COVERAGE_FEASIBILITY.md", "docs/post_seminar/PHASE_4_EVIDENCE_LIFECYCLE_AUDIT.md"], "experimental/post-seminar", "separate opportunity/state-aware diagnostics; not primary Scenario 5 campaign"),
        ("main", MAIN_COMMIT, ["results/urban_roundabout_campaign_corrected_final/combined/density_campaign_manifest.json", "results/urban_roundabout_campaign_corrected_final/combined/density_metrics_by_seed.csv", "results/urban_roundabout_campaign_corrected_final/combined/density_decisions.csv", "results/urban_roundabout_campaign_corrected_final/combined/density_trace_audit.csv", "results/urban_roundabout_campaign_corrected_final/effective_config.json"], "frozen corrected-final Dataset B", "Method B state-aware Scenario 5 revision; separate from report-linked Dataset A"),
        ("research/recall-70-feasibility", "96a7e903438c7316c25ed5e4b2e2cad433229224", ["docs/post_seminar/PHASE_6_8RSU_PILOT_AR.md"], "rejected pilot", "8-RSU sensing extension; resource gates failed"),
        ("research/vpuft-v5-validator-prototype", "4687266bae35d680d77730b1dd4d929a6ea57900", ["docs/post_seminar/V5_VALIDATOR_ARCHITECTURE.md"], "experimental", "V5 committee/quorum exploratory architecture"),
        ("security/coordinator-evidence-v5", "abe80d00a7a9b2bbc8d722c449f4c401827bab8f", ["docs/post_seminar/COORDINATOR_ASSUMPTIONS.md"], "experimental", "deterministic coordinator extension"),
        ("security/v5-evidence-availability", "2df02a0f17dc4782b833b882edbc3ec30c1e8e8d", ["docs/post_seminar/EVIDENCE_AVAILABILITY_V5.md"], "security reference; rejected performance profile", "evidence availability prototype; resource gate failed"),
        ("security/v5-evidence-availability-optimization", "944d65b15711c8a79b94b4355c27211148b30ac5", ["docs/post_seminar/EVIDENCE_AVAILABILITY_OPTIMIZATION_NO_GO_AR.md"], "rejected", "time-delaying batch optimization; lost a TP / gate failures"),
        ("security/v5-cross-view-safety", "5c344e0a9a0590c8dbb055208c8a18e86e4ab7f7", ["docs/post_seminar/V5_SINGLE_VIEW_SAFETY_BOUNDARY.md"], "experimental safeguard", "opt-in single-view fail-closed boundary; not full PBFT"),
        ("security/evidence-omission-feasibility", "d6fa44df28788f3497a0e7e209c28d7b354c7a94", ["docs/post_seminar/V5_EVIDENCE_OMISSION_FEASIBILITY_GATE_AR.md"], "unresolved security limitation", "demonstrated coordinator omission counterexample"),
    ]:
        for p in paths:
            try:
                b = git_bytes(ref, p)
                files.append({"path": p, "ref": f"{ref}@{commit}", "sha256": sha(b), "status": status, "role": role})
            except subprocess.CalledProcessError:
                files.append({"path": p, "ref": f"{ref}@{commit}", "sha256": None, "status": status, "role": role+"; cited path absent at ref, see branch report/index"})
    return {
        "package": "V-PUFT Final Scenario 5 Evidence Freeze",
        "generated_at": "2026-11-15",
        "read_only_analysis": True,
        "scenario5_source_of_truth_status": "UNRESOLVED BETWEEN REPORT-LINKED DATASET A AND METHOD-B DATASET B",
        "dataset_a_report_linked": {"branch": SCENARIO_REF, "commit": SCENARIO_COMMIT, "canonical_cases_per_architecture": 5921, "confusion_totals_distributed": {"TP":396,"FP":63,"TN":5182,"FN":280}, "central_vs_distributed_identity_agreement": "5921/5921", "metrics_semantics": "historical case-record counts; no explicit terminal-state exclusion"},
        "dataset_b_method_b": {"branch": "main", "commit": MAIN_COMMIT, "canonical_case_rows_per_architecture": 17418, "central_c100_evaluated": 14593, "central_c100_excluded_terminal": 2825, "distributed_evaluated": 14585, "distributed_excluded_terminal": 2833, "confusion_totals_c100": {"TP":639,"FP":9,"TN":12981,"FN":964}, "confusion_totals_distributed": {"TP":641,"FP":9,"TN":12974,"FN":961}, "central_vs_distributed_identity_agreement": "17416/17418", "metrics_semantics": "metrics.py excludes already_revoked_terminal_state rows"},
        "dataset_a_vs_b_identity_comparison": {"canonical_key":"(topology, vehicle_count, seed, case_id)","shared":5095,"A_only":826,"B_only":12323,"shared_ground_truth_mismatches":0,"shared_attack_type_mismatches":0,"shared_decision_mismatches_between_revisions":300},
        "core_current_branch": {"branch": "research/vpuft-post-seminar-optimization", "commit": "fdca82f6a3fd5273df454bee709a2800f97f941a"},
        "v7_supplement": {"campaign_units": 40, "topologies": ["corridor", "grid", "intersection", "smoke"], "seeds_per_topology": 10, "recall_80_9_percent_scenario5_use": False},
        "artifact_status": {"historical_sources_modified": False, "simulations_run": False, "existing_worktree_dirty_before_package": True, "preexisting_untracked_and_deleted_artifacts_preserved": True, "raw_scenario5_traces_in_git": False, "trace_audit_uses_machine_local_absolute_paths": True},
        "files": files,
        "hash_note": "SHA-256 values are computed over the exact Git blob bytes shown by each ref/path. Missing cited paths are explicitly marked rather than inferred.",
    }


def main() -> None:
    write_csv(OUT / "FINAL_SCENARIO5_EVIDENCE_MATRIX.csv", scenario_rows())
    package_docs()
    (OUT / "FINAL_EXPERIMENT_FREEZE_MANIFEST.json").write_text(json.dumps(manifest(), indent=2, ensure_ascii=False)+"\n", encoding="utf-8")


if __name__ == "__main__":
    main()
