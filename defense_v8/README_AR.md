# V-PUFT Defense v8 — Phase A Final

هذه الحزمة هي النسخة المصححة للمرحلة A بعد كل المراجعات الأخيرة.

## المبدأ الحاكم

- **v7 تبقى مجمدة ولا يتم تعديلها.**
- لا إعادة SUMO.
- لا إعادة detector.
- لا إعادة sensor rebuild.
- لا إعادة calibration أو candidate search.
- لا تغيير candidate 650.
- لا تغيير الأوزان أو Mixed policy.
- المرحلة A = تحليل إحصائي/تفسيري فقط فوق نتائج v7 المجمدة.

## أين تضع المجلد؟

فك الضغط من جذر المشروع:

`C:\Users\reemg\OneDrive\Desktop\master\6\v10`

بعد الفك يصبح عندك:

`v10\defense_v8\`

ولا تنقل ملفات v7 ولا تستبدل أي ملف من `src/` أو `results/full_campaign_v7/`.

## ماذا تم تصحيحه؟

### paired_stats_v8.py
- Stratified cluster bootstrap داخل كل topology مع الحفاظ على 10/10/10/10.
- Wilcoxon + paired permutation.
- Matched-pairs rank-biserial + Cohen's dz.
- Holm فقط للعائلة الأساسية: Recall / FRR / MCC.
- النتائج الثانوية معلّمة Exploratory وغير مصححة.
- Attack-specific recall معلّم صراحةً **Exploratory / unadjusted for multiplicity**.
- تم إدخال جدول الهجمات داخل SUMMARY.md نفسه.
- benign مستبعد من attack-specific recall.
- SHA-256 لملفات الإدخال يسجل في manifest.

### case_agreement_v8.py
- لا يوجد `drop_duplicates()` صامت.
- أي duplicate case key يؤدي إلى FAIL CLOSED وexit 2.
- المفتاح يجب أن يكون `(topology, seed, case_id)`.
- Ground-truth يجب أن يتطابق بين المعماريات للحالة المشتركة.
- attack_type يجب أن يتطابق للحالة المشتركة.
- n_cases_A/B/shared/A-only/B-only قبل الاتفاق.
- Exact McNemar عندما discordant <= 25.
- النص النهائي لا يدّعي أن evidence sets متطابقة لمجرد أن القرارات متطابقة.
- SHA-256 للـfinal_decisions يسجل في manifest.

### latency_decomposition_v8.py
- لا يعيد بناء case_opened_at.
- يقرأ stage P95 مباشرة من `final_metrics_by_seed.csv`.
- لا stacked bars.
- لا sum-of-P95.
- لا share-of-total.
- Detection لم يعد موسوماً بأنه "shared by construction".
- Detection/evidence acquisition قد يتأثر بالـevidence view ومسار النقل.
- Finalization هو أنظف مرحلة لمقارنة Central vs PBFT.
- SHA-256 للمدخل يسجل في manifest.

### frozen_contract_v8.py
- أوزان candidate 650 تطابق حرفياً.
- Mixed.required_modalities == 1.
- sum(weights) == 1.
- يسجل hashes للـtraces.
- إذا وجد `FINAL_FREEZE_v7_20260809/EXTERNAL_ARTIFACT_HASHES.csv` يقارن hash الكونفيغ الحالي بالـfreeze ويوقف عند الاختلاف.

## التشغيل

من PowerShell داخل `v10`:

```powershell
.\defense_v8\run_phase_a.ps1
```

السكربت يبدأ بفحص Frozen Contract. إذا فشل الفحص، يتوقف ولا يشغل أي تحليل.

## المخرجات

- `results/full_campaign_v7/statistical_inference/`
- `results/full_campaign_v7/case_agreement/`
- `results/full_campaign_v7/latency_decomposition/`
- `results/full_campaign_v7/defense_v8_contract_manifest.json`

بعد انتهاء Phase A أرسل:
1. `statistical_inference/SUMMARY.md`
2. `case_agreement/SUMMARY.md`
3. `latency_decomposition/SUMMARY.md`

ولا تشغل Phase B robustness قبل مراجعة هذه الثلاثة.
