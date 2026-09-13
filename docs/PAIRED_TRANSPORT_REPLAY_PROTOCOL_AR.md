# بروتوكول إعادة التشغيل المقترنة لعشوائية النقل

## لماذا نحتاج هذا التحليل؟

استخدمت حملة الكثافة الأصلية أثر SUMO وحالات أدلة مشتركة، لكنها استخدمت تياري
عشوائية مختلفين للنقل في المركزي والموزع. لذلك لا يمكن إسناد الفروق التصنيفية
الصغيرة إلى المعمارية وحدها. يعالج هذا الامتداد المشكلة دون إعادة SUMO.

## ماذا يفعل؟

لكل EvidenceAttestation يولد مفتاحاً مستقراً من معرف الدليل والبذرة. إذا نُقل
الدليل في كلا المسارين، يحصل على سحب فقد وjitter وإعادة محاولة مطابق. لا تتأثر
هذه السحوبات بإرسال رسائل PBFT إضافية أو باختلاف ترتيب الرسائل.

لا يجعل ذلك المسارين متطابقين مصطنعاً:

- دليل موجود لدى المنسق الموزع يبقى محلياً ولا يدفع hop لاسلكياً.
- طابور الخادم يبقى خاصاً بالمركزي.
- إعادة التأهيل وPBFT والنسخ تبقى كلفة موزعة.
- queueing يبقى بحسب روابط كل معمارية.

## المقارنات الثلاث لكل خلية

1. `distributed_crn_honest`.
2. `central_crn_available_0ms` مع `availability=1.0` لعزل مسار المعمارية.
3. `central_crn_operational_0ms` مع `availability=0.995` لعزل أثر نموذج توافر الخادم.

تشغّل هذه المقارنات على 200 أثر محفوظ، أي 600 تشغيل معماري. لا تعاد محاكاة
الحركة أو الكشف. مستويات backhaul من 20 إلى 200 ms تشتق بعد ذلك من التشغيل
المركزي 0 ms لأن التنفيذ يضيف التأخير أحادي الاتجاه خطياً؛ وقد ثبت ذلك في جميع
خلايا الحملة الأصلية.

## حدود الادعاء

هذا تحليل حساسية post-hoc يبقى استكشافياً. يحسن الإسناد السببي داخل نموذج
المحاكاة، لكنه لا يحول الزمن إلى قياس ميداني ولا يثبت أمان PBFT إنتاجياً.

## التشغيل على PowerShell

من جذر المشروع وبعد تفعيل `.venv`:

```powershell
python -m pip install -e .
python -m pytest -q -ra
& .\scripts\run_paired_transport_replay.ps1
```

إذا انقطع التشغيل، يعاد الأمر الأخير نفسه؛ الخيار `--resume` يكمل الخلايا
المكتملة ولا يعيدها.

## متابعة التقدم

```powershell
$Done = (
    Get-ChildItem `
        "$env:USERPROFILE\VPUFT_density_paired_replay\cells" `
        -Filter cell_complete.json `
        -File `
        -Recurse `
        -ErrorAction SilentlyContinue
).Count

[PSCustomObject]@{
    Completed = $Done
    Total = 200
    Percent = [math]::Round(($Done / 200) * 100, 1)
    Remaining = 200 - $Done
}
```

## المخرجات النهائية

توجد في:

`%USERPROFILE%\VPUFT_density_paired_replay\combined`

وأهمها:

- `PAIRED_TRANSPORT_RESULTS_AUDIT.md`
- `paired_metrics_by_seed.csv`
- `paired_pooled_confusion.csv`
- `paired_case_agreement.csv`
- `paired_classification_flips.csv`
- `paired_breakeven.csv`
- `paired_core_comparisons.csv`
- `paired_message_type_architecture_summary.csv`
- `paired_remote_derived_metrics.csv`
