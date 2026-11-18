# تسليم المراجعة العلمية المستقلة إلى Claude — قراءة فقط

راجع commit الدمج على main دون تشغيل SUMO أو إعادة حساب النتائج أو تعديل الملفات.

## أسئلة التدقيق

1. **Dataset A مقابل Dataset B:** سجل التجميد يعلن أن مصدر الحقيقة غير محسوم. Dataset A مرتبطة بتقرير الدفاع وتضم 5,921 سجلاً وفق المصدر؛ Dataset B هي corrected-final Method B وتستبعد نوافذ ما بعد REVOKED. حدد نطاق الرسالة والتقرير الذي اعتمدته الكلية قبل اعتماد الجداول، ولا تخلط المجموعتين.
2. راجع الحزمة docs/final_scenario5_evidence_package/METHOD_B_CORRECTED_FINAL وتعريف المقامات والتجميع، ولا تعِد تسمية Recall التاريخي.
3. افصل v7 وPhase 6 و8-RSU وV5 والحساسية وAblation عن نتائج Scenario 5 الأصلية.
4. دقق مثال حجب الأدلة، وغياب إثبات اكتمال الحزمة، وعدم توفر استعادة آمنة للمنسق، وعدم إثبات سلامة PBFT عبر views.
5. راجع pooled مقابل macro، والنوافذ الطرفية بعد الإلغاء، وكشف فرص الهجوم مقابل الحماية، وتوفر traces.
6. طابق PROVENANCE_INDEX.json وبصمات SHA-256، وحدد المواد المحلية غير الموجودة في Git.

## المواد الأساسية

PROJECT_MASTER_INDEX_AR.md، EXPERIMENT_REGISTER.csv، POST_SEMINAR_COMPARISON_AR.md، CLAIMS_AND_LIMITATIONS_AR.md، PROVENANCE_INDEX.json، وdocs/post_seminar/POST_SEMINAR_ARCHIVE_INDEX.md.

صنّف كل ملاحظة إلى: مانع علمي، تصحيح ادعاء أو جدول، تحسين عرض، أو مقبول. لا تعدل المستودع أثناء التدقيق.
