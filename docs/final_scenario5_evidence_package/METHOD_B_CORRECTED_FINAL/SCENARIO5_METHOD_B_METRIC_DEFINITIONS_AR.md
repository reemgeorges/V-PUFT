# تعريفات مقاييس Scenario 5 Method B

**وحدة العد:** سجل نافذة قرار في `density_decisions.csv` ضمن (topology, vehicle_count, seed, case_id). الحقيقة هي `ground_truth_malicious`. التنبؤ الإيجابي هو `committed=1` و`new_state=revoked`. تستبعد Method B فقط السجلات التي تحمل `reason=already_revoked_terminal_state` من TP/FP/TN/FN؛ تبقى هذه النوافذ في العدد الخام وتُحصى منفصلة.

- TP: حالة خبيثة أُبطلت بقرار ملتزم؛ FP: حالة حميدة أُبطلت؛ TN: حالة حميدة لم تُبطل؛ FN: حالة خبيثة لم تُبطل.
- Precision = TP/(TP+FP).
- State-aware Recall = TP/(TP+FN) بعد استبعاد النوافذ الطرفية؛ يتغير مقامه بتغير توقيت الإبطال.
- FRR = FP/(FP+TN)، أي معدل الإبطال الكاذب بين الحالات الحميدة المؤهلة.
- F1 = 2PR/(P+R).
- MCC = (TP·TN−FP·FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN)).
- القسمة على مقام صفري تُرجع صفراً وفق `_safe_div` في التنفيذ.
- All-window confusion counts وصفية وتشمل النوافذ الطرفية؛ ليست بديلاً عن Method B.
- Fixed-denominator opportunity Recall وprotected-opportunity fraction غير متوفرين في Dataset B، ولا يجوز استنتاجهما من state-aware Recall.

**الأداء:** `latency_p95_ms` هو P95 E2E المسجل من فتح الحالة إلى إنهائها؛ `cpu_time_seconds` هو CPU المسجل لكل تشغيل؛ `messages_per_decision` هو مؤشر الرسائل لكل قرار كما سجله التشغيل؛ `packet_delivery_ratio` هو PDR المسجل. P95 ledger هو مئين 95 لـ `ledger_available_at - finalized_at` بعد الإنهاء. P95 consensus هو مئين 95 لـ `finalized_at - qualified_at`.

**التجميع:** pooled يجمع TP/FP/TN/FN على البذور أولاً ثم يحسب النسبة. Macro يحسب النسبة لكل seed ثم يأخذ المتوسط الحسابي غير الموزون. قيم الأداء لكل كثافة متوسط حسابي لعشر قيم seed-level، وليست pooled percentile.

لا يوجد تعريف موثق في هذه الحملة لنسبة overhead موحدة للإجماع أو السجل. decision CSV لا يحتوي على `opened_at` أو عينات profiler؛ لذلك لا يمكن إعادة بناء CPU أو P95 E2E مستقلاً. ملفات mobility/attack الخام غير متاحة ضمن مجلد الحملة.
