# تعديلات الفصل الخامس المطلوبة الآن

<!-- POST_CLAUDE_REMEDIATION_V3 -->
## ملحق إلزامي بعد التدقيق المستقل

هذه النقاط تكمل التعليمات أدناه وتصبح المرجع الأحدث:

1. Centralized وDistributed يستهلكان `bundle.rsu_cases`، بينما Ahmed-Inspired يستهلك `bundle.witness_cases`.
   لذلك Ahmed↔RSU ليست ablation لعامل واحد ولا يجوز نسبة فرق Recall إلى Blockchain/PBFT/الشهود وحدهم.
2. لا تستخدم «كثافة الجذور» كتفسير سببي منفرد؛ التحليل الموسع يدعم حزمة عوامل مترابطة
   (نوع الحساس، الضجيج، المدى، الكثافة، hops، freshness).
3. التسليم الفعلي شبه الكامل يستبعد packet loss كتفسير عملي للفروق المرصودة، لكنه لا يثبت أن transport
   غير مؤثر من حيث المبدأ لأن arrival time يدخل في freshness.
4. MCC يبقى وصفياً فقط؛ Holm-adjusted p≈0.1986 في التحليل الكامل و1.0000 بعد استبعاد smoke.
5. قورنت تجريبياً طرق دمج المصادقة وتبادل الرسائل بين المعماريات مع تثبيت Ed25519 لضبط المقارنة؛ أما benchmark لمختلف cryptographic primitives/PKI/Group/Ring/Threshold Ring فلم يُنفذ ويبقى Related Work.
6. `independent_roots` مفقود تاريخياً من Ahmed decisions؛ إصلاح الكود للتشغيلات المستقبلية فقط دون backfill.
7. إعادة الإنتاج يجب أن تستخدم Git LFS والأوزان من
   `results/full_campaign_v7/sensitivity_shared_views_mixedfix/selected_weights.json`.

## 1) تصحيح قسم PBFT / Safety فوراً

احذف أي جملة من نوع:

> لم تسجل انتهاكات Safety أو حالات Liveness Failure أو View Change.

واستخدم حالياً:

> حققت المعماريتان الموزعتان نجاحاً كاملاً لمرحلة الإجماع ضمن ظروف الحملة النهائية، ولم تسجل الحملة حالات فشل حيوية أو تغيير قائد. أما انتهاكات الأمان Safety Violations فلا تُقدَّم في هذه الدراسة بوصفها نتيجة تجريبية للحملة الأساسية، لأن محرك الإجماع المجمد لم يتضمن مولداً لاقتراحات خبيثة ذات حمولة غير صحيحة، كما أن مؤشر `safety_violation` لم يكن مسار قياس تشغيلياً يمكن أن يتحول إلى حالة موجبة في هذه الحملة. لذلك يقتصر الاستنتاج التجريبي الحالي على نجاح الإجماع والحيوية ضمن ظروف الاختبار، بينما يبقى اختبار Safety تحت malicious semantic proposals ضمن حدود الدراسة/العمل اللاحق.

ولا تكتب بعد الآن أن Safety = 0 "تم قياسها".

## 2) قسم Latency

لا تكتب أن نافذة Detection مشتركة بين المعماريات "by construction".
بعد تشغيل `latency_decomposition_v8.py` استخدم `SUMMARY.md` الناتج.

## 3) قسم 5.17 Centralized vs Distributed

لا تثبّت الصياغة النهائية قبل تشغيل `case_agreement_v8.py`.
- إذا agreement < 1: المجاميع متطابقة لكن بعض الحالات مختلفة.
- إذا agreement = 1: التصنيف متطابق على shared cases، لكن لا ندعي أن evidence sets الداخلية متطابقة دون قياس مباشر.

## 4) الإحصاء

بعد `paired_stats_v8.py`:
- Recall / FRR / MCC = primary family مع Holm.
- Precision / F1 / latency / messages / bytes / memory = exploratory.
- تحليل كل هجوم منفرد = exploratory attack-stratified bootstrap وغير مصحح لتعدد المقارنات.
- إذا CI للهجوم لا يشمل الصفر، قل: "اتجاه الفرق بقي مستقراً ضمن التحليل الاستكشافي".
- لا تقل: "ثبتت الدلالة الإحصائية" للهجوم المنفرد إلا إذا صُمم له اختبار confirmatory مسبقاً.

## 5) selection_feasible=false

> تم تحديد Recall ≥ 0.95 وFRR ≤ 0.05 بوصفهما أهداف feasibility مسبقة قبل اختيار المرشح النهائي، وليس بوصفهما ضماناً بأن بيانات الدراسة ستسمح بتحقيقهما. وعندما لم يحقق أي مرشح الشرطين عبر أسوأ fold × evidence-view، أبقينا `selection_feasible=false` ولم نخفض الحدود بعد الاطلاع على النتائج.

لا تقل إن 0.95 معيار عالمي شائع إلا مع مرجع صريح.
