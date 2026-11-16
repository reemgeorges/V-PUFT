# تكرار تحليل الحساسية — نتائج وحدود التنفيذ

## حالة الحملة

- الآثار المشتركة المُولّدة: **12/12**.
- خلايا المعمارية المكتملة: **103/120**؛ لا تُعامل الخلايا غير المنفذة كإخفاقات تجريبية.
- زمن التشغيل المسجل: **3651.8 ثانية** مقابل حد preregistration البالغ 3600 ثانية.
- تجاوز الحد: **51.8 ثانية** بسبب خلية بدأت قبل الحد وأكملت checkpoint بعدها؛ لم تبدأ خلية أخرى.
- حجم مجلد التنفيذ: **2,007,798,978 بايت** مقابل حد 3,000,000,000 بايت.
- الخلايا الناقصة: **17**. لا توجد نتيجة تُنسب إليها.
- وحدة التكرار الإحصائية هي seed. استخدمت المقارنات المزدوجة بذورًا مكتملة في baseline والنسخة المقابلة معًا.
- استخدام المصدر الواحد (`position_offset.required_sources=1`) اختبار ضغط لسياسة أضعف، وليس توصية.

## النتائج المزدوجة

يعرض الجدول فروق المتوسطات على مستوى البذور بين كل إعداد وخط الأساس المطابق، مع فواصل t وصفية 95%. بسبب صغر n، لا تُفهم الفواصل أو اتجاهات البذور كاختبار دلالة أو تعميم واسع.

| الكثافة | المعمارية | الإعداد | n | البذور | Δ Recall الحالة [95% CI] | Δ Recall فرص الهجوم [95% CI] | Δ FRR | Δ TP pooled | Δ FP pooled | Δ CPU (ث) | Δ P95 E2E (ms) | Δ رسائل/حالة |
|---:|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 20 | C100 | freshness_12s | 6 | 7003;7004;7005;7006;7007;7008 | -0.0152 [-0.0541, +0.0238] | -0.0137 [-0.0364, +0.0089] | -0.0020 | -1 | -1 | -0.021 | +0.265 | +0.000 |
| 20 | C100 | freshness_30s | 6 | 7003;7004;7005;7006;7007;7008 | +0.0000 [+0.0000, +0.0000] | +0.0000 [+0.0000, +0.0000] | +0.0000 | +0 | +0 | +0.031 | +0.000 | +0.000 |
| 20 | C100 | position_sources_1 | 6 | 7003;7004;7005;7006;7007;7008 | +0.0000 [+0.0000, +0.0000] | +0.0000 [+0.0000, +0.0000] | +0.0000 | +0 | +0 | +0.042 | +0.000 | +0.000 |
| 20 | C100 | position_sources_3 | 6 | 7003;7004;7005;7006;7007;7008 | -0.0909 [-0.0909, -0.0909] | -0.0353 [-0.0353, -0.0353] | -0.0001 | -6 | +0 | +0.042 | +2.120 | +0.000 |
| 20 | Distributed | freshness_12s | 6 | 7003;7004;7005;7006;7007;7008 | -0.0152 [-0.0541, +0.0238] | -0.0137 [-0.0364, +0.0089] | -0.0020 | -1 | -1 | -0.034 | -0.585 | -0.103 |
| 20 | Distributed | freshness_30s | 6 | 7003;7004;7005;7006;7007;7008 | +0.0000 [+0.0000, +0.0000] | +0.0000 [+0.0000, +0.0000] | +0.0000 | +0 | +0 | +0.089 | +0.000 | +0.000 |
| 20 | Distributed | position_sources_1 | 6 | 7003;7004;7005;7006;7007;7008 | +0.0000 [+0.0000, +0.0000] | +0.0000 [+0.0000, +0.0000] | +0.0000 | +0 | +0 | +0.031 | +0.000 | +0.000 |
| 20 | Distributed | position_sources_3 | 6 | 7003;7004;7005;7006;7007;7008 | -0.0909 [-0.0909, -0.0909] | -0.0353 [-0.0353, -0.0353] | -0.0001 | -6 | +0 | -0.008 | -0.993 | -0.299 |
| 100 | C100 | freshness_12s | 4 | 7003;7004;7005;7006 | -0.0447 [-0.0745, -0.0148] | -0.0759 [-0.1211, -0.0306] | -0.0012 | -8 | -2 | -0.188 | +2.348 | +0.000 |
| 100 | C100 | freshness_30s | 4 | 7003;7004;7005;7006 | +0.0000 [+0.0000, +0.0000] | +0.0000 [+0.0000, +0.0000] | +0.0000 | +0 | +0 | +0.211 | +0.000 | +0.000 |
| 100 | C100 | position_sources_1 | 4 | 7003;7004;7005;7006 | +0.0000 [+0.0000, +0.0000] | +0.0000 [+0.0000, +0.0000] | +0.0000 | +0 | +0 | -0.156 | +0.000 | +0.000 |
| 100 | C100 | position_sources_3 | 4 | 7003;7004;7005;7006 | -0.0657 [-0.0863, -0.0451] | -0.0216 [-0.0277, -0.0156] | -0.0000 | -11 | +0 | +0.004 | +5.164 | +0.000 |
| 100 | Distributed | freshness_12s | 4 | 7003;7004;7005;7006 | -0.0447 [-0.0745, -0.0148] | -0.0759 [-0.1211, -0.0306] | -0.0012 | -8 | -2 | -0.246 | -4.254 | -0.157 |
| 100 | Distributed | freshness_30s | 4 | 7003;7004;7005;7006 | +0.0000 [+0.0000, +0.0000] | +0.0000 [+0.0000, +0.0000] | +0.0000 | +0 | +0 | +0.367 | +0.000 | +0.000 |
| 100 | Distributed | position_sources_1 | 4 | 7003;7004;7005;7006 | +0.0000 [+0.0000, +0.0000] | +0.0000 [+0.0000, +0.0000] | +0.0000 | +0 | +0 | +0.270 | +0.000 | +0.000 |
| 100 | Distributed | position_sources_3 | 4 | 7003;7004;7005;7006 | -0.0657 [-0.0863, -0.0451] | -0.0216 [-0.0277, -0.0156] | -0.0000 | -11 | +0 | -0.035 | -0.419 | -0.170 |

## اختلاف C100 وDistributed

الفروق التالية محسوبة على trace وseed نفسيهما. الفرق الإيجابي يعني Distributed − C100.
| الإعداد | الكثافة | المقياس | n | الفرق المتوسط | 95% CI |
|---|---:|---|---:|---:|---:|
| baseline | 20 | malicious_revocation_recall | 6 | +0.0000 | [+0.0000, +0.0000] |
| baseline | 20 | false_revocation_rate | 6 | +0.0000 | [+0.0000, +0.0000] |
| baseline | 20 | opportunity_detection_recall | 6 | +0.0000 | [+0.0000, +0.0000] |
| baseline | 20 | cpu_time_seconds | 6 | +0.0234 | [-0.0302, +0.0771] |
| baseline | 20 | latency_p95_ms | 6 | -88.4229 | [-92.5802, -84.2656] |
| baseline | 20 | messages_per_decision | 6 | -11.0011 | [-11.1797, -10.8226] |
| baseline | 20 | packet_delivery_ratio | 6 | +0.0013 | [+0.0005, +0.0020] |
| baseline | 20 | ledger_consistency_delay_p95_ms | 6 | +13.4501 | [+11.5671, +15.3332] |
| baseline | 100 | malicious_revocation_recall | 5 | +0.0040 | [-0.0071, +0.0151] |
| baseline | 100 | false_revocation_rate | 5 | +0.0000 | [-0.0000, +0.0000] |
| baseline | 100 | opportunity_detection_recall | 5 | +0.0016 | [-0.0028, +0.0060] |
| baseline | 100 | cpu_time_seconds | 5 | +0.2188 | [+0.0272, +0.4103] |
| baseline | 100 | latency_p95_ms | 5 | -218.1006 | [-237.4757, -198.7254] |
| baseline | 100 | messages_per_decision | 5 | -10.2559 | [-10.2999, -10.2118] |
| baseline | 100 | packet_delivery_ratio | 5 | +0.0001 | [-0.0014, +0.0016] |
| baseline | 100 | ledger_consistency_delay_p95_ms | 5 | +14.6281 | [+13.2755, +15.9806] |
| freshness_12s | 20 | malicious_revocation_recall | 6 | +0.0000 | [+0.0000, +0.0000] |
| freshness_12s | 20 | false_revocation_rate | 6 | +0.0000 | [+0.0000, +0.0000] |
| freshness_12s | 20 | opportunity_detection_recall | 6 | +0.0000 | [+0.0000, +0.0000] |
| freshness_12s | 20 | cpu_time_seconds | 6 | +0.0104 | [-0.0143, +0.0351] |
| freshness_12s | 20 | latency_p95_ms | 6 | -89.2734 | [-93.7764, -84.7704] |
| freshness_12s | 20 | messages_per_decision | 6 | -11.1038 | [-11.2531, -10.9545] |
| freshness_12s | 20 | packet_delivery_ratio | 6 | +0.0014 | [+0.0006, +0.0021] |
| freshness_12s | 20 | ledger_consistency_delay_p95_ms | 6 | +13.4489 | [+11.5578, +15.3399] |
| freshness_12s | 100 | malicious_revocation_recall | 4 | +0.0000 | [+0.0000, +0.0000] |
| freshness_12s | 100 | false_revocation_rate | 4 | +0.0000 | [+0.0000, +0.0000] |
| freshness_12s | 100 | opportunity_detection_recall | 4 | +0.0000 | [+0.0000, +0.0000] |
| freshness_12s | 100 | cpu_time_seconds | 4 | +0.1289 | [-0.2188, +0.4766] |
| freshness_12s | 100 | latency_p95_ms | 4 | -222.1824 | [-252.6993, -191.6655] |
| freshness_12s | 100 | messages_per_decision | 4 | -10.4271 | [-10.4972, -10.3570] |
| freshness_12s | 100 | packet_delivery_ratio | 4 | +0.0001 | [-0.0020, +0.0022] |
| freshness_12s | 100 | ledger_consistency_delay_p95_ms | 4 | +14.6455 | [+13.8463, +15.4446] |
| freshness_30s | 20 | malicious_revocation_recall | 6 | +0.0000 | [+0.0000, +0.0000] |
| freshness_30s | 20 | false_revocation_rate | 6 | +0.0000 | [+0.0000, +0.0000] |
| freshness_30s | 20 | opportunity_detection_recall | 6 | +0.0000 | [+0.0000, +0.0000] |
| freshness_30s | 20 | cpu_time_seconds | 6 | +0.0807 | [-0.1115, +0.2729] |
| freshness_30s | 20 | latency_p95_ms | 6 | -88.4229 | [-92.5802, -84.2656] |
| freshness_30s | 20 | messages_per_decision | 6 | -11.0011 | [-11.1797, -10.8226] |
| freshness_30s | 20 | packet_delivery_ratio | 6 | +0.0013 | [+0.0005, +0.0020] |
| freshness_30s | 20 | ledger_consistency_delay_p95_ms | 6 | +13.4501 | [+11.5671, +15.3332] |
| freshness_30s | 100 | malicious_revocation_recall | 4 | +0.0000 | [+0.0000, +0.0000] |
| freshness_30s | 100 | false_revocation_rate | 4 | +0.0000 | [+0.0000, +0.0000] |
| freshness_30s | 100 | opportunity_detection_recall | 4 | +0.0000 | [+0.0000, +0.0000] |
| freshness_30s | 100 | cpu_time_seconds | 4 | +0.3438 | [-0.8560, +1.5435] |
| freshness_30s | 100 | latency_p95_ms | 4 | -215.5799 | [-242.3151, -188.8447] |
| freshness_30s | 100 | messages_per_decision | 4 | -10.2706 | [-10.2946, -10.2467] |
| freshness_30s | 100 | packet_delivery_ratio | 4 | +0.0001 | [-0.0021, +0.0022] |
| freshness_30s | 100 | ledger_consistency_delay_p95_ms | 4 | +14.1550 | [+13.6782, +14.6317] |
| position_sources_1 | 20 | malicious_revocation_recall | 6 | +0.0000 | [+0.0000, +0.0000] |
| position_sources_1 | 20 | false_revocation_rate | 6 | +0.0000 | [+0.0000, +0.0000] |
| position_sources_1 | 20 | opportunity_detection_recall | 6 | +0.0000 | [+0.0000, +0.0000] |
| position_sources_1 | 20 | cpu_time_seconds | 6 | +0.0130 | [-0.0290, +0.0550] |
| position_sources_1 | 20 | latency_p95_ms | 6 | -88.4229 | [-92.5802, -84.2656] |
| position_sources_1 | 20 | messages_per_decision | 6 | -11.0011 | [-11.1797, -10.8226] |
| position_sources_1 | 20 | packet_delivery_ratio | 6 | +0.0013 | [+0.0005, +0.0020] |
| position_sources_1 | 20 | ledger_consistency_delay_p95_ms | 6 | +13.4501 | [+11.5671, +15.3332] |
| position_sources_1 | 100 | malicious_revocation_recall | 4 | +0.0000 | [+0.0000, +0.0000] |
| position_sources_1 | 100 | false_revocation_rate | 4 | +0.0000 | [+0.0000, +0.0000] |
| position_sources_1 | 100 | opportunity_detection_recall | 4 | +0.0000 | [+0.0000, +0.0000] |
| position_sources_1 | 100 | cpu_time_seconds | 4 | +0.6133 | [+0.1971, +1.0295] |
| position_sources_1 | 100 | latency_p95_ms | 4 | -215.5799 | [-242.3151, -188.8447] |
| position_sources_1 | 100 | messages_per_decision | 4 | -10.2706 | [-10.2946, -10.2467] |
| position_sources_1 | 100 | packet_delivery_ratio | 4 | +0.0001 | [-0.0021, +0.0022] |
| position_sources_1 | 100 | ledger_consistency_delay_p95_ms | 4 | +14.1550 | [+13.6782, +14.6317] |
| position_sources_3 | 20 | malicious_revocation_recall | 6 | +0.0000 | [+0.0000, +0.0000] |
| position_sources_3 | 20 | false_revocation_rate | 6 | +0.0000 | [+0.0000, +0.0000] |
| position_sources_3 | 20 | opportunity_detection_recall | 6 | +0.0000 | [+0.0000, +0.0000] |
| position_sources_3 | 20 | cpu_time_seconds | 6 | -0.0260 | [-0.0999, +0.0478] |
| position_sources_3 | 20 | latency_p95_ms | 6 | -91.5358 | [-96.0498, -87.0217] |
| position_sources_3 | 20 | messages_per_decision | 6 | -11.2999 | [-11.4750, -11.1249] |
| position_sources_3 | 20 | packet_delivery_ratio | 6 | +0.0012 | [+0.0004, +0.0019] |
| position_sources_3 | 20 | ledger_consistency_delay_p95_ms | 6 | +13.0743 | [+11.8085, +14.3402] |
| position_sources_3 | 100 | malicious_revocation_recall | 4 | +0.0000 | [+0.0000, +0.0000] |
| position_sources_3 | 100 | false_revocation_rate | 4 | +0.0000 | [+0.0000, +0.0000] |
| position_sources_3 | 100 | opportunity_detection_recall | 4 | +0.0000 | [+0.0000, +0.0000] |
| position_sources_3 | 100 | cpu_time_seconds | 4 | +0.1484 | [-0.2116, +0.5084] |
| position_sources_3 | 100 | latency_p95_ms | 4 | -221.1636 | [-252.8641, -189.4632] |
| position_sources_3 | 100 | messages_per_decision | 4 | -10.4407 | [-10.4866, -10.3948] |
| position_sources_3 | 100 | packet_delivery_ratio | 4 | -0.0000 | [-0.0020, +0.0019] |
| position_sources_3 | 100 | ledger_consistency_delay_p95_ms | 4 | +15.4045 | [+12.7078, +18.1012] |

- حالات FP جديدة مقارنة بخط الأساس في السجلات المزدوجة: **0**.
- `detected opportunity` تعني أن رسالة ضارة مرصودة وترتبط بنافذة حالتها النهائية REVOKED. `protected opportunity` تعني أن أول إلغاء ملتزم سبق زمن إرسال الرسالة؛ لا يُعامل الحقلان كشيء واحد.
- استُبعدت نوافذ ما بعد الإلغاء النهائي من Method B وفق `already_revoked_terminal_state`، وعُدّت واستُخرجت لكل خلية.
