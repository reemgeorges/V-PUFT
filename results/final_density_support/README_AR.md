# بيانات دعم الكثافة والكاش النهائية

تحتوي هذه المجموعة على مدخلات ونتائج وصفية لازمة لتدقيق الفصل الخامس:

- `density_campaign_manifest.json`: تصميم حملة الكثافة وحدود الادعاء.
- `density_trace_audit.csv`: تحقق أعداد المركبات والحالات والأحداث لكل طبولوجيا وكثافة وبذرة.
- `density_topology_v2v_cache.csv`: النتائج الخام لحساسية Trust Token/TTL حسب الطبولوجيا والكثافة.
- `density_topology_v2v_cache_summary.csv`: الملخص الوصفي للكاش.
- `density_topology_v2v_cache_step_changes.csv`: تغيرات الكاش بين الكثافات المتجاورة.

لا تُستخدم جداول المقارنة المعمارية القديمة من حملة الكثافة الأولى كمرجع نهائي، لأن المقارنة المعتمدة أصبحت Evidence-CRN Paired Transport Replay الموجودة في:

`results/final_paired_transport_crn/`

هذه الملفات داعمة للكثافة والكاش فقط، والأزمنة مخرجات نموذجية وليست قياسات حقلية.
