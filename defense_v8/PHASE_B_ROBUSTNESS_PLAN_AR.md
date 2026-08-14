# Phase B — Robustness Plan (لا تشغله الآن)

## لا تستخدم السيناريوهات القديمة التالية كاختبارات ناجحة
- S2 equivocate: no-op في مسار المحرك الحالي.
- S4 accept_invalid: no-op في غياب invalid semantic proposal.
- S6 compromised_rsus: لا يتفعّل في architecture-only replay لأنه موجود في detector path.
- S5 القديم: غير صالح كـ"عطلين" لأن أحد عطليه كان equivocate no-op.

## Liveness المقترح لاحقاً
- L0 baseline reproduction — يجب أن يطابق v7.
- L1: `rsu-1` offline لأنه قائد view 0.
- L2: مدقق واحد `reject_valid` مع n=4,f=1,quorum=3؛ متوقع أن يكون حدياً تحت PDR<1.
- L3: عطلان فعّالان حقيقيان، مثل `rsu-1=offline` + مدقق آخر `reject_valid`.

## Central robustness
- availability = 0.99 / 0.95 / 0.90
- compromised + false_revocation
- compromised + censorship

## Safety
الحملة المجمدة لا تختبر malicious semantic proposals. لا تستخدم `safety_violation=0` كدليل على Safety.
أي Safety injection يبقى امتداداً منفصلاً بعد Phase A فقط إذا أمكن بناء harness نظيف دون تعديل v7.

## Fault Activation Audit إلزامي
- fault_configured
- fault_activated
- n_fault_events
- view_changes
- consensus_failures
إذا configured=true وactivated=false فالسيناريو غير صالح كاختبار.
