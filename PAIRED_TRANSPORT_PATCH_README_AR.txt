حزمة التصحيح: Evidence-level Common Random Numbers
==================================================

هذه الحزمة تضاف فوق فرع:
extension/trust-cache-byzantine-rsu

لا تحذف نتائج حملة الكثافة ولا تعيد SUMO.

بعد فك الحزمة داخل جذر المشروع نفذ:

python -m pip install -e .
python -m pytest -q -ra
& .\scripts\run_paired_transport_replay.ps1

المسار الذي يستخدمه السكربت للآثار المحفوظة هو:
%USERPROFILE%\VPUFT_density_results\traces

المخرجات الجديدة توضع منفصلة في:
%USERPROFILE%\VPUFT_density_paired_replay

الحملة الأصلية ونتائج v7 لا تُعدلان.

مهم:
- المركزي availability=1.0 يعزل المقارنة المعمارية.
- المركزي availability=0.995 يقيس أثر التوافر تشغيلياً.
- المقارنة post-hoc supplementary ولا تتحول إلى confirmatory.
- backhaul 20/50/100/200 يشتق بدقة من 0 ms لتجنب أربع إعادات متطابقة.
