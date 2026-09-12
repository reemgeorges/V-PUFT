# أوامر تشغيل امتداد V-PUFT

نفّذ الأوامر من جذر النسخة الجديدة:

```bash
cd /workspace/scratch/69a0b47336f9/V-PUFT-extension
```

## 1. اختبار سريع للكود

```bash
python -m pytest -q -ra
python -m compileall -q src scripts
git diff --check
```

اختبار SUMO قد يظهر `SKIPPED` إذا لم تكن SUMO/TraCI مثبتة. هذا لا يمنع replay لأن الحملة تستخدم آثار v7 المجمدة.

## 2. Smoke test صغير

```bash
PYTHONPATH=src python -m vpuft.cli extension-campaign \
  --config configs/extension_smoke.json \
  --output-dir results/extension_smoke_check
```

## 3. الحملة الكاملة من الآثار المجمدة

```bash
OUTPUT_ROOT=results/extension_frozen_replay_v4 \
  scripts/run_extension_frozen_replay.sh
```

السكريبت قابل للاستكمال: إذا وجد `extension_manifest.json` لطبولوجيا مكتملة، يتجاوزها ولا يعيدها.

هذا التشغيل يقوم آلياً بما يلي:

1. يعيد replay لآثار Smoke وCorridor وIntersection وGrid.
2. يستخدم أوزان v7 المختارة من `selected_weights.json`.
3. لا يشغّل SUMO.
4. لا يعيد Centralized Near-Edge.
5. يدمج النتائج.
6. يشغّل حساسية Trust Token/TTL لأعداد 20–100 مركبة.
7. يولد تقرير التدقيق النهائي.

## 4. إعادة التحليل فقط من دون إعادة الحملة

```bash
PYTHONPATH=src python scripts/analyze_extension_results.py \
  --input-dir results/extension_frozen_replay_v4/combined
```

## 5. أهم الملفات الناتجة

```bash
cd results/extension_frozen_replay_v4/combined
ls -lh \
  extension_global_summary.csv \
  extension_key_comparisons.csv \
  extension_case_agreement.csv \
  extension_consensus_outcomes.csv \
  extension_network_messages.csv \
  compromised_evidence_injection_audit.csv \
  v2v_trust_cache_summary.csv \
  EXTENSION_RESULTS_AUDIT.md
```

لا تستخدم مجلدات v1–v3 في الكتابة النهائية؛ النسخة المعتمدة للامتداد هي `extension_frozen_replay_v4`.
