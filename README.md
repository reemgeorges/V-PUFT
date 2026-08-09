# V-PUFT Research Framework v1.0.1

مشروع بحثي كامل وقابل للتجريب لموضوع:

**تقييم أداء شبكات المركبات اللاسلكية المعتمدة على سلاسل الكتل**  
**Performance Evaluation of Blockchain-Based VANETs**

يطبق المشروع بروتوكول ثقة مشتركاً:

**V-PUFT — Vehicular Provenance-aware Unified Framework for Trust**

على ثلاثة نماذج رئيسية فقط:

1. **Centralized V-PUFT**
2. **Distributed RSU V-PUFT + PBFT + Distributed Ledger**
3. **Ahmed-Inspired Witness V-PUFT + PBFT + Distributed Ledger**

النموذج الثالث مستوحى من معمارية الشهود والعتبة وPBFT وBlockchain في Ahmed et al. (Sensors, 2022, DOI: 10.3390/s22176715). وهو ليس ادعاءً بأنه الكود الأصلي للمؤلفين، ولا ينفذ Threshold Ring Signature الخاصة بالمقالة حرفياً. يحتفظ المشروع بوضع مرجعي لعتبة الشهود داخل نتائج الـAblation، بينما القرار الرئيسي يمر دائماً عبر V-PUFT.

---

## ما الذي يعمل فعلياً؟

- محرك V-PUFT واحد مشترك بين النماذج الثلاثة.
- أدلة موقعة بـEd25519 ومفاتيح حتمية قابلة لإعادة التجربة.
- `case_id` مستقل لكل مركبة ونوع هجوم.
- `observation_root_id` لمنع تضخيم الأدلة المشتقة من الملاحظة نفسها.
- معالجة الأدلة المؤيدة والمعارضة داخل الجذر نفسه.
- وزن هندسي موزون لعوامل:
  - ثقة الكاشف `C`
  - موثوقية المصدر `rho`
  - حداثة الدليل `F`
  - قابلية التحقق `Q`
  - استقلال الدليل `eta`
- نصاب متكيف حسب نوع الهجوم.
- حالات ثقة مرحلية: Trusted, Suspected, Quarantined, RevocationPending, Revoked.
- خادم مركزي مع Workers وQueue وفشل واختراق وسجل تدقيق احتياطي.
- شبكة موزعة مع loss, jitter, retries, queue delay.
- PBFT-style موقّع مع:
  - PRE-PREPARE
  - PREPARE certificates
  - COMMIT certificates
  - vote locks
  - leader timeout
  - view change
  - Byzantine/offline behavior
- سجل Hash-linked موزع مع replication وstate recovery.
- نموذج شهود مركبات مستوحى من مقالة Ahmed مع RSU validation ومرجع witness-threshold داخلي.
- SUMO/TraCI حقيقي مع سيناريو صغير جاهز، هجمات، RSUs، CAM/DENM، traces مشتركة.
- حملة موحدة تشغل النماذج الثلاثة على الـTrace نفسه.
- تحليل حساسية للأوزان مع:
  - Grouped Cross-Validation بحسب Seed
  - Holdout نهائي غير مستخدم في الاختيار
  - قيود Recall وFalse Revocation Rate
  - Bootstrap re-selection وفواصل ثقة
  - Local sensitivity
  - Global candidate ranking
  - Ablation study
  - Permutation importance
- اختبارات Unit/Integration واختبار SUMO يُشغّل تلقائياً عند توفر SUMO.

---

# 1. التشغيل السريع دون SUMO

هذا المسار يثبت أن المشروع والخوارزميات والنماذج وتحليل الحساسية تعمل:

## Windows PowerShell

```powershell
cd V_PUFT_Research_Framework_v1.0.1.1
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest
vpuft demo --config configs/demo.json --output-dir results/demo
```

دون تثبيت المشروع:

```powershell
$env:PYTHONPATH="src"
python -m vpuft.cli demo --config configs/demo.json --output-dir results/demo
```

## Linux/macOS

```bash
cd V_PUFT_Research_Framework_v1.0.1.1
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
vpuft demo --config configs/demo.json --output-dir results/demo
```

توجد نتيجة مرجعية جاهزة داخل:

```text
results/demo_reference/
```

هي بيانات اصطناعية لا تستخدم كنتيجة للرسالة، لكنها تثبت أن المسار البرمجي الكامل يعمل.

---

# 2. تثبيت SUMO على Windows

الطريقة الأسهل:

```powershell
winget install --name sumo
```

ثم أغلق PowerShell وافتحه مجدداً، وتحقق:

```powershell
sumo --version
netconvert --version
```

ثبّت حزم بايثون المطلوبة:

```powershell
pip install -e ".[all]"
```

إذا لم يجد Python مكتبة TraCI رغم تثبيت SUMO، اضبط:

```powershell
$env:SUMO_HOME="C:\Program Files (x86)\Eclipse\Sumo"
$env:PYTHONPATH="$env:SUMO_HOME\tools;$env:PYTHONPATH"
```

قد يختلف مسار SUMO حسب طريقة التثبيت.

---

# 3. فحص البيئة

```powershell
vpuft doctor --config configs/sumo_smoke.json
```

القيمة المطلوبة:

```json
"ready_for_sumo": true
```

التقرير يتحقق من:

- `sumo`
- `netconvert`
- `traci`
- `sumolib`
- إصدار SUMO

---

# 4. تجهيز شبكة SUMO الصغيرة

المشروع يحتوي على:

```text
sumo/smoke/
├── smoke.nod.xml
├── smoke.edg.xml
├── smoke.rou.xml
├── smoke.sumocfg
├── rsus.add.xml
├── rsus.json
└── attacks.json
```

شغّل:

```powershell
vpuft prepare-sumo --config configs/sumo_smoke.json --force
```

سيُنشئ:

```text
sumo/smoke/smoke.net.xml
```

باستخدام `netconvert`.

---

# 5. تشغيل SUMO/TraCI فعلياً لSeed واحد

```powershell
vpuft sumo-trace `
  --config configs/sumo_smoke.json `
  --scenario-dir sumo/smoke `
  --seed 1001 `
  --output-dir results/sumo_seed_1001
```

المخرجات:

```text
results/sumo_seed_1001/
├── mobility_trace.csv
├── generated_messages.csv
├── attack_ground_truth.csv
├── local_detections.csv
├── shared_detection_trace.jsonl
├── shared_detection_trace.csv
├── evidence_campaign.csv
├── sumo_tripinfo.xml
├── scenario_manifest.json
└── run_summary.json
```

## الهجمات الموجودة في السيناريو

- Position spoofing
- Speed spoofing
- Replay
- Certificate tampering
- Flooding
- False DENM
- Mixed attack
- مركبات سليمة للمقارنة

---

# 6. تشغيل النماذج الثلاثة على Trace نفسه

```powershell
vpuft replay `
  --config configs/sumo_smoke.json `
  --trace results/sumo_seed_1001/shared_detection_trace.jsonl `
  --output-dir results/sumo_seed_1001_models
```

هذا هو شرط المقارنة العادلة: لا يعاد تشغيل الحركة لكل نموذج، بل يُولد الـTrace مرة واحدة ثم يمر إلى النماذج الثلاثة.

---

# 7. حملة SUMO متعددة البذور

مثال أولي بخمس Seeds:

```powershell
vpuft sumo-campaign `
  --config configs/full_experiment.json `
  --scenario-dir sumo/smoke `
  --output-dir results/sumo_campaign_5 `
  --seeds 1001 1002 1003 1004 1005
```

تشغيل الحملة وتحليل الحساسية معاً:

```powershell
vpuft sumo-campaign `
  --config configs/full_experiment.json `
  --scenario-dir sumo/smoke `
  --output-dir results/sumo_campaign_10 `
  --seeds 1001 1002 1003 1004 1005 1006 1007 1008 1009 1010 `
  --sensitivity `
  --candidates 5000 `
  --bootstrap-repeats 500 `
  --min-recall 0.95 `
  --max-frr 0.05
```

لا يسمح المشروع بتحليل الحساسية بأقل من أربع Seeds مستقلة.

---

# 8. تحليل الحساسية منفصلاً

```powershell
vpuft sensitivity `
  --input results/sumo_campaign_10/architecture_campaign/evidence_campaign.csv `
  --config configs/full_experiment.json `
  --output-dir results/sumo_campaign_10/sensitivity_recheck `
  --candidates 5000 `
  --bootstrap-repeats 500 `
  --permutation-repeats 200 `
  --min-recall 0.95 `
  --max-frr 0.05
```

أهم المخرجات:

- `selected_weights.json`
- `selected_weights_config.json`
- `candidate_ranking.csv`
- `global_candidate_sensitivity.csv`
- `holdout_predictions.csv`
- `holdout_metrics_by_attack.csv`
- `bootstrap_reselection.csv`
- `bootstrap_parameter_summary.csv`
- `weight_stability.png`
- `local_weight_sensitivity.csv`
- `baseline_ablation_comparison.csv`
- `permutation_importance.csv`
- `METHODOLOGY_REPORT.md`

---

# 9. المقاييس التي يخرجها المشروع

## قرار الثقة

- TP, FP, TN, FN
- Trust Precision
- Malicious Vehicle Revocation Recall
- False Revocation Rate
- Malicious Acceptance Rate
- F1
- MCC

## الزمن

- Detection latency p95
- Evidence qualification latency p95
- Consensus latency p95
- End-to-end latency p50, p95, p99
- Ledger consistency delay p95

## الاتصال

- Total messages
- Messages per decision
- Total bytes
- Bytes per decision
- Packet Delivery Ratio
- Retransmissions
- Queue delay

## Blockchain وPBFT

- Consensus success rate
- Liveness failures
- Safety violations
- View changes
- Ledger blocks
- Ledger consistency
- State recoveries

## الموارد

- CPU time
- Peak memory

## الأدلة

- Independent roots
- Correlated reports suppressed
- Correlation suppression rate
- Article native witness threshold vs Ahmed-inspired V-PUFT ablation

---

# 10. بنية المشروع

```text
src/vpuft/
├── architectures/
│   ├── centralized.py
│   ├── distributed_rsu.py
│   └── ahmed_witness.py
├── sumo/
│   ├── attacks.py
│   ├── detector.py
│   ├── doctor.py
│   ├── prepare.py
│   ├── runner.py
│   └── campaign.py
├── config.py
├── domain.py
├── crypto.py
├── evidence.py
├── weighting.py
├── qualification.py
├── state_machine.py
├── network.py
├── consensus.py
├── ledger.py
├── trace.py
├── simulation.py
├── runner.py
├── metrics.py
├── sensitivity.py
└── cli.py
```

---

# 11. الحدود العلمية الصريحة

- المشروع إطار محاكاة بحثي، وليس نظام VANET إنتاجياً.
- PBFT منفذ كمحاكي رسائل موقّع مع نصابات وView Change، وليس مكتبة إجماع موزع للنشر الحقيقي.
- كاشف SUMO يستخدم الحقيقة الأرضية المتاحة للمحاكاة لبناء plausibility evidence؛ يجب مقارنة نتائجه لاحقاً مع كاشف منشور أو VeReMi عند كتابة الرسالة النهائية.
- نموذج Ahmed مستوحى من المعمارية المنشورة، وليس إعادة تنفيذ حرفي للتوقيع الحلقي العتبي؛ هذه النقطة موثقة لمنع ادعاء غير صحيح.
- نتائج `demo_reference` ليست نتائج علمية للرسالة.
- الأوزان النهائية لا تعتمد إلا بعد حملة SUMO متعددة البذور وتثبيت القيود قبل فتح مجموعة الاختبار.

راجع أيضاً:

- `docs/METHODOLOGY.md`
- `docs/ARCHITECTURE.md`
- `docs/ARTICLE_MAPPING.md`
- `docs/THREAT_MODEL.md`
- `docs/LIMITATIONS.md`
- `docs/TEST_REPORT.md`

---

# 12. تشغيل أربع طبولوجيات

الطبولوجيات المرفقة:

```text
sumo/smoke         حلقة حضرية
sumo/corridor      ممر/طريق سريع ثنائي الاتجاه
sumo/intersection  تقاطع رباعي
sumo/grid          شبكة طرق 3×3
```

تشغيلها جميعاً على البذور نفسها، ثم اختيار أوزان واحدة مشتركة:

```powershell
vpuft topology-campaign `
  --config configs/full_experiment.json `
  --scenarios sumo/smoke sumo/corridor sumo/intersection sumo/grid `
  --output-dir results/four_topologies `
  --seeds 1001 1002 1003 1004 1005 1006 1007 1008 1009 1010 `
  --sensitivity `
  --candidates 5000 `
  --bootstrap-repeats 500 `
  --min-recall 0.95 `
  --max-frr 0.05
```

المخرجات الجامعة:

- `topology_architecture_summary.csv`
- `all_topologies_evidence_campaign.csv`
- `multi_topology_manifest.json`
- مجلد مستقل لكل طبولوجيا
- تحليل حساسية واحد عبر الطبولوجيات الأربع
