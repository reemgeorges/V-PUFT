# Remaining risky-claim lexical scan

Lexical inventory of active/non-archive material for contextual review; hits are not automatically errors.
The generated scan file itself is excluded to prevent recursive hit inflation.

| file | line | trigger | excerpt |
|---|---:|---|---|
| `README.md` | 18 | `Ring Signature` | النموذج الثالث مستوحى من معمارية الشهود والعتبة وPBFT وBlockchain في Ahmed et al. (Sensors, 2022, DOI: 10.3390/s22176715). وهو ليس ادعاءً بأنه الكود الأصلي للمؤلفين، ولا ينفذ Threshold Ring Signature  |
| `README.md` | 29 | `كثافة الجذور` | لا يجوز إسناد فرق Recall إلى Blockchain أو PBFT أو كثافة الجذور أو الشهود وحدهم. |
| `README.md` | 30 | `Byzantine` | - `validator_behaviors` فارغ في إعداد الحملة النهائية؛ لم تُختبر Byzantine safety تجريبياً. |
| `README.md` | 31 | `MCC` | - MCC أعلى وصفياً لمسار Ahmed لكنه غير دال تأكيدياً بعد Holm. |
| `README.md` | 61 | `VIEW-CHANGE` | - bounded view rotation after timeout (not a full VIEW-CHANGE/NEW-VIEW message protocol) |
| `README.md` | 362 | `MCC` | - MCC |
| `README.md` | 386 | `Byzantine` | - حقل `safety_violation` للتجهيز القياسي فقط؛ لا يمثل إثبات Byzantine safety في baseline المجمد |
| `README.md` | 444 | `Byzantine` | - PBFT منفذ كمُنهٍ بحثي PBFT-style برسائل موقعة ونصاب PRE-PREPARE/PREPARE/COMMIT ودوران bounded للـview بعد timeout؛ ولا ينفذ VIEW-CHANGE/NEW-VIEW كاملاً ولا يقدم baseline المجمد اختبار Byzantine safe |
| `docs/ARCHITECTURE.md` | 48 | `Byzantine` | PBFT-style simulation includes recipient certificates, vote locks, loss/retries, timeout-driven bounded leader/view rotation, and recovery. It does not implement a full VIEW-CHANGE/NEW-VIEW message pr |
| `docs/ARTICLE_MAPPING.md` | 5 | `Ring Signature` | Ahmed, Di, and Mukathe, “A Blockchain-Enabled Incentive Trust Management with Threshold Ring Signature Scheme for Traffic Event Validation in VANETs,” Sensors 2022, 22(17), 6715. DOI: 10.3390/s2217671 |
| `docs/ARTICLE_MAPPING.md` | 25 | `Ring Signature` | - threshold ring signature cryptographic construction |
| `docs/EXPERIMENT_PROTOCOL.md` | 27 | `MCC` | - trust precision, recall, F1, MCC, FRR |
| `docs/EXPERIMENT_PROTOCOL.md` | 31 | `Safety` | - consensus success, timeout-driven bounded view/leader rotations and liveness; Safety is reportable only in a separate run that actually activates malicious semantic proposals and a working safety me |
| `docs/LIMITATIONS.md` | 6 | `Ring Signature` | 4. Ahmed-inspired mode does not reproduce threshold ring signatures literally. |
| `docs/METHODOLOGY.md` | 88 | `MCC` | 6. Rank by worst-fold MCC, then mean MCC. |
| `docs/TEST_REPORT.md` | 22 | `VIEW-CHANGE` | - PBFT quorum and timeout-driven bounded leader/view rotation (not a full VIEW-CHANGE/NEW-VIEW protocol) |
| `docs/THREAT_MODEL.md` | 18 | `Byzantine` | > an empirical Byzantine-Safety experiment. Future robustness runs must record fault configuration **and activation**. |
| `docs/THREAT_MODEL.md` | 51 | `Safety` | - the declared PBFT fault bound is respected in experiments claiming PBFT safety |
| `docs/analysis/PHASE_A_SUMMARIES.txt` | 4 | `MCC` | # Ahmed↔RSU is an integrated evidence-path comparison; MCC is non-confirmatory after Holm (adjusted p≈0.1986). |
| `docs/analysis/PHASE_A_SUMMARIES.txt` | 17 | `MCC` | - Primary family: recall, FRR, MCC, Holm-corrected at alpha = 0.05 |
| `docs/analysis/PHASE_A_SUMMARIES.txt` | 27 | `MCC` | \| Distributed RSU V-PUFT vs Centralized V-PUFT \| mcc \| 0.8307 \| 0.8307 \| +0.0000 \| [+0.0000, +0.0000] \| no \| |
| `docs/analysis/PHASE_A_SUMMARIES.txt` | 30 | `MCC` | \| Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT \| mcc \| 0.8307 \| 0.8475 \| +0.0168 \| [+0.0024, +0.0309] \| YES \| |
| `docs/analysis/PHASE_A_SUMMARIES.txt` | 33 | `MCC` | \| Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT \| mcc \| 0.8307 \| 0.8475 \| +0.0168 \| [+0.0025, +0.0311] \| YES \| |
| `docs/analysis/PHASE_A_SUMMARIES.txt` | 84 | `MCC` | \| mcc \| Distributed RSU V-PUFT vs Centralized V-PUFT \| 40 \| +0.0000 \| 1 \| +nan \| undefined \| no \| |
| `docs/analysis/PHASE_A_SUMMARIES.txt` | 85 | `MCC` | \| mcc \| Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT \| 40 \| +0.0171 \| 0.03972 \| +0.373 \| medium \| no \| |
| `docs/analysis/PHASE_A_SUMMARIES.txt` | 86 | `MCC` | \| mcc \| Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT \| 40 \| +0.0171 \| 0.03972 \| +0.373 \| medium \| no \| |
| `docs/analysis/PRESEMINAR_REPORTING_FIX_20260815.md` | 9 | `MCC` | - MCC remains descriptive/supportive only; Holm-adjusted p≈0.1986 is not confirmatory. |
| `docs/analysis/THESIS_CLAIM_AUDIT.json` | 13 | `MCC` | "MCC": "Higher descriptively; NOT confirmatory after Holm (adjusted p≈0.1986).", |
| `docs/analysis/THESIS_CLAIM_AUDIT.json` | 14 | `Safety` | "Safety": "Do not report zero violations as empirical safety evidence; malicious semantic proposals were not exercised.", |
| `docs/remediation/CLAIM_AUDIT.md` | 8 | `MCC` | \| Ahmed improves MCC \| REMOVE as confirmatory — Holm p≈0.1986 \| |
| `docs/remediation/CLAIM_AUDIT.md` | 9 | `Byzantine` | \| zero safety violations proves Byzantine safety \| REMOVE \| |
| `docs/remediation/CLAIM_AUDIT.md` | 10 | `VIEW-CHANGE` | \| full VIEW-CHANGE/NEW-VIEW is implemented \| REMOVE \| |
| `docs/remediation/CLAIM_AUDIT.md` | 11 | `Byzantine` | \| baseline exercises Byzantine faults \| REMOVE — `validator_behaviors={}` \| |
| `docs/remediation/CLAIM_AUDIT.md` | 15 | `authentication` | \| authentication schemes empirically benchmarked \| REMOVE — Ed25519 only \| |
| `docs/remediation/CLAIM_AUDIT.md` | 33 | `Safety` | `defense_v8/PHASE_B_ROBUSTNESS_PLAN_AR.md` was reviewed and already states that frozen Safety was not tested and that |
| `docs/remediation/CLAIM_AUDIT.md` | 41 | `VIEW-CHANGE` | interpretation header. Legacy claims about a full PBFT view-change path, identical evidence views for all |
| `docs/remediation/CLAIM_AUDIT.md` | 42 | `Safety` | architectures, and baseline empirical Safety are no longer left unqualified in active documentation. |
| `docs/remediation/CLAIM_AUDIT.md` | 48 | `view change` | than a universal single-variable isolation claim; replaced the remaining ambiguous Chapter-5 `View Change` |
| `docs/remediation/CLAUDE_RECONCILIATION.md` | 6 | `Byzantine` | \| PBFT safety overclaim \| Removed; no empirical Byzantine-safety claim \| |
| `docs/remediation/CLAUDE_RECONCILIATION.md` | 7 | `same trace` | \| “same trace” wording \| Shared raw upstream trace + source-specific RSU/witness views \| |
| `docs/remediation/CLAUDE_RECONCILIATION.md` | 11 | `MCC` | \| MCC risk \| Descriptive only after Holm \| |
| `docs/remediation/CLAUDE_RECONCILIATION.md` | 17 | `authentication` | \| authentication benchmark absent \| Empirical message exchange; authentication methods theoretical \| |
| `docs/remediation/FINAL_CONSISTENCY_AUDIT.md` | 6 | `Byzantine` | removes Byzantine-safety/MCC/causal overclaims, records without-smoke robustness, distinguishes packet loss from |
| `docs/remediation/FINAL_CONSISTENCY_AUDIT.md` | 8 | `authentication` | bytes/latency/authentication/LFS limits. |
| `docs/remediation/STATISTICAL_ROBUSTNESS_ADDENDUM.md` | 12 | `MCC` | - MCC raw p: 0.039717 vs 0.03972. |
| `docs/remediation/STATISTICAL_ROBUSTNESS_ADDENDUM.md` | 13 | `MCC` | - MCC Holm p: 0.19858 vs 0.1986. |
| `docs/remediation/STATISTICAL_ROBUSTNESS_ADDENDUM.md` | 18 | `MCC` | - MCC remains non-confirmatory; Holm p = 1.0000. |
| `docs/reproducibility/effective_final_configuration.json` | 35 | `MCC` | "mcc": 0.8263418399892304, |
| `docs/reproducibility/effective_final_configuration.json` | 63 | `Byzantine` | "max_byzantine": 1, |
| `docs/reproducibility/FINAL_REPRODUCTION_RUNBOOK.md` | 54 | `Byzantine` | The frozen baseline has `validator_behaviors={}` and does not support an empirical Byzantine-safety claim. |
| `docs/reproducibility/FINAL_REPRODUCTION_RUNBOOK.md` | 55 | `MCC` | MCC is descriptive only after Holm (adjusted p≈0.1986). |
| `docs/reproducibility/FINAL_REPRODUCTION_RUNBOOK.md` | 56 | `authentication` | Authentication-method benchmarking was not executed beyond Ed25519. |
| `defense_v8/CHAPTER5_REQUIRED_CORRECTIONS_AR.md` | 10 | `كثافة الجذور` | 2. لا تستخدم «كثافة الجذور» كتفسير سببي منفرد؛ التحليل الموسع يدعم حزمة عوامل مترابطة |
| `defense_v8/CHAPTER5_REQUIRED_CORRECTIONS_AR.md` | 14 | `MCC` | 4. MCC يبقى وصفياً فقط؛ Holm-adjusted p≈0.1986 في التحليل الكامل و1.0000 بعد استبعاد smoke. |
| `defense_v8/CHAPTER5_REQUIRED_CORRECTIONS_AR.md` | 15 | `authentication` | 5. المقارنة التجريبية لتقنيات authentication لم تُنفذ؛ التنفيذ يستخدم Ed25519، والباقي Related Work. |
| `defense_v8/CHAPTER5_REQUIRED_CORRECTIONS_AR.md` | 20 | `Safety` | ## 1) تصحيح قسم PBFT / Safety فوراً |
| `defense_v8/CHAPTER5_REQUIRED_CORRECTIONS_AR.md` | 24 | `Safety` | > لم تسجل انتهاكات Safety أو حالات Liveness Failure أو View Change. |
| `defense_v8/CHAPTER5_REQUIRED_CORRECTIONS_AR.md` | 28 | `safety_violation` | > حققت المعماريتان الموزعتان نجاحاً كاملاً لمرحلة الإجماع ضمن ظروف الحملة النهائية، ولم تسجل الحملة حالات فشل حيوية أو تغيير قائد. أما انتهاكات الأمان Safety Violations فلا تُقدَّم في هذه الدراسة بوصف |
| `defense_v8/CHAPTER5_REQUIRED_CORRECTIONS_AR.md` | 30 | `Safety` | ولا تكتب بعد الآن أن Safety = 0 "تم قياسها". |
| `defense_v8/CHAPTER5_REQUIRED_CORRECTIONS_AR.md` | 46 | `MCC` | - Recall / FRR / MCC = primary family مع Holm. |
| `defense_v8/paired_stats_v8.py` | 21 | `MCC` | small predeclared primary family (recall, FRR, MCC) only. Precision, F1, |
| `defense_v8/paired_stats_v8.py` | 70 | `MCC` | "mcc": +1, |
| `defense_v8/paired_stats_v8.py` | 83 | `MCC` | PRIMARY_POOLED = ["recall", "frr", "mcc"] |
| `defense_v8/paired_stats_v8.py` | 124 | `MCC` | "frr": frr, "f1": f1, "mcc": _safe_div(tp * tn - fp * fn, denom), |
| `defense_v8/paired_stats_v8.py` | 188 | `MCC` | metric_names = ["recall", "frr", "precision", "f1", "mcc"] |
| `defense_v8/paired_stats_v8.py` | 524 | `MCC` | lines.append(f"- Primary family: recall, FRR, MCC, Holm-corrected at alpha = {args.alpha}") |
| `defense_v8/PHASE_B_ROBUSTNESS_PLAN_AR.md` | 20 | `Safety` | ## Safety |
| `defense_v8/PHASE_B_ROBUSTNESS_PLAN_AR.md` | 21 | `safety_violation` | الحملة المجمدة لا تختبر malicious semantic proposals. لا تستخدم `safety_violation=0` كدليل على Safety. |
| `defense_v8/PHASE_B_ROBUSTNESS_PLAN_AR.md` | 22 | `Safety` | أي Safety injection يبقى امتداداً منفصلاً بعد Phase A فقط إذا أمكن بناء harness نظيف دون تعديل v7. |
| `defense_v8/README_AR.md` | 15 | `Byzantine` | - الحملة النهائية لا تثبت Byzantine safety، وMCC لمسار Ahmed غير دال بعد Holm. |
| `defense_v8/README_AR.md` | 48 | `MCC` | - Holm فقط للعائلة الأساسية: Recall / FRR / MCC. |
| `defense_v8/validate_chapter5_semantics.py` | 182 | `MCC` | r = comparison_row(pooled, "mcc", a, AHMED) |
| `defense_v8/validate_chapter5_semantics.py` | 183 | `MCC` | add(f"pooled_mcc_identity_{a}", approx(float(r.value_b) - float(r.value_a), float(r.difference), 1e-10), |
| `defense_v8/validate_chapter5_semantics.py` | 184 | `MCC` | "Pooled MCC difference equals B-A.") |
| `defense_v8/validate_chapter5_semantics.py` | 189 | `MCC` | mr = test_row(tests, "mcc", a, AHMED) |
| `defense_v8/validate_chapter5_semantics.py` | 194 | `MCC` | add(f"holm_mcc_{a}", (not as_bool(mr.holm_reject)) and float(mr.holm_adjusted_p) >= 0.05 and approx(float(mr.holm_adjusted_p), 0.1986, 8e-4), |
| `defense_v8/validate_chapter5_semantics.py` | 195 | `MCC` | "MCC is not confirmatory after Holm.", {"raw_p": float(mr.raw_p), "holm_p": float(mr.holm_adjusted_p)}) |
| `defense_v8/validate_chapter5_semantics.py` | 227 | `MCC` | add("table_5_3a_mcc_holm", "0.1986" in joined53 and "غير دال تأكيدياً بعد Holm" in joined53, |
| `defense_v8/validate_chapter5_semantics.py` | 228 | `MCC` | "MCC raw direction is separated from Holm-confirmatory inference.") |
| `defense_v8/validate_chapter5_semantics.py` | 327 | `Safety` | # H. Safety and blockchain claims are scoped to what was actually measured. |
| `defense_v8/validate_chapter5_semantics.py` | 330 | `Safety` | "no safety violations", |
| `defense_v8/validate_chapter5_semantics.py` | 331 | `Safety` | "لم تسجل انتهاكات safety", |
| `defense_v8/validate_chapter5_semantics.py` | 332 | `Safety` | "لم تُسجل انتهاكات safety", |
| `defense_v8/validate_chapter5_semantics.py` | 340 | `Safety` | "No unmeasured Safety/blockchain-accuracy claim is asserted.", {"forbidden_hits": bad}) |
| `defense_v8/validate_chapter5_semantics.py` | 341 | `safety_violation` | add("safety_scope_explicit", "safety_violation" in lower and "لم يُختبر تجريبياً" in chapter_text, |
| `defense_v8/validate_chapter5_semantics.py` | 342 | `Safety` | "Safety is explicitly treated as unmeasured under malicious semantic proposals.") |
| `results/full_campaign_v7/statistical_inference/SUMMARY.md` | 7 | `MCC` | > causal evidence for Blockchain, PBFT, witness density, or any one sensing factor. MCC remains non-confirmatory after Holm. |
| `results/full_campaign_v7/statistical_inference/SUMMARY.md` | 16 | `MCC` | - Primary family: recall, FRR, MCC, Holm-corrected at alpha = 0.05 |
| `results/full_campaign_v7/statistical_inference/SUMMARY.md` | 26 | `MCC` | \| Distributed RSU V-PUFT vs Centralized V-PUFT \| mcc \| 0.8307 \| 0.8307 \| +0.0000 \| [+0.0000, +0.0000] \| no \| |
| `results/full_campaign_v7/statistical_inference/SUMMARY.md` | 29 | `MCC` | \| Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT \| mcc \| 0.8307 \| 0.8475 \| +0.0168 \| [+0.0024, +0.0309] \| YES \| |
| `results/full_campaign_v7/statistical_inference/SUMMARY.md` | 32 | `MCC` | \| Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT \| mcc \| 0.8307 \| 0.8475 \| +0.0168 \| [+0.0025, +0.0311] \| YES \| |
| `results/full_campaign_v7/statistical_inference/SUMMARY.md` | 83 | `MCC` | \| mcc \| Distributed RSU V-PUFT vs Centralized V-PUFT \| 40 \| +0.0000 \| 1 \| 1 \| undefined \| undefined \| no \| |
| `results/full_campaign_v7/statistical_inference/SUMMARY.md` | 84 | `MCC` | \| mcc \| Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT \| 40 \| +0.0171 \| 0.03972 \| 0.1986 \| +0.373 \| medium \| no \| |
| `results/full_campaign_v7/statistical_inference/SUMMARY.md` | 85 | `MCC` | \| mcc \| Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT \| 40 \| +0.0171 \| 0.03972 \| 0.1986 \| +0.373 \| medium \| no \| |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 86 | `MCC` | <li><a href="#s510">5.10 تحليل MCC وF1</a></li> |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 145 | `MCC` | <span class="ltr">Recall/FRR/MCC</span>. كما أُجري تحليل اتفاق على مستوى الحالة وتفكيك مستقل لمراحل الزمن. |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 201 | `MCC` | <h3>5.4.4 F1 وMCC</h3> |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 203 | `MCC` | <div class="eq">MCC = (TP×TN − FP×FN) / √((TP+FP)(TP+FN)(TN+FP)(TN+FN))</div> |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 205 | `MCC` | استخدم MCC خصوصاً لأنه يدمج الحالات الأربع للمصفوفة الالتباسية، ويقلل خطر تفسير نظام مرتفع Recall |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 206 | `تفوق` | على أنه متفوق إذا كان ذلك على حساب عدد كبير من الإلغاءات الخاطئة. |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 281 | `MCC` | <thead><tr><th>TP</th><th>FP</th><th>TN</th><th>FN</th><th>Recall</th><th>FRR</th><th>Precision</th><th>F1</th><th>MCC</th><th>Balanced Accuracy</th></tr></thead> |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 285 | `MCC` | على منظور RSU بلغ Recall في Holdout نحو 78.61% وFRR نحو 1.61% وMCC نحو 0.8165، |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 286 | `MCC` | بينما بلغ Recall في منظور الشهود 88.06% وFRR نحو 3.14% وMCC نحو 0.8377. |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 291 | `أفضل` | <span class="ltr">selection_feasible = false</span>. تم الاحتفاظ بالمرشح الأفضل وفق قاعدة الترتيب الأصلية، |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 354 | `MCC` | <tr><th>المعمارية</th><th>Precision</th><th>Recall</th><th>FRR</th><th>F1</th><th>MCC</th><th>P95 Latency (ms)</th><th>Messages/Decision</th><th>Bytes/Decision</th><th>PDR</th></tr> |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 363 | `MCC` | لا توجد معمارية متفوقة مطلقاً. حقق Ahmed-Inspired أعلى Recall وF1 وأعلى قيمة وصفية لـMCC، |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 365 | `MCC` | لـMCC إلى ادعاء تأكيدي، لأن فرق MCC لم يبق دالاً بعد تصحيح Holm في التحليل الإحصائي اللاحق.</span></div> |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 368 | `MCC` | <div class="figure"><img alt="Global MCC" src="../Fig_03_Global_MCC.png"/><div class="caption">الشكل (5-3): معامل MCC حسب المعمارية.</div></div> |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 382 | `تفوق` | للحكم على تفوق المعمارية، لأن التحليل نفسه يبين زيادة متزامنة في FRR. |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 410 | `MCC` | <h2>5.10 تحليل MCC وF1</h2> |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 412 | `MCC` | حقق Ahmed-Inspired أعلى قيمة وصفية لـF1 (<span class="ltr">0.8730</span>) وأعلى قيمة وصفية لـMCC |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 415 | `MCC` | ففرق MCC، رغم أن فاصل Bootstrap المجمع لا يشمل الصفر، لم يبق دالاً بعد تصحيح Holm. |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 420 | `MCC` | على عشر وحدات من كل طوبولوجيا في كل إعادة سحب. شملت العائلة الأولية Recall وFRR وMCC، وطُبق عليها تصحيح |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 433 | `MCC` | <tr><td>MCC</td><td>Ahmed vs Centralized</td><td>0.8307</td><td>0.8475</td><td>+0.0168</td><td>[+0.0024, +0.0309]</td><td>+0.0171</td><td>0.03972</td><td><strong>0.1986</strong></td><td>+0.373 (medium |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 434 | `MCC` | <tr><td>MCC</td><td>Ahmed vs Distributed</td><td>0.8307</td><td>0.8475</td><td>+0.0168</td><td>[+0.0025, +0.0311]</td><td>+0.0171</td><td>0.03972</td><td><strong>0.1986</strong></td><td>+0.373 (medium |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 435 | `MCC` | <tr><td>Recall / FRR / MCC</td><td>Distributed vs Centralized</td><td colspan="2">متطابقة لكل مقياس في الأزواج الأربعين</td><td>0 تماماً</td><td>[0, 0]</td><td>0 تماماً</td><td>—</td><td>—</td><td>غير |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 463 | `MCC` | وبقي فرق FRR دالاً عند <span class="ltr">1.445×10⁻⁵</span>. أما MCC فبقي غير تأكيدي وأصبح |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 468 | `MCC` | (Recall raw p≈2.4038×10⁻⁶ مقابل 2.404×10⁻⁶، وMCC Holm≈0.19858 مقابل 0.1986). |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 482 | `أفضل` | <thead><tr><th>الهجوم</th><th>Centralized</th><th>Distributed RSU</th><th>Ahmed-Inspired Witness</th><th>الأفضل ضمن التجربة</th></tr></thead> |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 522 | `تفوق` | بيئة واحدة، مع بقاء حجم المكسب مختلفاً بين البيئات. كما يجب فصل الأداء المطلق عن حجم التفوق؛ فمثلاً كان Recall |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 601 | `تفوق` | لا يجوز تعميم تفوق RSU في Position/Speed على جميع الأنظمة الواقعية دون دراسة حساسية تجاه ضجيج الحساسات؛ |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 680 | `أفضل` | ظهر Distributed RSU أقل كلفة وفق عدّاد النقل في المحاكي، لكن لا يُفسر انخفاض <span class="ltr">bytes_per_decision</span> مقابل المسار المركزي كأفضلية معمارية عامة؛ فالأدلة المحلية لدى منسق RSU لا تعبر |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 699 | `Safety` | <strong>تصحيح ادعاء Safety:</strong> |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 700 | `Safety` | لا تُقدَّم قيمة «صفر Safety Violations» بوصفها نتيجة تجريبية. محرك الإجماع المجمد لم يتضمن مولداً لاقتراحات |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 701 | `safety_violation` | خبيثة ذات حمولة دلالية غير صحيحة، كما أن مؤشر <span class="ltr">safety_violation</span> لم يكن مسار قياس |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 702 | `Safety` | تشغيلياً يمكن أن يتحول إلى حالة موجبة في الحملة الأساسية. لذلك لا تسمح البيانات الحالية باختبار Safety تحت |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 713 | `Byzantine` | لكنه ليس اختبار إجهاد Byzantine شاملاً. اختبار الأعطال الفعالة أو الاقتراحات الدلالية الخبيثة يبقى امتداداً |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 724 | `VIEW-CHANGE` | ولا ينفذ VIEW-CHANGE/NEW-VIEW كاملاً. وكان <span class="ltr">validator_behaviors = {}</span> في إعداد الحملة |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 725 | `Byzantine` | النهائية، لذلك لا تقدم baseline اختبار Byzantine safety. كما أن |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 726 | `safety_violation` | <span class="ltr">safety_violation=false</span> لا يمثل قياس Safety عندما لا يُنشئ المسار التنفيذي |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 774 | `MCC` | <div class="figure"><img alt="MCC Topology" src="../Fig_08_MCC_By_Topology.png"/><div class="caption">الشكل (5-8): MCC عبر طوبولوجيات VANET المختلفة.</div></div><div class="figure"><img alt="Recall To |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 779 | `MCC` | <span class="ltr">0.8600</span> وMCC نحو <span class="ltr">0.8643</span>، |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 781 | `MCC` | وMCC نحو <span class="ltr">0.8608</span>. هذه قراءة شرطية ضمن السيناريو ولا تثبت أن Corridor نفسه سبب الفرق |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 782 | `أفضل` | أو أنه أفضل طوبولوجيا بصورة عامة. |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 785 | `كثافة الجذور` | <strong>لا تفسير بكثافة الجذور وحدها:</strong> |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 786 | `كثافة الجذور` | في التحليل الموسع كانت نسبة كثافة الجذور في Intersection نحو 1.09× مع مكسب Recall يقارب +11 نقطة، |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 789 | `كثافة الجذور` | لكثافة الجذور وحدها. |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 827 | `أفضل` | <thead><tr><th>الأولوية</th><th>المسار/التكوين الأفضل وصفياً ضمن هذه التجربة</th><th>السبب</th></tr></thead> |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 834 | `MCC` | <tr><td>أعلى MCC وصفي</td><td>Ahmed-Inspired Witness</td><td>MCC = 0.8474، لكن فرق MCC غير دال تأكيدياً بعد Holm (adjusted p=0.1986)</td></tr> |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 837 | `أفضل` | هذه المفاضلة أهم من ترتيب معماري خطي من الأفضل إلى الأسوأ. ففي تطبيق قد تكون تكلفة إلغاء مركبة شرعية مرتفعة، |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 849 | `MCC` | <li><strong>MCC أعلى وصفياً لا تأكيدياً:</strong> القيمة الإجمالية لـAhmed أعلى، لكن فرق MCC لم يبق دالاً بعد Holm (adjusted p = 0.1986).</li> |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 853 | `Safety` | <li><strong>PBFT لا يعوض ضعف التأهيل:</strong> الإجماع يبدأ بعد نجاح التأهيل؛ كما أن baseline حقق نجاح إجماع كاملاً من دون أن يشكل اختبار Safety بيزنطي تحت اقتراحات دلالية خبيثة.</li> |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 862 | `MCC` | ومصدر الأدلة متماثلين. مؤشرات Recall وFRR وMCC تقيس جودة القرار، ولا تقيس مباشرة مقاومة العبث بالسجل أو قابلية |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 878 | `تفوق` | <li><strong>Ahmed ليس دليلاً على تفوق معماري:</strong> |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 900 | `Safety` | <h3>5.20.2 حدود اختبار PBFT وSafety</h3> |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 903 | `Safety` | Safety Violations لا تُعامل كقياس تجريبي في هذه الرسالة، لأن المحرك المجمد لم يتضمن مولداً لاقتراحات دلالية |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 904 | `safety_violation` | خبيثة، ولأن مؤشر <span class="ltr">safety_violation</span> لم يكن مساراً تشغيلياً قابلاً للوصول إلى قيمة موجبة |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 905 | `Safety` | في الحملة. لذلك يقتصر الاستنتاج على نجاح الإجماع والحيوية ضمن شروط baseline، بينما يبقى اختبار Safety العدائي |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 920 | `أفضل` | مستمدة من الأدبيات. تم الاحتفاظ بالمرشح الأفضل وفق قاعدة الترتيب الأصلية من دون تخفيف لاحق للشروط. |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 979 | `MCC` | كانت قيمة MCC الإجمالية في Ahmed أعلى وصفياً، لكن فرق MCC لم يبق دالاً بعد تصحيح Holm، ولذلك لا يُستخدم MCC |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 980 | `تفوق` | وحده كدليل تأكيدي على تفوق شامل. أما Mixed فأظهر أكبر مكسب استكشافي لمسار الشهود (+56.13 نقطة مئوية مجمعاً) |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 989 | `Safety` | PBFT في baseline، لكن Safety تحت اقتراحات دلالية خبيثة لم يُختبر تجريبياً ويظل من حدود الدراسة. |
| `results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion/chapter_5_results_discussion_ar.html` | 993 | `أفضل` | لا تدعم النتائج فكرة «معمارية أفضل مطلقاً». تدعم بدلاً من ذلك نتيجة أدق: <strong>مصدر الأدلة، وقدرة المسار على |
