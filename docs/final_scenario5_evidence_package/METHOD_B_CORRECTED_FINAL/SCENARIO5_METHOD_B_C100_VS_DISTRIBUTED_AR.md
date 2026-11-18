# مقارنة C100 وDistributed — Scenario 5 Method B

المصدر Dataset B وحده عند المرجع `0c0c10b3d6cbb2075e430a299e3c18cdf382320a`. C100 هو `centralized_remote_100ms` وDistributed هو `distributed_density_honest`. لكل منهما 17,418 سجل حالة؛ تقاطع المفاتيح 17,418، وغير المطابق صفر. اختلاف الحقيقة المرجعية أو نوع الهجوم على الحالات المشتركة صفر.

## مجاميع Method B

| المعمارية | TP | FP | TN | FN | مؤهل | مستبعد بعد REVOKED | كل السجلات | Precision | Recall | FRR | F1 | MCC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| C100 | 639 | 9 | 12981 | 964 | 14593 | 2825 | 17418 | 0.986111 | 0.398628 | 0.000693 | 0.567748 | 0.604069 |
| Distributed | 641 | 9 | 12974 | 961 | 14585 | 2833 | 17418 | 0.986154 | 0.400125 | 0.000693 | 0.569272 | 0.605273 |

اختلف قرار الإبطال في حالتين malicious فقط. هويات FP المؤهلة: 9 في كل جانب، والفرق بين مجموعتي الهويات صفر؛ لم تُضف Distributed حالة FP.

| الكثافة | البذرة | case_id | المركبة | الهجوم | سبب C100 | سبب Distributed | إتمام C100 | إتمام Distributed |
|---:|---:|---|---|---|---|---|---|---:|
| 60 | 1002 | case-urban_roundabout-1002-veh_044-w0002 | veh_044 | speed_offset | central_server_unavailable | committed | لا يوجد | 44.1124202550157 s |
| 100 | 1004 | case-urban_roundabout-1004-veh_020-w0001 | veh_020 | position_offset | central_server_unavailable | committed | لا يوجد | 29.102440445804085 s |

الحالتان ناجمتان عن `central_server_unavailable` في C100 مقابل إنهاء ناجح في Distributed؛ لا تثبتان وحدهما تحسناً في خوارزمية QE.

## النوافذ الطرفية الإضافية في Distributed

| الكثافة | البذرة | case_id | المركبة | GT malicious | سبب C100 | سبب Distributed |
|---:|---:|---|---|---:|---|---|
| 60 | 1002 | case-urban_roundabout-1002-veh_044-w0003 | veh_044 | 0 | insufficient_weighted_margin | already_revoked_terminal_state |
| 60 | 1002 | case-urban_roundabout-1002-veh_044-w0004 | veh_044 | 0 | insufficient_independent_evidence_diversity | already_revoked_terminal_state |
| 60 | 1002 | case-urban_roundabout-1002-veh_044-w0005 | veh_044 | 0 | insufficient_independent_evidence_diversity | already_revoked_terminal_state |
| 100 | 1004 | case-urban_roundabout-1004-veh_020-w0002 | veh_020 | 1 | insufficient_weighted_margin | already_revoked_terminal_state |
| 100 | 1004 | case-urban_roundabout-1004-veh_020-w0003 | veh_020 | 0 | insufficient_independent_evidence_diversity | already_revoked_terminal_state |
| 100 | 1004 | case-urban_roundabout-1004-veh_020-w0004 | veh_020 | 0 | insufficient_independent_evidence_diversity | already_revoked_terminal_state |
| 100 | 1004 | case-urban_roundabout-1004-veh_020-w0005 | veh_020 | 0 | insufficient_independent_evidence_diversity | already_revoked_terminal_state |
| 100 | 1004 | case-urban_roundabout-1004-veh_020-w0006 | veh_020 | 0 | insufficient_independent_evidence_diversity | already_revoked_terminal_state |

توجد 8 نوافذ terminal إضافية بعد الإبطال المبكر في Distributed: واحدة malicious وسبع benign. لذا يختلف المقام المؤهل رغم تطابق مجموعة السجلات الخام. Recall هنا state-aware، ولا توجد فرصة هجوم ذات مقام ثابت في هذه الحملة.

## إيضاح C0 وC100 وحالتي عدم الإتاحة

### C0 مقابل C100

تتطابق مؤشرات التصنيف في Dataset B بين C0 (centralized_remote_0ms_control) وC100 (centralized_remote_100ms): TP=639 وFP=9 وTN=12,981 وFN=964 في كل منهما، مع 14,593 نافذة مؤهلة و2,825 مستبعدة بعد REVOKED. وتطابقت قرارات الحالات الـ17,418. هذا يثبت تكافؤ التصنيف في هذه السجلات لا تكافؤ الكمون أو الإتاحة في كل الظروف.

### حالتا عدم إتاحة الخادم والصفوف الطرفية

الحالتان: density 60 / seed 1002 / veh_044 / speed_offset / case-urban_roundabout-1002-veh_044-w0002؛ وdensity 100 / seed 1004 / veh_020 / position_offset / case-urban_roundabout-1004-veh_020-w0001. في C100 تعذر الإنهاء بسبب central_server_unavailable؛ وفي Distributed تم الإنهاء. تلاهما ثماني نوافذ already_revoked_terminal_state في Distributed (واحدة malicious وسبع benign). هذا فرق إتاحة وإنهاء وآثاره على حالة المركبة ومقام Method B، ولا يثبت تفوق QE أو PBFT-style detection.
