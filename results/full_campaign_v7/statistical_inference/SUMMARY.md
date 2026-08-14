# Post-Freeze Statistical Validation (V-PUFT v8)

This analysis re-runs no experiment. It reports intervals, paired tests and
effect sizes over the frozen v7 results. No v7 number is replaced.

- Pairing unit: `['topology', 'seed']`
- Bootstrap: stratified cluster resampling, composition per replicate {'corridor': 10, 'grid': 10, 'intersection': 10, 'smoke': 10}
- Resamples: 10000 bootstrap, 20000 permutation
- Effect sizes: matched-pairs rank-biserial and Cohen's dz (paired design)
- Primary family: recall, FRR, MCC, Holm-corrected at alpha = 0.05
- Exploratory family: precision, F1, latency, messages, bytes, memory (uncorrected)
- RNG seed: 20260814

## Primary metrics - pooled difference with 95% stratified cluster-bootstrap CI

| Comparison | Metric | A | B | Difference | 95% CI | CI excludes 0 |
|---|---|---|---|---|---|---|
| Distributed RSU V-PUFT vs Centralized V-PUFT | recall | 0.8090 | 0.8090 | +0.0000 | [+0.0000, +0.0000] | no |
| Distributed RSU V-PUFT vs Centralized V-PUFT | frr | 0.0164 | 0.0164 | +0.0000 | [+0.0000, +0.0000] | no |
| Distributed RSU V-PUFT vs Centralized V-PUFT | mcc | 0.8307 | 0.8307 | +0.0000 | [+0.0000, +0.0000] | no |
| Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | recall | 0.8090 | 0.8935 | +0.0846 | [+0.0635, +0.1057] | YES |
| Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | frr | 0.0164 | 0.0309 | +0.0145 | [+0.0138, +0.0151] | YES |
| Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | mcc | 0.8307 | 0.8475 | +0.0168 | [+0.0024, +0.0309] | YES |
| Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | recall | 0.8090 | 0.8935 | +0.0846 | [+0.0634, +0.1060] | YES |
| Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | frr | 0.0164 | 0.0309 | +0.0145 | [+0.0139, +0.0151] | YES |
| Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | mcc | 0.8307 | 0.8475 | +0.0168 | [+0.0025, +0.0311] | YES |

## Exploratory metrics - pooled difference with 95% stratified cluster-bootstrap CI

| Comparison | Metric | A | B | Difference | 95% CI | CI excludes 0 |
|---|---|---|---|---|---|---|
| Distributed RSU V-PUFT vs Centralized V-PUFT | precision | 0.9084 | 0.9084 | +0.0000 | [+0.0000, +0.0000] | no |
| Distributed RSU V-PUFT vs Centralized V-PUFT | f1 | 0.8558 | 0.8558 | +0.0000 | [+0.0000, +0.0000] | no |
| Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | precision | 0.9084 | 0.8544 | -0.0540 | [-0.0577, -0.0503] | YES |
| Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | f1 | 0.8558 | 0.8735 | +0.0178 | [+0.0055, +0.0298] | YES |
| Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | precision | 0.9084 | 0.8544 | -0.0540 | [-0.0579, -0.0502] | YES |
| Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | f1 | 0.8558 | 0.8735 | +0.0178 | [+0.0055, +0.0300] | YES |

## Exploratory attack-stratified recall - unadjusted for multiplicity

This section is explicitly exploratory. Attack-specific contrasts were examined after the global pattern was known, so the intervals below must not be presented as confirmatory hypothesis tests. `CI excludes 0` is descriptive evidence of a stable direction under the stratified cluster bootstrap, not a multiplicity-adjusted claim of statistical significance.

| Attack | Comparison | Recall A | Recall B | Difference | 95% CI | CI excludes 0 |
|---|---|---|---|---|---|---|
| certificate_tamper | Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | 1.0000 | 1.0000 | +0.0000 | [+0.0000, +0.0000] | no |
| certificate_tamper | Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | 1.0000 | 1.0000 | +0.0000 | [+0.0000, +0.0000] | no |
| certificate_tamper | Distributed RSU V-PUFT vs Centralized V-PUFT | 1.0000 | 1.0000 | +0.0000 | [+0.0000, +0.0000] | no |
| false_denm | Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | 0.7109 | 0.8750 | +0.1641 | [+0.0930, +0.2422] | YES |
| false_denm | Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | 0.7109 | 0.8750 | +0.1641 | [+0.0873, +0.2385] | YES |
| false_denm | Distributed RSU V-PUFT vs Centralized V-PUFT | 0.7109 | 0.7109 | +0.0000 | [+0.0000, +0.0000] | no |
| flood | Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | 0.9600 | 0.9600 | +0.0000 | [-0.0238, +0.0236] | no |
| flood | Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | 0.9600 | 0.9600 | +0.0000 | [-0.0165, +0.0236] | no |
| flood | Distributed RSU V-PUFT vs Centralized V-PUFT | 0.9600 | 0.9600 | +0.0000 | [+0.0000, +0.0000] | no |
| mixed | Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | 0.3355 | 0.8968 | +0.5613 | [+0.5128, +0.6104] | YES |
| mixed | Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | 0.3355 | 0.8968 | +0.5613 | [+0.5128, +0.6118] | YES |
| mixed | Distributed RSU V-PUFT vs Centralized V-PUFT | 0.3355 | 0.3355 | +0.0000 | [+0.0000, +0.0000] | no |
| position_offset | Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | 0.9688 | 0.8187 | -0.1500 | [-0.2125, -0.0938] | YES |
| position_offset | Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | 0.9688 | 0.8187 | -0.1500 | [-0.2064, -0.0938] | YES |
| position_offset | Distributed RSU V-PUFT vs Centralized V-PUFT | 0.9688 | 0.9688 | +0.0000 | [+0.0000, +0.0000] | no |
| replay | Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | 0.7468 | 0.8734 | +0.1266 | [+0.1250, +0.1290] | YES |
| replay | Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | 0.7468 | 0.8734 | +0.1266 | [+0.1250, +0.1290] | YES |
| replay | Distributed RSU V-PUFT vs Centralized V-PUFT | 0.7468 | 0.7468 | +0.0000 | [+0.0000, +0.0000] | no |
| speed_offset | Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | 0.9874 | 0.8679 | -0.1195 | [-0.1698, -0.0687] | YES |
| speed_offset | Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | 0.9874 | 0.8679 | -0.1195 | [-0.1709, -0.0696] | YES |
| speed_offset | Distributed RSU V-PUFT vs Centralized V-PUFT | 0.9874 | 0.9874 | +0.0000 | [+0.0000, +0.0000] | no |

## Primary family - Holm-corrected

| Metric | Comparison | n | Mean diff | Raw p | Holm-adjusted p | rank-biserial | Effect | Holm reject |
|---|---|---|---|---|---|---|---|---|
| malicious_revocation_recall | Distributed RSU V-PUFT vs Centralized V-PUFT | 40 | +0.0000 | 1 | 1 | undefined | undefined | no |
| malicious_revocation_recall | Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | 40 | +0.0849 | 2.404e-06 | 1.683e-05 | +0.898 | large | YES |
| malicious_revocation_recall | Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | 40 | +0.0849 | 2.404e-06 | 1.683e-05 | +0.898 | large | YES |
| false_revocation_rate | Distributed RSU V-PUFT vs Centralized V-PUFT | 40 | +0.0000 | 1 | 1 | undefined | undefined | no |
| false_revocation_rate | Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | 40 | +0.0144 | 2.658e-08 | 2.392e-07 | +1.000 | large | YES |
| false_revocation_rate | Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | 40 | +0.0144 | 2.658e-08 | 2.392e-07 | +1.000 | large | YES |
| mcc | Distributed RSU V-PUFT vs Centralized V-PUFT | 40 | +0.0000 | 1 | 1 | undefined | undefined | no |
| mcc | Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | 40 | +0.0171 | 0.03972 | 0.1986 | +0.373 | medium | no |
| mcc | Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | 40 | +0.0171 | 0.03972 | 0.1986 | +0.373 | medium | no |

## Exploratory family - uncorrected, not confirmatory

| Metric | Comparison | n | Mean diff | Raw p (uncorrected) | rank-biserial | Effect | Raw p < alpha?* |
|---|---|---|---|---|---|---|---|
| trust_precision | Distributed RSU V-PUFT vs Centralized V-PUFT | 40 | +0.0000 | 1 | undefined | undefined | no |
| trust_precision | Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | 40 | -0.0536 | 3.532e-08 | -1.000 | large | YES |
| trust_precision | Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | 40 | -0.0536 | 3.532e-08 | -1.000 | large | YES |
| trust_f1 | Distributed RSU V-PUFT vs Centralized V-PUFT | 40 | +0.0000 | 1 | undefined | undefined | no |
| trust_f1 | Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | 40 | +0.0179 | 0.01442 | +0.444 | medium | YES |
| trust_f1 | Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | 40 | +0.0179 | 0.01442 | +0.444 | medium | YES |
| latency_p95_ms | Distributed RSU V-PUFT vs Centralized V-PUFT | 40 | +172.7508 | 1.819e-12 | +1.000 | large | YES |
| latency_p95_ms | Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | 40 | +498.8992 | 1.819e-12 | +1.000 | large | YES |
| latency_p95_ms | Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | 40 | +326.1485 | 1.819e-12 | +1.000 | large | YES |
| messages_per_decision | Distributed RSU V-PUFT vs Centralized V-PUFT | 40 | -2.6678 | 5.905e-06 | -0.822 | large | YES |
| messages_per_decision | Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | 40 | +120.0078 | 1.819e-12 | +1.000 | large | YES |
| messages_per_decision | Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | 40 | +122.6756 | 1.819e-12 | +1.000 | large | YES |
| bytes_per_decision | Distributed RSU V-PUFT vs Centralized V-PUFT | 40 | -3050.6075 | 1.819e-12 | -1.000 | large | YES |
| bytes_per_decision | Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | 40 | +91465.4923 | 1.819e-12 | +1.000 | large | YES |
| bytes_per_decision | Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | 40 | +94516.0998 | 1.819e-12 | +1.000 | large | YES |
| peak_memory_kb | Distributed RSU V-PUFT vs Centralized V-PUFT | 40 | -78.0850 | 2.923e-06 | -0.785 | large | YES |
| peak_memory_kb | Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | 40 | +8275.1710 | 1.819e-12 | +1.000 | large | YES |
| peak_memory_kb | Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | 40 | +8353.2561 | 1.819e-12 | +1.000 | large | YES |

* Exploratory only: this flag uses the uncorrected raw p-value and is not a confirmatory multiplicity-adjusted decision.

## Wording rules for Chapter 5

1. Every point estimate gets an interval. Replace "improved recall by 8.49 points" with "improved pooled recall by X.XX points (95% stratified cluster-bootstrap CI [L, U], paired across N seed-topology units, Wilcoxon p = ..., rank-biserial r = ...)".

2. If an interval includes zero, say so and downgrade the claim to "no difference detectable at this sample size". A reported null is stronger than an unqualified estimate.

3. Exploratory-family results must be labelled exploratory in the text. They are not corrected for multiplicity and must not carry a confirmatory claim.

4. Attack-stratified recall is exploratory and unadjusted for multiplicity. If an attack-specific bootstrap CI excludes zero, describe the direction as stable under the exploratory stratified bootstrap; do not call it a confirmatory significant difference.

5. For the primary family, always report both the raw paired p-value and the Holm-adjusted p-value. The confirmatory decision follows `holm_reject`, not the raw p-value alone.
