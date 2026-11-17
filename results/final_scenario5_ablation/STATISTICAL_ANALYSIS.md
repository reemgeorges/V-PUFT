# Paired statistical analysis — Scenario 5 bounded component ablation

All comparisons are paired by density, seed, and architecture. The experimental unit for uncertainty summaries is the SUMO seed, not the case window. Each density has four paired seeds; ranges are descriptive only and do not support a strong significance claim.

State-aware metrics exclude post-first-revocation terminal windows. Fixed-opportunity detection Recall uses the emitted malicious-message universe from each matched trace. Protected-opportunity fraction separately counts malicious transmissions emitted strictly after the first committed vehicle revocation.

The variants A and C are insecure counterfactuals. Their effect sizes are component diagnostics, not candidate configurations.

## Paired differences

`paired_comparison_summary.csv` contains mean and median candidate-minus-baseline differences, per-seed improvement/unchanged/worsened counts, and observed min/max paired ranges. The expected beneficial direction is recorded per metric; post-revocation exclusions are descriptive only.

## Decision changes

Case-level revocation decisions changed in 286 paired cells/cases. See `case_level_changes.csv` for exact case identities and benign/malicious labels.

## Aggregate tables

Pooled confusion metrics are computed from summed TP/FP/TN/FN across the four seeds. Macro metrics are means of per-seed values. They are not interchangeable.

See `aggregated_metrics.csv`, `paired_comparison_by_seed.csv`, and `paired_comparison_summary.csv` for numeric results.
