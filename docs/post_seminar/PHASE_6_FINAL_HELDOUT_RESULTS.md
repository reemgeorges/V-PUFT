# Phase 6 final held-out validation

## Design and completion

This is the frozen infrastructure candidate selected from mobility/geometry training seeds 1001–1006: rsu-5 at (-150, 500), rsu-6 at (200, -500). Held-out seeds 1007–1010 were not used for selection or retuning. The 20 paired cells cover densities 20, 40, 60, 80, 100 and all four seeds. The 13 new candidate cells were executed in this continuation; the other seven came from saved Phase 6 pilot/holdout results. All 20 candidate cell summaries mark `completed=true`; no failed or skipped cell remains.

For each pair, baseline and candidate mobility, generated-message, and attack-ground-truth files have identical SHA-256 hashes. Attack opportunities are derived from emitted malicious message identities and fixed 15-second vehicle windows, independently of detection. Zero-observation opportunities remain in the denominator. First committed revocation is credited in its own window; later windows are terminal and counted as protected only in the fixed-universe measure. Original state-aware decisions are preserved. Decision counts differ modestly between layouts, so confusion totals and fixed opportunity denominators are shown separately.

## Paired results by density

The following table pools the four seeds at each density. Opportunity Recall is first-revocation TP divided by opportunities before terminal revocation. Fixed protection is (first-revocation TP + post-revocation terminal opportunities) divided by **all emitted opportunities**. State-aware Recall is pooled TP/(TP+FN). Counts are sums over four seeds.

| Density | Opportunities | Observed C0→C1 | Opportunity Recall C0→C1 | Fixed protection C0→C1 | State-aware Recall C0→C1 | TP C0→C1 | FP C0→C1 | TN C0→C1 | FN C0→C1 |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 20 | 76 | 63→65 | .197→.281 | .355→.461 | .364→.435 | 16→20 | 0→0 | 356→342 | 28→26 |
| 40 | 148 | 135→138 | .319→.361 | .480→.534 | .438→.476 | 35→39 | 1→0 | 706→697 | 45→43 |
| 60 | 228 | 199→199 | .307→.341 | .465→.509 | .417→.470 | 58→62 | 0→0 | 1027→1016 | 81→70 |
| 80 | 287 | 251→251 | .278→.307 | .429→.464 | .415→.444 | 71→76 | 0→0 | 1375→1361 | 100→95 |
| 100 | 347 | 300→300 | .242→.264 | .369→.398 | .396→.423 | 80→85 | 2→2 | 1708→1697 | 122→116 |

The denominator fixed protection counts correspond to protected opportunities: 27→35/76, 71→79/148, 106→116/228, 123→133/287, and 128→138/347. Across all 1,086 emitted opportunities, observation changed from 1,016 to 1,019 (+3; no pair lost observed opportunities). Fixed-universe protected fraction increased from 455/1,086 = 41.9% to 501/1,086 = 46.1%. Mean across the 20 paired cells: opportunity Recall .2685→.3109; fixed-universe protection .4195→.4729; historical state-aware Recall .4063→.4499.

## Common and union cases

The exact opportunity IDs observed under both layouts and under either layout are in `results/post_seminar_phase6_final/opportunity_case_unions.csv`. On the common observed set, mean protected fractions across seeds by density were C0→C1: 42.8→55.5%, 52.6→58.5%, 53.3→58.3%, 49.0→53.0%, and 42.7→46.0%. On the union set they were 41.5→53.9%, 51.5→57.3%, 53.3→58.3%, 49.0→53.0%, and 42.7→46.0%. These comparisons retain a common evaluated opportunity universe and do not attribute missing observations to successful detection.

## False positives and case counts

No new false-positive case was introduced. At density 40, seed 1009, the baseline false positive on `case-urban_roundabout-1009-veh_024-w0003` (vehicle `veh_024`) was absent under C1. At density 100, seeds 1008 and 1010, the same false-positive cases occurred in both layouts: `case-urban_roundabout-1008-veh_079-w0003` and `case-urban_roundabout-1010-veh_079-w0003` (vehicle `veh_079`). Thus pooled FP was 3→2. FRR averaged over cells was 0.00054→0.00023. Precision averaged 98.96%→99.53%; pooled F1 and MCC were not treated as independent-seed evidence and per-cell metric rows are retained in the paired CSV.

The state-aware evaluated-window totals changed by density: 400→388, 787→779, 1,166→1,148, 1,546→1,532, and 1,912→1,900. This reflects placement-dependent decision/evaluation rows; it is why state-aware Recall is not the primary cross-placement metric. The emitted-opportunity denominator remains fixed at the paired source set shown above.

| Density | Precision C0→C1 | FRR C0→C1 | F1 C0→C1 | MCC C0→C1 | Vehicle revocations C0→C1 |
|---:|---:|---:|---:|---:|---:|
| 20 | 1.000→1.000 | .0000→.0000 | .533→.607 | .581→.636 | 4.00→5.00 |
| 40 | .972→1.000 | .0014→.0000 | .604→.644 | .632→.669 | 8.75→9.75 |
| 60 | 1.000→1.000 | .0000→.0000 | .589→.639 | .622→.663 | 14.50→15.50 |
| 80 | 1.000→1.000 | .0000→.0000 | .587→.615 | .622→.645 | 17.75→19.00 |
| 100 | .976→.977 | .0012→.0012 | .564→.590 | .599→.620 | 20.00→21.25 |

## Coverage and resource metrics

Mean messages with at least two RSU observers across cells increased 341.7→368.4 (+26.7); gains were concentrated at densities 20 and 100, while the mean count fell at densities 40–80. Mean P95 E2E was 14,103.94→14,115.55 ms (+11.61 ms, approximately 0.08%). Mean CPU was 5.9375→5.9297 seconds (−0.0078 seconds); paired seed-level 95% interval is broad and includes substantial gains and losses. Messages per case increased 20.14→22.02 (+1.88, about 9.4%). Mean PDR was effectively unchanged at 98.01%; mean ledger consistency delay was 15.30→15.34 ms (+0.05 ms). The existing network model retains RSU-ID-based routes and does not recompute spatial radio paths, so E2E is not evidence of geographic routing improvement.

| Density | CPU s C0→C1 | P95 E2E ms C0→C1 | Messages/case C0→C1 | PDR C0→C1 | Ledger delay ms C0→C1 |
|---:|---:|---:|---:|---:|---:|
| 20 | 2.109→2.316 | 14071.11→14116.49 | 22.16→25.09 | .9798→.9796 | 13.84→14.43 |
| 40 | 4.453→3.949 | 14108.85→14108.08 | 21.65→23.53 | .9800→.9801 | 16.06→15.10 |
| 60 | 6.102→6.313 | 14114.17→14118.38 | 20.66→22.25 | .9807→.9805 | 15.70→15.96 |
| 80 | 8.539→7.730 | 14110.78→14114.54 | 18.91→20.31 | .9798→.9801 | 15.37→16.00 |
| 100 | 8.484→9.340 | 14114.77→14120.23 | 17.30→18.91 | .9802→.9804 | 15.51→15.22 |

## Paired statistics and decision

All four seeds improved in fixed-universe protection and opportunity Recall when averaged across densities; every individual density had higher mean fixed protection, and the observed-opportunity count never decreased in any pair (it rose in three cells and tied in 17). In the per-density analysis, fixed protection improved in 4/4 seeds at every density; opportunity Recall improved in 4/4 at every density. State-aware TP improved in 4/4 seeds for densities 20, 40, 80, 100, and 3/4 at density 60. Multi-observer message counts did not improve at every density, despite their aggregate increase.

Descriptive two-sided 95% Student-t intervals are computed over **four seed-level paired mean differences**, not over windows; n=4 is too small for a strong significance claim. Overall fixed protection gain was +5.34 percentage points (interval +4.46 to +6.21 pp); opportunity Recall gain +4.24 pp (interval +2.96 to +5.52 pp); state-aware TP +1.10 per cell (interval +0.69 to +1.51). CPU difference −0.008 s (interval −2.03 to +2.02 s); P95 E2E +11.61 ms (interval +8.84 to +14.37 ms). Treat all intervals as exploratory.

**Decision:** retain this as a promising, separately labeled infrastructure coverage improvement for controlled follow-up, not as a QE/PBFT algorithm improvement and not yet as deployment-validated. It met the no-observation-loss and consistent fixed-protection gates and introduced no FP, but multi-observer gains vary by density, messages/case rose about 9.4%, the held-out sample has only four seeds, and the network model omits spatial path recomputation. Do not claim statistical significance or generalization beyond these paired scenarios.

## Artifacts and reproducibility

- `final_paired_comparison.csv`: all 20 seed-density paired metric rows.
- `opportunity_case_unions.csv`: common, union, baseline-only, candidate-only opportunity IDs.
- `false_positive_case_audit.csv`: exact FP case overlap and changes.
- `paired_input_manifest.json`: completion markers and matching hashes for mobility, emitted messages, and attack truth.
- `paired_seed_statistics.csv` and `.json`: paired deltas and small-sample intervals.
- `scripts/evaluate_phase6_final.py`, `scripts/summarize_phase6_final.py`, `scripts/verify_phase6_final_pairs.py`: evaluation and integrity checks.
