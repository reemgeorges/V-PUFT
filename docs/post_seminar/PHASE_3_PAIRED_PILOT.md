# Phase 3 paired pilot: B0 / B1 / B8

## Protocol

The pilot replayed the same generated shared detection traces for all three variants at density/seed cells `(20,1001)`, `(60,1001)`, and `(100,1001)`. B0 uses the baseline representative-only diversity behavior. B1 enables the earlier diversity-aware root assignment. B8 enables the new provenance-safe observer matching while leaving B1's reassignment option off, isolating the new branch. Network, policy, weights, labels, 15-second freshness horizon, fixed windows, architecture, and seed were otherwise held constant.

The trace SHA-256 values below identify paired inputs; they do not establish byte-identical historical reproduction of frozen traces:

| Density | Seed | Bytes | SHA-256 |
|---:|---:|---:|---|
| 20 | 1001 | 15,124,700 | `9d2262ab4639d2873b9dbe66ab1c62acf5eeedca9020ddadbb2933e9039d103c` |
| 60 | 1001 | 74,413,783 | `7ab6eaca6ace0f6caae986c9be9085c60bb9c37e0bf5c573d9979682f324ed0d` |
| 100 | 1001 | 122,704,706 | `56ac3aab651eaa737a78a0f2a6b97b0e9e01553e4f6010cc64949c83af8b4c6c` |

## Results

Each row is the exact single paired seed result. Recall, precision, FRR, and F1 are proportions. E2E is P95 milliseconds. CPU is measured Python process CPU seconds for the run. Messages per Case is the architecture metric.

| Variant | Density | TP | FP | TN | FN | Recall | Precision | FRR | F1 | P95 E2E ms | CPU s | Messages/Case |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| B0 | 20 | 4 | 0 | 89 | 7 | 0.363636 | 1.000000 | 0 | 0.533333 | 14,067.895 | 2.203125 | 21.6723 |
| B1 | 20 | 4 | 0 | 89 | 7 | 0.363636 | 1.000000 | 0 | 0.533333 | 14,067.895 | 2.203125 | 21.6723 |
| B8 | 20 | 4 | 0 | 89 | 7 | 0.363636 | 1.000000 | 0 | 0.533333 | 14,067.895 | 2.203125 | 21.6723 |
| B0 | 60 | 14 | 0 | 257 | 21 | 0.400000 | 1.000000 | 0 | 0.571429 | 14,146.033 | 7.437500 | 20.6667 |
| B1 | 60 | 15 | 0 | 253 | 20 | 0.428571 | 1.000000 | 0 | 0.600000 | 14,146.334 | 6.500000 | 20.7692 |
| B8 | 60 | 15 | 0 | 253 | 20 | 0.428571 | 1.000000 | 0 | 0.600000 | 14,146.334 | 6.843750 | 20.7692 |
| B0 | 100 | 20 | 0 | 430 | 31 | 0.392157 | 1.000000 | 0 | 0.563380 | 14,115.816 | 6.046875 | 17.3732 |
| B1 | 100 | 22 | 0 | 422 | 28 | 0.440000 | 1.000000 | 0 | 0.611111 | 14,129.509 | 5.953125 | 17.5000 |
| B8 | 100 | 22 | 0 | 422 | 28 | 0.440000 | 1.000000 | 0 | 0.611111 | 14,129.509 | 9.515625 | 17.5000 |

## Paired interpretation and FP audit

B8 matched B1 exactly on TP/FP/TN/FN, Recall, Precision, FRR, F1, P95 E2E, and Messages/Case for all three cells. Relative to B0, B8 reduced window FN by 1 at density 60 and by 3 at density 100, while FP remained zero; those gains are identical to the existing B1 gains and are not an incremental B8 gain. B8's CPU was equal at density 20, 0.344 seconds higher than B1 at density 60 (+5.3%), and 3.563 seconds higher at density 100 (+59.8%). P95 E2E was unchanged from B1 to reported precision.

The paired B8-only new false-positive list has **0 rows**. There are no new false-positive cases to explain. These small cells cannot establish that FP risk is zero across the full scenario.

The pilot is one seed per density and is descriptive, not a significance test. B8 is not selected over B1: it has no incremental Recall or latency benefit and adds CPU cost at high density. Therefore the 50-cell B8 campaign was not run. Artifacts and exact per-run metrics are under `results/post_seminar_phase3/limited_v2/`.
