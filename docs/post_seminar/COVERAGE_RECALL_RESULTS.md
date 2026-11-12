# Held-out coverage pilot results

Pilot: seed 1007 at densities 20 and 100. Mobility, generated CAM/DENM files, and attack truth are byte-identical between placements. The candidate was registered before this pilot. Original and candidate maps are `results/post_seminar_phase5/coverage_original.png` and `coverage_candidate.png`. `pilot_paired_metrics.csv` and `pilot_paired_deltas.csv` contain the full metrics and within-cell differences, including MCC, vehicle revocation, PDR, and ledger delay. Two pilot cells do not support a significance test.

| Density | Variant | TP | FP | TN | FN | Recall | Precision | FRR | F1 | MCC | P95 E2E ms | CPU s | Messages/case |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 20 | C0 | 4 | 0 | 88 | 7 | .363636 | 1 | 0 | .533333 | .580381 | 14071.382 | 2.250 | 23.068 |
| 20 | C1 | 5 | 0 | 83 | 5 | .500000 | 1 | 0 | .666667 | .686725 | 14123.771 | 2.781 | 29.000 |
| 20 | C2 | 5 | 0 | 83 | 5 | .500000 | 1 | 0 | .666667 | .686725 | 14123.771 | 3.031 | 29.000 |
| 100 | C0 | 21 | 0 | 423 | 29 | .420000 | 1 | 0 | .591549 | .626939 | 14112.987 | 8.844 | 17.524 |
| 100 | C1 | 19 | 0 | 422 | 20 | .487179 | 1 | 0 | .655172 | .682008 | 14138.014 | 5.859 | 19.522 |
| 100 | C2 | 19 | 0 | 422 | 19 | .500000 | 1 | 0 | .666667 | .691707 | 14136.849 | 9.625 | 19.520 |

The density-100 Recall increase is misleading as a security improvement. C0 evaluates 50 at-risk malicious windows; C1 evaluates only 39 and TP falls by two. Window identities also change with visibility, so direct case-ID differences are not a paired detection effect. At the message level, of 1,897 identically emitted malicious messages, C0 observes 1,514 with at least one RSU and 481 with at least two; C1 observes only 1,054 with at least one, although 581 have at least two. At density 20, of 425 emitted malicious messages, observed totals are 295/322 and multi-observed totals are 77/187 for C0/C1. The candidate concentrates overlap while creating blind spots at density 100. FP and FRR stay zero in these two cells, but this cannot offset lost attack visibility. C1 vehicle revocations are 5 versus 4 at density 20 and 19 versus 21 at density 100. PDR remains approximately .979–.980; relocation-dependent radio paths are not modeled. The apparent density-100 CPU saving also reflects fewer observed cases and cannot be interpreted as a processing improvement.
