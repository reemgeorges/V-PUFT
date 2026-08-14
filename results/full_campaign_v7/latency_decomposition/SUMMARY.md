# Latency Decomposition (V-PUFT v8, post-freeze)

No experiment was re-run. Stage durations are read from the frozen
`final_metrics_by_seed.csv`, where metrics.py already defines them as
independent stage deltas rather than cumulative sums.

**Unit of analysis:** each row is a per-seed P95; the tables report the
distribution of those per-seed P95 values across the seed-topology units.

**Arithmetic warning carried into the thesis:** the stage values below do
not sum to the end-to-end value, and must never be drawn as a stacked bar.
P95(A) + P95(B) + P95(C) is not P95(A+B+C).

## Stage medians (of per-seed P95, ms)

| Architecture | Stage | Median | IQR | Interpretation scope |
|---|---|---|---|---|
| Centralized V-PUFT | Detection / evidence acquisition | 8000.0 | 8000.0 - 8000.0 | Evidence acquisition/detection; may vary with evidence view and delivery path |
| Centralized V-PUFT | Qualification (V-PUFT) | 14130.1 | 14103.5 - 14149.9 | V-PUFT qualification after detection |
| Centralized V-PUFT | Finalization (central or PBFT) | 0.0 | 0.0 - 0.0 | Finalization path; cleanest Central-vs-PBFT comparison |
| Centralized V-PUFT | End-to-end (NOT the sum of the stages above) | 14184.0 | 14156.8 - 14211.0 | End-to-end case latency from case opening to finalization |
| Distributed RSU V-PUFT | Detection / evidence acquisition | 8000.0 | 8000.0 - 8000.0 | Evidence acquisition/detection; may vary with evidence view and delivery path |
| Distributed RSU V-PUFT | Qualification (V-PUFT) | 14324.0 | 14283.0 - 14351.3 | V-PUFT qualification after detection |
| Distributed RSU V-PUFT | Finalization (central or PBFT) | 45.0 | 42.7 - 65.9 | Finalization path; cleanest Central-vs-PBFT comparison |
| Distributed RSU V-PUFT | End-to-end (NOT the sum of the stages above) | 14361.7 | 14323.4 - 14391.5 | End-to-end case latency from case opening to finalization |
| Ahmed-Inspired Witness V-PUFT | Detection / evidence acquisition | 8000.0 | 8000.0 - 8775.0 | Evidence acquisition/detection; may vary with evidence view and delivery path |
| Ahmed-Inspired Witness V-PUFT | Qualification (V-PUFT) | 14589.2 | 14478.3 - 14817.1 | V-PUFT qualification after detection |
| Ahmed-Inspired Witness V-PUFT | Finalization (central or PBFT) | 45.6 | 43.9 - 113.5 | Finalization path; cleanest Central-vs-PBFT comparison |
| Ahmed-Inspired Witness V-PUFT | End-to-end (NOT the sum of the stages above) | 14623.1 | 14511.3 - 14854.9 | End-to-end case latency from case opening to finalization |

## Paired stage comparisons

| Stage | Comparison | n | Median diff (ms) | Wilcoxon p | Interpretation scope |
|---|---|---|---|---|---|
| Detection / evidence acquisition | Distributed RSU V-PUFT vs Centralized V-PUFT | 40 | +0.00 | - | Evidence acquisition/detection; may vary with evidence view and delivery path |
| Detection / evidence acquisition | Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | 40 | +0.00 | 0.0009766 | Evidence acquisition/detection; may vary with evidence view and delivery path |
| Detection / evidence acquisition | Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | 40 | +0.00 | 0.0009766 | Evidence acquisition/detection; may vary with evidence view and delivery path |
| Qualification (V-PUFT) | Distributed RSU V-PUFT vs Centralized V-PUFT | 40 | +185.71 | 1.819e-12 | V-PUFT qualification after detection |
| Qualification (V-PUFT) | Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | 40 | +461.47 | 1.819e-12 | V-PUFT qualification after detection |
| Qualification (V-PUFT) | Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | 40 | +293.44 | 1.819e-12 | V-PUFT qualification after detection |
| Finalization (central or PBFT) | Distributed RSU V-PUFT vs Centralized V-PUFT | 40 | +44.95 | 1.819e-12 | Finalization path; cleanest Central-vs-PBFT comparison |
| Finalization (central or PBFT) | Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | 40 | +45.63 | 1.819e-12 | Finalization path; cleanest Central-vs-PBFT comparison |
| Finalization (central or PBFT) | Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | 40 | +1.94 | 0.07034 | Finalization path; cleanest Central-vs-PBFT comparison |
| End-to-end | Distributed RSU V-PUFT vs Centralized V-PUFT | 40 | +167.80 | 1.819e-12 | End-to-end case latency from case opening to finalization |
| End-to-end | Ahmed-Inspired Witness V-PUFT vs Centralized V-PUFT | 40 | +433.71 | 1.819e-12 | End-to-end case latency from case opening to finalization |
| End-to-end | Ahmed-Inspired Witness V-PUFT vs Distributed RSU V-PUFT | 40 | +295.14 | 1.819e-12 | End-to-end case latency from case opening to finalization |

## Text for section 5.12 - place BEFORE any number

> The end-to-end value reported here is measured from the opening of an evidence case until finalization, not from the arrival of a single V2X message. It therefore includes evidence acquisition/detection, V-PUFT qualification and finalization. The detection/evidence-acquisition stage is not assumed to be identical across architectures: it may vary with the evidence view and delivery path and is therefore part of the broader architectural comparison. The qualification stage reports the V-PUFT interval after detection, while the finalization stage is the cleanest measure for comparing centralized finalization with PBFT. The end-to-end figure is not a single-message dissemination latency and should not be interpreted as such. Finally, the reported values are percentiles and are not additive: P95(A)+P95(B)+P95(C) is not P95(A+B+C), so the stages are shown separately and no share-of-total claim is made.
