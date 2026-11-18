# Provenance-Safe Evidence Optimization and B1 Validation

## Executive result

This bounded analysis replayed saved six-RSU (C1) and eight-RSU (C3) detection traces. It did not rerun SUMO, change production code, alter QE policy, or modify frozen results. B1 improved the number of fixed-universe attack opportunities detected in both layouts, with no new false-positive cases in this small replay. Its state-aware Recall gains are larger than the fixed-opportunity detection gains because the state-aware metric changes after revocation. B1 is not a resource optimization: it adds computation and does not reduce messages. The eight-RSU C3+B1 combination remains outside the preregistered CPU and messages-per-case limits.

The D1 report-suppression candidate is rejected. The 67.21% row reduction is only a diagnostic upper bound on rows in a pre-transport export. It is not an estimate of CPU or network savings, and the grouped reports are not semantically interchangeable.

## Scope, inputs, and reproducibility

The analysis uses the six paired C1/C3 cells at densities 20, 60, and 100 and seeds 2101 and 2102 from the completed 8-RSU pilot. B0 and B1 replay the same saved detection input for each cell. The paired manifest hashes confirm identical mobility, emitted-message identities, and attack ground truth between layouts. C3 adds sensing-only RSUs 7 and 8; validators remain RSUs 1–4, and witness routing is held constant. No B0/B1 change alters detector output or evidence generation.

The C3 density-100 seed-2102 primary directory is incomplete (575-case completion absent; its partial run has 484 cases). The completed `seed_2102_retry1` artifact (575 cases) is used for the final paired result. An earlier exploratory row derived from the incomplete directory is excluded. B0 replay decisions were checked against the saved B0 decisions, and B0/B1 replay determinism was checked. The manifest and compact summaries are under `results/provenance_evidence_optimization_final/`.

Only two seeds per density are available. These results are descriptive paired pilot evidence, not a basis for claims of statistical significance or broad generalization.

## Evidence lifecycle and redundancy audit

The relevant path is: detector observation → signed attestation and provenance → transport/forwarding → case bundle → signature/provenance sanitization → root aggregation and representative selection → qualification and validator requalification → PBFT-style processing/finalization. `trace.py` creates attestation identity/signatures and bundles. `architectures/base.py` removes only repeated copies with an identical attestation ID before signature verification. `distributed_extension.py` forwards evidence reports before coordinator qualification and sends the bundle to validators. `weighting.py` aggregates by observation root, retaining the strongest support and opposition contributions per root. `qualification.py` implements B0 and the optional B1 representative assignment.

The Phase 4 pre-transport FN export contains 24,408 report rows and 8,003 `(case, observation root, source, direction)` groups. One row per group would reduce this export by 67.21%; 4,722 groups contain multiple rows. However, the export contains **zero exact duplicate rows** across the fields it records. Within groups, 3,699 have different attestation IDs, 1,785 differ in observation time, 2,133 differ in age at qualification, and 3,017 differ in evidence weight. The export omits detector confidence, source reliability, freshness factor, verifiability, independence, signed evidence hash/signature, public-key ID, reason codes, source kind, and administrative domain. Therefore it cannot establish that one report safely subsumes the others.

The grouped reports may differ in freshness at the actual qualification time, signature/provenance, supporting versus opposing direction, witness identity, source/domain independence, weight, or the alternative representative needed to satisfy source/zone/modality requirements. B0 already aggregates repeated contributions by root, so repeated rows do not simply multiply independent-root weight. Suppressing rows before transport could also alter delivery, loss, ordering, arrival time, and freshness. Suppressing after delivery can at most reduce local processing; it cannot reduce messages already sent. No D1 code was implemented and no D1 CPU or communication saving was measured.

Four characterization tests preserve the rejection rationale: selecting only maximum-weight evidence before delivery can discard the only fresh report; grouping without geographic identity can remove B1's only useful alternate representative; opposing evidence must remain represented; arrival-order permutation must not change the result. They are tests of unsafe candidate behavior and existing invariants, not evidence that a compression implementation is safe.

## B0 versus B1: fixed-universe and state-aware outcomes

The primary cross-layout detector measure is detected attack opportunities divided by the fixed ground-truth opportunity universe. It includes opportunities with zero observer coverage and is not shrunk by terminal revocation. Protected-opportunity fraction is reported separately: detected opportunities plus opportunities protected after an earlier terminal revocation. Historical state-aware Recall is also shown, but it has a post-revocation case denominator and must not be interpreted as the same estimand.

| Layout | Density | State-aware Recall B0 → B1 | Detected opportunities B0 → B1 / fixed total | Opportunity Recall B0 → B1 | Protected opportunities B0 → B1 / total |
|---|---:|---:|---:|---:|---:|
| C1, six RSUs | 20 | 43.56% → 43.56% | 8 → 8 / 38 | 21.05% → 21.05% | 17 → 17 / 38 |
| C1, six RSUs | 60 | 43.32% → 49.24% | 27 → 30 / 114 | 23.68% → 26.32% | 54 → 60 / 114 |
| C1, six RSUs | 100 | 37.86% → 42.57% | 35 → 39 / 174 | 20.11% → 22.41% | 66 → 74 / 174 |
| C3, eight RSUs | 20 | 87.50% → 93.75% | 12 → 12 / 38 | 31.58% → 31.58% | 28 → 29 / 38 |
| C3, eight RSUs | 60 | 76.92% → 87.50% | 38 → 40 / 114 | 33.33% → 35.09% | 86 → 92 / 114 |
| C3, eight RSUs | 100 | 71.79% → 78.62% | 55 → 60 / 174 | 31.61% → 34.48% | 119 → 128 / 174 |

Across the fixed 326 opportunities per layout, C1 detection rises from 70/326 (21.47%) to 77/326 (23.62%); protected fraction rises from 137/326 (42.02%) to 151/326 (46.32%). C3 detection rises from 105/326 (32.21%) to 112/326 (34.36%); protected fraction rises from 233/326 (71.47%) to 249/326 (76.38%). Thus B1 adds seven detected opportunities in each layout (+2.15 percentage points), while the eight-RSU observation footprint differs from C1 by only 0, 1, and 1 observed opportunities at densities 20, 60, and 100 respectively in these paired cells.

### Classification metrics

Values below are the mean of the two seeds at each density; TP/FP/TN/FN are also two-seed means because the source summary reports per-seed means. They are not pooled independent trials.

| Layout / density | TP B0→B1 | FP B0→B1 | TN B0→B1 | FN B0→B1 | Precision B0→B1 | FRR B0→B1 | F1 B0→B1 | MCC B0→B1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| C1 / 20 | 5→5 | 0→0 | 86.5→86.5 | 6.5→6.5 | 1→1 | 0→0 | .6066→.6066 | .6364→.6364 |
| C1 / 60 | 14.5→16 | 0→0 | 259.5→254.5 | 19→16.5 | 1→1 | 0→0 | .6042→.6599 | .6351→.6800 |
| C1 / 100 | 19.5→21.5 | 1→1 | 429→422 | 32→29 | .9512→.9555 | .2326%→.2364% | .5416→.5890 | .5760→.6142 |
| C3 / 20 | 7→7 | 0→0 | 79.5→79.5 | 1→.5 | 1→1 | 0→0 | .9333→.9667 | .9296→.9648 |
| C3 / 60 | 20→21 | 0→0 | 238.5→235.5 | 6→3 | 1→1 | 0→0 | .8696→.9333 | .8662→.9295 |
| C3 / 100 | 30.5→33 | 0→0 | 391→381 | 12→9 | 1→1 | 0→0 | .8356→.8802 | .8345→.8763 |

There are no new false-positive case events in the paired B1 replay. C1 has two pre-existing false-positive events at density 100 (one per seed); B1 preserves them. C3 has none. FRR is essentially unchanged; the small nonzero C1 density-100 rate changes slightly because its state-aware denominator changes.

The case-transition audit finds 18 cases newly reaching TP under B1 (7 C1, 11 C3), no revocation reversals, and four later windows no longer counted as TP because B1 had already revoked the vehicle on an earlier window. Those four are terminalized evaluation windows, not lost revocations. No exact newly introduced FP IDs exist. Detailed transitions and case rows are in the compact result CSVs.

## Evidence independence and the mechanism behind B1

B1 changes representative assignment within existing roots. It does not create roots or observations. For malicious reports with at least two eligible items, root counts are C1 179→178 and C3 139→135; source-diverse counts are C1 55→68 and C3 123→135; geographic-zone-diverse counts change by the same amounts. These totals show the effect is source and zone representation, not increased independent-root availability. The exact new TP cases arise where B1's alternative representatives allow existing source/zone diversity conditions to be satisfied while retaining legitimate provenance. It remains possible for B1 to select a lower-weight representative and reduce supporting strength; the qualification results demonstrate why it must be treated as a decision-changing algorithm variant rather than a neutral deduplicator.

B1 did not change attempted or arrived evidence counts. On nonterminal cases, evidence arrival/time inputs matched; downstream trace differences are attributable to earlier terminal revocation and exclusion of later windows. Witness routing and detection inputs were held fixed.

## Resource measurements and limits

The replay runner measured process CPU around the architecture replay, with three repeats per cell; it does not enable `tracemalloc`, unlike the historical `measured_run` path. Values are therefore paired within this harness and must not be mixed numerically with historical pilot CPU. The small number of repeats and observed run-to-run variability limit precision.

| Same-harness mean across densities | C1 B0 → B1 | C3 B0 → B1 | B1 change |
|---|---:|---:|---:|
| CPU seconds | 3.3776 → 3.8568 | 4.6068 → 5.2760 | +14.19% C1; +14.53% C3 |
| Messages / case | 22.4195 → 22.5129 | 30.6230 → 30.7118 | +0.42% C1; +0.29% C3 |
| P95 E2E | 14,119.32 → 14,131.16 ms | 14,138.13 → 14,138.53 ms | +0.084% C1; +0.003% C3 |
| PDR | .98124 → .98116 | .98048 → .98037 | small decrease |
| Ledger consistency delay | 14.729 → 14.878 ms | 16.242 → 16.598 ms | small increase |

The per-stage `cProfile` artifact is an attribution view, not a benchmark: cumulative values overlap across nested functions, profiler overhead is material, and exclusive stage groupings are not additive measures of savings. It records costs in signature verification, evidence/root work, coordinator callbacks, QE, transport-send calls, and PBFT. No stage has been shown to be safely removable with a measured CPU gain. B1 increases replay CPU by about 14–15% within each layout and leaves communication effectively unchanged. The cross-configuration C3+B1 versus C1+B0 replay is approximately +56.21% CPU and +36.99% messages/case, but the independent historical 8-RSU pilot had already measured +44.27% CPU and +37.12% messages/case for C3+B0 versus C1+B0. These are different harness comparisons and should not be conflated.

Against the unchanged 8-RSU acceptance gates, C3 is already over the +25% CPU and +20% messages/case limits; the P95 E2E increase remains below +5%. B1 does not repair the resource failure and adds CPU. The bounded evidence-processing result is therefore a **NO-GO for deployment as an eight-RSU resource optimization**. B1 is an offline-supported classification variant worth a separately preregistered, adequately seeded validation; this two-seed pilot is not enough to call it validated for deployment.

## Security assessment and recommendation

- D1 suppression/compression: **rejected**. The available report grouping is not proof of semantic equivalence, and no reduction in delivered messages follows from post-delivery deduplication.
- B1: preserves signed attestations and root identity, and the tested implementation does not invent independent evidence. It changes representative selection and can alter decisions. It produced no new FP in these six cells, but this is limited evidence, not a security guarantee.
- Independent roots, source identities, zones, modalities, freshness, opposing evidence, signatures, and validator requalification remain required. The single-observer withholding and Byzantine coordinator completeness limitations remain unchanged.
- No production source or QE policy was changed. No frozen experiment data was modified.

**Recommendation:** preserve B0 as the historical baseline; do not adopt D1. Record B1 as a promising but unvalidated qualification variant, with a fresh-seed paired pilot required before any deployment claim. Do not claim 70% fixed-opportunity detection: C3+B1 reached 112/326 (34.36%) across this small paired opportunity universe, despite higher state-aware Recall.

## Artifacts and checks

The analysis scripts are `scripts/analyze_provenance_evidence.py`, `scripts/audit_phase_provenance_b1_cases.py`, `scripts/audit_provenance_group_redundancy.py`, and `scripts/summarize_provenance_evidence_results.py`. The characterization tests are in `tests/test_provenance_redundancy_candidate.py`. Compact manifests, paired metrics, opportunity metrics, transitions, and profile attribution are in `results/provenance_evidence_optimization_final/`.

Validation performed: Python syntax checks, the four new characterization tests, focused security/B1/provenance/opportunity regressions, and the full pytest suite (114 passed). The full suite used the read-only historical Phase 2 artifacts in the original research checkout and did not alter them. No new SUMO campaign was run.
