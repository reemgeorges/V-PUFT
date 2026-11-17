# Scenario 5 bounded component ablation: preregistered design

## Objective and scope

This bounded study estimates the contribution of two original evidence-processing components under the accepted Scenario 5 input traces. It is not protocol optimization and does not propose either weakened variant for deployment. It does not modify the production qualification engine, detector, attacks, mobility, QE policy, PBFT, or frozen Dataset B.

## Frozen input and comparison set

- Source worktree: `research/final-scenario5`, starting commit `563dc613e880800cdfe673a7f3f14e20d50176e7`.
- Topology: Scenario 5, Urban Roundabout.
- Densities: 20 and 100 vehicles.
- Seeds: 7003, 7004, 7005, 7006 per density (eight paired raw traces).
- Architectures: C100 (100 ms centralized backhaul) and Distributed (0 ms architecture-specific central backhaul, distributed processing otherwise unchanged).
- Variants: frozen baseline, A (report-level evidence-mass counterfactual), C (diversity-gate counterfactual). No combined A+C variant.
- Total comparison cells: 8 traces × 3 variants × 2 architectures = 48. Baseline cells are reused only when their exact trace hash and effective configuration match; the available saved baseline rows for the selected eight traces are complete.
- Pilot: seeds 7003 and 7004 at each density. Reuse eight saved baseline cells and execute only 16 ablation cells (24 comparisons including baseline). Continue with seeds 7005 and 7006 only after validating pilot isolation and matched trace/metric integrity.

## Selected ablations

### A — Disable correlated-report suppression in evidence mass (insecure counterfactual)

The adapter computes supporting and opposing mass from each fresh, signature-valid attestation report rather than first collapsing reports by `observation_root_id`. It retains the original root IDs and computes root/source/zone/modality diversity from the production root aggregation. It does not create roots, sources, zones, or attestations. The hard validity gate, freshness calculation, five exponents, opposing evidence, margin threshold, representative threshold, cryptographic-decisive rule, and diversity gates stay unchanged. Multiple reports of one root can therefore increase the numeric mass, including reports in opposing directions; this deliberately removes the original correlation-suppression protection and is an insecure diagnostic counterfactual.

### C — Bypass independent-diversity gates (insecure counterfactual)

The adapter retains the production evidence aggregation, signatures, validity, freshness, weights, opposition, margin threshold, and cryptographic-decisive rule, but evaluates the ordinary margin path without requiring the roots/sources/zones/modalities gate. Reported diversity counts remain the true production counts. This is explicitly a policy-weakening counterfactual, not a deployment candidate. It is not a one-factor source-count sensitivity test.

## Invariants and matched-input checks

The same immutable raw detection trace is converted once into the same runtime cases for all variants. Ground truth, case IDs/windows, emitted messages, observation roots, source IDs, geographic cells, signatures, membership, architecture settings, and Method B first-revocation evaluation remain fixed. Each adapter is attached only to the architecture instance's qualification-engine slot. The baseline uses the unwrapped production engine. Each completed cell must have one decision per case, identical case identity sets to baseline, and a trace/config hash recorded in the manifest. Fixed-denominator opportunity counts reuse the trace's emitted attack schedule and are calculated independently of detection; the adapter never sees those labels.

## Outcomes

Per cell: TP, FP, TN, FN, post-revocation exclusions, state-aware Recall/Precision/FRR/F1/MCC, fixed-denominator detected attack opportunities and protected opportunities, P95 E2E, messages/case, bytes/case, CPU, PDR, and P95 ledger consistency delay where present. Paired comparisons use seed as the unit within each density and architecture. Four seeds are descriptive; no strong significance claim is planned. Detection and terminal protection are reported separately.

## Resource limits and stopping rules

- Maximum total comparison cells: 48; no additional runs or regenerated SUMO traces.
- Maximum wall time for newly executed replay cells: 30 minutes, excluding offline summary analysis.
- Maximum new output: 500 MB; preserve at least 5 GB free space.
- Pilot is rejected if adapter isolation fails, case populations differ, trace hashes mismatch, metrics cannot be reconciled, or any unexpected baseline-path change occurs.
- If pilot checks pass, execute only the remaining 16 A/C cells for seeds 7005/7006. Reuse saved baseline cells. Missing/failed cells remain explicit; do not replace seeds.
- No ablation is accepted as a security improvement. A or C results describe component contribution only.

## Reproducibility

Raw traces remain at their existing local preservation path and are not copied into or committed with this study. The output manifest records their SHA-256 values, source code/config hashes, original run provenance, and whether baseline rows were reused. Frozen corrected-final Dataset B is not mixed with these newly generated sensitivity traces.
