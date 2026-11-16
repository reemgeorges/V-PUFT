# Sensitivity Replication Preregistration — Scenario 5

**Protocol freeze:** before follow-up SUMO generation or result inspection. **Dataset:** fresh paired replication; separate from Dataset B and the 2026-11-16 pilot. **Code base:** accepted `research/final-scenario5` at pilot commit `f52322f54a0bc4aacf46ce00fa640b7c297ebcd1`; the execution manifest will record the exact execution commit and source hashes.

## Questions and hypotheses

1. Does changing the evidence freshness window from 15 seconds to 12 or 30 seconds change state-aware Method B qualification, attack-opportunity detection, or protection?
2. Does changing the `position_offset` required source count from 2 to 1 or 3 change those outcomes while the independent-root requirement and every other setting remain fixed?
3. Are these paired effects consistent across C100 and Distributed when both consume identical generated sensing traces?

These are sensitivity questions, not parameter optimization. No winning value will be selected. `required_sources=1` is explicitly a weakened-policy stress test and cannot be recommended from Recall alone.

## Frozen design

- **Scenario:** Urban Roundabout, SUMO-generated movement and the existing attack definitions.
- **Densities:** 20 and 100 vehicles.
- **Fresh seeds:** 7003, 7004, 7005, 7006, 7007, 7008 at each density. These are distinct from pilot seeds 7001–7002 and frozen Dataset B seeds 1001–1010.
- **Shared input:** generate one mobility/attack/detection trace per density-seed pair (12 total); reuse its exact files for all five configurations and both architectures.
- **Configurations:** baseline (freshness 15s, position-offset sources 2); freshness 12s; freshness 30s; position-offset sources 1; position-offset sources 3.
- **Architecture:** C100 and Distributed for every cell. The C100 backhaul remains 100ms; Distributed retains its original path.
- **Maximum:** 12 traces × 5 configurations × 2 architectures = **120 architecture executions**. No additional factors or cells are authorized by this registration.

## Controlled settings

Keep attack schedules, vehicles, detection traces, QE weights and thresholds, roots, geographic cells, modalities, detector logic, signatures, freshness decay, transport assumptions, four PBFT validators, quorum and evaluation implementation at baseline. The only per-variant changes are the named freshness or `position_offset.required_sources` values. The independent-root requirement remains unchanged. C100 and Distributed receive the same trace bytes within every paired seed/configuration.

## Outcomes and estimands

- State-aware Method B: TP, FP, TN, FN; pooled and per-seed macro Precision, Recall, FRR, F1, MCC; terminal post-first-committed-revocation windows excluded exactly as the existing evaluator specifies. Report excluded counts and denominators.
- Message-level fixed-universe analysis: denominator is unique malicious message IDs emitted by the attack injector. Report observed, unobserved, detected (observed message whose mapped 15-second case commits revocation), and protected (first committed revocation finalized strictly before its emission) separately. Do not call protected opportunities detected opportunities.
- Resource/transport: CPU process time, P95 E2E, messages per case, PDR, ledger consistency P95. Include units and per-seed values.
- Pair each variant with its baseline at identical density, seed and architecture. Seeds, not cases, are replication units. Report mean, median, individual paired seed deltas, and 95% Student-t intervals for seed-level differences when defined. With n=6, intervals are descriptive and conditional on distributional assumptions; no claim of strong significance or causal generalization is planned.

## Reproducibility and stop rules

- Record commit, code/config hashes, all generated trace and ground-truth hashes, effective configuration hashes, per-cell completion status, output hashes, failure reasons and resource measurements.
- Use checkpointed cell outputs and resume only cells without a verified completed marker. Preserve failed attempts; never overwrite completed cells.
- Raw traces/results go to a unique local-only directory outside OneDrive; small manifests and aggregate outputs go to `results/final_scenario5_sensitivity/replication_2026-11-16/`.
- Hard limits: 3,000,000,000 raw-output bytes; 3,600 seconds wall time; require at least 5,000,000,000 bytes free before starting. Stop and retain checkpoints if any limit is reached. Do not expand the design silently.
- No algorithm changes, no SUMO video, no Ablation, no change to frozen Dataset B. Any failed or missing run is reported. Analysis will not select favorable seeds, omit difficult opportunities, or retune any setting.

## Pre-flight basis

The earlier 64-run pilot occupied 669,373,148 bytes and took 525.125 seconds end-to-end. Approximately 664,951,627 bytes were shared generated inputs for four traces; linear scaling to twelve traces is approximately 1.995GB. Pilot per-run outputs add only several megabytes when scaled to 120 cells. The registered raw cap is 3GB to allow overhead and temporary writes. The host volume had approximately 100.0GB free at the last check. OneDrive environment variables identify the repository parent, but no OneDrive process was running and existing files were hydrated local files; therefore raw replication artifacts will be placed outside OneDrive to avoid relying on or triggering cloud synchronization.