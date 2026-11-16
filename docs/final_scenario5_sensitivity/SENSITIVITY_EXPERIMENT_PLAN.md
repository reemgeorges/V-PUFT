# Scenario 5 Sensitivity Pilot: Preregistered Plan

Status: preregistered before pilot execution. No outcomes are included here.

## Questions
- Measure the one-factor-at-a-time effects of evidence freshness, source diversity, packet delivery probability, and centralized backhaul delay on Method B decisions and model cost.
- Compare C100 and Distributed on the same SUMO detection traces.
- This new pilot is not a reproduction of frozen Dataset B.

## Baseline and provenance
- Branch: research/final-scenario5
- Commit: c1878e8d6bef7a44830d8b44d5f55d47d5810f3c
- Effective baseline: results/urban_roundabout_campaign_corrected_final/effective_config.json
- Scenario: sumo/urban_roundabout
- C100 means centralized_remote_100ms; Distributed uses its existing zero-extra-backhaul path.
- Frozen Dataset B files are inputs for configuration reference only and will not be modified.

## One-factor-at-a-time values
- Evidence freshness: baseline 15 seconds for all policies; perturb to 12 seconds and 30 seconds. Twelve seconds is the configured detector freshness-decay time constant. Thirty seconds is twice the configured 15-second case window and probes a permissive temporal boundary.
- Required independent sources for position_offset only: baseline 2; perturb to 1 and 3, the adjacent valid integer requirements. Required roots remain 2. The value 1 is a deliberately weaker-policy stress condition, not an acceptable policy recommendation by Recall alone.
- Packet delivery probability: baseline 0.98; perturb to 0.95 and 1.00. Both alternatives appear in configs/experiment_grid.json. This is an input impairment; observed PDR remains an output.
- C100 extra backhaul: baseline 100 ms; perturb to 20 and 200 ms, levels declared by DensityCampaignConfig. This factor applies to C100 only. Distributed stays at its existing zero-extra-backhaul path.
- No source, detector, attack, mobility, sensor, validator, quorum, cryptographic, weighting, QE, or evaluation implementation is changed. Config-only policy sensitivity is labeled as such.

## Pairing
- Densities 20 and 100.
- Fresh seeds 7001 and 7002 per density. Exact-seed search found no prior matching run records in this worktree.
- Generate four shared SUMO traces (density by seed) once. Replay each same trace under every architecture and config.
- Within a trace, cases, observations, timestamps, attack schedule and ground truth must match exactly.
- Use identical scenario seeds and the simulator existing deterministic transport keys for every replay. Matching logical messages therefore reuse their keyed draws; messages that only exist in one variant have no pair. This defines a new paired sensitivity baseline and does not reproduce Dataset B transport draws.
- Recompute Method B: first committed revocation window remains eligible; subsequent terminal windows are excluded. Fixed-opportunity metrics are reported only if the generated trace contains a verifiable opportunity universe.

## Execution and stopping budget
- Baseline: 4 trace cells x 2 architectures = 8 architecture runs.
- Freshness, source, and PDR: 3 factors x 2 perturbations x 4 cells x 2 architectures = 48.
- Backhaul: 2 perturbations x 4 cells x C100 only = 8.
- Total cap: 64 architecture runs plus 4 trace generations; 68 run units, below 80 architecture-scenario executions.
- Stop after the pilot; no expansion to more seeds or densities is authorized here.
- Wall-clock cap 60 minutes; new output cap 2 GB. Preserve completed cells and mark incomplete cells if either limit is reached.
- Historical Dataset B has measured median CPU times around 1.16-1.20 s per architecture at density 20 and 5.14-5.34 s at density 100. This estimates about 208 CPU seconds for 64 architecture replays, excluding trace generation, plotting and I/O. Time the first trace generation before continuing.
- Save effective configs, hashes, trace identities, outputs and failures under results/final_scenario5_sensitivity/.

## Outcomes and analysis
For every config, architecture, density and seed, report Method B TP/FP/TN/FN, precision, state-aware recall, FRR, F1, MCC, eligible and terminal-excluded windows, P95 E2E, CPU time, messages per case, observed PDR and P95 ledger consistency delay. Keep case-level decisions and first-revocation timestamps.
Report paired seed-level differences, pooled counts and macro averages separately. With two seeds per density, intervals are descriptive and no significance claims are made. Separate attack-opportunity detection from protection; do not compute fixed-universe recall without verified opportunity schedules and denominators.

## Validity and decision gates
- Abort if effective config propagation fails or intended model behavior is unchanged.
- Abort comparisons if trace hashes, case IDs, mobility, attacks or ground truth differ across variants.
- Do not choose or tune a level by its Recall.
- The source threshold of 1 is a weaker-policy stress test.
- Do not claim field validity, generalization from two seeds, or full Byzantine tolerance.
- A larger campaign requires a separate design and budget review.
