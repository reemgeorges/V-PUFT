# Phase 1 post-seminar audit

Date: 2026-11-11

Baseline: `0c0c10b3d6cbb2075e430a299e3c18cdf382320a` (`main`, equal to `origin/main`)

Working branch: `research/vpuft-post-seminar-optimization`

## Scope and preservation

This phase is diagnostic only. No policy threshold, evidence qualification rule, frozen configuration, original result, or production implementation was changed. The corrected Scenario 5 artifacts were read in place. The generated audit JSON is a new file under `docs/post_seminar/` and the analyzer refuses to overwrite an existing output.

Pre-existing untracked work was preserved and excluded: `Capture_VPUFT_SUMO_Slide.ps1`, `capture_vpuft_steps_for_slides.py`, and `results/urban_roundabout/`.

## Repository and test baseline

`rg --files -g '!**/.git/**'` was used to enumerate the repository. The project is a Python 3.10+ package with source under `src/vpuft`, tests under `tests`, Scenario 5 inputs under `sumo/urban_roundabout` and `configs`, and frozen/corrected outputs under `results`.

The unmodified baseline suite passed: **58 passed in 45.49 s**. The four new focused tests pass. After all additions, the full suite passes: see the final verification section.

## Scenario 5 FN audit

The canonical paired architecture is `distributed_density_honest`; the central variants have the same classification decisions and differ operationally. The audit uses the 52,254-row combined decisions file and the exact effective policy file.

### Window-level versus eventual revocation

- Raw non-revoked malicious rows: **1,410**.
- Post-revocation terminal no-op windows: **449**. These are neither new detection opportunities nor genuine at-risk FN.
- At-risk FN windows: **961**.
- Malicious vehicles: **1,050**.
- Vehicles eventually revoked: **650**.
- Vehicles never revoked: **400**.
- Vehicles with at least one FN window: **997**; **597** of those were eventually revoked.

At-risk FN windows by density and ground-truth attack:

| Vehicles | false_denm | flood | mixed | position_offset | speed_offset | certificate_tamper | replay | Total |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 20 | 12 | 10 | 20 | 10 | 20 | 0 | 0 | 72 |
| 40 | 18 | 9 | 42 | 26 | 21 | 0 | 0 | 116 |
| 60 | 49 | 35 | 48 | 40 | 35 | 0 | 0 | 207 |
| 80 | 62 | 42 | 66 | 36 | 49 | 0 | 0 | 255 |
| 100 | 62 | 67 | 78 | 44 | 60 | 0 | 0 | 311 |
| **Total** | **203** | **163** | **254** | **156** | **185** | **0** | **0** | **961** |

Certificate tamper and replay have zero at-risk FN: their apparent raw FN rows are entirely terminal windows after successful revocation.

### Recorded root causes

| Cause | At-risk FN windows | Evidence |
|---|---:|---|
| Independent roots below policy minimum | 96 | 5 rows had 0 roots and 91 had 1 root; all affected policies require 2. |
| Margin threshold | 18 | 8 flood rows at density 80, 9 flood rows at 100, and 1 position-offset row at 100. |
| Source/zone/modality diversity unresolved | 847 | Each had enough roots but the decision artifact records only the aggregate diversity reason, not distinct source/zone/modality counts. |
| Message loss | 0 | All 961 at-risk FN rows have `arrived_attestations == attempted_attestations`. |
| Stale evidence | 0 | All 961 have `expired_evidence == 0`. |
| Failed finalization | 0 | None reached qualification/finalization; `qualified_at` and `finalized_at` are absent. |

The 18 margin failures are not marginal as a single group. Flood at density 80 has mean margin -0.131616 against 0.50 (mean shortfall 0.631616); flood at 100 has mean -0.569769 (mean shortfall 1.069769). The single position-offset case has margin 0.371523 against 0.45 (shortfall 0.078477).

The dominant defensible conclusion is therefore: **the current low Recall is a pre-finalization evidence-diversity problem, not transport loss, staleness, or PBFT failure**. The available frozen combined output cannot split the largest 847-row bucket into source versus geographic-zone versus modality failure.

## Coordinator selection and failure handling

`DistributedRSUExtendedVPUFT._select_coordinator` uses validator-local observations. It orders by `(observed_at, attestation_id)`, so simultaneous observations are deterministic and independent of input list order; the added test proves this. If no validator-local observation exists, it hashes `case_id` into the configured validator tuple.

Limits found:

- Selection does not consider whether the chosen coordinator is currently online.
- Coordinator identity depends on `attestation_id` for simultaneous observations; this is deterministic, but it is not an explicit canonical tuple such as observation root + validator ID.
- Coordinator failure is handled later by PBFT bounded view changes. Offline/invalid leaders rotate deterministically across validators, and exhaustion produces `liveness_failure_after_max_views`.
- The corrected campaign has **0 view changes, 0 liveness failures, and 0 failed finalizations**, so it provides no empirical coordinator-failure stress evidence.

## CAM/DENM provenance and evidence-root deduplication

`AttackInjector` creates `original_message_id = cam-<seed>-<vehicle>-<index>` and derives `observation_root_id = root-SHA256(original_message_id)`. Flood and mixed retransmission variants change `message_id` but retain both the original ID and evidence root. Replay changes the replay transport ID while retaining the historical message's original ID/root. Each RSU observation copies that same root. Vehicle-witness observations intentionally derive a separate witness root from `(message root, witness ID)`.

`events_to_cases` transfers the root unchanged into signed attestations. `aggregate_by_root` groups all RSU-derived reports by `observation_root_id`, selects at most one net directional contribution, and records the remainder as duplicates. The new test shows two RSU reports of one original CAM become one root contribution with `duplicate_count == 1`.

This demonstrates association and deduplication in code. The corrected-final bundle lacks raw traces, so a committee-ready empirical table mapping one original message to multiple RSU reports cannot be regenerated from that bundle alone.

## CPU time and P95 E2E latency audit

Mean results across 10 seeds:

| Architecture | Density | CPU s | P95 E2E ms | Messages | Mean queue ms |
|---|---:|---:|---:|---:|---:|
| Distributed | 20 | 1.2250 | 14075.2307 | 2637.2 | 0.4974 |
| Distributed | 100 | 6.3391 | 14113.7061 | 9815.1 | 2.3782 |
| Central 0 ms | 20 | 1.1406 | 14058.3251 | 3940.3 | 1.8849 |
| Central 0 ms | 100 | 5.6922 | 14234.8183 | 15638.6 | 7.0344 |
| Central 100 ms | 20 | 1.1500 | 14158.3251 | 3940.3 | 1.8849 |
| Central 100 ms | 100 | 5.9297 | 14334.8183 | 15638.6 | 7.0344 |

CPU grows by 5.175x for distributed, 4.990x for central 0 ms, and 5.156x for central 100 ms from density 20 to 100. CPU/message correlation is 0.9044, 0.9338, and 0.9266 respectively. This points to per-message/evidence processing as the first profiling target, especially distributed validator requalification and evidence-bundle serialization.

P95 is dominated by the 15 s evidence window/qualification timing, not PBFT. Distributed consensus P95 is only 64.36–107.63 ms, while qualification P95 is about 14.01 s. Central 100 ms is exactly 100 ms above the central 0 ms control. Queue delay strongly tracks central P95 (correlation 0.9848); distributed P95 is flatter despite rising load.

## Missing data and blockers

1. `density_trace_audit.csv` points to 50 `shared_detection_trace.jsonl` files, but `results/urban_roundabout_campaign_corrected_final/traces/` is absent.
2. Combined decisions omit `distinct_sources`, `distinct_zones`, `distinct_modalities`, and per-attestation provenance. This blocks exact attribution of 847 diversity failures.
3. No profiler output exists, so CPU attribution is correlational rather than function-level.
4. The honest corrected campaign activates no coordinator/PBFT faults, so failure recovery is code/test evidence only.

## Recommended Phase 2 implementation

First restore or deterministically regenerate the 50 corrected shared traces without replacing frozen outputs. Add audit-only decision metadata for distinct roots/sources/zones/modalities and per-stage CPU timers. Then run a paired diagnostic replay (same traces and thresholds) to split the 847 diversity failures and profile detector, root aggregation, validator requalification, serialization, PBFT, and ledger replication. Only after that evidence should qualification or security thresholds be considered.

## Files inspected

- Repository/control: `pyproject.toml`, `requirements.txt`, `.gitignore`, and the complete path inventory from `rg --files`.
- Scenario/config/results: `configs/urban_roundabout_campaign.json`, `results/urban_roundabout_campaign_corrected_final/effective_config.json`, and every file under its `combined/` directory.
- Core/security: `src/vpuft/config.py`, `domain.py`, `qualification.py`, `weighting.py`, `trace.py`, `metrics.py`, `state_machine.py`, `state_aware_evaluation.py`, `consensus.py`, `network.py`, and `des.py`.
- Architectures: `src/vpuft/architectures/base.py`, `centralized.py`, `distributed_rsu.py`, `distributed_extension.py`, and `ahmed_witness.py`.
- SUMO/provenance: `src/vpuft/sumo/attacks.py`, `detector.py`, `sensors.py`, `runner.py`, `campaign.py`, and `density.py`.
- Tests: all files under `tests/` were collected/executed; targeted source inspection included `test_weighting.py`, `test_evidence_semantics_v2.py`, `test_post_freeze_extension.py`, `test_event_time_scheduler.py`, `test_state_aware_evaluation.py`, `test_architecture_transport_fairness.py`, and `test_urban_roundabout_scenario.py`.

## Commands executed

Key reproducible commands (PowerShell):

```text
git -c safe.directory='C:/Users/reemg/OneDrive/Desktop/master/6/v10' status --short --branch
git -c safe.directory='C:/Users/reemg/OneDrive/Desktop/master/6/v10' rev-parse HEAD
git -c safe.directory='C:/Users/reemg/OneDrive/Desktop/master/6/v10' log -8 --oneline --decorate
git -c safe.directory='C:/Users/reemg/OneDrive/Desktop/master/6/v10' branch --all --verbose --no-abbrev
rg --files -g '!**/.git/**'
rg -n "coordinator|evidence_root|root_id|message_id|original|dedup|finaliz|stale|margin|independent|diversity" src tests scripts configs/urban_roundabout_campaign.json
git -c safe.directory='C:/Users/reemg/OneDrive/Desktop/master/6/v10' switch -c research/vpuft-post-seminar-optimization 0c0c10b3d6cbb2075e430a299e3c18cdf382320a
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m pytest tests\test_post_seminar_phase1_audit.py tests\test_phase1_coordinator_and_provenance.py
.\.venv\Scripts\python.exe scripts\post_seminar_phase1_audit.py --decisions results\urban_roundabout_campaign_corrected_final\combined\density_decisions.csv --config results\urban_roundabout_campaign_corrected_final\effective_config.json --output docs\post_seminar\phase_1_fn_audit.json
```

Several read-only PowerShell `Get-Content`/`Get-ChildItem` inspections and inline pandas aggregations were also executed to inspect schemas and calculate the tables above.
