# Five-validator architecture prototype (V5)

## Scope and preservation

This prototype is isolated on `research/vpuft-v5-validator-prototype`, based on `10286c426bff74752feaaceac88fd7ddb5833e8a`. It changes committee/quorum configuration and membership binding only. Historical V4 defaults remain four validators with quorum three. No Phase 6, security-hardening, six/eight-RSU pilot, ground truth, detector, weights, QE policy, or frozen trace was edited. The bounded replay uses only the completed C3 eight-RSU traces; density 100 / seed 2102 explicitly uses `seed_2102_retry1` because that is the unique directory with a completed run marker.

## Membership, roles, and fault domains

The V5 committee is **rsu-1, rsu-2, rsu-3, rsu-4, rsu-5**. All eight RSUs remain sensing-capable. **rsu-6, rsu-7, rsu-8** are excluded from PBFT voting and ledger replica membership in V5. In the paired replay, the coordinator pool is held at rsu-1 through rsu-4 for both architectures, so adding rsu-5 does not silently change coordinator selection. Witness routing and QE evidence requirements remain inherited from the same effective baseline configuration.

The frozen placement manifest maps the five validators to administrative domains as follows: domain-1 has rsu-1 and rsu-2; domain-2 has rsu-3 and rsu-4; domain-3 has rsu-5. Consequently, `f=1` is a **single-validator/node fault assumption**. A correlated compromise of domain-1 or domain-2 can compromise two committee members and exceeds the assumed Byzantine budget. The artifacts do not establish independent operators or infrastructure control for those domains; no domain-level fault-tolerance claim is made.

## Quorum rule

For two certificates of size `q` in a committee of size `n`, the minimum intersection is `2q-n`. Requiring `2q-n>f` ensures at least one non-Byzantine validator in the intersection, under the stated bound of at most `f` Byzantine identities. Progress despite up to `f` unavailable validators additionally requires `q<=n-f`.

| Configuration | `n,f,q` | Minimum intersection | Availability bound | Result |
|---|---:|---:|---:|---|
| Historical V4 | 4,1,3 | 2 (>1) | 3 = 4-1 | Accepted |
| V5 target | 5,1,4 | 3 (>1) | 4 = 5-1 | Accepted |
| Unsafe V5 | 5,1,3 | 1 (not >1) | 3 <= 4 | Rejected |
| V5 unanimity | 5,1,5 | 5 (>1) | 5 > 4 | Rejected for availability |

Configuration validation enforces both inequalities; consensus and quorum trust tokens use the resolved quorum, and signed proposal/vote payloads bind the canonical validator set, fault budget, quorum, and membership epoch. This prevents an old membership-epoch or different-committee signature from being interpreted as a current vote in the modeled verification path.

This arithmetic does **not** establish complete PBFT safety. The implementation still lacks authenticated PREPARED certificates carried through correct VIEW-CHANGE / NEW-VIEW processing. Vote locks are view-scoped. The existing simulator finalization guard is an optional in-process application invariant; it is not a distributed consensus proof. The earlier cross-view counterexample and evidence-coordinator withholding limitation remain applicable and are intentionally not hidden by this V5 change.

## Bounded V4/V5 replay

Both variants replay the same six completed C3 detection traces and identical case identities/ground truth at densities 20, 60, and 100 for seeds 2101 and 2102. The replay does not run SUMO. It executes each deterministic case set three times per architecture for CPU variability. The input manifest records each trace SHA-256; V4 and V5 share the same trace for every pair. The completed retry1 trace is used at density 100 / seed 2102. Metrics below are descriptive for six paired cells, not an inferential campaign.

| Measure, summed/mean across six cells | V4 (3/4) | V5 (4/5) | Paired change |
|---|---:|---:|---:|
| Input cases | 2,102 | 2,102 | 0 |
| TP / FP / TN / FN | 115 / 0 / 1,418 / 38 | 115 / 0 / 1,418 / 38 | unchanged |
| Recall / Precision / FRR | 0.7516 / 1.000 / 0 | 0.7516 / 1.000 / 0 | unchanged |
| Successful finalizations | 115 | 115 | 0 |
| Consensus progress failures | 0 | 0 | 0 |
| Ledger-consistent cells | 6/6 | 6/6 | unchanged |
| Total transmission attempts | 61,557 | 63,793 | +2,236 (+3.63%) |
| PBFT / state-recovery messages | 3,166 | 5,166 | +2,000 (+63.17%) |
| Evidence transport messages | 58,040 | 58,159 | +119 (+0.21%) |
| Messages per input case | 29.285 | 30.349 | +3.63% |
| Mean CPU median per cell | 3.544 s | 3.813 s | +0.268 s (+7.56%) |
| Mean P95 E2E | 14,138.13 ms | 14,150.41 ms | +12.28 ms (+0.087%) |
| Mean P95 PBFT latency | 124.40 ms | 135.43 ms | +11.03 ms (+8.87%) |
| Mean P95 ledger consistency delay | 14.588 ms | 15.491 ms | +0.903 ms (+6.19%) |
| Mean PDR | 0.980515 | 0.980359 | -0.000156 |

Across paired cells, CPU median increased in all six pairs (mean relative increase 7.84%; cell range 3.34%–12.10%). Total messages and PBFT-class messages also increased in every pair. P95 E2E increased in all pairs, though the mean increase was small relative to the approximately 14.1 s simulated end-to-end window. CPU is wall-machine dependent and only six cells were replayed. The approximately 63% increase in PBFT-class traffic is expected from a fifth participant and 4-vote phase threshold; overall traffic rises less because evidence transport dominates the message total. Evidence-transport count itself rises by 119 attempts total, not by the full 2,236. No network geometry was recomputed, so this is not a geographic latency claim.

Decision totals are unchanged across V4 and V5 in these paired replays: 115 TP, no FP, 1,418 TN, and 38 FN. This is a committee/quorum resource replay, not evidence that V5 improves Recall. `results/v5_validator_prototype/v4_v5_paired_replay.csv` contains all six cell rows; `paired_replay_manifest.json` records trace/config fingerprints and committee settings.

## Tests and interpretation

The full test suite passed **130 tests** when run with the V5 worktree code and the original checkout as read-only working directory for three legacy tests that require untracked Phase 2 trace data. Running from the isolated worktree without those artifacts yielded three `FileNotFoundError`s in those legacy data-dependent tests; the code tests themselves passed. The worktree's new V5 test paths are anchored to their own repository root so they work with either invocation directory.

Tests cover V4 3/4 compatibility, V5 4/5 acceptance and V5 3/5 rejection, availability bounds, role separation, coordinator-pool control, signature binding to committee/epoch, replay rejection across epochs, vote-order behavior, one missing validator, delayed and multiple unavailable validators, finalization-guard semantics, and same-view equivocation against shared vote state. Existing characterization tests for cross-view and evidence-withholding limitations remain unchanged.

The pilot establishes quorum arithmetic and modeled liveness behavior under the tested schedules. It does not prove full PBFT safety under view changes, Byzantine coordinator completeness, independent administrative fault domains, or real distributed process persistence. **GO** for the bounded isolated V5 architecture prototype and thesis description as a quorum-intersection-safe simulator configuration; **NO-GO** for describing it as complete PBFT or end-to-end `f=1` Byzantine fault tolerance, or for merging it into validated production/research baselines.
