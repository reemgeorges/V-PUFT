# V5 coordinator and evidence protocol design

## Baseline and scope

This branch starts at validated V5 commit `4687266bae35d680d77730b1dd4d929a6ea57900`. It keeps five validators, `f=1`, quorum `4/5`, source signatures, root/source/zone/modality requirements, weights, QE margins, witness routing, and the saved V5 results unchanged. No full SUMO campaign is in scope.

Threat assumptions are stated separately: (a) up to one Byzantine validator identity, (b) an RSU that can emit or withhold its own signed evidence, and (c) a coordinator selected from the validator committee that may censor or equivocate. `f=1` is a node-level assumption; the V5 membership has two validators in each of two known administrative domains, so it does not tolerate a correlated compromise of either domain. A sole observer can withhold a report before any other party knows it exists.

## Coordinator identity: implement now

For one fixed membership epoch, canonical case identity is NFC-normalized and trimmed. The deterministic coordinator is `SHA256(canonical_json([epoch, case_id, sorted(eligible_validators)])) mod committee_size`. All five V5 validators are eligible. Thus simultaneous reports, evidence-subset differences, arrival reordering, and validator tuple ordering cannot change the selected identity if participants share the same canonical case ID and epoch. This is assignment, not election: it does not authenticate an announcement, make the coordinator honest, guarantee availability, or provide failover.

If the deterministic coordinator is known offline before processing, the safe bounded behavior is fail-closed: no evidence qualification bundle or PBFT request is issued. The implementation will not appoint a replacement. A replacement requires a fenced coordinator term/lease and a transfer rule that prevents the old coordinator from completing an already prepared proposal. Without those rules, a timeout alone cannot prevent split brain.

## Evidence announcements: verifier primitive, protocol not integrated

The current simulator sends reports to one coordinator and sends that coordinator's bundle to validators. Validator requalification proves only that each validator recomputes the same result from the submitted bundle; it does not prove completeness. A coordinator can omit a valid opposing report and obtain matching requalification of the incomplete bundle. Existing source signatures prove origin/integrity of included reports, not completeness.

A defensible future design needs an evidence-availability stage before qualification:

1. The observing source multicasts its original signed attestation, bound to canonical case ID, observation root, source, direction, evidence hash, membership epoch, and announcement sequence. It never creates a new root.
2. Each validator verifies and stores the exact signed object, rejects same-ID/different-digest equivocation, and signs a receipt bound to the object and epoch.
3. A bundle carries a verifiable receipt certificate and the complete set of certified supporting, opposing, and neutral reports through an explicit cutoff. Every validator reconciles it against its own stored receipts before requalification; missing certified reports cause rejection, not neutral-to-support conversion.
4. Qualification uses only original signed observations, freshness at the qualification instant, and unchanged root-independence rules. No report without a valid announcement certificate is promoted into evidence.

This branch adds an inert verifier primitive in `src/vpuft/evidence_announcement.py`: a caller may sign a receipt payload for a valid original attestation, verify a four-distinct-validator certificate bound to the exact attestation and V5 membership, and reconcile a proposed bundle against certificates already held in a validator-local inventory. Tests show that the helper rejects an omitted locally certified opposing report, duplicate or insufficient receipt signers, membership replay, changed evidence, and attestation-ID equivocation. It cannot establish that a signer actually received the item; the caller must invoke receipt creation only after transport delivery and hold the signing key locally. The current simulator's central `KeyRegistry` does not provide process-isolated key custody. The architecture does not call this helper.

The simulator still has no durable per-validator announcement stores, receipt dissemination protocol, cutoff/finality rule, or reliable-broadcast timing assumptions. An inert verifier helper does not stop a coordinator from omitting both a report and its certificate if validators do not independently hold the certificate. A valid certificate proves only the signers' receipt assertions under the key-custody assumption; it does not prove sensor truth, freshness at later qualification, or that no unannounced report exists. The existing adversarial tests therefore remain valid, and this branch does not claim the live architecture prevents omission. Reports never announced beyond a sole observer remain fundamentally undetectable.

## Coordinator failure and cross-view safety

No automatic replacement is safe in the current model. A deterministic standby or timeout is not a fence: an isolated old coordinator may continue. The bounded implementation rejects an initially known-offline deterministic coordinator without starting PBFT and reports a liveness failure. Mid-request crashes and authenticated replacement remain unresolved.

The current vote lock is scoped by `(validator, view, phase, case_id)` and the code lacks prepared-certificate transfer and complete VIEW-CHANGE / NEW-VIEW verification. The 4/5 intersection arithmetic alone is insufficient to establish cross-view PBFT safety; an honest validator's state transition across views must be represented and enforced. No partial view-change code will be added. Existing characterization tests of conflicting cross-view outcomes remain as expected failures/known weaknesses.

## Required invariants and tests

- Same canonical case, fixed epoch, and validator set always select one coordinator independent of arrival order or local evidence subset.
- Every member of the five-validator V5 committee is eligible in the new config; V4/V5 historical configs remain untouched.
- An initially unavailable coordinator causes no qualification, PBFT request, or finalization; no competing fallback starts.
- Evidence signatures and root identities remain unchanged. Tests continue to demonstrate that current requalification accepts an incomplete bundle and cannot detect sole-observer suppression.
- Cross-view tests continue to expose the absent protocol guarantee. No result is described as complete Byzantine fault tolerance.

## Go/no-go boundary

The deterministic assignment, fail-closed preflight, and standalone signed-announcement verifier are bounded components tested here. Evidence completeness is not active in the architecture; coordinator takeover and cross-view safety require separate protocol work and cannot be certified by the current simulator abstraction. The overall branch must be reported as partial hardening, not as closing the V5 security gaps.

## Paired replay result

` scripts/replay_coordinator_security_v5.py` compares V5's previous first-observer selection over `rsu-1`–`rsu-4` with deterministic SHA-256 assignment over all five validators. It replays six completed C3 eight-RSU trace cells (densities 20/60/100, seeds 2101/2102; density 100 / seed 2102 uses completed `retry1`) with three repeated runs. No SUMO run was launched. Both variants use V5 quorum 4/5, identical effective baseline weights and QE policies, identical input traces, and unchanged witness routing.

| Aggregate across 2,102 paired input cases | Historical first observer, pool 4 | Deterministic case/epoch hash, pool 5 | Change |
|---|---:|---:|---:|
| TP / FP / TN / FN | 115 / 0 / 1,418 / 38 | 115 / 0 / 1,418 / 38 | unchanged |
| Recall / Precision / FRR | 75.16% / 100% / 0% | 75.16% / 100% / 0% | unchanged |
| Successful finalizations / liveness failures | 115 / 0 | 115 / 0 | unchanged |
| Mean CPU median per cell | 3.177 s | 3.346 s | +0.169 s (+5.33%) |
| Total transmission attempts | 63,793 | 76,614 | +12,821 (+20.10%) |
| PBFT/state-recovery attempts | 5,166 | 5,169 | +3 (+0.06%) |
| Evidence transport attempts | 58,159 | 70,973 | +12,814 (+22.03%) |
| Messages per input case | 31.594 | 37.533 | +18.80% |
| Mean P95 E2E | 14,150.41 ms | 14,153.08 ms | +2.68 ms (+0.019%) |
| Mean PDR | 0.980359 | 0.979904 | -0.000455 |
| Mean P95 ledger delay | 15.491 ms | 15.155 ms | -0.336 ms |

Every paired cell had identical TP/FP/TN/FN and successful-finalization counts. All five validators were selected at least once under the deterministic strategy. The measured cost is concentrated in evidence transport, not PBFT traffic. This is consistent with selecting a coordinator that did not itself observe a report and therefore needs an extra modeled forward; the saved aggregate does not separate every evidence-message subtype. The six-cell replay shows no classification improvement. Detailed paired metrics and trace fingerprints are in `results/coordinator_security_v5/`.

Focused security, coordinator, V5 compatibility, and evidence-censorship characterization tests passed 48 tests. The complete suite passed 141 tests with the isolated branch code; three legacy tests required Phase 2 raw traces, read from the original checkout without modification. A V5-specific adversarial test reproduced two conflicting 4/5 commits in views 0 and 1 on one shared simulator consensus object. Retained tests also show incomplete-bundle requalification remains possible in the live architecture. Static pre-request coordinator unavailability fails closed; a crash after processing begins is not handled.
