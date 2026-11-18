# Final Security Hardening (Research Prototype)

This isolated branch adds two opt-in controls without changing the frozen research branch or Phase 6 artifacts.

## Simulator final-outcome guard

`DistributedExtensionConfig.simulator_finalization_guard_enabled` defaults to `false`. When enabled, one `SimulatorFinalizationGuard` is created for a simulator run and shared with its PBFT-style finalizer. It evaluates a request only after that instance has obtained a commit certificate. Failed or timed-out attempts reserve nothing. The first committed digest for a canonical case ID is accepted; a retry with that digest is idempotent; a different committed digest is returned as `simulator_conflicting_final_outcome_rejected` and recorded in the guard conflict log. The application state machine and ledger therefore do not accept the rejected outcome.

This is an atomic application-level gate inside one simulator process. It is not a distributed lock, replicated state machine, PBFT proof, or protection across independent simulator processes. Its terminal policy is fail-closed: after an accepted result, conflicting outcomes require investigation and a new simulation run; there is no automatic override. Since a malicious but certificate-bearing first outcome can still win, this safeguard does not determine which of two competing requests is semantically correct.

The original behavior remains available with the guard disabled. The default coordinator remains `first_observer_then_hash`.

## Deterministic coordinator option

The opt-in `canonical_case_epoch_hash` strategy hashes canonical JSON containing the normalized membership epoch, canonical case identity, and sorted normalized validator identities with SHA-256, then maps the digest to one validator. Evidence membership and arrival order do not enter the mapping. Empty case IDs, empty epochs, or invalid canonical membership are rejected. The strategy does not announce or authenticate a coordinator, establish membership agreement, or provide availability or failover.

## Evidence boundary

Validators verify the signatures and requalify the evidence they receive. That process cannot prove that a coordinator included all evidence known elsewhere. The existing tests demonstrate that omitting valid signed opposing attestations can make a partial bundle qualify, while validator requalification still agrees on that incomplete bundle. Evidence withheld before any transmission by a sole observer leaves no transport record and is undetectable by this model. No evidence inventory, commitment, storage, or retrieval protocol was added.

The security claim therefore remains conditional on an honest evidence coordinator delivering its complete available bundle. The simulator-level final-outcome gate must not be described as end-to-end `f=1` Byzantine tolerance.

## Validation boundary

Characterization tests retain the original cross-view counterexample when the guard is disabled. Guard tests cover same-digest retry, conflicts in one and later views, overlapping callbacks, sharing across finalizer objects, and timeout recovery. Coordinator tests cover evidence-set/order independence, canonical validator ordering, epoch separation, and invalid identities. Evidence tests retain signed-opposition omission, incomplete-bundle requalification, sole-observer silence, and root/signature semantics. See the Arabic committee response and test output for measured regression results.

## Paired smoke run

A deterministic three-case smoke set (one detected malicious case, one insufficient-evidence malicious case, one benign no-evidence case; same case objects and seed 9017) compared four settings. Baseline and guard-only both produced TP=1, FP=0, TN=1, FN=1; Recall=0.50, Precision=1.00, FRR=0; P95 E2E=2041.872 ms; 12.000 messages/case; PDR=1.00; ledger delay P95=8.560 ms; one consistent ledger block. The deterministic coordinator alone and together with the guard retained those classification and latency results, but used 12.333 messages/case (+1 evidence-exchange message total) because the selected coordinator changed which evidence transfer was local. The measured wall-clock CPU values varied from 0.0051 to 0.0074 seconds for these tiny runs and are not evidence of CPU improvement; guard-only did not change simulated message or latency metrics. This smoke run is a regression check, not a security efficacy estimate.
