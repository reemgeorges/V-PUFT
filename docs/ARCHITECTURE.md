# Architecture

## Shared V-PUFT pipeline

```text
Mobility / attack ground truth
        ↓
CAM/DENM generation
        ↓
RSU and vehicle-witness observations
        ↓
Signed EvidenceAttestation
        ↓
Case isolation by vehicle + attack type
        ↓
Observation-root de-correlation
        ↓
Weighted evidence fusion
        ↓
Attack-adaptive evidence quorum
        ↓
Staged trust state transition
        ↓
Architecture-specific finalization
```

## Model 1 — Centralized V-PUFT

```text
RSU evidence → network → central queue/workers → V-PUFT → central finalization → primary ledger + audit replica
```

Failure variables:

- server availability
- worker count
- service time
- queue capacity
- false-revocation compromise
- censorship compromise

## Model 2 — Distributed RSU V-PUFT

```text
RSU evidence → coordinator/remote-RSU evidence exchange → V-PUFT qualification → signed PBFT-style finalization → distributed hash-linked ledger → state recovery
```

PBFT-style simulation includes recipient certificates, vote locks, loss/retries, timeout-driven bounded leader/view rotation, and recovery. It does not implement a full VIEW-CHANGE/NEW-VIEW message protocol, and the frozen final campaign did not activate Byzantine validator behavior.

## Model 3 — Ahmed-Inspired Witness V-PUFT

```text
Vehicle witness evidence → RSU validation → witness package → V-PUFT → PBFT → distributed ledger
```

The article-native witness threshold is recorded as an ablation reference. It does not replace V-PUFT in the main third model.

## Fairness rule

The same mobility, attacks, seeds, raw upstream messages and ground truth are produced once. Centralized and Distributed consume the RSU evidence view, while Ahmed-Inspired consumes the witness evidence view. Thus Centralized↔Distributed is the clean finalization comparison; Ahmed↔RSU is an integrated evidence-path comparison, not a single-variable ablation. The trust formula remains shared.
