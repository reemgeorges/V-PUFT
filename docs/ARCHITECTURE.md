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
RSU evidence → local V-PUFT qualification → signed PBFT → distributed hash-linked ledger → state recovery
```

PBFT simulation includes recipient certificates, vote locks, loss/retries, leader failure, view change, and recovery.

## Model 3 — Ahmed-Inspired Witness V-PUFT

```text
Vehicle witness evidence → RSU validation → witness package → V-PUFT → PBFT → distributed ledger
```

The article-native witness threshold is recorded as an ablation reference. It does not replace V-PUFT in the main third model.

## Fairness rule

The same mobility, attacks, seeds, message roots and ground truth are produced once. All architectures replay the same trace. The difference is evidence source and finalization/storage architecture, not a separate trust formula.
