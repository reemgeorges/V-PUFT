# Threat Model

## Vehicle attacks

- position spoofing
- speed spoofing
- replay
- certificate tampering
- flooding
- false DENM
- mixed attack

## Infrastructure faults and attacks

- central server outage
- central false-revocation compromise
- central censorship compromise
- PBFT leader offline
- validator reject-valid behavior
- validator accept-invalid behavior
- validator equivocation
- packet loss
- retries and link queues
- incomplete ledger replication
- state recovery
- compromised RSU false attestation
- compromised vehicle witness false report

## Evidence attacks

- multiple reports derived from one observation
- replay of one root
- correlated evidence inflation
- conflicting support and opposition within one root
- multiple source identities

## Assumptions

- cryptographic primitives are not broken
- deterministic keys are for reproducibility, not operational key management
- the declared PBFT fault bound is respected in experiments claiming PBFT safety
- SUMO provides the experiment's ground truth
- the detector is an idealized simulation detector and must not be described as a field-deployed sensor system
