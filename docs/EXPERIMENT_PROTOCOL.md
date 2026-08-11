# Experiment Protocol

## Calibration phase

- Use dedicated seeds for development and holdout.
- Select V-PUFT exponents once.
- Freeze weights and thresholds before the final architecture campaign.
- Do not reuse final-test seeds to change attack policies.

## Main factors

- architecture: central / distributed RSU / Ahmed-inspired witness
- vehicle count and traffic density
- packet delivery ratio
- network latency and jitter
- malicious vehicle ratio
- compromised RSU count
- compromised witness ratio
- central workers and queue capacity
- PBFT validator failures
- attack type

## Minimum outputs

- trust precision, recall, F1, MCC, FRR
- p50/p95/p99 end-to-end decision latency
- messages and bytes per decision
- PDR and retransmissions
- consensus success, view changes, liveness and safety
- ledger consistency and recovery
- CPU and memory
- evidence correlation suppression

## Pairing

All compared models must use the same seed and shared trace. Statistical comparisons should be paired by seed/scenario.
