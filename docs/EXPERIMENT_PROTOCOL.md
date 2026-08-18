# Experiment Protocol

## Calibration phase

- Use dedicated seeds for development and holdout.
- Select V-PUFT exponents once.
- Freeze weights and thresholds before the final architecture campaign.
- Do not reuse final-test seeds to change attack policies.

## Main factors

The list below describes the protocol/design factor space. It must not be read as a claim that every factor was activated in the frozen final campaign; in particular, the final baseline used `validator_behaviors={}`.

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
- consensus success, timeout-driven bounded view/leader rotations and liveness; Safety is reportable only in a separate run that actually activates malicious semantic proposals and a working safety measurement path
- ledger consistency and recovery
- CPU and memory
- evidence correlation suppression

## Pairing

All compared models must use the same seed and shared upstream mobility/attack trace. Evidence views may differ by architecture (RSU for Centralized/Distributed; witness for Ahmed-Inspired), so pairing by seed/scenario does not imply identical internal evidence sets. Statistical comparisons should be paired by seed/scenario.
