# PBFT-Style Safety Scope

The original simulator's vote lock is keyed by `(validator, view, phase, case_id)`. In characterization tests, one shared PBFT object can commit digest A in one view and digest B in a later view because the view is part of the lock key. Independent PBFT objects have independent vote state and do not constitute evidence of a shared-validator safety violation. The simulator also lacks full prepared-certificate propagation and PBFT NEW-VIEW rules.

The opt-in `SimulatorFinalizationGuard` is narrower than consensus safety. It observes an already committed PBFT-style outcome and atomically records the first final digest by canonical case ID. It lets a failed attempt leave the case available, treats an identical retry idempotently, and records/rejects a later conflicting committed outcome. Concurrent callbacks serialize on a lock. Stale conflicting callbacks therefore cannot replace the accepted application result.

This proves only an at-most-one accepted final digest in a single simulator execution when all relevant contexts share the guard instance. It does not stop validators from signing conflicting votes, prevent conflicting certificates, work across processes, select the semantically correct request, or guarantee progress. The first certificate-bearing outcome remains terminal. Recovery is deliberately manual: investigate the conflict and start a new run after correcting the scenario or inputs; do not silently clear the state.

Full PBFT safety would require persistent per-validator protocol state and the prepared-certificate and safe view-change/new-view rules, with corresponding liveness and adversarial validation. Those changes are outside this bounded hardening.
