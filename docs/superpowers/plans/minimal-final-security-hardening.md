# Minimal V-PUFT Security Hardening Plan

- Verify the existing audit worktree and characterization tests.
- Write failing tests for shared final-outcome admission and async stale callback handling.
- Implement an opt-in simulator-level final-outcome safeguard while preserving disabled behavior.
- Implement an optional deterministic coordinator strategy with canonical case, epoch, and validator ordering.
- Document the guarantee boundary and coordinator/evidence threat model.
- Run focused, historical audit, related, and full tests; compare paired smoke runs.
- Commit only validated audit-worktree changes.
