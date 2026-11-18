# Coordinator Assumptions

The default `first_observer_then_hash` strategy is unchanged. It can disagree across coordinators with different local evidence subsets.

The optional `canonical_case_epoch_hash` strategy computes:

```text
SHA256(canonical_json([membership_epoch, canonical_case_id, sorted_validator_ids]))
    modulo validator_count
```

Case and validator strings use Unicode NFC normalization and whitespace trimming. The case ID and membership epoch must be non-empty; canonical validator identities must be unique and non-empty. Validator ordering in configuration and evidence arrival order do not change the selected identity. A distinct membership epoch changes the hash input; distinct epochs are not guaranteed mathematically to select different validators for every case.

This is deterministic selection under a shared, fixed membership epoch. It is not a consensus round. It assumes all participants use the same canonical case ID, epoch, validator set, and mapping implementation. It does not authenticate a coordinator announcement, prove that participants actually share the epoch, detect a coordinator crash before PBFT starts, or specify takeover. The existing PBFT view rotation only addresses leader unavailability after finalization begins; coordinator availability before that point remains unmodeled.
