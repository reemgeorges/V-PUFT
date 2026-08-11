# Test Report

Validation command:

```bash
PYTHONPATH=src pytest -q
```

Status at packaging time:

- 11 tests passed.
- 1 SUMO end-to-end test was skipped because the packaging environment did not contain a SUMO binary or TraCI package.
- Python compilation of `src` and `tests` passed.
- A complete synthetic campaign and sensitivity run completed and is included in `results/demo_reference`.

Covered tests:

- deterministic Ed25519 signatures
- invalid-signature rejection
- root de-duplication
- independent-root qualification
- PBFT quorum and view change
- all three architecture smoke test
- sensitivity analysis smoke test
- trace JSONL round trip
- deterministic replay keys
- position attack injection and detection
- replay preserving original observation root
- SUMO readiness doctor
- real SUMO smoke test when the binary is available
