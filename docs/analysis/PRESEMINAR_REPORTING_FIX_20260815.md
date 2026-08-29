# V-PUFT — Pre-Seminar Reporting Fix (2026-08-15)

Scope: **reporting/validation only**. No SUMO run, detector rebuild, recalibration, architecture replay, policy change, weight change, or PBFT core change.

## Corrected in Chapter 5

- Table 5-3a now exposes pooled A and B values so the +8.46 pp pooled recall difference is arithmetically closed.
- FRR direction is explicitly marked as an **adverse increase** even though it is confirmatory after Holm.
- MCC remains descriptive/supportive only; Holm-adjusted p≈0.1986 is not confirmatory.
- Attack-specific exploratory intervals are reported consistently for Certificate Tamper, Flood, Mixed, Replay, False DENM, Position Offset, and Speed Offset, always using the Ahmed-vs-Distributed contrast in the attack narrative.
- False DENM mechanism language is explicitly non-causal: no isolated experiment identified witness diversity as the sole cause.
- Detection/Evidence Acquisition = 8000 ms with zero IQR for Centralized/Distributed is identified as a configured/model interval under the current setup, not a variable measured performance quantity across the 40 units.
- P95 stage values are explicitly non-additive and the percentile cases need not be the same cases.
- Section 5.17 TOC/body title is unified.
- κ=1 is framed correctly: changing finalization to PBFT did not change classification under fixed trust/evidence. This does **not** experimentally prove or disprove ledger tamper resistance, independent auditability, or removal of a trusted finalizer; those were not directly measured.

## Validation upgrade

`defense_v8/validate_chapter5_semantics.py` reads the actual Phase-A CSV outputs and verifies numerical identities, Holm decisions, attack CIs, candidate-650 weights, `selection_feasible=false`, Mixed `required_modalities=1`, case agreement, and Chapter 5 reporting semantics. It writes a source-derived `VALIDATION.json`.

`FINAL_MANIFEST.json` includes SHA-256 hashes for the chapter and the direct statistical/calibration inputs used by the reporting layer.

`audit_thesis_claims.py` is read-only and is intended to find stale claims in the abstract, Chapter 1, Chapter 6, or other prose. It does not auto-rewrite thesis text.
