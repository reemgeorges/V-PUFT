# Phase 3 implementation audit: provenance-safe observer diversity

## Scope and baseline

This audit uses the existing research branch and its frozen policy/weights. The new option `provenance_safe_observer_diversity` defaults to `False`; no frozen config or historical result was changed. The Phase 3 replay used the three exact JSONL trace files also named in the Phase 2 trace manifest. Their recorded SHA-256 digests are in `results/post_seminar_phase3/limited_v2/shared_trace_manifest.csv`'s source manifest reference; the exact digests are reproduced in the paired-results report. Matching trace counts alone are not treated as byte-identical reproduction of the old frozen campaign.

## Findings from the full implementation diff

`aggregate_by_root()` in `src/vpuft/weighting.py` groups by `observation_root_id`; it selects the strongest valid support and opposition reports, subtracts them, and emits one `RootContribution`. Thus multiple receiving RSUs do not increase root count or aggregate support mass. A root with equally strong contradictory directions becomes neutral. This behavior remains the source of root independence and support/opposition semantics.

The optional qualification branch first applies the existing freshness filter, then only considers attestations with support direction, `validity == 1`, and individual evidence weight at least the attack policy's `min_representative_weight`. It restricts those reports to roots whose aggregated net contribution is supporting and meets the existing representative threshold. For each diversity dimension separately, a deterministic maximum bipartite matching assigns each supporting root to at most one distinct attribute value. Consequently, a root may contribute at most one source, one zone, and one modality credit; it cannot provide two source credits or two zone credits. Requirements greater than one therefore require that many distinct supporting roots and distinct attribute values for each such dimension.

This is a conservative security interpretation: independent message roots provide independent evidence contributions; source and zone diversity are additional attributes backed by those roots. Several observers of one CAM may add signed observer metadata, but cannot turn that CAM into several roots or several source/zone credits. A single root can be matched to one value in each dimension, potentially using different eligible observer attestations. This does not prove the claimed physical location or sensor behavior is truthful: a compromised but correctly authenticated RSU can lie. Cryptographic validation establishes signer identity/integrity, not honest sensing.

The matcher does not include expired reports, reports whose validity is zero, opposing/neutral reports, or below-threshold reports. Signature verification is enforced at the architecture sanitization boundary; qualification assumes it receives sanitized attestations, as the existing architecture does. The feature does not weaken roots, diversity, freshness, margin, or cryptographic-decisive policy thresholds. The false option branch preserves the original representative-only source/zone/modality counts.

## Remaining limits and risks

- The Phase 1 set of 847 unresolved diversity FN windows cannot be retrospectively separated into source, zone, modality, and overlap counts because the frozen per-decision records did not persist all those counters. Do not infer that all 847 are recoverable by this change.
- The matching treats each authenticated source's signed zone/modality fields as claims. A compromised authenticated RSU can lie about them. The matching bounds each root's credits but is not a Byzantine sensor-truth mechanism.
- The B8 option does not add a transport protocol. It only uses eligible, already-delivered observer attestations at qualification time.
- The code's existing evidence-coordinator deterministic tie-break and PBFT view-change behavior are unchanged. PBFT leader replacement is not evidence-coordinator recovery; this Phase 3 change does not claim coordinator crash recovery.
- An earlier direct command using global Python exited 1 because that interpreter had no `pytest` installed. The repository `.venv` includes pytest. The first actual test execution then found one incorrectly calibrated fixture: confidence 0.01 gave weight 0.395 (minimum 0.05), so the implementation correctly counted it. The fixture was lowered to confidence `1e-30`; the corrected targeted suite passed.

## Decision

B8 is safe enough for a limited pilot under the tested root-counting invariants, but it is not justified for the full 50-cell campaign as an improvement over B1. The pilot produced the same classifications as B1 at all sampled densities and had higher CPU at density 100. The feature remains optional and disabled by default. A full B8 campaign should wait for a research question that benefits from broader estimation or a measured optimization that removes its CPU overhead.
