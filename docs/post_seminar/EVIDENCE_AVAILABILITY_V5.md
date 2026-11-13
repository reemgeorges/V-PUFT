# V5 evidence availability: implementation and bounded validation

## Scope

This opt-in simulator profile starts from coordinator-security commit
`abe80d00a7a9b2bbc8d722c449f4c401827bab8f`. It uses the existing five V5
validators, `f=1`, and quorum `4/5`. The historical profile remains the
default: `evidence_availability_enabled` is false unless the explicit profile
`configs/extension_v5_evidence_availability.json` is selected. No SUMO run,
QE-policy change, detector change, or historical-result edit was made.

## Protocol now exercised by the architecture

1. An observing RSU transports the complete original signed attestation to
   each validator. A vehicle witness still uses its configured witness-RSU
   uplink before validator dissemination.
2. A validator stores an attestation only after modeled delivery, source
   signature verification, and validity checks. Its in-memory inventory is
   keyed by canonical case identity and signed attestation ID; the original
   root, source, direction, modality, cell, timestamps, signature, and payload
   are retained. Repeated delivery of the same signed item is idempotent.
3. After storing the full payload, a validator signs a receipt bound to the
   membership digest/epoch, canonical case, attestation ID, and digest of the
   exact source-signed payload. Receipts are gossiped through the simulated
   transport. A digest-only receipt cannot be stored as evidence.
4. If a receipt arrives before its payload, the validator waits for the
   outstanding direct announcement to finish. If the payload is still absent,
   it requests the original payload from the receipt signer over modeled
   request/response messages and verifies the source signature and digest
   before storing it.
5. A 4-of-5 certificate is formed per attestation. The deterministic
   coordinator builds a bundle only from its certified inventory. Validators
   compare the proposal against their own certified and directly observed
   items, verify the certificates and exact bundle digest, and requalify the
   proposal. A known omission fails closed before PBFT. The canonical bundle
   digest is included in the PBFT payload, binding the case, membership
   digest, attestation payload digests, and receipt signatures.

The protocol preserves supporting and opposing reports. It does not merge
different observation roots: qualification still applies the original source,
root, zone, modality, signature, freshness, and QE rules.

## Guarantee and boundary

Under the simulator assumptions that a valid source-signed payload is
delivered to the validators, honest validators retain their independent
inventories, receipt keys are not compromised, and the modeled transport
completes its retry schedule, a coordinator cannot silently remove evidence
that has a valid 4-validator availability certificate and still obtain an
honest 4-of-5 qualification/PBFT decision. Any two 4-of-5 sets intersect in
at least three validators; with at most one Byzantine validator, at least two
members of the intersection are honest. Those validators can reconcile the
proposal against retained evidence.

This is not proof of real distributed delivery. Inventories and keys live in
one simulator process; transport callbacks model delivery and do not provide
durable storage, process isolation, authenticated network channels, or a real
receipt persistence service. The retry schedule is a finite model assumption,
not a partial-synchrony protocol. An item that does not get a 4-receipt
certificate is not eligible for a qualified proposal; honest validators that
already received it still reject a proposal omitting it. If evidence never
reaches any honest validator, or a sole observer never announces it, the
system cannot know that it exists. Silence is not evidence completeness.

If the selected coordinator is known offline before its case begins, this
profile fails closed; it does not elect a replacement. It does not implement
PBFT VIEW-CHANGE or NEW-VIEW. The existing adversarial cross-view conflicting
certificate test remains unresolved. Consequently this profile does not
establish full PBFT safety or end-to-end Byzantine tolerance.

## Adversarial validation

The focused transport, announcement, coordinator, and prior security-audit
tests pass (46 tests). They exercise:

- Delivered opposing evidence omitted by the coordinator: validators reject
  the incomplete bundle and no PBFT finalization occurs.
- Different coordinator bundles to different validators: exact bundle-digest
  disagreement is rejected.
- A validator withholding its receipt, one offline non-coordinator, invalid
  receipts, tampered source attestations, delayed receipts, and payload
  retrieval: invalid evidence is not certified; with one offline member, the
  remaining four can certify and finalize under the tested transport case.
- Duplicate announcements: inventory remains idempotent and root count does
  not increase.
- Evidence never announced by its sole observer: no runtime mechanism can
  detect it; this is an explicit expected limitation.
- Historical profile with the feature disabled: it emits no availability
  announcement traffic and retains its prior transport path.
- Cross-view conflict: the existing characterization test still demonstrates
  that quorum intersection alone does not repair the simulator's missing
  VIEW-CHANGE/NEW-VIEW safety rules.

The full suite passes when run from the original checkout so its read-only
Phase 2 traces resolve: **155 passed**. Running the same tests from this
isolated worktree without those external traces gives 152 passed and three
`FileNotFoundError`s in Phase 2 evidence-acquisition tests; the missing files
are present in the original checkout and were read-only. No trace was copied
or edited.

## Saved-trace performance smoke test

One paired replay was completed after the final retrieval scheduling change:
density 20, seed 2101, 121 cases, 19 attack opportunities, one repetition per
variant. Both variants used the same saved C3 trace with SHA-256
`25d11c53c23d7ae71d745661d8837a70739b1b64f9759f789035cff37e02364b` and the
same V5 membership epoch. No SUMO was run. Since this is one cell and one
repeat, resource values are a smoke measurement without a variability
estimate.

| Metric | Deterministic V5 baseline | Evidence availability | Change |
|---|---:|---:|---:|
| TP / FP / TN / FN | 5 / 0 / 87 / 5 | 5 / 0 / 87 / 5 | unchanged |
| State-aware Recall | 0.5000 | 0.5000 | 0 |
| Precision / FRR | 1.0000 / 0.0000 | 1.0000 / 0.0000 | unchanged |
| Fixed-opportunity detection Recall | 4/19 = 0.2105 | 4/19 = 0.2105 | 0 |
| Protected-opportunity fraction, including terminal protection | 9/19 = 0.4737 | 9/19 = 0.4737 | 0 |
| Opportunities observed / unobserved | 16 / 3 | 16 / 3 | unchanged |
| CPU seconds | 1.1094 | 154.8125 | +13,854.93% |
| Total transmission attempts | 4,642 | 126,431 | +121,789 (+2,623.63%) |
| Messages per input case | 38.36 | 1,044.88 | +1,006.52 |
| Evidence-protocol messages | 4,396 | 126,186 | +121,790 |
| Of which: announcements / receipts / retrieval | 0 / 0 / 0 | 22,054 / 104,112 / 0 | — |
| Transmitted bytes | 3,550,144 | 43,292,128 | +39,741,984 (+1,119.45%) |
| P95 E2E | 14,081.62 ms | 14,119.54 ms | +0.269% |
| P95 ledger consistency | 14.853 ms | 15.441 ms | +0.588 ms |
| PDR | 0.98298 | 0.97982 | −0.00316 |
| Successful finalizations | 5 | 5 | unchanged |

The smoke test shows no classification or recall gain because the protocol is
designed to constrain evidence omission, not improve detection. The previous
resource gates were CPU overhead at most +25%, messages per case at most +20%,
and P95 E2E overhead at most +5%, with no new false positives. E2E and FP pass
in this single cell; CPU and message overhead fail by a wide margin. This is a
**NO-GO for deployment or broad performance claims**. It is a functional
security-prototype result only. The new fanout/gossip design needs a bounded
protocol optimization and repeated paired measurements before it can be
considered further.

## Reproducibility and artifacts

The authoritative one-cell result is in
`results/coordinator_evidence_availability_v5_final2/` with its paired CSV,
metrics CSV, and manifest. Earlier pilot folders are preserved and are not
used as the final-code measurement. The replay script refuses to overwrite a
nonempty output directory and refuses to call an incomplete trace complete.

No new full six-cell campaign was run. Frozen research results and the source
branch were not changed. The existing cross-view safety defect remains a
separate blocker to any claim of complete Byzantine fault tolerance.
