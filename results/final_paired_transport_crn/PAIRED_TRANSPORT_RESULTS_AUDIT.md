# Evidence-CRN Paired Transport Replay — Audit

## Integrity

- SUMO rerun: **NO**
- Saved density traces reused: **YES**
- Completed cells: **200/200**
- Architecture runs: **600** (three per cell)
- Evidence loss/jitter/retry draws paired by attestation key: **YES**
- Queueing, local coordinator delivery and PBFT-only traffic remain architecture-specific: **YES**
- Analysis family: **post-hoc supplementary sensitivity**

## Classification agreement

- central_crn_available_0ms: 17 unique changes / 70791 shared cases; agreement=99.975986%.
- central_crn_operational_0ms: 51 unique changes / 70791 shared cases; agreement=99.927957%.

## Backhaul

- Central runs were executed once at 0 ms.
- The configured one-way backhaul levels were derived by the exact additive rule already implemented and verified in the original campaign: [0.0, 20.0, 50.0, 100.0, 200.0].
- Break-even points inside the tested 0–200 ms range: **6/40 comparator cells**.
- Those rows represent **3 unique topology × density conditions** repeated across the two central comparators.
- Values outside that range are explicitly labeled model extrapolations.

## Statistical boundary

- Holm families: **24** comparator × metric families, each containing **20** topology × density comparisons.
- Holm rejections: **240/480**; the smallest adjusted p-value is **0.0390625**.
- With ten paired seeds, that value is the attainable boundary produced when all non-zero seed differences point in the same direction. The family remains post-hoc/supplementary and must not be relabeled confirmatory.

## Communication and queue delay

- central_crn_available_0ms: messages=3181388, bytes=2239697152, message-weighted queue delay=6308.7430 ms.
- central_crn_operational_0ms: messages=3181388, bytes=2239697152, message-weighted queue delay=6308.7430 ms.
- distributed_crn_honest: messages=2521234, bytes=2649744576, message-weighted queue delay=5295.2645 ms.

- The message-weighted descriptive queue delay is lower for the distributed path in this replay. Interpretation must remain conditional on message mix: Central uses one evidence-message type, whereas Distributed includes evidence exchange, evidence bundles, PBFT, ledger replication and read-cache synchronization.
- The per-seed paired ``mean_queue_delay_ms`` remains valid as a run-level outcome. The message-type table now separately reports both the unweighted cell mean and the message-count-weighted per-message mean.

## Interpretation boundary

This replay removes order-dependent transport RNG as an explanation for evidence-delivery differences. It does not make the architectures identical: coordinator-local evidence avoids a network hop in the distributed path, central queueing remains central, and validator requalification/PBFT/replication remain distributed costs. The availability=1.0 central ablation isolates architectural processing from the separate availability=0.995 operational stimulus. Timing remains simulated, and the analysis remains post-hoc/exploratory.
