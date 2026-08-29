# Final consistency audit contract

`Code ↔ base config + selected weights ↔ frozen results ↔ statistics ↔ thesis ↔ README ↔ reproduction`

The remediation preserves `selection_feasible=false`, separates finalization from evidence-path comparisons,
removes Byzantine-safety/MCC/causal overclaims, records without-smoke robustness, distinguishes packet loss from
arrival-time freshness, fixes future Ahmed instrumentation without rewriting historical decisions, and documents
bytes/latency/authentication/LFS limits.

No frozen scientific numeric CSV/JSON input is intentionally changed. Reporting-only edits under
`results/full_campaign_v7` are limited to the derived Chapter-5 HTML/index/metadata/manifest plus interpretation
notes in the existing statistical-inference, case-agreement and latency-decomposition `SUMMARY.md` files.
Active architecture/protocol/threat/test documentation is reconciled to the same scope boundary.

The exact original Python dependency versions are not reconstructible from the frozen repository because no dependency lockfile/pip-freeze artifact is present; the runbook states this limitation explicitly.
