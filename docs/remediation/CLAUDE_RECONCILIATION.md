# Claude audit reconciliation

| Finding | Remediation |
|---|---|
| Ahmed confounds evidence path with architecture | Reframed as integrated evidence-path; Centralized↔Distributed reserved for finalization isolation |
| PBFT safety overclaim | Removed; no empirical Byzantine-safety claim |
| “same trace” wording | Shared raw upstream trace + source-specific RSU/witness views |
| broken weights path | Corrected to `sensitivity_shared_views_mixedfix/selected_weights.json` |
| embedded config weights differ from final replay | Effective-final composition documented |
| UTF-8 corruption 5.16.1/5.19.1/5.20.7 | Repaired |
| MCC risk | Descriptive only after Holm |
| without-smoke | Added |
| density-only explanation | Removed |
| perfect delivery ⇒ transport impossible | Corrected: loss not explanatory here; timing/freshness still possible |
| Ahmed independent_roots missing historically | Future instrumentation + test; no frozen backfill |
| bytes semantics | Modeling caveat added |
| authentication benchmark absent | Empirical message exchange; authentication methods theoretical |
| LFS reproduction | documented |


<!-- POST_CLAUDE_DEFENSE_REPORT_AUDIT_V3 -->
## Defense/report consistency closure

Legacy Phase-A defense instructions were retained as historical context but explicitly superseded where their broad
“do not modify src/results” wording conflicted with traceable post-audit reporting corrections and future-only instrumentation.
Statistical, case-agreement and latency summaries now carry the same causal-scope boundary as Chapter 5.

<!-- POST_CLAUDE_ACTIVE_DOCS_V4 -->
## Active-documentation propagation

The same post-audit scope now propagates beyond README/Chapter 5 into architecture, experiment-protocol,
test-report and threat-model documentation. Historical Phase-A numerical tables remain unchanged but are
explicitly marked as a historical snapshot whose interpretation is superseded by the canonical claim audit.

<!-- POST_CLAUDE_FINAL_REVIEW_V5 -->
## Reproducibility closure

The effective-final configuration is now self-contained: baseline config plus the selected candidate-650 weights,
matching replay semantics. The runbook also records that the exact original Python dependency versions cannot be
reconstructed because the frozen baseline contains version ranges but no lockfile/pip-freeze artifact.
