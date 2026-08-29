# Canonical claim audit

| Claim | Verdict |
|---|---|
| Blockchain/PBFT improves classification accuracy | REMOVE |
| Centralized↔Distributed isolates finalization | SUPPORTED |
| Ahmed is a better architecture because Recall is higher | QUALIFY — integrated evidence-path |
| Ahmed improves MCC | REMOVE as confirmatory — Holm p≈0.1986 |
| zero safety violations proves Byzantine safety | REMOVE |
| full VIEW-CHANGE/NEW-VIEW is implemented | REMOVE |
| baseline exercises Byzantine faults | REMOVE — `validator_behaviors={}` |
| all three consume exactly same evidence | QUALIFY — shared upstream raw trace, separate views |
| lower Distributed bytes proves decentralization cheaper | REMOVE |
| ≈14 s is PBFT latency | REMOVE |
| authentication schemes empirically benchmarked | REMOVE — Ed25519 only |
| candidate met feasibility constraints | REMOVE — `selection_feasible=false` |
| root density explains Ahmed gain | REMOVE |
| perfect delivery makes transport irrelevant | QUALIFY — arrival timing can affect freshness |
| frozen Ahmed decisions expose independent_roots | REMOVE |
| Corridor is universally best topology | REMOVE |


<!-- POST_CLAUDE_DEFENSE_REPORT_AUDIT_V3 -->
## Defense/report propagation audit

The post-audit interpretation boundary was propagated to:
- `defense_v8/README_AR.md`
- `defense_v8/CHAPTER5_REQUIRED_CORRECTIONS_AR.md`
- `results/full_campaign_v7/statistical_inference/SUMMARY.md`
- `results/full_campaign_v7/case_agreement/SUMMARY.md`
- `results/full_campaign_v7/latency_decomposition/SUMMARY.md`

`defense_v8/PHASE_B_ROBUSTNESS_PLAN_AR.md` was reviewed and already states that frozen Safety was not tested and that
equivocation/accept-invalid scenarios can be no-ops without a semantic fault harness, so no scientific correction was required.

<!-- POST_CLAUDE_ACTIVE_DOCS_V4 -->
## Active documentation closure

The final audit also reconciled `docs/ARCHITECTURE.md`, `docs/EXPERIMENT_PROTOCOL.md`,
`docs/TEST_REPORT.md`, `docs/THREAT_MODEL.md`, and the historical `docs/analysis/PHASE_A_SUMMARIES.txt`
interpretation header. Legacy claims about a full PBFT view-change path, identical evidence views for all
architectures, and baseline empirical Safety are no longer left unqualified in active documentation.

<!-- POST_CLAUDE_FINAL_REVIEW_V5 -->
## Final-review closure

The last review softened residual causal wording for Centralized↔Distributed to “cleanest comparison” rather
than a universal single-variable isolation claim; replaced the remaining ambiguous Chapter-5 `View Change`
label with bounded view/leader rotation; and made configured-vs-activated fault semantics explicit.
