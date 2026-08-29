# Case-Level Agreement (V-PUFT v8, post-freeze)

<!-- POST_CLAUDE_REMEDIATION_V3 -->
> **Post-audit scope.** Complete Centralized↔Distributed case agreement supports classification equivalence on the shared
> RSU-view cases and is the clean comparison for finalization. Ahmed comparisons use a different witness evidence view;
> their disagreement/agreement rates describe an integrated evidence path and do not isolate a single architectural cause.

No experiment was re-run. This analysis explains, at the level of individual
cases, why two architectures report identical aggregate confusion matrices.

## Coverage and agreement

| Pair | A | B | Shared | A-only | B-only | Agreement | Kappa | Discordant | Test | p |
|---|---|---|---|---|---|---|---|---|---|---|
| Centralized V-PUFT vs Distributed RSU V-PUFT | 5992 | 5992 | 5992 | 0 | 0 | 1.000000 | 1.0000 | 0 | none | 1 |
| Centralized V-PUFT vs Ahmed-Inspired Witness V-PUFT | 5992 | 5953 | 5953 | 39 | 0 | 0.955989 | 0.8393 | 262 | chi2_continuity_corrected | 0 |
| Distributed RSU V-PUFT vs Ahmed-Inspired Witness V-PUFT | 5992 | 5953 | 5953 | 39 | 0 | 0.955989 | 0.8393 | 262 | chi2_continuity_corrected | 0 |

## Text for section 5.17

The measured agreement is exactly 1.0. Suggested wording:

> Across all 5992 shared cases, the two RSU-based architectures issued identical trust decisions. Their identical aggregate confusion matrices are therefore explained by complete case-level classification agreement on the shared case set. This supports treating classification quality as equivalent for those cases in the frozen campaign, while communication, latency, consensus and ledger metrics remain separate dimensions of the architectural comparison. This result does not by itself prove that the internal evidence sets or processing traces were identical.
