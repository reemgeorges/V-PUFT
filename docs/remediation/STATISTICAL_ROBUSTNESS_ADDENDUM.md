# Statistical robustness addendum

No SUMO, detector, architecture, or calibration rerun is represented here.

These figures are transcribed from the independent Claude audit package supplied for remediation
(`V_PUFT_AUDIT_REPORT_AR.md` / `VPUFT_CORRECTIONS_PACKAGE_AR.md`). They are audit-derived secondary analyses,
not a new SUMO/detector/architecture/calibration run performed by this repository remediation.

Independent reimplementation matched the frozen statistics to rounding:
- Recall raw p: 2.4038e-06 vs 2.404e-06.
- FRR raw p: 2.6576e-08 vs 2.658e-08.
- MCC raw p: 0.039717 vs 0.03972.
- MCC Holm p: 0.19858 vs 0.1986.

After excluding `smoke` (n=30 instead of 40):
- Recall Ahmed-vs-RSU ≈ +7.55 pp; Holm p = 8.535e-04.
- FRR remains adverse/significant; Holm p = 1.445e-05.
- MCC remains non-confirmatory; Holm p = 1.0000.
- Centralized↔Distributed classification difference remains zero.

Expanded evidence-composition analysis rejects a density-only explanation: Intersection ≈1.09× root density with ≈+11 pp
Recall gain, Corridor ≈2.52× with ≈+6 pp, Spearman ≈0.40. Interpret this as a correlated sensor/source/path bundle.
