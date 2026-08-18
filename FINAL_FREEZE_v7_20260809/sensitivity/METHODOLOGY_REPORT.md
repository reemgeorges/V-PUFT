# V-PUFT Weight Selection Report

- Development seeds: [1001, 1002, 1004, 1005, 1006, 1008, 1009, 1010]
- Untouched holdout seeds: [1003, 1007]
- Minimum recall constraint: 0.95
- Maximum false-revocation-rate constraint: 0.05
- Candidate count evaluated: 1202
- Bootstrap repetitions: 200
- Selected weights: `{"C": 0.3652673861753211, "F": 0.06370517641034751, "Q": 0.40608957775126925, "eta": 0.0029852581432305157, "rho": 0.16195260151983162}`
- Decision thresholds: fixed predeclared per-attack policies from the experiment configuration
- Opposing-evidence coefficients: fixed predeclared per-attack policies from the experiment configuration
- Holdout MCC: 0.826342
- Holdout recall: 0.833333
- Holdout FRR: 0.023749
- Calibration fairness: RSU and witness evidence are separate runtime views; one shared weight vector is selected.
- Validation robustness: ranking and feasibility use the weakest fold x evidence-source view, not a fused RSU+witness case.

The holdout groups were not used during candidate selection. Weight stability is reported by grouped bootstrap re-selection; factor contribution is checked by ablation and grouped permutation importance. Only the five V-PUFT weight exponents are calibrated. Attack-specific diversity requirements, margin thresholds, and opposing-evidence coefficients remain predeclared and fixed. Evidence aggregation uses a regularized additive log-evidence mass so supporting and opposing channels retain their relative magnitude instead of independently saturating to one.
