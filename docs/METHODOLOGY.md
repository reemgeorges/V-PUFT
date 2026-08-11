# Methodology

## 1. Evidence representation

Each attestation contains:

- case ID
- observation root ID
- source and validator identities
- administrative domain
- sensor modality
- geographic cell
- attack type
- supporting/opposing direction
- detector confidence
- source reliability
- freshness
- verifiability
- independence
- evidence hash
- Ed25519 signature

## 2. Evidence weight

For valid attestation `i`:

```text
w_i = V_i × C_i^alpha_C × rho_i^alpha_rho × F_i^alpha_F × Q_i^alpha_Q × eta_i^alpha_eta
```

Constraints:

```text
alpha_j >= 0
sum(alpha_j) = 1
```

`V_i` is a hard gate. A failed attestation signature gives zero weight.

## 3. Root-level de-correlation

All derived reports with the same `observation_root_id` are one evidentiary root. Within a root, the strongest support and strongest opposition are compared:

```text
net_root = max_support_weight - max_opposition_weight
root_weight = abs(net_root)
```

Thus one root cannot count as two independent roots merely because it was relayed by many nodes.

## 4. Case strength

Supporting and opposing roots use noisy-OR aggregation:

```text
S_plus  = 1 - product(1 - root_support_weight)
S_minus = 1 - product(1 - root_opposition_weight)
margin  = S_plus - lambda × S_minus
```

## 5. Attack-adaptive evidence quorum

A case must satisfy the attack policy:

- minimum independent roots
- minimum distinct sources
- minimum zones
- minimum modalities
- weighted margin threshold

Cryptographically decisive attacks, such as certificate tampering or replay with verifiable proof, may use a separate decisive path.

## 6. Separation of evidence and consensus

```text
Evidence quorum Q_E ≠ PBFT quorum Q_B
```

PBFT is started only after evidence qualification. Consensus cannot turn weak or correlated evidence into valid evidence.

## 7. Weight sensitivity

1. Split by independent seeds, never by individual rows.
2. Keep 20% of seeds as an untouched holdout.
3. Generate non-negative exponent vectors from a Dirichlet distribution.
4. Search weights, global margin threshold, and opposing-evidence coefficient.
5. Apply predeclared recall and false-revocation constraints.
6. Rank by worst-fold MCC, then mean MCC.
7. Evaluate once on holdout.
8. Re-select with grouped bootstrap for confidence intervals.
9. Run local perturbation, single-factor ablations, equal-weight baseline and permutation importance.

The same selected weights are deployed to all three architectures.

## 8. Statistical outputs

The framework produces per-seed values for later confidence intervals and paired statistical testing. Final thesis analysis should compare the same seeds across models and report effect sizes, not only p-values.
