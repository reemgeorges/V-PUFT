# Controlled Topology × Vehicle-Density Campaign — Audit

## Design integrity

- Expected shared SUMO traces: **50**
- Completed unique shared traces: **50**
- Requested/observed vehicle counts match: **True**
- Same trace paired across architectures: **True**
- Frozen v7 modified: **False**
- Unique Distributed vs Centralized classification changes: **0/5921**
- Unique agreement rate: **100.000000%**
- Repeated total across all 2 backhaul levels: **0**
  (the same classification comparison is repeated at every latency level)

## Outputs

- `density_architecture_summary.csv`: every metric by topology, vehicle count and architecture.
- `density_paired_comparisons.csv`: seed-paired Distributed minus Remote differences.
  It includes a paired bootstrap CI, Wilcoxon p-value, rank-biserial effect and
  a 10-cell Holm adjustment within each metric and a
  5-cell adjustment within each metric/backhaul
  stratum. Both remain supplementary/exploratory.
- `density_step_changes.csv`: exact absolute and relative 20→40→60→80→100 changes.
- `density_breakeven_by_topology_vehicle_count.csv`: density-specific parametric break-even points.
- `density_case_agreement.csv`: decision agreement audit at every backhaul level.
- `density_attack_summary.csv`: attack-stratified results by topology, density and architecture.
- `density_message_type_architecture_summary.csv`: message-type counts, bytes, loss and queue delay.
- `density_topology_v2v_cache_summary.csv`: topology-aware light-cache results.
- `density_topology_v2v_cache_step_changes.csv`: exact cache changes between adjacent densities.

## Claim boundary

These are controlled simulation/model results. They support density-conditional
comparisons inside the implemented SUMO and transport models, not field-radio,
production-server or universal PBFT performance claims.
