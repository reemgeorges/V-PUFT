# Sensitivity pilot statistical analysis

Seed-level runs are the units of replication. Each density has two paired seeds; the values below are descriptive paired differences, not significance tests. No confidence interval or p-value is claimed from n=2 per density.

| Factor | Level | Architecture | Density | n | Mean dRecall | Median | Improved/same/worse | Seed deltas | Range |
|---|---|---|---:|---:|---:|---:|---|---|---|
| C100_backhaul_ms | 20.0 | C100 | 20 | 2 | +0.0000 | +0.0000 | 0/2/0 | +0.0000, +0.0000 | [+0.0000, +0.0000] |
| C100_backhaul_ms | 20.0 | C100 | 100 | 2 | +0.0000 | +0.0000 | 0/2/0 | +0.0000, +0.0000 | [+0.0000, +0.0000] |
| C100_backhaul_ms | 200.0 | C100 | 20 | 2 | +0.0000 | +0.0000 | 0/2/0 | +0.0000, +0.0000 | [+0.0000, +0.0000] |
| C100_backhaul_ms | 200.0 | C100 | 100 | 2 | +0.0000 | +0.0000 | 0/2/0 | +0.0000, +0.0000 | [+0.0000, +0.0000] |
| baseline | baseline | C100 | 20 | 2 | +0.0000 | +0.0000 | 0/2/0 | +0.0000, +0.0000 | [+0.0000, +0.0000] |
| baseline | baseline | Distributed | 20 | 2 | +0.0000 | +0.0000 | 0/2/0 | +0.0000, +0.0000 | [+0.0000, +0.0000] |
| baseline | baseline | C100 | 100 | 2 | +0.0000 | +0.0000 | 0/2/0 | +0.0000, +0.0000 | [+0.0000, +0.0000] |
| baseline | baseline | Distributed | 100 | 2 | +0.0000 | +0.0000 | 0/2/0 | +0.0000, +0.0000 | [+0.0000, +0.0000] |
| freshness_window_seconds | 12.0 | C100 | 20 | 2 | -0.0455 | -0.0455 | 0/1/1 | -0.0909, +0.0000 | [-0.0909, +0.0000] |
| freshness_window_seconds | 12.0 | Distributed | 20 | 2 | -0.0455 | -0.0455 | 0/1/1 | -0.0909, +0.0000 | [-0.0909, +0.0000] |
| freshness_window_seconds | 12.0 | C100 | 100 | 2 | -0.0330 | -0.0330 | 0/0/2 | -0.0460, -0.0200 | [-0.0460, -0.0200] |
| freshness_window_seconds | 12.0 | Distributed | 100 | 2 | -0.0234 | -0.0234 | 0/0/2 | -0.0268, -0.0200 | [-0.0268, -0.0200] |
| freshness_window_seconds | 30.0 | C100 | 20 | 2 | +0.0000 | +0.0000 | 0/2/0 | +0.0000, +0.0000 | [+0.0000, +0.0000] |
| freshness_window_seconds | 30.0 | Distributed | 20 | 2 | +0.0000 | +0.0000 | 0/2/0 | +0.0000, +0.0000 | [+0.0000, +0.0000] |
| freshness_window_seconds | 30.0 | C100 | 100 | 2 | +0.0000 | +0.0000 | 0/2/0 | +0.0000, +0.0000 | [+0.0000, +0.0000] |
| freshness_window_seconds | 30.0 | Distributed | 100 | 2 | +0.0000 | +0.0000 | 0/2/0 | +0.0000, +0.0000 | [+0.0000, +0.0000] |
| packet_delivery_ratio | 0.95 | C100 | 20 | 2 | +0.0000 | +0.0000 | 0/2/0 | +0.0000, +0.0000 | [+0.0000, +0.0000] |
| packet_delivery_ratio | 0.95 | Distributed | 20 | 2 | +0.0000 | +0.0000 | 0/2/0 | +0.0000, +0.0000 | [+0.0000, +0.0000] |
| packet_delivery_ratio | 0.95 | C100 | 100 | 2 | +0.0000 | +0.0000 | 0/2/0 | +0.0000, +0.0000 | [+0.0000, +0.0000] |
| packet_delivery_ratio | 0.95 | Distributed | 100 | 2 | +0.0000 | +0.0000 | 0/2/0 | +0.0000, +0.0000 | [+0.0000, +0.0000] |
| packet_delivery_ratio | 1.0 | C100 | 20 | 2 | +0.0000 | +0.0000 | 0/2/0 | +0.0000, +0.0000 | [+0.0000, +0.0000] |
| packet_delivery_ratio | 1.0 | Distributed | 20 | 2 | +0.0000 | +0.0000 | 0/2/0 | +0.0000, +0.0000 | [+0.0000, +0.0000] |
| packet_delivery_ratio | 1.0 | C100 | 100 | 2 | +0.0000 | +0.0000 | 0/2/0 | +0.0000, +0.0000 | [+0.0000, +0.0000] |
| packet_delivery_ratio | 1.0 | Distributed | 100 | 2 | +0.0000 | +0.0000 | 0/2/0 | +0.0000, +0.0000 | [+0.0000, +0.0000] |
| position_offset.required_sources | 1 | C100 | 20 | 2 | +0.0000 | +0.0000 | 0/2/0 | +0.0000, +0.0000 | [+0.0000, +0.0000] |
| position_offset.required_sources | 1 | Distributed | 20 | 2 | +0.0000 | +0.0000 | 0/2/0 | +0.0000, +0.0000 | [+0.0000, +0.0000] |
| position_offset.required_sources | 1 | C100 | 100 | 2 | +0.0000 | +0.0000 | 0/2/0 | +0.0000, +0.0000 | [+0.0000, +0.0000] |
| position_offset.required_sources | 1 | Distributed | 100 | 2 | +0.0000 | +0.0000 | 0/2/0 | +0.0000, +0.0000 | [+0.0000, +0.0000] |
| position_offset.required_sources | 3 | C100 | 20 | 2 | -0.0909 | -0.0909 | 0/0/2 | -0.0909, -0.0909 | [-0.0909, -0.0909] |
| position_offset.required_sources | 3 | Distributed | 20 | 2 | -0.0909 | -0.0909 | 0/0/2 | -0.0909, -0.0909 | [-0.0909, -0.0909] |
| position_offset.required_sources | 3 | C100 | 100 | 2 | -0.0719 | -0.0719 | 0/0/2 | -0.0714, -0.0723 | [-0.0723, -0.0714] |
| position_offset.required_sources | 3 | Distributed | 100 | 2 | -0.0719 | -0.0719 | 0/0/2 | -0.0714, -0.0723 | [-0.0723, -0.0714] |
