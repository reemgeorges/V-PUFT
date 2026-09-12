# Post-Freeze V-PUFT Extension — Results Audit

> Source: frozen v7 sensor traces replayed with selected v7 weights. SUMO and Centralized Near-Edge were not rerun.

## Architectural results

| Variant | Recall | FRR | Precision | MCC | P95 latency (ms) | Msg/decision | Bytes/decision |
|---|---:|---:|---:|---:|---:|---:|---:|
| distributed_extension_concealment_rsu | 0.583182 | 0.016492 | 0.877021 | 0.672232 | 14414.63 | 39.16 | 42838.27 |
| distributed_extension_false_accusation_rsu | 0.809059 | 0.024445 | 0.870551 | 0.807790 | 14605.29 | 43.46 | 56652.39 |
| distributed_extension_guard_false_accusation_rsu | 0.605201 | 0.016304 | 0.876607 | 0.684463 | 14509.80 | 42.01 | 49465.10 |
| distributed_extension_guard_honest | 0.605201 | 0.016304 | 0.876607 | 0.684463 | 14508.09 | 38.62 | 46908.16 |
| distributed_extension_honest | 0.809059 | 0.016492 | 0.908184 | 0.830297 | 14609.75 | 39.83 | 53360.31 |
| distributed_extension_malicious_validator | 0.809059 | 0.016492 | 0.908184 | 0.830297 | 14859.55 | 39.98 | 53371.53 |

## Controlled comparisons

- `distributed_extension_false_accusation_rsu` versus `distributed_extension_honest`: classification changes=40/5992 (0.6676%), ΔRecall=+0.000000, ΔFRR=+0.007953, ΔP95=-4.47 ms.
- `distributed_extension_concealment_rsu` versus `distributed_extension_honest`: classification changes=227/5992 (3.7884%), ΔRecall=-0.225877, ΔFRR=+0.000000, ΔP95=-195.12 ms.
- `distributed_extension_malicious_validator` versus `distributed_extension_honest`: classification changes=0/5992 (0.0000%), ΔRecall=+0.000000, ΔFRR=+0.000000, ΔP95=+249.80 ms.
- `distributed_extension_guard_false_accusation_rsu` versus `distributed_extension_guard_honest`: classification changes=0/5992 (0.0000%), ΔRecall=+0.000000, ΔFRR=+0.000000, ΔP95=+1.71 ms.
- `distributed_extension_guard_honest` versus `distributed_extension_honest`: classification changes=205/5992 (3.4212%), ΔRecall=-0.203859, ΔFRR=-0.000188, ΔP95=-101.66 ms.

## V2V cache/TTL sensitivity

| TTL (s) | Cache hit rate | V2I queries avoided | Stale acceptance rate | Mean authorization latency (ms) | Bytes/interaction |
|---:|---:|---:|---:|---:|---:|
| 0.0 | 0.000000 | 0.00 | 0.000000 | 16.9122 | 1430.76 |
| 1.0 | 0.029081 | 15.30 | 0.000000 | 16.4326 | 1389.14 |
| 2.0 | 0.056446 | 30.00 | 0.000083 | 15.9770 | 1349.99 |
| 5.0 | 0.119869 | 65.78 | 0.000375 | 14.9301 | 1258.89 |
| 10.0 | 0.207526 | 119.92 | 0.001087 | 13.4786 | 1133.17 |
| 30.0 | 0.404711 | 252.82 | 0.006004 | 10.1792 | 851.44 |

## V2V density sensitivity

| Vehicles | Cache hit rate | V2I queries avoided | Stale acceptance rate | Mean authorization latency (ms) | Bytes/interaction |
|---:|---:|---:|---:|---:|---:|
| 20 | 0.232847 | 55.88 | 0.004028 | 13.0991 | 1096.96 |
| 40 | 0.155243 | 74.52 | 0.001111 | 14.3105 | 1206.53 |
| 60 | 0.116806 | 84.10 | 0.000556 | 14.9679 | 1263.23 |
| 80 | 0.096146 | 92.30 | 0.000278 | 15.3112 | 1293.77 |
| 100 | 0.080319 | 96.38 | 0.000319 | 15.5695 | 1317.33 |

## Six-RSU read-cache replication

- Read-only cache sync messages delivered to non-validator RSUs: 9786.
- Modeled cache-sync traffic: 10960320 bytes.
- The read replica lets any RSU answer locally; only the four configured validators retain PBFT voting/write authority.

## Audit conclusions

- Lowest modeled mean V2V authorization latency occurred at TTL=30.0s, but its stale-acceptance rate was 0.006004.
- Relative to TTL=0.0s, this is a modeled latency reduction of 6.7331 ms per interaction on average.
- A malicious-validator result is defensible only where `fault_activated`/`invalid_proposal_attempted` is recorded.
- False-accusation and concealment are separate claims; one must not be generalized to the other.
- Leave-one-source-out protects false-revocation safety at a measurable recall cost; it is an ablation, not a free improvement.
- Timing remains simulated/parametric and must not be described as field latency.
