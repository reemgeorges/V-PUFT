# V-PUFT Scenario 5 Defense Demonstration — Storyboard

**Format:** 1920×1080, 24 fps, 2:12, English captions, no narration or music.  
**Visualization:** Trace-based rendering of saved SUMO/TraCI output; not a native SUMO-GUI capture.  
**Dataset:** Sensitivity-replication trace reused by the bounded ablation baseline; density 20, seed 7003. This is not frozen corrected-final Dataset B.  
**Trace SHA-256:** cb43f7bbb9d3594a6d006ce5525c86f293ea6c2d0d5b7ba8409181a8d9547bc7  
**Selected event:** veh_000, position_offset, case case-urban_roundabout-7003-veh_000-w0001.

| Video time | Scene | Recorded content |
|---|---|---|
| 00:00–00:10 | Title | V-PUFT: Evidence-Aware Trust in Vehicular Networks; exact scenario, density, seed and campaign. |
| 00:10–00:32 | Urban roundabout and RSUs | Recorded road geometry and positions; RSUs and 450 m range are configuration overlays. Coordinates use netOffset=(500,500). |
| 00:32–00:54 | Real attack event | At SUMO time 15.000 s, CAM cam-7003-veh_000-000014 carries position_offset. Trajectory: (195.114, 998.400) m; reported: (260.114, 1014.650) m. Ground truth is an offline comparison. |
| 00:54–01:24 | Evidence observations | Recorded observations at 15.0 and 17.0 s with source/root/cell labels. Two RSU rows sharing a root are one root. Final accepted-bundle membership is unavailable. |
| 01:24–01:50 | Final trust decision | Saved case record: qualified at 29.007453 s; committed revoked state at 29.068121 s; ledger available at 29.082916 s. No vote-level PBFT stages are fabricated. |
| 01:50–02:12 | Scientific takeaway | Evidence-aware qualification before a trust decision; this playback establishes neither full Byzantine tolerance nor coordinator recovery. |

## Synchronization and interpretation

Video elapsed time is editorial pacing, not simulation time; the on-screen trace clock shows the recorded simulation time. Decision-stage highlights are staged for explanation. Vehicle dots use the last saved mobility coordinate at or before the displayed time; positions are held between one-second samples without invented intermediate movement. The red marker uses the exact CAM-reported position; the green marker uses the recorded trajectory position cross-checked against mobility. This is an offline ground-truth overlay, not detector input.

The evidence panel reads evidence_campaign.csv for the selected case window. It reports logged observations only; the case record does not identify the exact complete bundle accepted by QE. Qualification, final state, finalization and ledger timestamps come from the matching baseline Distributed record. SUMO and V-PUFT algorithms are not running together during rendering.
