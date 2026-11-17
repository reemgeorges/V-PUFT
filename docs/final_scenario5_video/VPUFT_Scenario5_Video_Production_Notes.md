# V-PUFT Scenario 5 Video Production Notes

## Output
- MP4: C:\Users\reemg\OneDrive\Desktop\master\6\v10-final-scenario5\results\final_scenario5_video\VPUFT_Scenario5_Defense_Demo.mp4
- Resolution/frame rate: 1920×1080 at 24 fps
- Duration: 132 seconds (2:12)
- Encoding: H.264 / libx264, yuv420p; no audio
- Visualization: trace-based, not native SUMO-GUI capture
- Playback pacing: editorial; on-screen trace clock is simulation time
- Video SHA-256: ec44e59352c3dff4e274a3432723406704df738a8da10d0c6d5673909eba22d8

## Reproduction
Run from the final research worktree with Pillow, NumPy and imageio-ffmpeg installed:

~~~powershell
& C:\Users\reemg\OneDrive\Desktop\master\6\v10\.venv\Scripts\python.exe scripts\render_final_scenario5_defense_video.py
~~~

The renderer validates the trace hash, ground-truth event, CAM-to-mobility coordinate match, saved committed case decision, production-baseline marker and effective-configuration hash. It can accept source-path overrides if the preserved local trace moves. It does not start SUMO, regenerate traces or rerun V-PUFT.

## Visual conventions
- Gray dots: other vehicles at their latest recorded position at or before the shown time.
- Gold dot: veh_000 at its recorded trajectory position.
- Blue squares show configured RSU coordinates; the solid arc highlights the configured 450 m RSU-5 range after network-offset translation. They are overlays, not native SUMO entities or proof of detection.
- Green ring: recorded trajectory; red cross: CAM-reported position. Their comparison uses offline ground truth.
- Evidence rows are direct source/root/cell observations. Their membership in the final QE bundle is unavailable.
- Qualification, final state, commit and ledger-availability times come from the saved baseline case record. Vote-level consensus stages are not shown because those records are unavailable.

## Source and limits
This is a sensitivity-replication/ablation trace, separate from frozen corrected-final Dataset B. The decision is labeled reused_saved_baseline; the run manifest says the production engine ran with no ablation adapter. This video synchronizes stored outputs; it is not a live end-to-end execution. It does not establish full Byzantine fault tolerance, safe coordinator recovery or complete evidence-bundle knowledge.
