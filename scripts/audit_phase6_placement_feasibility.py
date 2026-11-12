"""Training-only coverage Pareto audit for two movable RSUs."""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

from select_phase5_rsu_placement import BASE, OUT, RSUS, RADIUS, road_candidates


def main() -> None:
    samples = []
    for density in (20, 60, 100):
        for seed in range(1001, 1007):
            path = BASE / f"traces/urban_roundabout/vehicles_{density}/seed_{seed}/mobility_trace.csv"
            frame = pd.read_csv(path, usecols=["simulation_time", "x", "y", "road_id"])
            frame = frame[frame.simulation_time.mod(5).eq(0)]
            frame = frame.iloc[np.linspace(0, len(frame)-1, min(1500, len(frame)), dtype=int)].copy()
            frame["density"] = density
            samples.append(frame)
    data = pd.concat(samples, ignore_index=True)
    xy = data[["x", "y"]].to_numpy() - 500
    points = road_candidates() + [(r["x"], r["y"]) for r in RSUS[4:]]
    candidate = np.array(points)
    fixed = np.array([(r["x"], r["y"]) for r in RSUS[:4]])
    f = np.linalg.norm(xy[:, None, :] - fixed[None, :, :], axis=2) <= RADIUS
    c = np.linalg.norm(xy[:, None, :] - candidate[None, :, :], axis=2) <= RADIUS
    fc = np.array([(int((x+500)//250), int((y+500)//250)) for x,y in fixed])
    cc = np.array([(int((x+500)//250), int((y+500)//250)) for x,y in candidate])
    categories = {d: np.flatnonzero(data.density.to_numpy()==d) for d in (20,60,100)}
    roads = {str(k): v.to_numpy() for k,v in data.groupby('road_id').groups.items() if len(v)>=50}

    def measures(i, j):
        masks = np.column_stack((f,c[:,i],c[:,j]))
        any_seen = masks.any(axis=1)
        cells = np.vstack((fc,cc[i],cc[j]))
        multi = np.zeros(len(data),dtype=bool)
        for a in range(6):
            for b in range(a+1,6):
                if not np.array_equal(cells[a],cells[b]):
                    multi |= masks[:,a]&masks[:,b]
        return any_seen,multi

    original = measures(len(points)-2,len(points)-1)
    base_coverage = {d:float(original[0][idx].mean()) for d,idx in categories.items()}
    base_road = {road:float(original[0][idx].mean()) for road,idx in roads.items()}
    rows=[]
    for i in range(len(points)):
        for j in range(i+1,len(points)):
            if np.linalg.norm(candidate[i]-candidate[j])<100:continue
            any_seen,multi=measures(i,j)
            coverage={d:float(any_seen[idx].mean()) for d,idx in categories.items()}
            road_min=min(float(any_seen[idx].mean())-base_road[road] for road,idx in roads.items())
            gate=all(coverage[d]>=base_coverage[d]-0.01 for d in categories) and road_min>=-0.05
            rows.append({'site_5_x':points[i][0],'site_5_y':points[i][1],
                         'site_6_x':points[j][0],'site_6_y':points[j][1],
                         'coverage_20':coverage[20],'coverage_60':coverage[60],'coverage_100':coverage[100],
                         'multi_cell_fraction':float(multi.mean()),'worst_road_coverage_delta':road_min,
                         'passes_coverage_gate':int(gate)})
    frame=pd.DataFrame(rows)
    frame.sort_values(['passes_coverage_gate','multi_cell_fraction'],ascending=False).to_csv(OUT/'phase6_training_placement_feasibility.csv',index=False)
    summary={'candidate_pairs':len(frame),'passing_pairs':int(frame.passes_coverage_gate.sum()),
             'baseline_coverage_by_density':base_coverage,'baseline_multi_cell_fraction':float(original[1].mean()),
             'best_passing_multi_cell_fraction':float(frame.loc[frame.passes_coverage_gate.eq(1),'multi_cell_fraction'].max()) if frame.passes_coverage_gate.any() else None,
             'road_segments_audited':len(roads)}
    (OUT/'phase6_training_feasibility_summary.json').write_text(json.dumps(summary,indent=2))
    print(json.dumps(summary,indent=2))


if __name__=='__main__':main()
