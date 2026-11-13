from __future__ import annotations
import argparse, cProfile, hashlib, json, pstats, statistics, time
from dataclasses import replace
from pathlib import Path
import pandas as pd
from vpuft.architectures import DistributedRSUExtendedVPUFT
from vpuft.config import load_config
from vpuft.crypto import KeyRegistry
from vpuft.trace import build_trace_bundle, read_events_jsonl
from run_phase2_ablation import decision_frame, metric_row
CELLS=((20,2101),(20,2102),(60,2101),(60,2102),(100,2101),(100,2102))
def not_frame_equal(left,right):
 try:
  pd.testing.assert_frame_equal(left,right,check_dtype=False,check_exact=False,rtol=0,atol=1e-10)
  return False
 except AssertionError:
  return True

def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''): h.update(b)
 return h.hexdigest()
def profile_rows(prof,layout,variant):
 out={}
 for (filename,_line,fn),(_prim,calls,self_s,cum_s,_callers) in pstats.Stats(prof).stats.items():
  f=filename.lower()
  if fn=='verify_attestation': stage='signature_verification'
  elif fn in {'sanitize_case','evidence_weight','aggregate_by_root','case_evidence_masses'}: stage='attestation_root_processing'
  elif fn=='qualify': stage='qualification'
  elif 'network.py' in f and fn in {'send','send_async'}: stage='transport_send_processing'
  elif 'consensus.py' in f: stage='pbft_processing'
  elif 'distributed_extension.py' in f: stage='coordinator_forwarding_callbacks'
  elif 'scheduler.py' in f: stage='event_scheduler'
  else: continue
  x=out.setdefault(stage,{'calls':0,'exclusive_cpu_s':0.0,'cumulative_cpu_s':0.0})
  x['calls']+=calls; x['exclusive_cpu_s']+=self_s; x['cumulative_cpu_s']+=cum_s
 return [{'layout':layout,'variant':variant,'density':100,'seed':2101,'stage':k,**v} for k,v in sorted(out.items())]
def main():
 p=argparse.ArgumentParser(); p.add_argument('--config',type=Path,required=True); p.add_argument('--trace-root',type=Path,required=True); p.add_argument('--output',type=Path,required=True); p.add_argument('--repeats',type=int,default=3); p.add_argument('--cell',action='append',default=[]); p.add_argument('--layouts',default='C1,C3'); p.add_argument('--variants',default='B0,B1'); p.add_argument('--opportunity-eval',action='store_true'); p.add_argument('--save-decisions',action='store_true'); a=p.parse_args()
 if a.repeats<1: raise ValueError('at least one repeat run required')
 cells=CELLS if not a.cell else tuple(tuple(map(int,x.split(':'))) for x in a.cell)
 layouts=tuple(x.strip() for x in a.layouts.split(','))
 if not layouts or any(x not in ('C1','C3') for x in layouts): raise ValueError('layouts must be C1 and/or C3')
 variants=tuple(x.strip() for x in a.variants.split(','))
 if not variants or any(x not in ('B0','B1') for x in variants): raise ValueError('variants must be B0 and/or B1')
 base=load_config(a.config); rows=[]; pairs=[]; profs=[]; opportunity_rows=[]; opportunity_pairs=[]; decision_records=[]
 for density,seed in cells:
  cases_by={}; paths={}; events_by={}; frames={}; opportunity_by={}; fp_rows=[]
  for layout in layouts:
   trace=a.trace_root/'pilot'/layout/f'vehicles_{density}'/f'seed_{seed}'/'shared_detection_trace.jsonl'
   if not (trace.parent/'run_summary.json').is_file():
    choices=sorted(p for p in trace.parent.parent.glob(f'seed_{seed}_retry*') if (p/'run_summary.json').is_file())
    if len(choices)!=1: raise FileNotFoundError(f'expected one completed immutable trace for {layout}/{density}/{seed}: {choices}')
    trace=choices[0]/'shared_detection_trace.jsonl'
   events=read_events_jsonl(trace); events_by[layout]=events
   bundle=build_trace_bundle(events,KeyRegistry(base.security.deterministic_master_seed),window_seconds=base.detector.case_window_seconds,namespace=f'urban_roundabout-vehicles-{density}')
   cases_by[layout]=bundle.rsu_cases; paths[layout]=trace
  for layout in layouts:
   if layout=='C1': cfg0=replace(base,simulation=replace(base.simulation,rsu_count=6)); sensing=()
   else:
    ext=replace(base.distributed_extension,sensing_only_rsu_ids=('rsu-7','rsu-8')); cfg0=replace(base,simulation=replace(base.simulation,rsu_count=8),distributed_extension=ext); sensing=('rsu-7','rsu-8')
   for variant in variants:
    diverse=variant=='B1'
    ext=replace(cfg0.distributed_extension,coordinator_strategy='first_observer_then_hash',cache_verified_evidence_bundle=False,diversity_aware_root_assignment=diverse,provenance_safe_observer_diversity=False,sensing_only_rsu_ids=sensing)
    cfg=replace(cfg0,distributed_extension=ext); cases=cases_by[layout]; cpuvals=[]; first=None; result=None; frame=None
    for rep in range(a.repeats):
     t=time.process_time(); result=DistributedRSUExtendedVPUFT(cfg,KeyRegistry(cfg.security.deterministic_master_seed)).run(cases,seed); cpu=time.process_time()-t
     frame=decision_frame(result,cases,density=density,seed=seed,variant=f'{layout}_{variant}'); cpuvals.append(cpu)
     current=frame[['case_id','new_state','committed','qualified_at','finalized_at']].sort_values('case_id').reset_index(drop=True)
     if first is None: first=current
     elif not_frame_equal(current,first): raise AssertionError(f'repeat decisions differ: {layout}/{variant}/{density}/{seed}')
    m=metric_row(result,cases,frame,density=density,seed=seed,variant=f'{layout}_{variant}',cpu=statistics.median(cpuvals),wall=float('nan'),peak=float('nan'),acquisition={})
    metas=[json.loads(x) for x in frame.metadata_json]
    malicious=[meta for meta,truth in zip(metas,frame.ground_truth_malicious) if int(truth)==1]
    m.update(replay_repeats=a.repeats,cpu_mean_s=statistics.mean(cpuvals),cpu_median_s=statistics.median(cpuvals),cpu_min_s=min(cpuvals),cpu_max_s=max(cpuvals),cpu_stdev_s=statistics.stdev(cpuvals) if len(cpuvals)>1 else 0.0,case_count=len(cases),trace_sha256=sha(paths[layout]),malicious_cases_ge2_roots=sum(int(x.get('independent_roots',0)>=2) for x in malicious),malicious_cases_ge2_sources=sum(int(x.get('distinct_sources',0)>=2) for x in malicious),malicious_cases_ge2_zones=sum(int(x.get('distinct_zones',0)>=2) for x in malicious),mean_supporting_strength=sum(float(x.get('supporting_strength',0)) for x in malicious)/max(1,len(malicious)),mean_opposing_strength=sum(float(x.get('opposing_strength',0)) for x in malicious)/max(1,len(malicious))); rows.append(m); frames[(layout,variant)]=frame
    if a.save_decisions: decision_records.append(frame)
    if a.opportunity_eval:
     from vpuft.opportunity_evaluation import opportunity_frame
     messages=pd.read_csv(paths[layout].parent/'generated_messages.csv')
     observed={str(e.message_id) for e in events_by[layout] if e.source_kind.value=='rsu'}
     opp=opportunity_frame(messages,frame,observed,window_seconds=15.0)
     opportunity_by[layout]=opp
     total=len(opp); detected=int(opp.detected_opportunity.sum()); terminal=int(opp.terminal_after_revocation.sum())
     opportunity_rows.append({'layout':layout,'variant':variant,'density':density,'seed':seed,'attack_opportunities':total,'observed_opportunities':int(opp.observed_opportunity.sum()),'unobserved_opportunities':int((~opp.observed_opportunity).sum()),'detected_opportunities':detected,'opportunity_detection_recall':detected/total if total else 0.0,'terminal_opportunities':terminal,'protected_opportunities':detected+terminal,'protected_opportunity_fraction':(detected+terminal)/total if total else 0.0})
    if variant=='B0':
     oldp=paths[layout].parent/f'{layout}_B0_decisions.csv'
     if oldp.is_file():
      old=pd.read_csv(oldp)[['case_id','new_state','committed','qualified_at','finalized_at']].sort_values('case_id').reset_index(drop=True)
      if not_frame_equal(old,first): raise AssertionError(f'historical B0 mismatch {density}/{seed}')
    if density==100 and seed==2101:
     prof=cProfile.Profile(); prof.enable(); DistributedRSUExtendedVPUFT(cfg,KeyRegistry(cfg.security.deterministic_master_seed)).run(cases,seed); prof.disable(); profs.extend(profile_rows(prof,layout,variant))
    print(f'{layout}/{variant} d={density} seed={seed} cases={len(cases)} CPU median={statistics.median(cpuvals):.6f}',flush=True)
  for layout in layouts:
   if (layout,'B1') in frames:
    oldframe=frames.get((layout,'B0'))
    if oldframe is None:
     reference=paths[layout].parent/f'{layout}_B0_decisions.csv'
     if reference.is_file(): oldframe=pd.read_csv(reference)
    if oldframe is None: continue
    oldfp=set(oldframe.loc[(oldframe.ground_truth_malicious==0)&(oldframe.predicted_revoked==1),'case_id'])
    for item in frames[(layout,'B1')].loc[(frames[(layout,'B1')].ground_truth_malicious==0)&(frames[(layout,'B1')].predicted_revoked==1)].itertuples(index=False):
     if item.case_id not in oldfp: fp_rows.append({'layout':layout,'density':density,'seed':seed,'case_id':item.case_id,'vehicle_id':item.vehicle_id})
  if set(layouts)=={'C1','C3'}:
   for variant in variants:
    l=next(x for x in rows if x['variant']==f'C1_{variant}' and x['density']==density and x['seed']==seed); r=next(x for x in rows if x['variant']==f'C3_{variant}' and x['density']==density and x['seed']==seed)
    pairs.append({'density':density,'seed':seed,'variant':variant,'C1_trace_sha256':l['trace_sha256'],'C3_trace_sha256':r['trace_sha256'],'C1_cases':l['case_count'],'C3_cases':r['case_count'],'C1_TP':l['TP'],'C3_TP':r['TP'],'C1_FP':l['FP'],'C3_FP':r['FP'],'C1_FN':l['FN'],'C3_FN':r['FN'],'C1_recall':l['recall'],'C3_recall':r['recall'],'C1_cpu_median_s':l['cpu_median_s'],'C3_cpu_median_s':r['cpu_median_s'],'C1_p95_e2e_ms':l['p95_e2e_ms'],'C3_p95_e2e_ms':r['p95_e2e_ms'],'C1_messages_case':l['messages_per_case'],'C3_messages_case':r['messages_per_case']})
    if a.opportunity_eval and variant in variants and 'C1' in opportunity_by and 'C3' in opportunity_by:
     oa=opportunity_by['C1']; ob=opportunity_by['C3']; j=oa[['opportunity_id','detected_opportunity','terminal_after_revocation']].merge(ob[['opportunity_id','detected_opportunity','terminal_after_revocation']],on='opportunity_id',suffixes=('_C1','_C3'),validate='one_to_one')
     opportunity_pairs.append({'density':density,'seed':seed,'variant':variant,'common_opportunities':len(j),'C1_detected':int(j.detected_opportunity_C1.sum()),'C3_detected':int(j.detected_opportunity_C3.sum()),'C1_protected':int((j.detected_opportunity_C1|j.terminal_after_revocation_C1).sum()),'C3_protected':int((j.detected_opportunity_C3|j.terminal_after_revocation_C3).sum()),'C1_to_C3_newly_detected':int((~j.detected_opportunity_C1 & j.detected_opportunity_C3).sum()),'C3_to_C1_lost_detection':int((j.detected_opportunity_C1 & ~j.detected_opportunity_C3).sum())})
 a.output.mkdir(parents=True,exist_ok=True); pd.DataFrame(rows).to_csv(a.output/'offline_b0_b1_metrics.csv',index=False); pd.DataFrame(pairs).to_csv(a.output/'offline_b0_b1_paired.csv',index=False); pd.DataFrame(profs).to_csv(a.output/'cprofile_stage_attribution.csv',index=False); pd.DataFrame(fp_rows,columns=['layout','density','seed','case_id','vehicle_id']).to_csv(a.output/'new_false_positive_cases.csv',index=False); pd.DataFrame(opportunity_rows).to_csv(a.output/'opportunity_metrics.csv',index=False); pd.DataFrame(opportunity_pairs).to_csv(a.output/'opportunity_paired.csv',index=False)
 if a.save_decisions: pd.concat(decision_records,ignore_index=True).to_csv(a.output/'case_decisions.csv.gz',index=False,compression='gzip')
 print(f'wrote {a.output}',flush=True)
if __name__=='__main__': main()
