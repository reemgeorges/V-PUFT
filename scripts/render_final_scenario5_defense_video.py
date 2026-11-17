#!/usr/bin/env python
"""Trace-based defense video renderer; does not run SUMO or V-PUFT algorithms."""
import argparse,csv,hashlib,json,math,pathlib
from collections import defaultdict
from datetime import datetime,timezone
import xml.etree.ElementTree as ET
import imageio_ffmpeg
import numpy as np
from PIL import Image,ImageDraw,ImageFont

W,H,FPS,DURATION=1920,1080,24,132.0
DENSITY,SEED,VEHICLE=20,7003,"veh_000"
CASE_ID="case-urban_roundabout-7003-veh_000-w0001"
TRACE_SHA="cb43f7bbb9d3594a6d006ce5525c86f293ea6c2d0d5b7ba8409181a8d9547bc7"
EXECUTION_COMMIT="19fafe5ae71dc570c0809dabbdfc7483863d9cc7"
VIDEO_NAME="VPUFT_Scenario5_Defense_Demo.mp4"
REPO=pathlib.Path(r"C:\Users\reemg\OneDrive\Desktop\master\6\v10-final-scenario5")
TRACE=pathlib.Path(r"C:\Users\reemg\AppData\Local\VPUFT-Preservation-2026-11-15\sensitivity_replication_2026-11-16\shared_inputs\traces\density_20\seed_7003_attempt01")
SCENARIO=pathlib.Path(r"C:\Users\reemg\AppData\Local\VPUFT-Preservation-2026-11-15\sensitivity_replication_2026-11-16\shared_inputs\generated_scenarios\vehicles_20_attempt01")
C={"bg":"#07111f","panel":"#101d2d","panel2":"#142438","text":"#f4f7fb","muted":"#a9b8c8","accent":"#67d5ff","gold":"#ffd166","green":"#70e1a1","red":"#ff6b6b","road":"#526174","vehicle":"#8ca0b8","blue":"#4ea5ff"}
MAP=(64,164,986,1024);SIDE=(1012,164,1854,1024);WORLD=(-35,1035,-35,1035)
def sha(p):
 h=hashlib.sha256()
 with pathlib.Path(p).open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""):h.update(b)
 return h.hexdigest()
def rows(p):
 with pathlib.Path(p).open(newline="",encoding="utf-8-sig") as f:return list(csv.DictReader(f))
def exactly(items,label):
 items=list(items)
 if len(items)!=1:raise ValueError(f"Expected one {label}, found {len(items)}")
 return items[0]
def ft(n,b=False):
 for p in ([r"C:\Windows\Fonts\segoeuib.ttf",r"C:\Windows\Fonts\arialbd.ttf"] if b else [r"C:\Windows\Fonts\segoeui.ttf",r"C:\Windows\Fonts\arial.ttf"]):
  try:return ImageFont.truetype(p,n)
  except OSError:pass
 return ImageFont.load_default()
F={n:ft(n,n>=28) for n in (16,18,20,21,22,24,27,30,34,38,44,52,60)}
def wrap(d,s,f,w):
 lines=[];line=""
 for word in s.split():
  trial=word if not line else line+" "+word
  if d.textbbox((0,0),trial,font=f)[2]<=w or not line:line=trial
  else:lines.append(line);line=word
 if line:lines.append(line)
 return lines
def para(d,x,y,s,f,color,w,gap=7):
 for line in wrap(d,s,f,w):d.text((x,y),line,font=f,fill=color);y+=f.size+gap
 return y
def card(d,box,fill=None,outline=None,r=16,width=1):d.rounded_rectangle(box,radius=r,fill=fill or C["panel"],outline=outline,width=width)
def xy(p,box=MAP):
 x,y=p;x0,x1,y0,y1=WORLD;l,t,r,b=box;scale=min((r-l)/(x1-x0),(b-t)/(y1-y0))
 ox=l+((r-l)-scale*(x1-x0))/2;oy=t+((b-t)-scale*(y1-y0))/2
 return int(round(ox+(x-x0)*scale)),int(round(oy+(y1-y)*scale)),scale
def makebase(scenario,rsu_path):
 im=Image.new("RGB",(W,H),C["bg"]);d=ImageDraw.Draw(im);d.rectangle((0,0,W,130),fill="#0b1727")
 d.text((70,28),"V-PUFT",font=F[52],fill=C["accent"])
 d.text((280,43),"TRACE-BASED VISUALIZATION  |  NOT NATIVE SUMO-GUI CAPTURE",font=F[24],fill=C["muted"])
 d.text((70,1040),"Recorded SUMO/TraCI motion + saved case records | QE/PBFT were not executed inside SUMO",font=F[18],fill=C["muted"])
 card(d,MAP,"#0c1725","#26394c",24,2);card(d,SIDE,C["panel"],"#26394c",24,2)
 root=ET.parse(scenario/"urban_roundabout.net.xml").getroot();offset=list(map(float,root.find("location").get("netOffset","0,0").split(",")))
 paths=[]
 for edge in root.findall("edge"):
  for lane in edge.findall("lane"):
   pts=[xy(tuple(map(float,z.split(","))))[:2] for z in lane.get("shape","").split()]
   if len(pts)>1:paths.append(pts)
 q=ImageDraw.Draw(im)
 for pts in paths:q.line(pts,fill=C["road"],width=11,joint="curve");q.line(pts,fill="#738399",width=2,joint="curve")
 rsus=json.loads(rsu_path.read_text(encoding="utf-8-sig"));placements=[];q=ImageDraw.Draw(im)
 for r in rsus:
  px,py,scale=xy((float(r["x"])+offset[0],float(r["y"])+offset[1]));radius=450*scale
  if r["id"]=="rsu-5":
   for a in range(0,360,2):
    b=a+2;p1=(px+int(radius*math.cos(math.radians(a))),py-int(radius*math.sin(math.radians(a))))
    p2=(px+int(radius*math.cos(math.radians(b))),py-int(radius*math.sin(math.radians(b))))
    inside=lambda z: MAP[0]<=z[0]<=MAP[2] and MAP[1]<=z[1]<=MAP[3]
    if inside(p1) and inside(p2):q.line((p1,p2),fill="#285276",width=2)
  q.rounded_rectangle((px-10,py-10,px+10,py+10),radius=4,fill=C["blue"],outline="#e5f4ff",width=2)
  q.text((px+12,py-25),r["id"].replace("rsu-","R"),font=F[16],fill="#cceaff",stroke_width=2,stroke_fill=C["bg"])
  placements.append({"id":r["id"],"config_xy":[r["x"],r["y"]],"network_xy":[float(r["x"])+offset[0],float(r["y"])+offset[1]],"domain":r.get("domain")})
 return im,paths,placements,offset
def mobindex(mob):
 d=defaultdict(list)
 for r in mob:d[r["vehicle_id"]].append(r)
 for v in d.values():v.sort(key=lambda x:float(x["simulation_time"])
 )
 return d
def positions(idx,t):
 out=[]
 for vid,rs in idx.items():
  found=None
  for r in rs:
   if float(r["simulation_time"])<=t+1e-8:found=r
   else:break
  if found:out.append(found)
 return out
def section(t):return "title" if t<10 else "infrastructure" if t<32 else "attack" if t<54 else "evidence" if t<84 else "decision" if t<110 else "takeaway"
def simtime(t):
 if 10<=t<32:return max(0,min(15,(t-10)/22*15))
 if 32<=t<54:return 15.
 if 54<=t<84:return 15+(t-54)/30*14
 return 29.
def kv(d,x,y,items):
 for a,b in items:d.text((x,y),a,font=F[16],fill=C["muted"]);y+=24;d.text((x,y),b,font=F[22],fill=C["text"]);y+=42
 return y
def panel(d,s,t):
 x0,y0,x1,_=SIDE;x=x0+34;w=x1-x0-68
 title={"title":"V-PUFT: Evidence-Aware Trust in Vehicular Networks","infrastructure":"Urban roundabout and roadside units","attack":"Recorded malicious CAM event","evidence":"Evidence observations and provenance","decision":"Recorded trust decision","takeaway":"Scientific takeaway"}[s]
 d.text((x,y0+26),title,font=F[34],fill=C["text"]);y=y0+86
 if s=="title":
  y=para(d,x,y+12,"Scenario 5 — Urban Roundabout",F[30],C["accent"],w)+18
  for line in ["Density: 20 vehicles","Seed: 7003","Saved SUMO/TraCI sensitivity-replication trace","Used by ablation baseline; not frozen Dataset B."]:
   y=para(d,x,y,line,F[22],C["gold"] if "not frozen" in line else C["text"],w)+8
  card(d,(x,y,x+w,y+140),C["panel2"])
  para(d,x+18,y+18,"This video replays recorded vehicle coordinates and a saved case-level decision. It does not rerun SUMO or execute V-PUFT qualification inside SUMO.",F[20],C["muted"],w-36)
 elif s=="infrastructure":
  y=kv(d,x,y,[("DENSITY / SEED","20 vehicles  |  7003"),("CONFIGURED SENSOR RANGE","450 m"),("NETWORK COORDINATE OFFSET","(+500, +500) m")])+10
  y=para(d,x,y,"Blue squares are RSU configuration overlays, not native SUMO entities. The solid arc highlights RSU-5 at its configured 450 m range to keep overlapping coverage readable.",F[20],C["muted"],w)+14
  para(d,x,y,"RSU-5 in the converted network frame: (125, 1000) m. At t=15.0 s the recorded vehicle is about 70.1 m away.",F[20],C["text"],w)
 elif s=="attack":
  y=kv(d,x,y,[("ATTACK","position_offset"),("VEHICLE","veh_000"),("SUMO TIME","15.000 s"),("MESSAGE","cam-7003-veh_000-000014"),("GROUND TRUTH","Malicious (offline trace record)")])+8
  card(d,(x,y,x+w,y+242),C["panel2"])
  para(d,x+18,y+16,"Recorded position comparison at one timestamp",F[22],C["text"],w-36)
  para(d,x+18,y+62,"Trajectory: (195.114, 998.400) m",F[20],C["green"],w-36)
  para(d,x+18,y+105,"CAM reported: (260.114, 1014.650) m",F[20],C["red"],w-36)
  para(d,x+18,y+156,"Offline ground-truth comparison; not a runtime detector input.",F[18],C["muted"],w-36,6)
 elif s=="evidence":
  y=para(d,x,y,"Map markers: green is the recorded trajectory; red is the CAM-reported point. This is an offline comparison at t=15.0 s.",F[18],C["muted"],w)+8
  y=para(d,x,y,"Saved evidence_campaign.csv observations for the selected case window:",F[20],C["muted"],w)+8
  for label,root,cell,tm in [("RSU-5","root-334b4f…","cell-0-4","t=15.0"),("veh_004 witness","wroot-f16a36…","cell-0-3","t=15.0"),("veh_012 witness","wroot-df87d5…","cell-0-3","t=15.0")]:
   card(d,(x,y,x+w,y+62),C["panel2"]);d.text((x+12,y+7),label,font=F[18],fill=C["text"]);d.text((x+228,y+7),root,font=F[16],fill=C["accent"])
   d.text((x+12,y+34),cell+"  |  observed "+tm,font=F[16],fill=C["muted"]);y+=70
  card(d,(x,y+4,x+w,y+100),"#28243a","#705da0",12)
  para(d,x+14,y+16,"At t=17.0, RSU-1 and RSU-5 share one observation_root_id. Two reports, one root.",F[18],C["text"],w-28,5);y+=112
  para(d,x,y,"Case-window trace summary: 58 rows, 45 root IDs, 4 source IDs, 4 geographic cells. These are observations; final accepted bundle membership is not logged here.",F[18],C["gold"],w,6)
 elif s=="decision":
  para(d,x,y,"Case: "+CASE_ID,F[18],C["muted"],w);y+=30
  for gate,label,stamp,detail in [(84,"QUALIFICATION LOGGED","29.007453 s","Evidence qualified"),(90,"FINAL DECISION","29.068121 s","REVOKED  |  committed=1"),(96,"LEDGER AVAILABILITY","29.082916 s","Ledger available")]:
   active=t>=gate;color=C["green"] if active else "#66788c"
   card(d,(x,y,x+w,y+119),C["panel2"] if active else "#0d1826",color,14,2)
   d.ellipse((x+18,y+24,x+48,y+54),fill=color);d.text((x+65,y+13),label,font=F[18],fill=C["muted"] if active else "#6e7d8e")
   d.text((x+65,y+39),stamp,font=F[30],fill=C["text"] if active else "#718095")
   d.text((x+65,y+80),detail,font=F[20],fill=C["green"] if active else "#77879a");y+=134
  if t>=102:para(d,x,y+2,"The saved record contains the outcome and ledger time. Vote-level PRE-PREPARE / PREPARE / COMMIT records are unavailable and not depicted.",F[18],C["gold"],w,6)
 else:
  y=para(d,x,y+8,"V-PUFT assesses evidence provenance, quality and diversity before a trust decision is committed.",F[27],C["accent"],w,10)+22
  for msg,color in [("Shown: recorded SUMO movement, a malicious message, saved observations and a saved committed decision.",C["text"]),("Not shown: full Byzantine fault tolerance, safe coordinator recovery, or algorithm execution inside SUMO.",C["gold"])]:
   card(d,(x,y,x+w,y+160),C["panel2"]);para(d,x+18,y+18,msg,F[21],color,w-36,8);y+=178
def render(base,idx,msg,t):
 im=base.copy();d=ImageDraw.Draw(im);s=section(t);clock=simtime(t)
 d.text((72,135),s.upper(),font=F[18],fill=C["gold"])
 if s in ("infrastructure","attack","evidence","decision"):d.text((770,135),f"RECORDED TRACE TIME  {clock:05.1f} s",font=F[18],fill=C["muted"])
 for r in positions(idx,clock):
  px,py,_=xy((float(r["x"]),float(r["y"])))
  if r["vehicle_id"]==VEHICLE:
   d.ellipse((px-12,py-12,px+12,py+12),fill=C["gold"],outline="#ffffff",width=3)
   if s not in ("attack","evidence"):d.text((px+14,py-28),VEHICLE,font=F[18],fill=C["gold"],stroke_width=2,stroke_fill=C["bg"])
  else:d.ellipse((px-4,py-4,px+4,py+4),fill=C["vehicle"])
 if s=="attack" or (s=="evidence" and t<=54.5):
  ax,ay,_=xy((float(msg["true_x"]),float(msg["true_y"])));rx,ry,_=xy((float(msg["reported_x"]),float(msg["reported_y"])))
  d.line((ax,ay,rx,ry),fill=C["red"],width=4);d.ellipse((ax-13,ay-13,ax+13,ay+13),outline=C["green"],width=5)
  d.line((rx-12,ry-12,rx+12,ry+12),fill=C["red"],width=5);d.line((rx-12,ry+12,rx+12,ry-12),fill=C["red"],width=5)
 panel(d,s,t);d.text((1028,1004),"SOURCE: sensitivity-replication trace | seed 7003 | NOT Dataset B",font=F[16],fill=C["gold"])
 d.text((1715,1040),f"{int(t//60):02d}:{int(t%60):02d}",font=F[18],fill=C["muted"]);return im
def writecsv(p,rs):
 with p.open("w",newline="",encoding="utf-8-sig") as f:w=csv.DictWriter(f,fieldnames=list(rs[0]));w.writeheader();w.writerows(rs)
def main():
 p=argparse.ArgumentParser();p.add_argument("--repo",type=pathlib.Path,default=REPO);p.add_argument("--trace-dir",type=pathlib.Path,default=TRACE)
 p.add_argument("--scenario-dir",type=pathlib.Path,default=SCENARIO);p.add_argument("--decision-csv",type=pathlib.Path,default=REPO/"results/final_scenario5_ablation/ABLATION_CASE_DECISIONS.csv")
 p.add_argument("--run-manifest",type=pathlib.Path,default=REPO/"results/final_scenario5_ablation/ABLATION_RUN_MANIFEST.csv")
 p.add_argument("--effective-configs",type=pathlib.Path,default=REPO/"results/final_scenario5_ablation/ABLATION_EFFECTIVE_CONFIGS.json")
 p.add_argument("--rsus-json",type=pathlib.Path,default=REPO/"sumo/urban_roundabout/rsus.json")
 p.add_argument("--output-dir",type=pathlib.Path,default=REPO/"results/final_scenario5_video");p.add_argument("--docs-dir",type=pathlib.Path,default=REPO/"docs/final_scenario5_video")
 p.add_argument("--previews-only",action="store_true");a=p.parse_args();tr=a.trace_dir;sc=a.scenario_dir;out=a.output_dir;docs=a.docs_dir;out.mkdir(parents=True,exist_ok=True);docs.mkdir(parents=True,exist_ok=True)
 mob=rows(tr/"mobility_trace.csv");msgs=rows(tr/"generated_messages.csv");truth=rows(tr/"attack_ground_truth.csv");all_ev=rows(tr/"evidence_campaign.csv")
 dec=rows(a.decision_csv);runrows=rows(a.run_manifest)
 msg=exactly((r for r in msgs if r["message_id"]=="cam-7003-veh_000-000014"),"attack message")
 gt=exactly((r for r in truth if r["vehicle_id"]==VEHICLE and r["attack_type"]=="position_offset"),"ground truth")
 case=exactly((r for r in dec if r["variant_id"]=="baseline" and r["architecture"]=="Distributed" and r["density"]=="20" and r["seed"]=="7003" and r["case_id"]==CASE_ID),"baseline decision")
 run=exactly((r for r in runrows if r["variant_id"]=="baseline" and r["architecture"]=="Distributed" and r["density"]=="20" and r["seed"]=="7003"),"baseline run")
 evid=[r for r in all_ev if r["case_id"]==CASE_ID];m15=exactly((r for r in mob if r["vehicle_id"]==VEHICLE and float(r["simulation_time"])==15),"mobility at t15")
 sm=json.loads((tr/"scenario_manifest.json").read_text(encoding="utf-8"));tracehash=sha(tr/"shared_detection_trace.jsonl")
 if sm.get("mode")!="sumo_traci" or sm.get("seed")!=SEED or tracehash!=TRACE_SHA or run["trace_sha256"]!=TRACE_SHA or case["trace_sha256"]!=TRACE_SHA:raise ValueError("Trace provenance mismatch.")
 if msg["attack_type"]!="position_offset" or msg["ground_truth_malicious"].lower()!="true" or gt["ground_truth_malicious"]!="1":raise ValueError("Attack unsupported by records.")
 if abs(float(msg["generated_at"])-15)>1e-9 or not(float(gt["first_message_at"])<=15<=float(gt["last_message_at"])):raise ValueError("Attack outside ground-truth interval.")
 if abs(float(msg["true_x"])-float(m15["x"]))>1e-7 or abs(float(msg["true_y"])-float(m15["y"]))>1e-7:raise ValueError("CAM true position != mobility record.")
 if case["committed"]!="1" or case["predicted_revoked"]!="1" or case["new_state"]!="revoked" or case["reason"]!="committed":raise ValueError("No committed revocation in case record.")
 if run["execution_kind"]!="reused_saved_baseline" or case["execution_kind"]!="reused_saved_baseline" or run["execution_commit"]!=EXECUTION_COMMIT or run["adapter_script_sha256"]!="production_engine_no_adapter":raise ValueError("Unexpected baseline provenance.")
 if (len(evid),len({r["observation_root_id"] for r in evid}),len({r["source_id"] for r in evid}),len({r["geographic_cell"] for r in evid}))!=(58,45,4,4):raise ValueError("Evidence summary mismatch.")
 cfg=json.loads(a.effective_configs.read_text(encoding="utf-8"))["baseline"]["Distributed"]
 if not cfg["production_configuration_unchanged"] or cfg["adapter_mode"]!="baseline" or cfg["effective_config_sha256"]!=run["effective_config_sha256"] or float(cfg["effective_config"]["detector"]["rsu_range_m"])!=450:raise ValueError("Baseline config mismatch.")
 source={"scenario_manifest.json":tr/"scenario_manifest.json","mobility_trace.csv":tr/"mobility_trace.csv","generated_messages.csv":tr/"generated_messages.csv","attack_ground_truth.csv":tr/"attack_ground_truth.csv","evidence_campaign.csv":tr/"evidence_campaign.csv","shared_detection_trace.jsonl":tr/"shared_detection_trace.jsonl","local_detections.csv":tr/"local_detections.csv","sumo_tripinfo.xml":tr/"sumo_tripinfo.xml","urban_roundabout.net.xml":sc/"urban_roundabout.net.xml","urban_roundabout.rou.xml":sc/"urban_roundabout.rou.xml","urban_roundabout.sumocfg":sc/"urban_roundabout.sumocfg","rsus.json":a.rsus_json,"ABLATION_CASE_DECISIONS.csv":a.decision_csv,"ABLATION_RUN_MANIFEST.csv":a.run_manifest,"ABLATION_EFFECTIVE_CONFIGS.json":a.effective_configs}
 hs={k:sha(v) for k,v in source.items()}
 for k in ("urban_roundabout.net.xml","urban_roundabout.rou.xml","urban_roundabout.sumocfg","rsus.json"):
  if hs[k]!=sm["scenario_files"][k]:raise ValueError("Scenario input hash mismatch: "+k)
 base,paths,places,off=makebase(sc,a.rsus_json);idx=mobindex(mob)
 previews=[("preview_01_infrastructure.png",18.0),("preview_02_attack_evidence.png",54.0),("preview_03_committed_decision.png",100.0)];previewinfo=[]
 for name,t in previews:
  q=out/name;render(base,idx,msg,t).save(q,format="PNG",optimize=True);previewinfo.append({"file":str(q),"video_time_seconds":t,"sha256":sha(q)})
 video=None
 if a.previews_only and (out/VIDEO_NAME).is_file():
  existing=out/VIDEO_NAME
  video={"file":str(existing),"sha256":sha(existing),"bytes":existing.stat().st_size,"duration_seconds":DURATION,"width":W,"height":H,"fps":FPS,"codec":"H.264 / libx264","pixel_format":"yuv420p","audio":"none"}
 if not a.previews_only:
  q=out/VIDEO_NAME;writer=imageio_ffmpeg.write_frames(str(q),(W,H),pix_fmt_in="rgb24",pix_fmt_out="yuv420p",fps=FPS,codec="libx264",macro_block_size=1,output_params=["-crf","19","-preset","medium","-movflags","+faststart"],ffmpeg_log_level="error")
  writer.send(None)
  try:
   for n in range(int(DURATION*FPS)):
    t=n/FPS;writer.send(np.ascontiguousarray(np.asarray(render(base,idx,msg,t),dtype=np.uint8)))
    if n and n%(FPS*15)==0:print(f"Encoded {n}/{int(DURATION*FPS)} frames at {t:.1f}s",flush=True)
  finally:writer.close()
  video={"file":str(q),"sha256":sha(q),"bytes":q.stat().st_size,"duration_seconds":DURATION,"width":W,"height":H,"fps":FPS,"codec":"H.264 / libx264","pixel_format":"yuv420p","audio":"none"}
 # Build evidence-to-scene rows.
 maprows=[]
 def add(scene,label,st,vt,ref,decision,hsvalue,vtime,basis,lim):
  maprows.append({"scene_number":scene,"scene_label":label,"dataset_trace_path":str(tr),"density_vehicles":DENSITY,"seed":SEED,"vehicle_id":VEHICLE,"case_id":CASE_ID,"attack_type":"position_offset","sumo_simulation_timestamp_seconds":st,"vpuft_log_timestamp_seconds":vt,"evidence_or_event_reference":ref,"final_decision":decision,"source_file_sha256":hsvalue,"video_timestamp_mmss":vtime,"overlay_basis":basis,"limitations":lim})
 add(1,"Title / trace identity","","","scenario_manifest.json; mode=sumo_traci","",hs["scenario_manifest.json"],"00:00","direct source metadata","Sensitivity-replication trace reused by ablation baseline; not Dataset B.")
 add(2,"SUMO road network geometry","15.000","","urban_roundabout.net.xml; netOffset +500,+500","",hs["urban_roundabout.net.xml"],"00:10","direct network geometry","Coordinates use the network conversion frame.")
 add(2,"RSU configuration overlay","15.000","","rsus.json; configured range from baseline effective config","",hs["rsus.json"],"00:10","configuration overlay","Markers are not native SUMO entities or proof of an observation.")
 add(2,"Configured sensing range","15.000","","effective detector config: rsu_range_m=450","",hs["ABLATION_EFFECTIVE_CONFIGS.json"],"00:10","direct effective configuration","Only RSU-5 coverage is emphasized for readability.")
 add(3,"Attack CAM","15.000","",msg["message_id"],"",hs["generated_messages.csv"],"00:32","direct generated-message record","True-versus-reported comparison is an offline overlay.")
 add(3,"Attack ground-truth schedule","15.000","","attack_ground_truth.csv; position_offset interval 5.0?35.0 s","malicious",hs["attack_ground_truth.csv"],"00:32","direct ground-truth record","Offline evaluation label; not runtime detector input.")
 for tm,vtime in (("15.0","00:54"),("17.0","00:58")):
  for e in (r for r in evid if r["observed_at"]==tm):
   add(4,"Evidence observation at t="+tm,tm,"",e["source_id"]+" | "+e["observation_root_id"],"",hs["evidence_campaign.csv"],vtime,"direct evidence row","Observed row; exact final bundle membership is unavailable.")
 add(5,"Qualification","","", "case-level baseline record; reason="+case["reason"],"revoked",hs["ABLATION_CASE_DECISIONS.csv"],"01:24","direct case-level record","No vote-level PBFT transcript is shown.")
 add(5,"Finalization","",case["finalized_at"],"case-level record; committed="+case["committed"],case["new_state"],hs["ABLATION_CASE_DECISIONS.csv"],"01:30","direct case-level record","Does not establish full Byzantine tolerance.")
 add(5,"Ledger availability","",case["ledger_available_at"],"case-level record",case["new_state"],hs["ABLATION_CASE_DECISIONS.csv"],"01:36","direct case-level record","Saved ledger timestamp, not a SUMO-native event.")
 add(6,"Scientific takeaway","","","storyboard and production notes","No additional claim","","01:50","explanatory text","No claim of full Byzantine tolerance or safe coordinator recovery.")
 with (a.docs_dir/"VPUFT_Scenario5_Demo_Evidence_Map.csv").open("w",newline="",encoding="utf-8-sig") as f:w=csv.DictWriter(f,fieldnames=list(maprows[0]));w.writeheader();w.writerows(maprows)
 inputman=json.loads((a.repo/"results/final_scenario5_ablation/ABLATION_INPUT_TRACE_MANIFEST.json").read_text(encoding="utf-8"))
 match=exactly((z for z in inputman["traces"] if z["density"]==DENSITY and z["seed"]==SEED),"trace manifest entry")
 provenance={"artifact":"V-PUFT Scenario 5 defense demonstration","created_utc":datetime.now(timezone.utc).isoformat(),"branch":"research/final-scenario5","repository_head_at_render":"26c0de2ec0fd2c3e63a20da9fe585ba34b2c11e5","visualization":"trace-based; not native SUMO-GUI capture","execution_scope":"No SUMO rerun or V-PUFT algorithm re-execution; saved mobility and case records are synchronized for display.","campaign":{"name":"sensitivity replication trace reused by ablation baseline","frozen_corrected_final_dataset_b":False,"density":DENSITY,"seed":SEED,"trace_sha256":tracehash,"case_id":CASE_ID,"vehicle_id":VEHICLE,"attack_type":"position_offset","unique_vehicles":sm["counts"]["unique_vehicles_observed"]},"baseline":{"variant":"baseline","architecture":"Distributed","execution_kind":run["execution_kind"],"execution_commit":run["execution_commit"],"execution_branch":run["execution_branch"],"adapter":"production_engine_no_adapter","effective_config_sha256":run["effective_config_sha256"],"rsu_range_m":450.0,"case_record":{k:case[k] for k in ("opened_at","detected_at","qualified_at","finalized_at","ledger_available_at","committed","predicted_revoked","new_state","reason")}},"attack_event":{"message_id":msg["message_id"],"generated_at_sumo_seconds":float(msg["generated_at"]),"trajectory_position_m":[float(m15["x"]),float(m15["y"])],"reported_position_m":[float(msg["reported_x"]),float(msg["reported_y"])],"ground_truth_source":"attack_ground_truth.csv; offline evaluation record"},"rsu_geometry":{"configured_range_m":450.0,"net_offset":off,"positions_in_network_frame":places,"markers_are_native_sumo_entities":False,"rings_show":"configured range, not actual detection"},"evidence_trace":{"rows_for_case":len(evid),"unique_roots":len({r["observation_root_id"] for r in evid}),"source_ids":sorted({r["source_id"] for r in evid}),"geographic_cells":sorted({r["geographic_cell"] for r in evid}),"final_bundle_membership_available":False},"source_files_sha256":hs,"trace_manifest_sha256":sha(a.repo/"results/final_scenario5_ablation/ABLATION_INPUT_TRACE_MANIFEST.json"),"matched_trace_manifest_entry":match,"renderer_sha256":sha(pathlib.Path(__file__)),"video":video,"preview_frames":previewinfo,"limitations":["Trace-based visualization, not native SUMO-GUI capture.","QE/PBFT are not executed inside SUMO during rendering.","Exact final evidence-bundle membership is not logged.","No vote-level PBFT transcript is shown.","No full Byzantine fault-tolerance or safe coordinator-recovery claim.","Not frozen corrected-final Dataset B."]}
 (docs/"VPUFT_Scenario5_Demo_Provenance.json").write_text(json.dumps(provenance,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
 storyboard="""# V-PUFT Scenario 5 Defense Demonstration — Storyboard

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
"""
 (a.docs_dir/"VPUFT_Scenario5_Demo_Storyboard.md").write_text(storyboard,encoding="utf-8")
 notes=f"""# V-PUFT Scenario 5 Video Production Notes

## Output
- MP4: {out/VIDEO_NAME}
- Resolution/frame rate: 1920×1080 at 24 fps
- Duration: 132 seconds (2:12)
- Encoding: H.264 / libx264, yuv420p; no audio
- Visualization: trace-based, not native SUMO-GUI capture
- Playback pacing: editorial; on-screen trace clock is simulation time
- Video SHA-256: {video["sha256"] if video else "not rendered in preview-only mode"}

## Reproduction
Run from the final research worktree with Pillow, NumPy and imageio-ffmpeg installed:

~~~powershell
& C:\\Users\\reemg\\OneDrive\\Desktop\\master\\6\\v10\\.venv\\Scripts\\python.exe scripts\\render_final_scenario5_defense_video.py
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
"""
 (a.docs_dir/"VPUFT_Scenario5_Video_Production_Notes.md").write_text(notes,encoding="utf-8")
 print("PREVIEWS")
 for z in previewinfo:print(z["file"],z["sha256"])
 if video:print("VIDEO",video["file"],video["sha256"],video["bytes"])
 print("EVIDENCE_MAP",a.docs_dir/"VPUFT_Scenario5_Demo_Evidence_Map.csv")
 print("PROVENANCE",docs/"VPUFT_Scenario5_Demo_Provenance.json")
if __name__=="__main__":main()


