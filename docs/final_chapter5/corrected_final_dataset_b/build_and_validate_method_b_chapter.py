from pathlib import Path
import pandas as pd,json,hashlib,math,re,html
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
R=Path(__file__).resolve().parents[3]; O=R/"docs/final_chapter5/corrected_final_dataset_b"; F=O/"figures"; O.mkdir(parents=True,exist_ok=True); F.mkdir(exist_ok=True)
S=R/"results/urban_roundabout_campaign_corrected_final"; D=pd.read_csv(S/"combined/density_decisions.csv"); M=pd.read_csv(S/"combined/density_metrics_by_seed.csv"); P=pd.read_csv(R/"docs/final_scenario5_evidence_package/METHOD_B_CORRECTED_FINAL/SCENARIO5_METHOD_B_VERIFIED_METRICS.csv")
CLAIMS=R/"docs/final_scenario5_evidence_package/FINAL_THESIS_CLAIMS_AR.md"
dens=[20,40,60,80,100]; ars=["centralized_remote_0ms_control","centralized_remote_100ms","distributed_density_honest"]; labels=dict(zip(ars,["C0","C100","Distributed"]))
assert len(D)==52254 and set(D.architecture)==set(ars) and sorted(D.vehicle_count.unique())==dens and sorted(D.seed.unique())==list(range(1001,1011))
man=json.loads((S/"combined/density_campaign_manifest.json").read_text(encoding="utf-8")); cfg=json.loads((S/"effective_config.json").read_text(encoding="utf-8"))
assert man["expected_shared_traces"]==50 and man["architecture_evaluations_per_trace"]==3 and man["shared_trace_pairing"]
assert cfg["pbft"]["validators"]==["rsu-1","rsu-2","rsu-3","rsu-4"] and cfg["pbft"]["max_byzantine"]==1
def C(g):
 e=g[g.reason.astype(str)!="already_revoked_terminal_state"]; y=e.ground_truth_malicious.astype(int); p=((e.committed.astype(int)==1)&(e.new_state.astype(str)=="revoked")).astype(int)
 return dict(TP=int(((y==1)&(p==1)).sum()),FP=int(((y==0)&(p==1)).sum()),TN=int(((y==0)&(p==0)).sum()),FN=int(((y==1)&(p==0)).sum()),eligible=len(e),excluded=len(g)-len(e),total=len(g))
def div(x,y): return x/y if y else 0
def Q(c):
 p=div(c["TP"],c["TP"]+c["FP"]); r=div(c["TP"],c["TP"]+c["FN"]); fr=div(c["FP"],c["FP"]+c["TN"]); f=div(2*p*r,p+r); den=(c["TP"]+c["FP"])*(c["TP"]+c["FN"])*(c["TN"]+c["FP"])*(c["TN"]+c["FN"])
 return dict(precision=p,recall=r,FRR=fr,F1=f,MCC=(c["TP"]*c["TN"]-c["FP"]*c["FN"])/math.sqrt(den) if den else 0)
rows=[]
for a in ars:
 for d in dens:
  g=D[(D.architecture==a)&(D.vehicle_count==d)]; seedq=[]
  for s in range(1001,1011):
   x=g[g.seed==s]; c=C(x); q=Q(c); m=M[(M.architecture==a)&(M.vehicle_count==d)&(M.seed==s)]
   assert len(m)==1; m=m.iloc[0]
   assert c["eligible"]==int(m.security_cases_evaluated) and c["excluded"]==int(m.excluded_post_revocation_cases)
   for k,col in [("precision","trust_precision"),("recall","malicious_revocation_recall"),("FRR","false_revocation_rate"),("F1","trust_f1"),("MCC","mcc")]: assert abs(q[k]-float(m[col]))<1e-10
   rows.append({"level":"seed","architecture":a,"density":d,"seed":s,**c,**q}); seedq.append(q)
  c=C(g); q=Q(c); rows.append({"level":"density_pooled","architecture":a,"density":d,**c,**q})
  rows.append({"level":"density_macro","architecture":a,"density":d,"TP":"","FP":"","TN":"","FN":"","eligible":"","excluded":"","total":"","precision":sum(x["precision"] for x in seedq)/10,"recall":sum(x["recall"] for x in seedq)/10,"FRR":sum(x["FRR"] for x in seedq)/10,"F1":sum(x["F1"] for x in seedq)/10,"MCC":sum(x["MCC"] for x in seedq)/10})
T=pd.DataFrame(rows); T.to_csv(O/"SCENARIO5_METHOD_B_RECOMPUTED_METRICS.csv",index=False)
overall={a:{**C(D[D.architecture==a]),**Q(C(D[D.architecture==a]))} for a in ars}
exp=[(639,9,12981,964,14593,2825),(639,9,12981,964,14593,2825),(641,9,12974,961,14585,2833)]
for a,e in zip(ars,exp):
 c=overall[a]; assert tuple(c[k] for k in ["TP","FP","TN","FN","eligible","excluded"])==e
for a in ars[1:]:
 for d in dens:
  for l,p in [("density_pooled","density_pooled"),("density_macro","density_macro_seed_mean")]:
   x=P[(P.architecture==a)&(P.density==d)&(P.level==p)]; y=T[(T.architecture==a)&(T.density==d)&(T.level==l)]; assert len(x)==len(y)==1
   for k in ["precision","recall","FRR","F1","MCC"]: assert abs(float(x.iloc[0][k])-float(y.iloc[0][k]))<1e-10
key=["topology","vehicle_count","seed","case_id"]; cols=["ground_truth_malicious","predicted_revoked","committed","previous_state","new_state","reason"]
parts=[D[D.architecture==a].sort_values(key).reset_index(drop=True) for a in ars]
assert all(parts[0][key].equals(x[key]) for x in parts[1:]) and parts[0][cols].equals(parts[1][cols])
j=parts[1][key+cols].merge(parts[2][key+cols],on=key,suffixes=("_c","_d"),validate="one_to_one")
pd=j[j.predicted_revoked_c!=j.predicted_revoked_d]; assert len(pd)==2
assert {(int(x.vehicle_count),int(x.seed),x.case_id) for _,x in pd.iterrows()}=={(60,1002,"case-urban_roundabout-1002-veh_044-w0002"),(100,1004,"case-urban_roundabout-1004-veh_020-w0001")}
sd=j[(j.previous_state_c!=j.previous_state_d)|(j.new_state_c!=j.new_state_d)|(j.reason_c!=j.reason_d)]
td=j[(j.reason_c!="already_revoked_terminal_state")&(j.reason_d=="already_revoked_terminal_state")]; assert len(td)==8
unavail={a:int((D[D.architecture==a].reason=="central_server_unavailable").sum()) for a in ars[:2]}
fps={}
for a in ars:
 g=D[(D.architecture==a)&(D.reason!="already_revoked_terminal_state")]
 fps[a]=sorted(g[(g.ground_truth_malicious==0)&(g.committed==1)&(g.new_state=="revoked")].case_id.tolist())
assert fps[ars[1]]==fps[ars[2]] and len(fps[ars[2]])==9
perf={}
for a in ars:
 perf[a]={}
 for d in dens:
  g=M[(M.architecture==a)&(M.vehicle_count==d)]
  perf[a][d]={k:float(g[k].mean()) for k in ["latency_p95_ms","cpu_time_seconds","messages_per_decision","packet_delivery_ratio","ledger_consistency_delay_p95_ms"]}
perf_rows=[]
for a in ars:
 for d in dens:
  g=M[(M.architecture==a)&(M.vehicle_count==d)]
  perf_rows.append({"architecture":a,"label":labels[a],"density":d,"seed_count":len(g),
   "P95_E2E_ms_mean":float(g["latency_p95_ms"].mean()),
   "CPU_seconds_mean":float(g["cpu_time_seconds"].mean()),
   "messages_per_decision_mean":float(g["messages_per_decision"].mean()),
   "PDR_mean":float(g["packet_delivery_ratio"].mean()),
   "P95_ledger_consistency_delay_ms_mean":float(g["ledger_consistency_delay_p95_ms"].mean())})
type(M)(perf_rows).to_csv(O/"SCENARIO5_METHOD_B_PERFORMANCE_SUMMARY.csv",index=False)
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
oldfiles=[R/"results/urban_roundabout_campaign_corrected_final/combined/density_decisions.csv",S/"combined/density_metrics_by_seed.csv",S/"combined/density_campaign_manifest.json",S/"effective_config.json",R/"docs/final_scenario5_evidence_package/METHOD_B_CORRECTED_FINAL/SCENARIO5_METHOD_B_VERIFIED_METRICS.csv",R/"docs/final_chapter5/VPUFT_Chapter5_MethodB_Corrected_AR.md",R/"docs/final_chapter5/VPUFT_Scenario5_Defense_Report_Final.html",R/"docs/final_chapter5/VPUFT_Chapter5_Arabic_Complete.docx",R/"docs/final_chapter5/VPUFT_Chapter5_Arabic_Complete.pdf"]
hashes={str(x.relative_to(R)).replace("\\","/"):sha(x) for x in oldfiles}
plt.rcParams.update({"font.family":"Arial","font.size":11.5,"axes.titleweight":"bold"})
clr=dict(zip(ars,["#667085","#2F5597","#0F766E"]))
def prow(d,a): return T[(T.level=="density_pooled")&(T.density==d)&(T.architecture==a)].iloc[0]
for col,title,ylabel,name,ylim in [("recall","Method B state-aware Recall by density","Pooled state-aware Recall","01_state_aware_recall.png",(0,.55)),("latency_p95_ms","Recorded P95 end-to-end latency","P95 E2E (ms; seed mean)","02_p95_e2e_latency.png",(0,16000)),("messages_per_decision","Recorded messages per decision","Messages / decision (seed mean)","03_messages_per_decision.png",(0,40)),("cpu_time_seconds","Recorded CPU time","CPU seconds (seed mean)","04_cpu_time.png",(0,7))]:
 fig,ax=plt.subplots(figsize=(6.4,3.5))
 for a in ars:
  v=[float(prow(d,a)[col]) if col=="recall" else perf[a][d][col] for d in dens]
  ax.plot(dens,v,marker="o",lw=2.2,ms=5,label=labels[a],color=clr[a])
 ax.set(title=title,xlabel="Vehicle density (vehicles)",ylabel=ylabel); ax.set_xticks(dens); ax.set_ylim(*ylim); ax.grid(True,alpha=.24); ax.legend(frameon=False,ncol=3); fig.tight_layout(); fig.savefig(F/name,dpi=220,bbox_inches="tight"); plt.close(fig)
def pct(x): return f"{float(x)*100:.2f}%"
def n(x,k=4): return f"{float(x):.{k}f}"
base=(R/"docs/final_chapter5/VPUFT_Chapter5_MethodB_Corrected_AR.md").read_text(encoding="utf-8").lstrip("\ufeff")
def replace(t,s,e,b): return t[:t.index(s)]+b.rstrip()+"\n\n"+t[t.index(e,t.index(s)):]
b=["## نتائج التصنيف المجمعة عبر البذور","","الوحدة سجل نافذة قرار. تُستبعد النوافذ الطرفية فقط من أهلية Method B.","","| الكثافة | المعمارية | TP | FP | TN | FN | مؤهل | مستبعد terminal |","|---:|---|---:|---:|---:|---:|---:|---:|"]
for d in dens:
 for a in ars:
  r=prow(d,a); b.append(f"| {d} | {labels[a]} | {int(r.TP)} | {int(r.FP)} | {int(r.TN)} | {int(r.FN)} | {int(r.eligible)} | {int(r.excluded)} |")
b+=["","### المقاييس pooled حسب الكثافة","","| الكثافة | المعمارية | Precision | Recall pooled | FRR | F1 | MCC |","|---:|---|---:|---:|---:|---:|---:|"]
for d in dens:
 for a in ars:
  r=prow(d,a); b.append(f"| {d} | {labels[a]} | {pct(r.precision)} | {pct(r.recall)} | {pct(r.FRR)} | {n(r.F1)} | {n(r.MCC)} |")
b+=["","### المتوسط الحسابي macro عبر البذور","","المتوسط غير الموزون لعشر نسب seed-level، وليس نسبة محسوبة من المجاميع.","","| الكثافة | المعمارية | Precision macro | Recall macro | FRR macro | F1 macro | MCC macro |","|---:|---|---:|---:|---:|---:|---:|"]
for d in dens:
 for a in ars:
  r=T[(T.level=="density_macro")&(T.density==d)&(T.architecture==a)].iloc[0]; b.append(f"| {d} | {labels[a]} | {pct(r.precision)} | {pct(r.recall)} | {pct(r.FRR)} | {n(r.F1)} | {n(r.MCC)} |")
b+=["","### المجاميع الكلية","","| المعمارية | TP | FP | TN | FN | مؤهل | مستبعد | Precision | Recall state-aware | FRR | F1 | MCC |","|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
for a in ars:
 c=overall[a]; b.append(f"| {labels[a]} | {c['TP']} | {c['FP']} | {c['TN']} | {c['FN']} | {c['eligible']} | {c['excluded']} | {pct(c['precision'])} | {pct(c['recall'])} | {pct(c['FRR'])} | {n(c['F1'])} | {n(c['MCC'])} |")
base=replace(base,"## نتائج التصنيف المجمعة عبر البذور","## الأداء المسجل","\n".join(b))
pb=["## الأداء المسجل","","القيم متوسطات عشر قيم seed-level. P95 E2E بالميلي ثانية وCPU بالثانية. تأخير السجل يأتي بعد الإنهاء.","","### زمن الاستجابة والمعالجة","","| الكثافة | المعمارية | P95 E2E (ms) | CPU (s) |","|---:|---|---:|---:|"]
for d in dens:
 for a in ars: pb.append(f"| {d} | {labels[a]} | {perf[a][d]['latency_p95_ms']:.1f} | {perf[a][d]['cpu_time_seconds']:.3f} |")
pb+=["","### النقل والسجل","","| الكثافة | المعمارية | رسائل/قرار | PDR | P95 تأخير السجل (ms) |","|---:|---|---:|---:|---:|"]
for d in dens:
 for a in ars: pb.append(f"| {d} | {labels[a]} | {perf[a][d]['messages_per_decision']:.3f} | {perf[a][d]['packet_delivery_ratio']:.5f} | {perf[a][d]['ledger_consistency_delay_p95_ms']:.3f} |")
pb+=["","المسار المركزي لا يتضمن PBFT؛ لا توجد نسبة موحدة موثقة لـconsensus/ledger overhead. CPU وP95 E2E قيم محفوظة وليست إعادة بناء مستقلة من profiler."]
for fn,cap in [("01_state_aware_recall.png","الشكل 5-1: Recall الحالة pooled حسب الكثافة والمعمارية."),("02_p95_e2e_latency.png","الشكل 5-2: P95 E2E المسجل ومحوره يبدأ من الصفر."),("03_messages_per_decision.png","الشكل 5-3: الرسائل المسجلة لكل قرار، متوسط seed-level."),("04_cpu_time.png","الشكل 5-4: CPU المسجل بالثواني، متوسط seed-level.")]:
 pb += ["",f"![{cap}](figures/{fn})","",f"**{cap}** المصدر: مقاييس Dataset B المحفوظة."]
base=replace(base,"## الأداء المسجل","## الحالات التي اختلف فيها قرار الإبطال","\n".join(pb))
db=["## المقارنة على مستوى الهوية وتوافر الخادم","","تطابقت الهويات الثلاث 17,418/17,418؛ لا حالات غير متطابقة. تطابقت حقول القرار والحالة والسبب بين C0 وC100. اختلف قرار الإبطال الأولي بين C100 وDistributed في حالتين خبيثتين فقط، وبقيت هويات FP التسع متطابقة.","","| الكثافة | البذرة | case_id | المركبة | الهجوم | C100 | Distributed |","|---:|---:|---|---|---|---|---|",
"| 60 | 1002 | case-urban_roundabout-1002-veh_044-w0002 | veh_044 | speed_offset | central_server_unavailable؛ لا إبطال ملتزم | إبطال ملتزم عند 44.112420255 s |",
"| 100 | 1004 | case-urban_roundabout-1004-veh_020-w0001 | veh_020 | position_offset | central_server_unavailable؛ لا إبطال ملتزم | إبطال ملتزم عند 29.102440446 s |",
"",
"تلت ذلك ثماني نوافذ terminal إضافية في Distributed: واحدة خبيثة وسبع حميدة. وُسم 75 صفاً بـcentral_server_unavailable في كل من C0 وC100؛ الحالتان أعلاه فقط هما فرق الإبطال الأولي بين C100 وDistributed. التفسير هو اختلاف التوافر في المسار المحاكى، لا إثبات تفوق خوارزمية QE أو PBFT. كما تغيّر مقام Recall بسبب الاستبعاد الطرفي: 14,593 مؤهلة في C100 و14,585 في Distributed."]
base=replace(base,"## الحالات التي اختلف فيها قرار الإبطال","## تفسير النتائج","\n".join(db))
it="""## تفسير النتائج

تتقارب نتائج C100 وDistributed؛ Recall الحالة pooled يساوي 39.8628% و40.0125% على الترتيب، مع تسع حالات FP متطابقة الهوية. ارتبط قرارا الإبطال الأوليان المختلفان بتعذر إتمام المسار المركزي في حالتين. لا تعزل هذه النتيجة خوارزمية التأهيل أو الإجماع وحدها.

تطابق C0 وC100 تصنيفياً رغم فرق backhaul الإضافي 100 ms. تسجيل 75 سبباً لعدم توافر الخادم في كل منهما لا يعني أن التصنيف اختلف. لا تظهر المقارنة أفضلية كشف خوارزمية لـDistributed.

Recall هو state-aware بعد استبعاد النوافذ الطرفية. لا يتوفر في Dataset B مقام ثابت لفرص الهجوم أو fixed-universe protection fraction، فلا تستنتج منه هذه المقاييس."""
base=replace(base,"## تفسير النتائج","## القيود وإعادة الإنتاج",it)
start=base.index("المقارنة المعروضة هنا هي C100")
end=base.index("استُخدمت إعدادات الحملة الفعلية",start)
base=base[:start]+"المقارنة تشمل C0 عند 0 ms، وC100 عند 100 ms، وDistributed بالمعمارية الموزعة الأصلية. تختلف مسارات النقل والمعالجة، فلا تعزل المقارنة خوارزمية QE وحدها. "+base[end:]
supp="""## الدراسات التكميلية وحدود الأمن

دراسات Phase 1–6، وتوسعة 8-RSU، وV5، والمنسق الحتمي، وتوافر الأدلة، والحساسية وAblation تكميلية ومنفصلة عن Dataset B. في Phase 6 زادت الفرص المرصودة 948 إلى 953 (+5)، بخمس خلايا تحسن و15 ثابتة. ارتفعت الحماية على المقام الثابت 455/1,086 إلى 501/1,086 (+46): منها +21 فرصة مكتشفة في نافذتها و+25 فرصة طرفية حُميت بعد إبطال سابق. ليست +46 اكتشافات جديدة.

طيار 8-RSU تجاوز حد CPU (+44.27%) والرسائل لكل حالة (+37.12%)، ولذلك هو NO-GO. تحليل الحساسية اكتمل في 103/120 خلية؛ و17 لم تبدأ بسبب حد زمن التنفيذ. اكتمل Ablation في 48/48. المتغير C أزال بوابات تنوع الجذر والمصدر والمنطقة والوسيط، ولذلك فهو مقابل أضعف أمنياً لا إعداداً مقترحاً. عند الكثافة 20 ارتفع TP من 15 إلى 28 في C100 وDistributed؛ وتغيرت النوافذ المؤهلة/الطرفية من 402/74 إلى 342/134 في C100 ومن 402/74 إلى 341/135 في Distributed. وعند الكثافة 100 ارتفع TP من 79 إلى 137 في المعماريتين، وتغيرت المؤهلة/الطرفية من 1,923/357 إلى 1,657/623. بقي مقام فرص الهجوم ثابتاً (1,700 عند الكثافة 20 و7,612 عند 100): في C100 زادت الفرص المكتشفة/المحمية من 227/142 إلى 781/546 عند الكثافة 20، وفي Distributed إلى 774/561؛ وعند الكثافة 100 زادت من 2,179/1,106 إلى 3,298/2,828 في المعماريتين. لم تظهر FP جديدة في العينة، وانخفض FP من 1 إلى 0 عند الكثافة 20 ومن 2 إلى 0 عند 100؛ لا يثبت ذلك السلامة خارج العينة ولا يعوض إلغاء شروط الاستقلال. بقي خط الأساس الأصلي كما هو.

تجارب V5 والمنسق الحتمي وحد single-view وتوافر الأدلة منفصلة واستكشافية. لا تثبت تحمل Byzantine طرفاً إلى طرف؛ لا يوجد VIEW-CHANGE/NEW-VIEW كامل أو استعادة منسق آمنة. حجب الأدلة المعارضة من المنسق ثغرة مثبتة، والتوقيع لا يثبت اكتمال الأدلة."""
base=base.replace("## مصادر الأرقام",supp+"\n\n## مصادر الأرقام")
src_idx=base.rfind("\n## ")
if src_idx >= 0:
 base=base[:src_idx].rstrip()
 source_note="تُراجع أرقام هذا الفصل في [سجل Method B المحقق](../final_scenario5_evidence_package/METHOD_B_CORRECTED_FINAL/SCENARIO5_METHOD_B_VERIFIED_METRICS.csv)، وتعريفات المقاييس في [ملف التعريفات](../final_scenario5_evidence_package/METHOD_B_CORRECTED_FINAL/SCENARIO5_METHOD_B_METRIC_DEFINITIONS_AR.md)، وبصمات المدخلات في [ملف provenance](SCENARIO5_METHOD_B_PROVENANCE.json)."
 sup_idx=base.rfind("\n## ")
 if sup_idx >= 0:
  base=base[:sup_idx]+"\n\n"+source_note+base[sup_idx:]

base=base.replace("## نطاق النسخة ومصدر النتائج","## نطاق النسخة ومصدر النتائج\n\n**القرار النهائي:** Dataset B corrected-final هي المصدر المعتمد لجداول Method B. Dataset A وHTML التاريخي محفوظان دون تعديل ولا تمثل B إعادة إنتاج لهما. الفصل التاريخي DOCX/PDF ورسومه يخص v7 متعددة الطوبولوجيات، ولا تستخدم أرقامه هنا.\n",1)
(O/"VPUFT_Chapter5_MethodB_Corrected_Final_AR.md").write_text(base,encoding="utf-8")
def inline(s):
 s=html.escape(s,quote=False); s=re.sub(r"\*\*(.+?)\*\*",r"<strong>\1</strong>",s); s=re.sub(r"\[([^\]]+)\]\(([^)]+)\)",r'<a href="\2">\1</a>',s); return s
ls=base.splitlines(); el=[]; i=0
while i<len(ls):
 x=ls[i].strip()
 if not x: i+=1; continue
 if x.startswith("!["):
  m=re.match(r"!\[(.*?)\]\((.*?)\)",x)
  if m: el.append(f'<figure><img src="{html.escape(m.group(2),quote=True)}" alt="{html.escape(m.group(1),quote=True)}" width="620"></figure>')
  i+=1; continue
 if x.startswith("#"):
  z=len(x)-len(x.lstrip("#")); t=x[z:].strip(); tag="h1" if z==1 else ("h2" if z==2 else "h3"); attrs=' style="page-break-before:always"' if t in ("الأداء المسجل","الدراسات التكميلية وحدود الأمن") else ""; el.append(f"<{tag}{attrs}>{inline(t)}</{tag}>"); i+=1; continue
 if x.startswith("|"):
  rr=[]
  while i<len(ls) and ls[i].strip().startswith("|"):
   cc=[q.strip() for q in ls[i].strip().strip("|").split("|")]
   if not all(re.fullmatch(r":?-{3,}:?",q or "") for q in cc): rr.append(cc)
   i+=1
  if rr:
   def cell(tag,q):
    d="rtl" if re.search(r"[\u0600-\u06FF]",q) else "ltr"
    return f'<{tag} dir="{d}">'+inline(q)+f'</{tag}>'
   el.append("<table><thead><tr>"+"".join(cell("th",q) for q in rr[0])+"</tr></thead><tbody>")
   for row in rr[1:]: el.append("<tr>"+"".join(cell("td",q) for q in row)+"</tr>")
   el.append("</tbody></table>")
  continue
 if x.startswith("- "):
  ll=[]
  while i<len(ls) and ls[i].strip().startswith("- "): ll.append("<li>"+inline(ls[i].strip()[2:])+"</li>"); i+=1
  el.append("<ul>"+"".join(ll)+"</ul>"); continue
 ps=[x]; i+=1
 while i<len(ls) and ls[i].strip() and not ls[i].lstrip().startswith(("#","|","- ","![")): ps.append(ls[i].strip()); i+=1
 el.append("<p>"+" ".join(inline(v) for v in ps)+"</p>")
css="@page{size:A4;margin:2cm}body{font-family:Arial,'Traditional Arabic',sans-serif;font-size:10.5pt;line-height:1.48;color:#202124;direction:rtl;text-align:right}h1,h2,h3{color:#000;page-break-after:avoid;line-height:1.25}h1{font-size:21pt;text-align:center;margin:18pt 0}h2{font-size:15pt;margin:17pt 0 7pt}h2[style*='page-break-before']{page-break-before:always}h3{font-size:12pt;margin:13pt 0 6pt}p{text-align:justify;margin:0 0 8pt}table{border-collapse:collapse;width:100%;margin:8pt 0 12pt;direction:rtl;table-layout:auto}thead{display:table-header-group}tfoot{display:table-footer-group}tr{break-inside:avoid;page-break-inside:avoid}th,td{border:.6pt solid #D9D9D9;padding:4.5pt;text-align:center;vertical-align:middle;word-wrap:break-word}th{background:#24476B;color:#fff;font-size:8pt}td{font-size:8pt}tbody tr:nth-child(even){background:#F2F6FA}figure{text-align:center;margin:12pt auto 16pt;page-break-inside:avoid}figure img{width:16cm;max-width:100%;height:auto}ul{padding-right:20pt}"
doc='<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><title>الفصل الخامس المصحح وفق Dataset B Method B</title><style>'+css+'</style></head><body>'+"\n".join(el)+"</body></html>"
(O/"VPUFT_Scenario5_Dataset_B_Method_B_Corrected_Final.html").write_text(doc,encoding="utf-8")
CLAIMS.write_text("""# الادعاءات العلمية النهائية

## مصدر نتائج Scenario 5

Dataset B، حملة urban_roundabout_campaign_corrected_final المقيمة وفق Method B، هي المصدر المعتمد للجداول النهائية لسيناريو الدوار الحضري. Dataset A محفوظة دون تغيير بوصفها الحملة التاريخية المرتبطة بتقرير الدفاع عند commit 638a6d7؛ وتختلف في مجتمع الحالات والقرارات، لذا لا تمثل إعادة إنتاج Dataset B. لا تستخدم الجداول النهائية قيم Recall التاريخية الخمس غير القابلة للتتبع.

## المقارنة المعمارية

تعرض الجداول النهائية C0 وC100 وDistributed. تطابقت حقول القرار والحالة والسبب بين C0 وC100 على 17,418/17,418 هوية. يضيف C100 تأخير backhaul مقداره 100 ms مقارنة بضابط C0. اختلف قرار الإبطال الأولي بين C100 وDistributed في حالتين خبيثتين مرتبطتين بتعذر الخادم المركزي، وتبعت ذلك ثماني نوافذ طرفية لاحقة في Distributed. بقيت هويات حالات FP التسع متطابقة. هذه فروق توافر ومسار محاكى وليست دليلاً على تفوق QE أو PBFT في الكشف.

## تعريف المقاييس

Recall النهائي هو state-aware Method B: TP/(TP+FN) بعد استبعاد النوافذ ذات already_revoked_terminal_state. يُبلغ عدد النوافذ المستبعدة منفصلاً؛ ويتغير المقام مع توقيت الإبطال. لا توفر Dataset B مقام فرص هجوم ثابتاً أو fixed-universe protection fraction، ولا يستنتج أي منهما من Recall الحالة. أعداد التصنيف pooled تجمع أعداد البذور أولاً؛ أما macro فيحسب النسبة لكل seed ثم يأخذ المتوسط غير الموزون. متوسطات الأداء هي متوسطات قيم seed-level المسجلة، وليست قياسات ميدانية.

## المساهمة والحدود

يمكن وصف المساهمة بأنها إطار تجريبي لتأهيل الثقة والأدلة في VANET، مع مقارنة معالجة مركزية وموزعة في محاكاة Scenario 5. تدعم النتائج سلوك النموذج تحت إعداداته الموثقة، ولا تثبت أداءً ميدانياً أو تفوقاً عاماً للمعمارية الموزعة.

تظل دراسات Phase 1–6 و8-RSU وV5 والمنسق الحتمي وتوافر الأدلة والحساسية وAblation تكميلية ومنفصلة عن Dataset B. تجاوز طيار 8-RSU بوابتي CPU والرسائل. اكتمل تحليل الحساسية في 103/120 خلية، ولم تبدأ 17 خلية بسبب حد زمن التنفيذ. اكتمل Ablation في 48/48؛ وبعض مقابلاته أضعفت متطلبات الأمن وليست توصيات تشغيلية.

لا تثبت المحاكاة تحملاً كاملاً لـByzantine. حجب الأدلة المعارضة من منسق الأدلة خطر مثبت، ولم يكتمل PBFT عبر VIEW-CHANGE/NEW-VIEW أو استعادة منسق آمنة. حد single-view fail-closed محدود وليس برهان سلامة موزعة.
""",encoding="utf-8")
prov={"dataset":"Dataset B corrected-final Method B","source_commit":"0c0c10b3d6cbb2075e430a299e3c18cdf382320a","main_head_at_build":"a78272de4017286c5c31c6d90f4f49c7e464ce92","campaign":{"densities":dens,"seeds":list(range(1001,1011)),"shared_cells":50,"decision_rows_all_architectures":len(D),"rows_per_architecture":17418},"source_sha256":hashes,"recomputed_overall":overall,"identity_audit":{"common_identities":17418,"unmatched":0,"C0_C100_decision_equal":True,"C100_Distributed_primary_revocation_differences":2,"C100_Distributed_state_or_reason_differences":len(sd),"additional_terminal_rows_Distributed":len(td),"central_server_unavailable_rows":unavail,"false_positive_case_ids":fps},"config":{"validators":cfg["pbft"]["validators"],"max_byzantine":cfg["pbft"]["max_byzantine"],"central_availability":cfg["central"]["availability"],"validator_requalification":cfg["distributed_extension"]["validator_requalification"]},"limitations":["Fixed-denominator opportunity metrics unavailable in Dataset B.","Raw SUMO mobility and attack traces unavailable.","CPU and P95 E2E are copied from seed metrics; raw profiler unavailable.","No full Byzantine tolerance, evidence completeness, or safe coordinator recovery claim."]}
prov["supplementary_sources"]={
 "docs/final_scenario5_ablation/ABLATION_FINDINGS_AR.md":sha(R/"docs/final_scenario5_ablation/ABLATION_FINDINGS_AR.md"),
 "results/final_scenario5_ablation/aggregated_metrics.csv":sha(R/"results/final_scenario5_ablation/aggregated_metrics.csv")
}
(O/"SCENARIO5_METHOD_B_PROVENANCE.json").write_text(json.dumps(prov,ensure_ascii=False,indent=2),encoding="utf-8")
(O/"FINAL_CHAPTER5_RECONCILIATION_AUDIT_AR.md").write_text("""# تدقيق الفصل الخامس النهائي

Dataset B corrected-final هي المصدر المعتمد لجداول Method B النهائية. حُفظ تقرير HTML التاريخي لـDataset A والفصل التاريخي DOCX/PDF ورسومه دون تغيير، وأُنشئت نسخة منفصلة لـDataset B. صُحح ملف الادعاءات الذي كان يصف المصدر بأنه غير محسوم.

أعيد حساب TP وFP وTN وFN من 52,254 صف قرار، مع استبعاد النوافذ already_revoked_terminal_state فقط من أهلية Method B. تطابقت حسابات C100 وDistributed حسب الكثافة مع الحزمة الموثقة في مستويي pooled وmacro؛ وأعيد حساب C0 من السجلات. C0 وC100: 639/9/12,981/964، و14,593 مؤهلة و2,825 طرفية. Distributed: 641/9/12,974/961، و14,585 مؤهلة و2,833 طرفية.

تطابقت الهويات بين البنى الثلاث في 17,418 حالة. قرارات C0 وC100 متطابقة. فرق الإبطال الأولي بين C100 وDistributed اقتصر على حالتين خبيثتين؛ وتبعت ذلك ثماني نوافذ طرفية. هويات FP التسع متطابقة. يظهر وسم عدم توافر الخادم في 75 صفاً من C0 و75 من C100.

Recall هو state-aware بعد الاستبعاد الطرفي. المقاييس ذات المقام الثابت غير متاحة ولا تستنتج. أعداد التصنيف pooled، ومتوسطات البذور macro. قيم CPU وP95 E2E ومقاييس النقل مأخوذة من سجلات seed-level؛ لا تتوفر آثار profiler لإعادة بنائها. لا تدعي النسخة تفوق كشف Distributed أو تحملاً كاملاً لـByzantine. تبقى مشكلة حجب الأدلة وغياب VIEW-CHANGE/NEW-VIEW والاستعادة الآمنة.

مدقق الفصل القديم مرتبط بمخرجات v7 ولا يطبق على Dataset B؛ أضيف مدقق واختبارات خاصة بالحملة المصححة.
""",encoding="utf-8")
print("BUILT",O)
