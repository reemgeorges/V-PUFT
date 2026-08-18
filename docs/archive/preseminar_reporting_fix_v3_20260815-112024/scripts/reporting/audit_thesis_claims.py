#!/usr/bin/env python3
"""Read-only wording audit against the frozen V-PUFT/Phase-A contract.

It is deliberately conservative: it flags only statements that appear to make
an overclaim without nearby qualification. It never rewrites thesis prose.
"""
from __future__ import annotations
import argparse, json, re, zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

DEFAULT_EXT={'.md','.txt','.html','.htm','.tex','.docx'}


def extract_docx(path: Path) -> str:
    try:
        with zipfile.ZipFile(path) as z: data=z.read('word/document.xml')
        root=ET.fromstring(data)
        return ' '.join(t.text or '' for t in root.iter() if t.tag.endswith('}t'))
    except Exception: return ''

def read_text(path: Path) -> str:
    if path.suffix.lower()=='.docx': return extract_docx(path)
    return path.read_text(encoding='utf-8', errors='replace')

def clean(s: str)->str: return re.sub(r'<[^>]+>|\s+',' ',s).strip()

def windows(text: str, token_re: str, radius: int=180):
    for m in re.finditer(token_re,text,flags=re.I):
        yield m, clean(text[max(0,m.start()-radius):min(len(text),m.end()+radius)])

def has_any(s: str, terms):
    low=s.lower(); return any(t.lower() in low for t in terms)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('paths', nargs='*', help='Thesis files/folders to audit')
    ap.add_argument('--repo', default='.')
    ap.add_argument('--output', default='docs/analysis/THESIS_CLAIM_AUDIT.json')
    args=ap.parse_args()
    repo=Path(args.repo).resolve()
    roots=[Path(p).resolve() for p in args.paths] if args.paths else [repo/'docs', repo/'results/full_campaign_v7/thesis_final_reports']
    files=[]
    for root in roots:
        if root.is_file(): files.append(root)
        elif root.exists():
            files += [p for p in root.rglob('*') if p.is_file() and p.suffix.lower() in DEFAULT_EXT and not any(part.lower() in {'archive','legacy','.git'} for part in p.parts)]

    hits=[]
    seen=set()
    def emit(category,p,snippet):
        key=(category,str(p),snippet)
        if key not in seen:
            seen.add(key); hits.append({'category':category,'path':str(p),'snippet':snippet})

    for p in sorted(set(files)):
        text=read_text(p)
        if not text: continue
        low=text.lower()

        # Safety: only flag affirmative no-violation claims.
        for _,w in windows(text, r'\bSafety\b|safety_violation|سلامة'):
            if has_any(w,['no safety violations','لم تسجل انتهاكات safety','لم تُسجل انتهاكات safety','أثبتت سلامة pbft']) and not has_any(w,['غير قابل','لم يُختبر','لم يكن مسار','لا تُعامل','not measured','not tested']):
                emit('safety_overclaim',p,w)

        # MCC: positive significance/superiority without local Holm/descriptive qualification.
        for _,w in windows(text, r'\bMCC\b'):
            positive=has_any(w,['significant','دال إحصائ','دالاً','دالًا','دال بعد','دال بعد'])
            qualified=has_any(w,['غير دال','لم يبق دال','لم يبقَ دال','وصفي','descriptive','not significant','non-significant','holm','0.1986'])
            if positive and not qualified: emit('mcc_overclaim',p,w)

        # 8.49 is acceptable only when identified as paired/macro/mean-paired rather than the pooled CI estimate.
        for _,w in windows(text,r'8\.49'):
            if has_any(w,['تحسن','تحسّن','improv','increase','فرق']) and not has_any(w,['paired','مزدوج','متوسط','macro','جدول إجمالي','8.46']):
                emit('unqualified_8_49',p,w)

        # Mixed 56.13 must be exploratory/unadjusted in its local context.
        for _,w in windows(text,r'56\.13'):
            if not has_any(w,['استكشاف','explor','غير مصحح','unadjusted']): emit('unqualified_mixed',p,w)

        # Blockchain accuracy: flag causal accuracy-improvement claims unless explicitly scoped/negated.
        for _,w in windows(text,r'Blockchain|سلسلة\s+الكتل|البلوك\s*تشين'):
            positive=has_any(w,['improved detection','improved accuracy','increase recall','حسنت دقة','حسّنت دقة','رفعت دقة','تحسن الكشف','تحسّن الكشف'])
            qualified=has_any(w,['لم يظهر','لا يعني','لا تدعم','لم يغير التصنيف','لم يغيّر التصنيف','not measured','لم تُقَس','لم تقاس'])
            if positive and not qualified: emit('blockchain_accuracy_overclaim',p,w)

    report={
      'audit_only': True, 'auto_rewrite': False,
      'scope':[str(x) for x in roots], 'files_scanned':len(set(files)), 'hits':hits,
      'guidance':{
        '8.46':'Pooled recall difference with stratified cluster-bootstrap CI.',
        '8.49':'Mean paired difference across 40 topology-seed units / explicitly labelled macro-table context.',
        'MCC':'Higher descriptively; NOT confirmatory after Holm (adjusted p≈0.1986).',
        'Safety':'Do not report zero violations as empirical safety evidence; malicious semantic proposals were not exercised.',
        'Mixed':'Attack-stratified result is exploratory/unadjusted for multiplicity.',
        'Blockchain':'C-vs-D classification equality isolates zero classification effect under fixed trust/evidence; ledger tamper-resistance/auditability were not directly measured.'}}
    out=(repo/args.output) if not Path(args.output).is_absolute() else Path(args.output)
    out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(f'Scanned {report["files_scanned"]} files; risky wording hits: {len(hits)}')
    print('AUDIT ->',out)
    for h in hits[:40]: print(f'[{h["category"]}] {h["path"]}: {h["snippet"]}')
    if len(hits)>40: print(f'... {len(hits)-40} more hits in JSON report')

if __name__=='__main__': main()
