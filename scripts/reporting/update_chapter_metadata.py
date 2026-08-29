#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json
from datetime import datetime, timezone
from pathlib import Path

def sha256(p: Path)->str:
    return hashlib.sha256(p.read_bytes()).hexdigest().upper()

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--repo',default='.'); args=ap.parse_args()
    r=Path(args.repo).resolve()
    d=r/'results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion'
    meta=d/'chapter_metadata.json'; chapter=d/'chapter_5_results_discussion_ar.html'
    obj={}
    if meta.exists():
        try: obj=json.loads(meta.read_text(encoding='utf-8'))
        except Exception: obj={'previous_metadata_unparsed': True}
    obj['reporting_revision']='PRESEMINAR_FINAL_20260815'
    obj['reporting_revision_scope']='reporting_and_semantic_validation_only'
    obj['experiment_rerun']=False
    obj['frozen_v7_modified']=False
    obj['chapter_sha256']=sha256(chapter)
    obj['validation']='source-derived semantic/numerical validation; see VALIDATION.json'
    obj['updated_at_utc']=datetime.now(timezone.utc).isoformat()
    meta.write_text(json.dumps(obj,ensure_ascii=False,indent=2),encoding='utf-8')
    print('chapter_metadata ->',meta)
if __name__=='__main__': main()
