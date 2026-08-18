#!/usr/bin/env python3
"""Write a source-aware manifest for the final pre-seminar Chapter 5 artifacts."""
from __future__ import annotations
import argparse, hashlib, json
from datetime import datetime, timezone
from pathlib import Path


def sha256(p: Path) -> str:
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1<<20), b''):
            h.update(b)
    return h.hexdigest().upper()


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--repo', default='.')
    args=ap.parse_args()
    r=Path(args.repo).resolve()
    chapter_dir=r/'results/full_campaign_v7/thesis_final_reports/chapter_5_results_discussion'
    files=[
      chapter_dir/'chapter_5_results_discussion_ar.html',
      chapter_dir/'index.html',
      chapter_dir/'VALIDATION.json',
      chapter_dir/'chapter_metadata.json',
      r/'results/full_campaign_v7/statistical_inference/bootstrap_pooled_differences.csv',
      r/'results/full_campaign_v7/statistical_inference/bootstrap_by_attack.csv',
      r/'results/full_campaign_v7/statistical_inference/paired_tests_by_seed.csv',
      r/'results/full_campaign_v7/case_agreement/agreement_summary.csv',
      r/'results/full_campaign_v7/latency_decomposition/latency_stages.csv',
      r/'results/full_campaign_v7/sensitivity_shared_views_mixedfix/selected_weights.json',
      r/'configs/full_experiment.json',
    ]
    entries=[]
    for p in files:
        entries.append({
          'path': str(p.relative_to(r)).replace('\\','/'),
          'exists': p.exists(),
          'size_bytes': p.stat().st_size if p.exists() else None,
          'sha256': sha256(p) if p.exists() else None,
        })
    chapter=chapter_dir/'chapter_5_results_discussion_ar.html'
    index=chapter_dir/'index.html'
    manifest={
      'artifact': 'V-PUFT Chapter 5 pre-seminar final reporting package',
      'generated_at_utc': datetime.now(timezone.utc).isoformat(),
      'experiment_rerun': False,
      'frozen_v7_modified': False,
      'reporting_only_change': True,
      'chapter_index_identical': chapter.exists() and index.exists() and sha256(chapter)==sha256(index),
      'chapter_sha256': sha256(chapter) if chapter.exists() else None,
      'inputs_and_outputs': entries,
    }
    out=chapter_dir/'FINAL_MANIFEST.json'
    out.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    print('FINAL_MANIFEST ->', out)
    print('Chapter SHA-256 ->', manifest['chapter_sha256'])
    print('Chapter/index identical ->', manifest['chapter_index_identical'])
    if not manifest['chapter_index_identical']:
        raise SystemExit(1)

if __name__=='__main__': main()
