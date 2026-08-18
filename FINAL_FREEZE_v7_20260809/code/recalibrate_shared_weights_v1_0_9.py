from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from vpuft.config import load_config
from vpuft.sensitivity import select_weights


def main() -> None:
    parser = argparse.ArgumentParser(description='v1.0.9 shared-weight calibration with separate RSU/witness runtime views.')
    parser.add_argument('--input', default='results/full_campaign_v4/all_topologies_evidence_campaign.csv')
    parser.add_argument('--output', default='results/full_campaign_v6/sensitivity_shared_views')
    parser.add_argument('--config', default='configs/full_experiment.json')
    parser.add_argument('--candidates', type=int, default=1200)
    parser.add_argument('--folds', type=int, default=5)
    parser.add_argument('--bootstrap-repeats', type=int, default=200)
    parser.add_argument('--permutation-repeats', type=int, default=50)
    parser.add_argument('--min-recall', type=float, default=0.95)
    parser.add_argument('--max-frr', type=float, default=0.05)
    parser.add_argument('--random-seed', type=int, default=20260804)
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--checkpoint-every', type=int, default=25)
    parser.add_argument('--resume', action='store_true')
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    if not input_path.exists():
        raise SystemExit(f'Missing evidence CSV: {input_path}')

    df = pd.read_csv(input_path, usecols=lambda c: c in {'source_kind', 'case_id'})
    print('[v1.0.9] shared-weight recalibration only', flush=True)
    print('[v1.0.9] SUMO rerun: NO; detector rebuild: NO', flush=True)
    if 'source_kind' in df.columns:
        print('[v1.0.9] rows by source:', flush=True)
        print(df.groupby('source_kind').size().to_string(), flush=True)
        print('[v1.0.9] unique cases by source:', flush=True)
        print(df.groupby('source_kind')['case_id'].nunique().to_string(), flush=True)

    cfg = load_config(args.config)
    result = select_weights(
        input_path,
        output_path,
        cfg,
        candidates=args.candidates,
        folds=args.folds,
        min_recall=args.min_recall,
        max_frr=args.max_frr,
        bootstrap_repeats=args.bootstrap_repeats,
        permutation_repeats=args.permutation_repeats,
        random_seed=args.random_seed,
        resume=args.resume,
        checkpoint_every=args.checkpoint_every,
        jobs=args.jobs,
    )

    view_path = output_path / 'holdout_metrics_by_calibration_view.csv'
    views = pd.read_csv(view_path).to_dict(orient='records') if view_path.exists() else []
    summary = {
        'scope': 'shared V-PUFT weight recalibration only',
        'sumo_rerun_required': False,
        'detector_rebuild_required': False,
        'calibration_case_semantics': 'RSU and witness evidence are separate runtime views; never fused into one case',
        'selection_rule': 'one shared weight vector; ranking/constraints use worst fold x evidence-source view',
        'selected_weights': result.get('weights'),
        'selection_feasible': result.get('selection_feasible'),
        'holdout_metrics_overall': result.get('holdout_metrics'),
        'holdout_metrics_by_calibration_view': views,
        'output': str(output_path.resolve()),
    }
    (output_path / 'v1_0_9_shared_view_summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print('[v1.0.9] COMPLETE', flush=True)
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == '__main__':
    main()
