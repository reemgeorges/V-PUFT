from __future__ import annotations

import pandas as pd

from vpuft.sensitivity import _prepare_dataframe


def _row(source_kind: str) -> dict:
    return {
        'topology': 'smoke',
        'case_id': 'case-1',
        'observation_root_id': 'root-1',
        'seed': 1001,
        'attack_type': 'benign',
        'label': 0,
        'validity': 1,
        'direction': 0,
        'source_id': 'src-1',
        'source_kind': source_kind,
        'geographic_cell': 'cell-1',
        'sensor_modality': 'v2x',
        'detector_confidence': 0.8,
        'source_reliability': 0.9,
        'freshness': 0.9,
        'verifiability': 0.9,
        'independence': 0.8,
    }


def test_calibration_separates_rsu_and_witness_views(tmp_path):
    path = tmp_path / 'evidence.csv'
    pd.DataFrame([_row('rsu'), _row('vehicle_witness')]).to_csv(path, index=False)
    prepared = _prepare_dataframe(path)
    assert set(prepared['calibration_view']) == {'rsu', 'witness'}
    assert prepared['architecture'].nunique() == 2
    assert any('view=rsu::topology=smoke' in x for x in prepared['architecture'])
    assert any('view=witness::topology=smoke' in x for x in prepared['architecture'])
