#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
vpuft demo --config configs/demo.json --output-dir results/demo
