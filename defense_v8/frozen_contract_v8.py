"""
V-PUFT v8 - Frozen v7 contract verification.

PURPOSE
-------
Every post-freeze script imports this and calls verify_frozen_contract() before
doing anything else. If any element of the frozen v7 experiment has drifted, the
script aborts. Nothing is auto-corrected and nothing is warned-and-continued.

This exists because relying on a directory path to identify the correct weights
is fragile: a stale sibling directory silently yields stale weights, and the
failure is invisible in the output. Verifying the weight VALUES against the
numbers recorded in FREEZE_NOTES.txt removes that entire class of error.

The frozen constants below are transcribed from:
    FINAL_FREEZE_v7_20260809/FREEZE_NOTES.txt
    FINAL_FREEZE_v7_20260809/config/full_experiment_FINAL.json

Do not edit them. If they ever need to change, the freeze has been broken and
that is a decision to be made explicitly, not by editing this file.

USAGE (as a module)
-------------------
    from frozen_contract_v8 import verify_frozen_contract
    contract = verify_frozen_contract(config_path, weights_path, trace_paths)
    # raises FrozenContractError on any mismatch

USAGE (standalone check)
------------------------
    python frozen_contract_v8.py \
        --config  configs/full_experiment.json \
        --weights results/full_campaign_v7/sensitivity_shared_views_mixedfix/selected_weights.json \
        --traces  results/full_campaign_v7
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Frozen v7 constants - candidate 650
# ---------------------------------------------------------------------------

FROZEN_WEIGHTS = {
    "C": 0.3652673861753211,
    "rho": 0.16195260151983162,
    "F": 0.06370517641034751,
    "Q": 0.40608957775126925,
    "eta": 0.0029852581432305157,
}

FROZEN_CANDIDATE = 650

# Policy invariants that were corrected before the freeze and must not move again.
FROZEN_POLICY_CHECKS = {
    "mixed.required_modalities": 1,
}

# Exact-equality tolerance. These are transcribed float literals, not computed
# values, so they must match bit-for-bit. A loose tolerance here would defeat
# the entire purpose of the check.
WEIGHT_TOLERANCE = 0.0


class FrozenContractError(RuntimeError):
    """Raised when any part of the frozen v7 contract does not match."""


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest().upper()


def _expected_external_hash(freeze_root: Path | None, target_suffix: str) -> str | None:
    """Read an expected SHA-256 from the freeze's EXTERNAL_ARTIFACT_HASHES.csv."""
    if freeze_root is None:
        return None
    table = freeze_root / "EXTERNAL_ARTIFACT_HASHES.csv"
    if not table.exists():
        return None
    suffix = target_suffix.replace("\\", "/").lower()
    with table.open("r", encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            raw_path = str(row.get("Path", "")).replace("\\", "/").lower()
            if raw_path.endswith(suffix):
                value = str(row.get("Hash", "")).strip().upper()
                return value or None
    return None


def _check_weights(weights_path: Path) -> dict:
    if not weights_path.exists():
        raise FrozenContractError(f"Weights file not found: {weights_path}")

    payload = json.loads(weights_path.read_text(encoding="utf-8"))
    if "weights" not in payload:
        raise FrozenContractError(f"'weights' key missing in {weights_path}")

    loaded = payload["weights"]
    problems = []

    for key, expected in FROZEN_WEIGHTS.items():
        if key not in loaded:
            problems.append(f"  missing weight '{key}'")
            continue
        actual = float(loaded[key])
        if abs(actual - expected) > WEIGHT_TOLERANCE:
            problems.append(
                f"  {key}: expected {expected!r}, found {actual!r} "
                f"(delta {actual - expected:+.3e})"
            )

    extra = set(loaded) - set(FROZEN_WEIGHTS)
    if extra:
        problems.append(f"  unexpected weight keys: {sorted(extra)}")

    # The exponents must still form a convex combination.
    total = sum(float(loaded[k]) for k in FROZEN_WEIGHTS if k in loaded)
    if abs(total - 1.0) > 1e-9:
        problems.append(f"  weights do not sum to 1 (sum = {total!r})")

    if problems:
        raise FrozenContractError(
            "Loaded weights do not match frozen candidate "
            f"{FROZEN_CANDIDATE}:\n" + "\n".join(problems) +
            f"\n\nFile checked: {weights_path}\n"
            "This is almost always a stale sibling directory. Do NOT proceed."
        )

    candidate = payload.get("candidate", payload.get("candidate_id"))
    if candidate is not None and int(candidate) != FROZEN_CANDIDATE:
        raise FrozenContractError(
            f"Weights file declares candidate {candidate}, expected {FROZEN_CANDIDATE}."
        )

    return loaded


def _check_policies(config_path: Path) -> dict:
    if not config_path.exists():
        raise FrozenContractError(f"Config file not found: {config_path}")

    raw = json.loads(config_path.read_text(encoding="utf-8-sig"))
    policies = raw.get("policies", {})
    problems = []
    observed = {}

    for dotted, expected in FROZEN_POLICY_CHECKS.items():
        policy_name, _, field = dotted.partition(".")
        entry = policies.get(policy_name)
        if entry is None:
            problems.append(f"  policy '{policy_name}' not present in config")
            continue
        actual = entry.get(field)
        observed[dotted] = actual
        if actual != expected:
            problems.append(f"  {dotted}: expected {expected}, found {actual}")

    if problems:
        raise FrozenContractError(
            "Frozen policy invariants violated:\n" + "\n".join(problems) +
            f"\n\nFile checked: {config_path}"
        )

    return observed


def verify_frozen_contract(
    config_path: str | Path,
    weights_path: str | Path,
    trace_paths: list[str | Path] | None = None,
    *,
    freeze_root: str | Path | None = None,
    verbose: bool = True,
) -> dict:
    """
    Verify the frozen v7 contract. Raises FrozenContractError on any mismatch.

    Returns a manifest dict suitable for writing next to the run outputs, so
    that every result directory carries proof of which inputs produced it.
    """
    config_path = Path(config_path)
    weights_path = Path(weights_path)
    freeze_root_path = Path(freeze_root) if freeze_root is not None else None

    weights = _check_weights(weights_path)
    policies = _check_policies(config_path)

    config_hash = sha256_file(config_path)
    weights_hash = sha256_file(weights_path)

    expected_config_hash = _expected_external_hash(
        freeze_root_path, "configs/full_experiment.json"
    )
    external_config_hash_verified = False
    if expected_config_hash is not None:
        if config_hash != expected_config_hash:
            raise FrozenContractError(
                "Current configs/full_experiment.json does not match the SHA-256 "
                "recorded in the frozen EXTERNAL_ARTIFACT_HASHES.csv.\n"
                f"expected: {expected_config_hash}\n"
                f"actual:   {config_hash}"
            )
        external_config_hash_verified = True

    trace_hashes: dict[str, str] = {}
    if trace_paths:
        for tp in trace_paths:
            tp = Path(tp)
            if not tp.exists():
                raise FrozenContractError(f"Declared input trace not found: {tp}")
            trace_hashes[str(tp)] = sha256_file(tp)

    manifest = {
        "frozen_candidate": FROZEN_CANDIDATE,
        "weights": weights,
        "weights_file": str(weights_path),
        "weights_sha256": weights_hash,
        "config_file": str(config_path),
        "config_sha256": config_hash,
        "freeze_root": str(freeze_root_path) if freeze_root_path is not None else None,
        "expected_external_config_sha256": expected_config_hash,
        "external_config_hash_verified": external_config_hash_verified,
        "policy_invariants": policies,
        "input_trace_sha256": trace_hashes,
        "sumo_rerun": False,
        "detector_rerun": False,
        "calibration_rerun": False,
        "candidate_search_rerun": False,
    }

    if verbose:
        print("=== FROZEN V7 CONTRACT ===")
        print(f"Weights .............. MATCH (candidate {FROZEN_CANDIDATE})")
        print(f"Mixed modalities ..... MATCH ({policies.get('mixed.required_modalities')})")
        print(f"Config sha256 ........ {config_hash[:16]}...")
        if expected_config_hash is not None:
            print("Freeze config hash .... MATCH")
        else:
            print("Freeze config hash .... not available (value checks still enforced)")
        print(f"Weights sha256 ....... {weights_hash[:16]}...")
        if trace_hashes:
            print(f"Input traces ......... {len(trace_hashes)} RECORDED")
        print("Detector rerun ....... NO")
        print("SUMO rerun ........... NO")
        print("Calibration rerun .... NO")
        print("==========================\n")

    return manifest


def main() -> None:
    ap = argparse.ArgumentParser(description="Verify the frozen V-PUFT v7 contract.")
    ap.add_argument("--config", required=True)
    ap.add_argument("--weights", required=True)
    ap.add_argument("--traces", default=None,
                    help="Directory containing <topology>/sensor_detection_trace_all_seeds.jsonl")
    ap.add_argument("--topologies", nargs="+",
                    default=["smoke", "corridor", "intersection", "grid"])
    ap.add_argument("--freeze-root", default="FINAL_FREEZE_v7_20260809",
                    help="Frozen v7 directory containing EXTERNAL_ARTIFACT_HASHES.csv.")
    ap.add_argument("--write-manifest", default=None)
    args = ap.parse_args()

    trace_paths = []
    if args.traces:
        root = Path(args.traces)
        for topo in args.topologies:
            p = root / topo / "sensor_detection_trace_all_seeds.jsonl"
            if p.exists():
                trace_paths.append(p)

    try:
        manifest = verify_frozen_contract(
            args.config, args.weights, trace_paths, freeze_root=args.freeze_root
        )
    except FrozenContractError as exc:
        print("=== FROZEN V7 CONTRACT: FAILED ===", file=sys.stderr)
        print(str(exc), file=sys.stderr)
        sys.exit(2)

    if args.write_manifest:
        out = Path(args.write_manifest)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(f"manifest written to {out}")

    print("CONTRACT OK")


if __name__ == "__main__":
    main()
