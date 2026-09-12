from __future__ import annotations

import argparse
import json
from dataclasses import replace
from pathlib import Path

from .config import WeightConfig, load_config
from .experiments import run_experiment_grid
from .extension_campaign import run_extension_campaign
from .runner import run_campaign, run_trace_campaign
from .sensitivity import select_weights
from .sumo import doctor_report, prepare_sumo_scenario, run_multi_topology_campaign, run_sumo_campaign, run_sumo_trace
from .sumo.doctor import report_as_dict


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vpuft", description="V-PUFT research framework")
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="Check Python and SUMO/TraCI readiness")
    doctor.add_argument("--config", default=None)

    prepare = sub.add_parser("prepare-sumo", help="Build the bundled smoke network with netconvert")
    prepare.add_argument("--config", default=None)
    prepare.add_argument("--scenario-dir", default=None)
    prepare.add_argument("--force", action="store_true")

    sumo_trace = sub.add_parser("sumo-trace", help="Run one real SUMO/TraCI trace")
    sumo_trace.add_argument("--config", default=None)
    sumo_trace.add_argument("--scenario-dir", default=None)
    sumo_trace.add_argument("--output-dir", default="results/sumo_trace")
    sumo_trace.add_argument("--seed", type=int, default=None)
    sumo_trace.add_argument("--force-prepare", action="store_true")

    replay = sub.add_parser("replay", help="Replay a shared trace through the three architectures")
    replay.add_argument("--config", default=None)
    replay.add_argument("--trace", required=True)
    replay.add_argument("--output-dir", default="results/replay")

    sumo_campaign = sub.add_parser("sumo-campaign", help="Run multiple SUMO seeds, the three models, and optional sensitivity")
    sumo_campaign.add_argument("--config", default=None)
    sumo_campaign.add_argument("--scenario-dir", default=None)
    sumo_campaign.add_argument("--output-dir", default="results/sumo_campaign")
    sumo_campaign.add_argument("--seeds", nargs="+", type=int, required=True)
    sumo_campaign.add_argument("--sensitivity", action="store_true")
    sumo_campaign.add_argument("--candidates", type=int, default=1200)
    sumo_campaign.add_argument("--bootstrap-repeats", type=int, default=200)
    sumo_campaign.add_argument("--min-recall", type=float, default=0.90)
    sumo_campaign.add_argument("--max-frr", type=float, default=0.08)
    sumo_campaign.add_argument("--resume", action="store_true", help="Reuse completed seed runs and continue interrupted work")

    topology_campaign = sub.add_parser("topology-campaign", help="Run the same seeds on multiple SUMO road topologies")
    topology_campaign.add_argument("--config", default=None)
    topology_campaign.add_argument("--scenarios", nargs="+", required=True)
    topology_campaign.add_argument("--output-dir", default="results/topology_campaign")
    topology_campaign.add_argument("--seeds", nargs="+", type=int, required=True)
    topology_campaign.add_argument("--sensitivity", action="store_true")
    topology_campaign.add_argument("--candidates", type=int, default=1200)
    topology_campaign.add_argument("--bootstrap-repeats", type=int, default=200)
    topology_campaign.add_argument("--min-recall", type=float, default=0.90)
    topology_campaign.add_argument("--max-frr", type=float, default=0.08)
    topology_campaign.add_argument("--resume", action="store_true", help="Reuse completed topology/seed runs and continue interrupted work")

    campaign = sub.add_parser("campaign", help="Run the synthetic three-architecture campaign")
    campaign.add_argument("--config", default=None)
    campaign.add_argument("--output-dir", default="results/campaign")

    sensitivity = sub.add_parser("sensitivity", help="Select defensible V-PUFT weights")
    sensitivity.add_argument("--input", required=True)
    sensitivity.add_argument("--config", default=None)
    sensitivity.add_argument("--output-dir", default="results/sensitivity")
    sensitivity.add_argument("--candidates", type=int, default=1200)
    sensitivity.add_argument("--bootstrap-repeats", type=int, default=200)
    sensitivity.add_argument("--permutation-repeats", type=int, default=50)
    sensitivity.add_argument("--min-recall", type=float, default=0.90)
    sensitivity.add_argument("--max-frr", type=float, default=0.08)
    sensitivity.add_argument("--resume", action="store_true", help="Resume candidate search from checkpoints")
    sensitivity.add_argument("--checkpoint-every", type=int, default=25, help="Save candidate-search checkpoint every N candidates")
    sensitivity.add_argument("--jobs", type=int, default=1, help="Parallel candidate workers (1 is safest; try 2-4 on multi-core CPUs)")

    grid = sub.add_parser("grid", help="Run synthetic load/PDR/failure experiment grid")
    grid.add_argument("--config", default=None)
    grid.add_argument("--grid", default="configs/experiment_grid.json")
    grid.add_argument("--output-dir", default="results/grid")

    demo = sub.add_parser("demo", help="Run a testable synthetic campaign and sensitivity analysis")
    demo.add_argument("--config", default=None)
    demo.add_argument("--output-dir", default="results/demo")
    demo.add_argument("--candidates", type=int, default=250)
    demo.add_argument("--bootstrap-repeats", type=int, default=30)

    extension = sub.add_parser(
        "extension-campaign",
        help="Run dynamic-RSU, malicious-RSU/validator, and V2V TTL experiments without rerunning Centralized Near-Edge",
    )
    extension.add_argument("--config", default="configs/extension_campaign.json")
    extension.add_argument("--output-dir", default="results/extension_campaign")
    extension.add_argument(
        "--weights",
        default=None,
        help="Optional selected_weights.json used by the frozen v7 campaign",
    )
    extension.add_argument(
        "--traces",
        nargs="*",
        default=None,
        help="Optional frozen sensor trace JSONL files; avoids rerunning SUMO",
    )
    return parser


def main() -> None:
    args = _parser().parse_args()
    config = load_config(getattr(args, "config", None))

    if args.command == "doctor":
        report = doctor_report(config.sumo.sumo_binary, config.sumo.netconvert_binary)
        print(json.dumps(report_as_dict(report), indent=2))
    elif args.command == "prepare-sumo":
        scenario = args.scenario_dir or config.sumo.scenario_directory
        path = prepare_sumo_scenario(scenario, netconvert_binary=config.sumo.netconvert_binary, force=args.force)
        print(path)
    elif args.command == "sumo-trace":
        scenario = args.scenario_dir or config.sumo.scenario_directory
        manifest = run_sumo_trace(
            config,
            scenario_directory=scenario,
            output_directory=args.output_dir,
            seed=args.seed,
            force_prepare=args.force_prepare,
        )
        print(json.dumps(manifest, indent=2))
    elif args.command == "replay":
        manifest = run_trace_campaign(config, args.trace, args.output_dir)
        print(json.dumps(manifest, indent=2))
    elif args.command == "sumo-campaign":
        scenario = args.scenario_dir or config.sumo.scenario_directory
        manifest = run_sumo_campaign(
            config,
            scenario_directory=scenario,
            output_directory=args.output_dir,
            seeds=args.seeds,
            run_sensitivity=args.sensitivity,
            candidates=args.candidates,
            bootstrap_repeats=args.bootstrap_repeats,
            min_recall=args.min_recall,
            max_frr=args.max_frr,
            resume=args.resume,
        )
        print(json.dumps(manifest, indent=2))
    elif args.command == "topology-campaign":
        manifest = run_multi_topology_campaign(
            config,
            scenario_directories=args.scenarios,
            output_directory=args.output_dir,
            seeds=args.seeds,
            run_sensitivity=args.sensitivity,
            candidates=args.candidates,
            bootstrap_repeats=args.bootstrap_repeats,
            min_recall=args.min_recall,
            max_frr=args.max_frr,
            resume=args.resume,
        )
        print(json.dumps(manifest, indent=2))
    elif args.command == "campaign":
        print(json.dumps(run_campaign(config, args.output_dir), indent=2))
    elif args.command == "sensitivity":
        result = select_weights(
            args.input,
            args.output_dir,
            config,
            candidates=args.candidates,
            bootstrap_repeats=args.bootstrap_repeats,
            permutation_repeats=args.permutation_repeats,
            min_recall=args.min_recall,
            max_frr=args.max_frr,
            resume=args.resume,
            checkpoint_every=args.checkpoint_every,
            jobs=args.jobs,
        )
        print(json.dumps(result, indent=2))
    elif args.command == "grid":
        print(run_experiment_grid(config, args.grid, args.output_dir))
    elif args.command == "demo":
        root = Path(args.output_dir)
        campaign_dir = root / "campaign"
        sensitivity_dir = root / "sensitivity"
        run_campaign(config, campaign_dir)
        result = select_weights(
            campaign_dir / "evidence_campaign.csv",
            sensitivity_dir,
            config,
            candidates=args.candidates,
            bootstrap_repeats=args.bootstrap_repeats,
            permutation_repeats=10,
            min_recall=0.60,
            max_frr=0.35,
        )
        print(json.dumps(result, indent=2))
    elif args.command == "extension-campaign":
        if args.weights:
            selected = json.loads(Path(args.weights).read_text(encoding="utf-8"))
            config = replace(config, weights=WeightConfig(**selected["weights"]))
            config.validate()
        print(json.dumps(run_extension_campaign(config, args.output_dir, args.traces), indent=2))


if __name__ == "__main__":
    main()
