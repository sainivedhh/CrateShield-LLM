"""CLI usage:
    python -m crateshield analyze <name> <version> [--condition C] [--prescreen] [--no-holdout]
    python -m crateshield ablation [--conditions a,b,c] [--prescreen]
    python -m crateshield build-dataset [--probe]      # seeds + OSSF reports -> data/dataset.json
    python -m crateshield refresh-ossf                 # re-download OSSF reports from GitHub
    python -m crateshield serve [--port N]

Conditions: structured | structured_norag | raw | naive
"""
from __future__ import annotations

import argparse
import json
import sys

import logging
from crateshield.config import ALL_CONDITIONS, DATASET_PATH


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    parser = argparse.ArgumentParser(prog="crateshield")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_analyze = sub.add_parser("analyze")
    p_analyze.add_argument("name")
    p_analyze.add_argument("version")
    p_analyze.add_argument("--condition", default="structured", choices=list(ALL_CONDITIONS))
    p_analyze.add_argument("--prescreen", action="store_true",
                           help="skip the LLM when no cheap static signal fires (structured conditions)")
    p_analyze.add_argument("--no-holdout", action="store_true",
                           help="allow retrieval of the crate's own incident write-up (default off only when "
                                "no ground truth is given anyway)")

    p_abl = sub.add_parser("ablation")
    p_abl.add_argument("--conditions", default=",".join(ALL_CONDITIONS),
                       help="comma-separated subset of: " + ", ".join(ALL_CONDITIONS))
    p_abl.add_argument("--prescreen", action="store_true")
    p_abl.add_argument("--no-cargo-audit", action="store_true",
                       help="skip the cargo-audit baseline (it crawls the RustSec advisory DB via GitHub)")

    p_ds = sub.add_parser("build-dataset")
    p_ds.add_argument("--probe", action="store_true",
                      help="check crates.io availability first (metadata + HEAD only; downloads nothing)")

    sub.add_parser("refresh-ossf")

    p_serve = sub.add_parser("serve")
    p_serve.add_argument("--port", type=int, default=8000)

    args = parser.parse_args()

    if args.cmd == "analyze":
        from crateshield.pipeline import analyze_crate
        result = analyze_crate(args.name, args.version, condition=args.condition,
                               prescreen=args.prescreen, holdout=False if args.no_holdout else None)
        print(json.dumps(result, indent=2))

    elif args.cmd == "ablation":
        from crateshield.evaluation.ablation import run_full_ablation
        from crateshield.evaluation.metrics import print_ablation_table
        if not DATASET_PATH.exists():
            print(f"No dataset at {DATASET_PATH}", file=sys.stderr)
            sys.exit(1)
        dataset = json.loads(DATASET_PATH.read_text()).get("crates", [])
        conds = [c.strip() for c in args.conditions.split(",") if c.strip()]
        metrics = run_full_ablation(dataset, conditions=conds, prescreen=args.prescreen,
                                    include_cargo_audit=not args.no_cargo_audit)
        print_ablation_table(metrics)

    elif args.cmd == "build-dataset":
        from crateshield.ingestion import ossf
        ds = ossf.build_dataset(availability={} if args.probe else None)
        if args.probe:
            snap = ossf.probe_availability(ossf.dataset_targets(ds))
            ossf.save_availability(snap)
            ds = ossf.build_dataset(availability=snap)
        path = ossf.write_dataset(ds)
        print(f"wrote {path}: {ds['total_crates']} entries, {ds['analyzable_crates']} analyzable, "
              f"labels {ds['label_counts']}")

    elif args.cmd == "refresh-ossf":
        from crateshield.ingestion import ossf
        manifest = ossf.refresh_from_github()
        print(json.dumps(manifest, indent=2))
        print("Now run: python -m crateshield build-dataset --probe")

    elif args.cmd == "serve":
        import uvicorn
        uvicorn.run("crateshield.api:app", host="0.0.0.0", port=args.port, reload=True)


if __name__ == "__main__":
    main()
