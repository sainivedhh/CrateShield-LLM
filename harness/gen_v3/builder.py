"""CrateShield Benchmark v3 Generator Engine (Phase 2 & Phase 3).

Builds 50 clusters (10 tune, 40 eval) x 3 twins = 150 samples.
Supports --dry-run.
Preserves line endings and enforces Independence Firewall.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import logging
import os
from pathlib import Path
import random
import shutil
import time
from typing import Any
import yaml

import sys
ROOT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(ROOT_DIR / "src"))

from harness.gen_v3.client import generate_payload
from harness.gen_v3.config import TRACKER
from harness.gen_v3.mutate import apply_mutation_ladder, create_lookalike_twin, detect_line_ending
from harness.view import build_anonymized_view, compute_view_id
from crateshield.ingestion.downloader import preprocess_crate
from crateshield.llm.packing import pack_source

logger = logging.getLogger("builder_v3")

ROOT = Path(__file__).resolve().parents[2]
BENCH_V3_DIR = ROOT / "data" / "bench_v3"
CORPUS_DIR = BENCH_V3_DIR / "corpus_private"
TAXONOMY_PATH = BENCH_V3_DIR / "taxonomy.yaml"
MANIFEST_PATH = BENCH_V3_DIR / "manifest.json"
SELECTED_BASES_PATH = BENCH_V3_DIR / "selected_50_bases.json"


def sha256_tree(dir_path: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(dir_path.glob("**/*")):
        if p.is_file():
            h.update(p.relative_to(dir_path).as_posix().encode("utf-8"))
            h.update(p.read_bytes())
    return h.hexdigest()


def count_real_loc(crate_dir: Path) -> int:
    total = 0
    for rs in crate_dir.glob("**/*.rs"):
        try:
            lines = [l for l in rs.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]
            total += len(lines)
        except Exception:
            pass
    return total


def load_taxonomy() -> dict[str, Any]:
    with open(TAXONOMY_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def build_benchmark_v3(dry_run: bool = False, seed: int = 42) -> dict[str, Any]:
    rng = random.Random(seed)
    
    with open(SELECTED_BASES_PATH, "r", encoding="utf-8") as f:
        bases = json.load(f)
    assert len(bases) == 50, f"Expected 50 bases, got {len(bases)}"

    taxonomy = load_taxonomy()
    fam_by_id = {f["id"]: f for f in taxonomy["families"]}
    
    seen_fams = [f["id"] for f in taxonomy["families"] if f["split"] == "SEEN"]
    held_fams = [f["id"] for f in taxonomy["families"] if f["split"] == "HELD-OUT"]

    tune_bases = bases[:10]
    eval_bases = bases[10:]

    # Plan assignments
    ladder_levels = ["L0", "L1", "L2", "L3", "L4"]
    positions = ["start", "middle", "end"]
    host_styles = ["example-subdomain", "reserved-invalid-or-test", "none"]
    generators = [("gemini-3.5-flash-lite", "gemini-3.5-flash-lite"), ("groq-qwen-3.8-27b", "qwen/qwen3.8-27b")]

    records = []
    sample_counter = 1

    CORPUS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. TUNE SPLIT (10 clusters)
    print("--- Planning/Building TUNE Split (10 clusters) ---")
    for idx, base in enumerate(tune_bases):
        cluster_id = base["name"]
        pair_id = f"pair_v3_{cluster_id}"
        family_id = seen_fams[idx % len(seen_fams)]
        fam_meta = fam_by_id[family_id]
        level = ladder_levels[idx % len(ladder_levels)]
        pos = positions[idx % len(positions)]
        h_style = host_styles[idx % 2] if family_id != "F4" else "none"
        gen_id, gen_model = generators[idx % len(generators)]
        base_dir = Path(base["root"])

        carrier = "build.rs" if (base_dir / "build.rs").exists() else "src/lib.rs"

        # Triple: clean, malicious, lookalike
        sample_triplet = [
            ("clean", "BENIGN"),
            ("malicious", "MALICIOUS"),
            ("lookalike_benign", "BENIGN"),
        ]

        for twin_type, label in sample_triplet:
            sample_id = f"s3_{sample_counter:04d}_{twin_type}"
            sample_dir = CORPUS_DIR / sample_id
            if sample_dir.exists():
                shutil.rmtree(sample_dir)
            shutil.copytree(base_dir, sample_dir)

            hunk_ranges = []
            payload_bytes = 0

            carrier_path = sample_dir / carrier
            if not carrier_path.exists():
                rs_files = list(sample_dir.glob("**/*.rs"))
                carrier_path = rs_files[0] if rs_files else (sample_dir / "src" / "lib.rs")

            carrier_code = carrier_path.read_text(encoding="utf-8", errors="ignore") if carrier_path.exists() else "fn main() {}\n"

            if twin_type == "malicious":
                # Generate or dry-run payload
                gen_res = generate_payload(
                    behaviour_spec=fam_meta["behaviour_spec"],
                    base_crate_context=carrier_code[:1000],
                    carrier=carrier,
                    host_style=h_style,
                    generator_id=gen_id,
                    model=gen_model,
                    is_lookalike=False,
                    dry_run=dry_run,
                )
                mod_code, hunk_ranges, _ = apply_mutation_ladder(
                    base_code=carrier_code,
                    raw_payload=gen_res["code"],
                    ladder_level=level,
                    position=pos,
                    host_style=h_style,
                    seed=seed + sample_counter,
                    is_lookalike=False,
                )
                carrier_path.write_text(mod_code, encoding="utf-8")
                payload_bytes = len(mod_code.encode("utf-8")) - len(carrier_code.encode("utf-8"))

            elif twin_type == "lookalike_benign":
                gen_res = generate_payload(
                    behaviour_spec=fam_meta["benign_lookalike_spec"],
                    base_crate_context=carrier_code[:1000],
                    carrier=carrier,
                    host_style=h_style,
                    generator_id=gen_id,
                    model=gen_model,
                    is_lookalike=True,
                    dry_run=dry_run,
                )
                mod_code, hunk_ranges, _ = create_lookalike_twin(
                    base_code=carrier_code,
                    ladder_level=level,
                    position=pos,
                    host_style=h_style,
                    seed=seed + sample_counter,
                )
                carrier_path.write_text(mod_code, encoding="utf-8")
                payload_bytes = len(mod_code.encode("utf-8")) - len(carrier_code.encode("utf-8"))

            view_id = compute_view_id(cluster_id, salt="crateshield-v3")
            pre = preprocess_crate(cluster_id, base["version"], sample_dir)
            anonymized = build_anonymized_view(pre, salt="crateshield-v3")

            # Packing check for omitted region
            packed = pack_source(anonymized, budget_chars=60000)
            in_omitted = carrier_path.name in packed.get("omitted", [])

            rec = {
                "sample_id": sample_id,
                "pair_id": pair_id,
                "cluster_id": cluster_id,
                "split": "tune",
                "twin_type": twin_type,
                "label": label,
                "family": family_id,
                "seen_or_heldout": fam_meta["split"],
                "ladder_level": level,
                "carrier": carrier,
                "position": pos,
                "host_style": h_style if twin_type != "clean" else "none",
                "generator": gen_id if twin_type != "clean" else "none",
                "payload_bytes": max(0, payload_bytes),
                "hunk_line_ranges": hunk_ranges,
                "base_size": base["size_bytes"],
                "loc": count_real_loc(sample_dir),
                "payload_in_omitted_region": in_omitted,
                "view_hash": anonymized["view_hash"],
                "sha256": sha256_tree(sample_dir),
            }
            records.append(rec)
            sample_counter += 1

    # 2. EVAL SPLIT (40 clusters)
    print("--- Planning/Building EVAL Split (40 clusters) ---")
    eval_fam_plan = []
    # 25 SEEN clusters (5 each of F1, F2, F3, F4, F7)
    for fid in seen_fams:
        eval_fam_plan.extend([fid] * 5)
    # 15 HELD-OUT clusters (5 each of F5, F6, F8)
    for fid in held_fams:
        eval_fam_plan.extend([fid] * 5)
    rng.shuffle(eval_fam_plan)

    for idx, base in enumerate(eval_bases):
        cluster_id = base["name"]
        pair_id = f"pair_v3_{cluster_id}"
        family_id = eval_fam_plan[idx]
        fam_meta = fam_by_id[family_id]
        level = ladder_levels[idx % len(ladder_levels)]
        pos = positions[idx % len(positions)]
        h_style = host_styles[idx % 2] if family_id not in ("F4", "F8") else "none"
        gen_id, gen_model = generators[idx % len(generators)]
        base_dir = Path(base["root"])

        carrier = "build.rs" if (base_dir / "build.rs").exists() else "src/lib.rs"

        sample_triplet = [
            ("clean", "BENIGN"),
            ("malicious", "MALICIOUS"),
            ("lookalike_benign", "BENIGN"),
        ]

        for twin_type, label in sample_triplet:
            sample_id = f"s3_{sample_counter:04d}_{twin_type}"
            sample_dir = CORPUS_DIR / sample_id
            if sample_dir.exists():
                shutil.rmtree(sample_dir)
            shutil.copytree(base_dir, sample_dir)

            hunk_ranges = []
            payload_bytes = 0

            carrier_path = sample_dir / carrier
            if not carrier_path.exists():
                rs_files = list(sample_dir.glob("**/*.rs"))
                carrier_path = rs_files[0] if rs_files else (sample_dir / "src" / "lib.rs")

            carrier_code = carrier_path.read_text(encoding="utf-8", errors="ignore") if carrier_path.exists() else "fn main() {}\n"

            if twin_type == "malicious":
                gen_res = generate_payload(
                    behaviour_spec=fam_meta["behaviour_spec"],
                    base_crate_context=carrier_code[:1000],
                    carrier=carrier,
                    host_style=h_style,
                    generator_id=gen_id,
                    model=gen_model,
                    is_lookalike=False,
                    dry_run=dry_run,
                )
                mod_code, hunk_ranges, _ = apply_mutation_ladder(
                    base_code=carrier_code,
                    raw_payload=gen_res["code"],
                    ladder_level=level,
                    position=pos,
                    host_style=h_style,
                    seed=seed + sample_counter,
                    is_lookalike=False,
                )
                carrier_path.write_text(mod_code, encoding="utf-8")
                payload_bytes = len(mod_code.encode("utf-8")) - len(carrier_code.encode("utf-8"))

            elif twin_type == "lookalike_benign":
                gen_res = generate_payload(
                    behaviour_spec=fam_meta["benign_lookalike_spec"],
                    base_crate_context=carrier_code[:1000],
                    carrier=carrier,
                    host_style=h_style,
                    generator_id=gen_id,
                    model=gen_model,
                    is_lookalike=True,
                    dry_run=dry_run,
                )
                mod_code, hunk_ranges, _ = create_lookalike_twin(
                    base_code=carrier_code,
                    ladder_level=level,
                    position=pos,
                    host_style=h_style,
                    seed=seed + sample_counter,
                )
                carrier_path.write_text(mod_code, encoding="utf-8")
                payload_bytes = len(mod_code.encode("utf-8")) - len(carrier_code.encode("utf-8"))

            view_id = compute_view_id(cluster_id, salt="crateshield-v3")
            pre = preprocess_crate(cluster_id, base["version"], sample_dir)
            anonymized = build_anonymized_view(pre, salt="crateshield-v3")

            packed = pack_source(anonymized, budget_chars=60000)
            in_omitted = carrier_path.name in packed.get("omitted", [])

            rec = {
                "sample_id": sample_id,
                "pair_id": pair_id,
                "cluster_id": cluster_id,
                "split": "eval",
                "twin_type": twin_type,
                "label": label,
                "family": family_id,
                "seen_or_heldout": fam_meta["split"],
                "ladder_level": level,
                "carrier": carrier,
                "position": pos,
                "host_style": h_style if twin_type != "clean" else "none",
                "generator": gen_id if twin_type != "clean" else "none",
                "payload_bytes": max(0, payload_bytes),
                "hunk_line_ranges": hunk_ranges,
                "base_size": base["size_bytes"],
                "loc": count_real_loc(sample_dir),
                "payload_in_omitted_region": in_omitted,
                "view_hash": anonymized["view_hash"],
                "sha256": sha256_tree(sample_dir),
            }
            records.append(rec)
            sample_counter += 1

    manifest = {
        "version": "3.0",
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "seed": seed,
        "dry_run": dry_run,
        "total_clusters": 50,
        "tune_clusters": 10,
        "eval_clusters": 40,
        "total_samples": len(records),
        "samples": records,
    }

    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    usage = TRACKER.get_summary()
    print(f"Generated {len(records)} samples across 50 clusters.")
    print(f"Spend Tracker: {usage['calls']} calls, {usage['tokens_in']} prompt tokens, {usage['tokens_out']} completion tokens, ${usage['cost_usd']:.4f} USD")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build Benchmark v3 dataset")
    parser.add_argument("--dry-run", action="store_true", help="Perform dry run with zero API calls")
    args = parser.parse_args()
    build_benchmark_v3(dry_run=args.dry_run)