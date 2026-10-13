"""CrateShield Evaluation Harness v2 Benchmark Generator.

Implements Phase 2 and Phase 3 of Spec v2:
1. Builds data/bench_v2 with 10 Tune and 30 Fresh Eval base crates.
2. Disjoint from v1 eval base crates.
3. Injects tell-free v2 payloads with preserved line endings.
4. Alternates fabricated vs .invalid domains (H2).
5. Implements scale-test arm with real packing verification for payload_in_omitted_region (H3).
6. Computes real LOC counts and ISO created_at timestamps.
"""
from __future__ import annotations

from collections import defaultdict
import datetime
import json
import logging
from pathlib import Path
import random
import shutil
from typing import Any

from crateshield.config import DATA_DIR
from crateshield.ingestion.downloader import preprocess_crate
from crateshield.llm.packing import pack_source
from harness.audit_v2 import audit_line_endings_match, audit_twin_diff_hunk_clean, audit_tell_frequency
from harness.inject_v2 import inject_payload_v2, load_templates_v2
from harness.manifest import BenchmarkManifest, SampleRecord, save_manifest
from harness.sampler import classify_build_rs_behavior, is_crate_eligible, load_malicious_denylist, stratify_and_sample
from harness.view import build_anonymized_view, compute_view_id

logger = logging.getLogger("bench_v2")

BENCH_V2_DIR = DATA_DIR / "bench_v2"
PAYLOADS_V2_DIR = Path(__file__).resolve().parent / "payloads" / "v2"


def count_real_loc(crate_dir: Path) -> int:
    """Computes exact non-empty LOC across all .rs files in crate."""
    total_loc = 0
    for rs in crate_dir.glob("**/*.rs"):
        try:
            lines = [l for l in rs.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]
            total_loc += len(lines)
        except Exception:
            pass
    return total_loc


def generate_benchmark_v2(
    n_tune: int = 10,
    n_eval: int = 30,
    seed: int = 42,
) -> BenchmarkManifest:
    """Generates the complete v2 benchmark dataset."""
    BENCH_V2_DIR.mkdir(parents=True, exist_ok=True)
    pairs_dir = BENCH_V2_DIR / "pairs"
    pairs_dir.mkdir(parents=True, exist_ok=True)

    # 1. Load candidate crates
    v1_manifest_path = DATA_DIR / "bench_v1" / "manifest.json"
    v1_eval_bases = set()
    v1_tune_bases = set()
    if v1_manifest_path.exists():
        v1_data = json.loads(v1_manifest_path.read_text(encoding="utf-8"))
        v1_eval_bases = set(r["base_crate"] for r in v1_data.get("samples", []) if r.get("split") == "eval")
        v1_tune_bases = set(r["base_crate"] for r in v1_data.get("samples", []) if r.get("split") == "tune")

    cand_dir = DATA_DIR / "bench_v1" / "base_candidates"
    denylist = load_malicious_denylist()
    all_candidates = []

    for d in sorted(cand_dir.iterdir()):
        if not d.is_dir():
            continue
        build_rs = d / "build.rs"
        if not build_rs.exists():
            sub = [p for p in d.iterdir() if p.is_dir() and (p / "build.rs").exists()]
            if sub:
                build_rs = sub[0] / "build.rs"
            else:
                continue
        root = build_rs.parent
        crate_name = d.name.rsplit("-", 1)[0]
        ver = d.name.rsplit("-", 1)[1] if "-" in d.name else "1.0.0"

        ok, _ = is_crate_eligible({"name": crate_name}, root, denylist)
        if ok:
            b_class = classify_build_rs_behavior(build_rs.read_text(encoding="utf-8", errors="ignore"))
            sz = sum(f.stat().st_size for f in root.glob("**/*.rs"))
            loc = count_real_loc(root)
            all_candidates.append({
                "name": crate_name,
                "version": ver,
                "root_dir": str(root),
                "build_class": b_class,
                "size_bytes": sz,
                "loc": loc,
                "in_v1_eval": crate_name in v1_eval_bases,
                "in_v1_tune": crate_name in v1_tune_bases,
            })

    # Fresh candidates for eval (strictly not in v1 eval)
    fresh_for_eval = [c for c in all_candidates if not c["in_v1_eval"]]
    logger.info("Total eligible candidates: %d (Fresh for eval: %d)", len(all_candidates), len(fresh_for_eval))

    # Stratify and sample fresh eval bases
    eval_sampled = stratify_and_sample(fresh_for_eval, target_count=n_eval, seed=seed)
    eval_names = set(c["name"] for c in eval_sampled)

    # For tune bases: pick 10 disjoint from eval
    tune_pool = [c for c in all_candidates if c["name"] not in eval_names]
    tune_sampled = stratify_and_sample(tune_pool, target_count=n_tune, seed=seed + 99)

    # Verify disjointness
    tune_names = set(c["name"] for c in tune_sampled)
    assert not (tune_names & eval_names), "Tune and Eval bases must be strictly disjoint!"

    # Load v2 templates
    templates = load_templates_v2(PAYLOADS_V2_DIR)
    manifest = BenchmarkManifest(
        version="v2",
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        seed=seed,
        target_scale=n_tune + n_eval,
    )

    placements = ["P1", "P1", "P2", "P3", "P4", "P5"]
    domain_types = ["fabricated", "invalid"]

    sample_counter = 1
    dest_files_mal = []
    dest_files_ben = []

    splits = [("tune", tune_sampled), ("eval", eval_sampled)]

    for split_name, base_list in splits:
        for i, base in enumerate(base_list):
            base_name = base["name"]
            base_ver = base["version"]
            base_root = Path(base["root_dir"])
            pair_id = f"pair_v2_{base_name}_{base_ver}"

            # 1. Clean benign twin
            benign_id = f"s_{sample_counter:04d}_benign"
            benign_dest = pairs_dir / f"{split_name}_{benign_id}"
            if benign_dest.exists():
                shutil.rmtree(benign_dest)
            shutil.copytree(base_root, benign_dest)

            benign_loc = count_real_loc(benign_dest)
            benign_view_id = compute_view_id(base_name, salt="crateshield-v2")
            pre_benign = preprocess_crate(base_name, base_ver, benign_dest)
            view_benign = build_anonymized_view(pre_benign)

            rec_benign = SampleRecord(
                sample_id=benign_id,
                view_id=benign_view_id,
                pair_id=pair_id,
                cluster_id=base_name,
                tier=3,
                split=split_name,
                label="BENIGN",
                label_evidence="presumed-benign (no RustSec/OSSF report)",
                base_crate=base_name,
                base_version=base_ver,
                dump_date="2026-10-09",
                domain_type="none",
                payload_in_omitted_region=False,
                size_bytes=base["size_bytes"],
                loc=benign_loc,
                view_hash=view_benign["view_hash"],
            )
            manifest.records.append(rec_benign)
            sample_counter += 1
            if (benign_dest / "build.rs").exists():
                dest_files_ben.append(benign_dest / "build.rs")

            # 2. Injected twin
            tmpl = templates[(i + sample_counter) % len(templates)]
            placement = placements[(i + sample_counter) % len(placements)]
            domain_type = domain_types[i % 2]  # alternate fabricated vs invalid for H2

            # Scale-test arm: for large crates with modules, place in an omitted file
            target_omitted_file = None
            if split_name == "eval" and base["size_bytes"] > 60000 and (i % 3 == 0):
                base_packed = pack_source(view_benign, budget_chars=60000)
                omitted_files = [f for f in base_packed.get("omitted", []) if f.endswith(".rs")]
                if omitted_files:
                    target_omitted_file = omitted_files[i % len(omitted_files)]
                    placement = "P3"

            mal_id = f"s_{sample_counter:04d}_malicious"
            mal_dest = pairs_dir / f"{split_name}_{mal_id}"

            inj_res = inject_payload_v2(
                base_dir=base_root,
                dest_dir=mal_dest,
                template=tmpl,
                variant_idx=i,
                placement=placement,
                domain_type=domain_type,
                target_file_rel=target_omitted_file,
                seed=seed + i * 17,
            )

            # Audit line endings match
            inj_file_rel = inj_res["injected_file"]
            if inj_file_rel:
                b_file = base_root / inj_file_rel
                m_file = mal_dest / inj_file_rel
                if b_file.exists() and m_file.exists():
                    ok_le, msg_le = audit_line_endings_match(b_file, m_file)
                    if not ok_le:
                        logger.warning("Line ending issue in %s: %s", mal_id, msg_le)
                    ok_diff, msg_diff = audit_twin_diff_hunk_clean(b_file, m_file)
                    if not ok_diff:
                        logger.warning("Diff hunk issue in %s: %s", mal_id, msg_diff)
                    if m_file.name == "build.rs":
                        dest_files_mal.append(m_file)

            # Test packing omission status (H3 scale test)
            pre_mal = preprocess_crate(base_name, base_ver, mal_dest)
            view_mal = build_anonymized_view(pre_mal)
            packed = pack_source(view_mal, budget_chars=60000)

            # Check if injected file was omitted or truncated
            payload_omitted = False
            if inj_file_rel and inj_file_rel in packed.get("omitted", []):
                payload_omitted = True
            elif inj_file_rel and any(inj_file_rel in part for part in packed.get("partial", [])):
                payload_omitted = True

            mal_loc = count_real_loc(mal_dest)
            rec_mal = SampleRecord(
                sample_id=mal_id,
                view_id=benign_view_id,  # Shared neutral view_id per pair
                pair_id=pair_id,
                cluster_id=base_name,
                tier=3,
                split=split_name,
                label="MALICIOUS",
                label_evidence="injected-twin",
                base_crate=base_name,
                base_version=base_ver,
                dump_date="2026-10-09",
                template_id=inj_res["template_id"],
                category=inj_res["category"],
                placement=inj_res["placement"],
                obfuscation_level=inj_res["obfuscation_level"],
                surface_variant=inj_res["surface_variant"],
                domain_type=domain_type,
                payload_in_omitted_region=payload_omitted,
                payload_bytes=inj_res["payload_bytes"],
                size_bytes=base["size_bytes"] + inj_res["payload_bytes"],
                loc=mal_loc,
                template_author="independent-taxonomy-v2",
                seed=seed + i * 17,
                view_hash=view_mal["view_hash"],
            )
            manifest.records.append(rec_mal)
            sample_counter += 1

    # Run tell audit across all generated files
    if dest_files_mal and dest_files_ben:
        ok_tells, tell_violations = audit_tell_frequency(dest_files_mal, dest_files_ben, max_tell_ratio=0.20)
        if not ok_tells:
            logger.warning("Tell audit detected potential tells: %s", tell_violations)
        else:
            logger.info("Tell audit passed cleanly with 0 tell violations across all twin pairs.")

    manifest_path = BENCH_V2_DIR / "manifest.json"
    save_manifest(manifest, manifest_path)
    logger.info("Successfully generated BenchmarkManifest v2 with %d samples at %s", len(manifest.records), manifest_path)
    return manifest
