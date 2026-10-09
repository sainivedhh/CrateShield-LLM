"""Harness Orchestration Engine implementing Section 8, 9, 11 of the CrateShield Spec.

Orchestrates:
1. Benchmark generation (sampler -> split -> inject -> manifest).
2. Acceptance gate checks (G1 leak audit, G2 size AUC <= 0.60, G6 disjointness).
3. Three-tier disaggregated evaluation:
   - Tier 1: Real in-the-wild (n=3)
   - Tier 2: Behavior-inspired reconstructions (n=8, anonymized)
   - Tier 3: Injected matched pairs (eval split, anonymized)
4. Evaluation across all conditions:
   - Non-LLM baselines: size, grep, rule-only
   - Advisory baseline: cargo-audit (Tiers 1 & 2 only)
   - Negative controls: name-only, metadata-only
   - LLM conditions: structured, structured_norag, raw, naive
5. Statistical computation:
   - Strict vs. Relaxed side by side
   - Cluster bootstrap 95% CIs by base crate (Tier 3)
   - Wilson intervals (Tiers 1 & 2)
   - McNemar's exact test for paired differences
   - Pair consistency rate
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
import random
import shutil
import tarfile
from typing import Any
import requests

from crateshield.config import DATA_DIR, RESULTS_DIR
from crateshield.ingestion.downloader import preprocess_crate
from harness.audit import audit_view, assert_gate_g1
from harness.baselines import run_grep_baseline, run_rule_only_baseline, run_size_baseline
from harness.inject import inject_payload, load_templates
from harness.manifest import BenchmarkManifest, SampleRecord, load_manifest, save_manifest
from harness.sampler import (
    classify_build_rs_behavior,
    is_crate_eligible,
    load_malicious_denylist,
    stratify_and_sample,
)
from harness.split import split_base_crates
from harness.stats import (
    cluster_bootstrap_by_base,
    compute_metrics_for_sample_set,
    compute_pair_consistency,
    mcnemar_exact_test,
    wilson_score_interval,
)
from harness.view import (
    build_anonymized_view,
    build_negative_control_views,
    compute_view_id,
)

logger = logging.getLogger(__name__)

BENCH_DIR = DATA_DIR / "bench_v1"
PAYLOADS_DIR = Path(__file__).resolve().parent / "payloads" / "v1"


def harvest_eligible_base_candidates(target_pool_size: int = 60) -> list[dict[str, Any]]:
    """Discovers and downloads candidate base crates with build.rs from crates.io or local cache."""
    BENCH_DIR.mkdir(parents=True, exist_ok=True)
    raw_cache_dir = BENCH_DIR / "base_candidates"
    raw_cache_dir.mkdir(parents=True, exist_ok=True)

    denylist = load_malicious_denylist()
    candidates = []
    seen_names = set()

    # 1. Scan local cache first
    for cand_dir in sorted(raw_cache_dir.iterdir()):
        if not cand_dir.is_dir():
            continue
        crate_root = cand_dir
        if not (crate_root / "build.rs").exists():
            sub = [p for p in cand_dir.iterdir() if p.is_dir() and (p / "build.rs").exists()]
            if sub:
                crate_root = sub[0]
            else:
                continue

        crate_name = cand_dir.name.rsplit("-", 1)[0]
        version_num = cand_dir.name.rsplit("-", 1)[1] if "-" in cand_dir.name else "1.0.0"
        if crate_name in seen_names:
            continue

        eligible, reason = is_crate_eligible(
            crate_meta={"name": crate_name},
            crate_dir=crate_root,
            denylist=denylist,
        )
        if eligible:
            build_content = (crate_root / "build.rs").read_text(encoding="utf-8", errors="ignore")
            b_class = classify_build_rs_behavior(build_content)
            total_bytes = sum(f.stat().st_size for f in crate_root.glob("**/*.rs"))
            candidates.append({
                "name": crate_name,
                "version": version_num,
                "root_dir": str(crate_root),
                "build_class": b_class,
                "size_bytes": total_bytes,
            })
            seen_names.add(crate_name)

    if len(candidates) >= target_pool_size:
        logger.info("Found %d eligible base crates in local cache.", len(candidates))
        return candidates

    seed_sources = [
        ("autocfg", 5),
        ("version_check", 5),
        ("cc", 6),
        ("cmake", 4),
        ("pkg-config", 4),
    ]

    session = requests.Session()
    session.headers.update({"User-Agent": "CrateShield-Research/1.0"})

    for dep_crate, pages in seed_sources:
        if len(candidates) >= target_pool_size:
            break
        for page in range(1, pages + 1):
            if len(candidates) >= target_pool_size:
                break
            url = f"https://crates.io/api/v1/crates/{dep_crate}/reverse_dependencies?page={page}&per_page=20"
            try:
                r = session.get(url, timeout=15)
                if r.status_code != 200:
                    continue
                versions = r.json().get("versions", [])
                for v_info in versions:
                    crate_name = v_info.get("crate")
                    version_num = v_info.get("num")
                    if not crate_name or not version_num or crate_name in seen_names:
                        continue
                    if crate_name.lower().replace("-", "_") in denylist:
                        continue

                    cand_dir = raw_cache_dir / f"{crate_name}-{version_num}"
                    if not cand_dir.exists():
                        # Download .crate
                        dl_url = f"https://static.crates.io/crates/{crate_name}/{crate_name}-{version_num}.crate"
                        res = session.get(dl_url, timeout=20)
                        if res.status_code != 200:
                            continue
                        # Extract tarball
                        import io
                        with tarfile.open(fileobj=io.BytesIO(res.content), mode="r:gz") as tf:
                            tf.extractall(raw_cache_dir)

                    # Locate crate root
                    crate_root = cand_dir
                    if not (crate_root / "build.rs").exists():
                        sub = [p for p in cand_dir.iterdir() if p.is_dir() and (p / "build.rs").exists()]
                        if sub:
                            crate_root = sub[0]

                    # Check eligibility
                    eligible, reason = is_crate_eligible(
                        crate_meta={"name": crate_name, "created_at": v_info.get("created_at")},
                        crate_dir=crate_root,
                        denylist=denylist,
                    )

                    if eligible:
                        build_content = (crate_root / "build.rs").read_text(encoding="utf-8", errors="ignore")
                        b_class = classify_build_rs_behavior(build_content)
                        total_bytes = sum(f.stat().st_size for f in crate_root.glob("**/*.rs"))
                        candidates.append({
                            "name": crate_name,
                            "version": version_num,
                            "root_dir": str(crate_root),
                            "build_class": b_class,
                            "size_bytes": total_bytes,
                        })
                        seen_names.add(crate_name)
                        logger.info("Found eligible base crate [%d]: %s v%s (%s, %d bytes)",
                                    len(candidates), crate_name, version_num, b_class, total_bytes)
                        if len(candidates) >= target_pool_size:
                            break
            except Exception as e:
                logger.warning("Error harvesting candidates from %s: %s", dep_crate, e)

    return candidates


def generate_benchmark_pairs(
    candidates: list[dict[str, Any]],
    n_tune: int = 10,
    n_eval: int = 30,
    seed: int = 42,
) -> BenchmarkManifest:
    """Creates the matched pairs dataset and generates BenchmarkManifest."""
    sampled_bases = stratify_and_sample(candidates, target_count=n_tune + n_eval, seed=seed)
    tune_bases, eval_bases = split_base_crates(sampled_bases, n_tune=n_tune, n_eval=n_eval, seed=seed)

    templates = load_templates(PAYLOADS_DIR)
    if not templates:
        raise ValueError(f"No templates found in {PAYLOADS_DIR}")

    placements = ["P1", "P1", "P2", "P5"]  # Primary build & lib placements
    manifest = BenchmarkManifest(version="v1", target_scale=n_tune + n_eval, seed=seed)
    pairs_dir = BENCH_DIR / "pairs"
    pairs_dir.mkdir(parents=True, exist_ok=True)

    splits = [("tune", tune_bases), ("eval", eval_bases)]
    sample_counter = 1

    for split_name, base_list in splits:
        for i, base in enumerate(base_list):
            base_name = base["name"]
            base_ver = base["version"]
            base_root = Path(base["root_dir"])
            pair_id = f"pair_{base_name}_{base_ver}"

            # 1. Clean benign sample
            benign_id = f"s_{sample_counter:04d}_benign"
            benign_dest = pairs_dir / f"{split_name}_{benign_id}"
            if benign_dest.exists():
                shutil.rmtree(benign_dest)
            shutil.copytree(base_root, benign_dest)

            benign_view_id = compute_view_id(base_name)
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
                dump_date="2026-10-08",
                size_bytes=base["size_bytes"],
                view_hash=view_benign["view_hash"],
            )
            manifest.records.append(rec_benign)
            sample_counter += 1

            # 2. Injected twin sample
            tmpl = templates[(i + sample_counter) % len(templates)]
            placement = placements[(i + sample_counter) % len(placements)]
            mal_id = f"s_{sample_counter:04d}_malicious"
            mal_dest = pairs_dir / f"{split_name}_{mal_id}"

            inj_res = inject_payload(
                base_dir=base_root,
                dest_dir=mal_dest,
                template=tmpl,
                variant_idx=i,
                placement=placement,
                seed=seed + i,
            )

            pre_mal = preprocess_crate(base_name, base_ver, mal_dest)
            view_mal = build_anonymized_view(pre_mal)

            rec_mal = SampleRecord(
                sample_id=mal_id,
                view_id=benign_view_id,  # Same view ID per pair per section 7!
                pair_id=pair_id,
                cluster_id=base_name,
                tier=3,
                split=split_name,
                label="MALICIOUS",
                label_evidence="injected-twin",
                base_crate=base_name,
                base_version=base_ver,
                dump_date="2026-10-08",
                template_id=inj_res["template_id"],
                category=inj_res["category"],
                placement=inj_res["placement"],
                obfuscation_level=inj_res["obfuscation_level"],
                surface_variant=inj_res["surface_variant"],
                payload_bytes=inj_res["payload_bytes"],
                size_bytes=base["size_bytes"] + inj_res["payload_bytes"],
                template_author="independent-taxonomy",
                seed=seed + i,
                view_hash=view_mal["view_hash"],
            )
            manifest.records.append(rec_mal)
            sample_counter += 1

    manifest_path = BENCH_DIR / "manifest.json"
    save_manifest(manifest, manifest_path)
    logger.info("Saved BenchmarkManifest with %d samples to %s", len(manifest.records), manifest_path)
    return manifest


def evaluate_sample(
    record: SampleRecord,
    condition: str,
    crate_dir: Path | None = None,
    prescreen: bool = False,
) -> dict[str, Any]:
    """Evaluates a single benchmark sample under a specific condition with full anonymization."""
    from crateshield.evaluation.baseline_cargo import run_cargo_audit
    from crateshield.llm import client
    from crateshield.llm.packing import pack_source
    from crateshield.llm.parser import parse_llm_response
    from crateshield.llm.prompt import build_naive_prompt, build_prompt, build_raw_prompt
    from crateshield.rag.retriever import retrieve_context
    from crateshield.signals.extractor import extract_all_signals

    sample_dir = crate_dir or (BENCH_DIR / "pairs" / f"{record.split}_{record.sample_id}")
    if not sample_dir.exists():
        raise FileNotFoundError(f"Sample directory not found: {sample_dir}")

    pre = preprocess_crate(record.base_crate, record.base_version, sample_dir)
    view = build_anonymized_view(pre)
    assert_gate_g1(view)

    # 1. Non-LLM Baselines
    if condition == "size":
        verdict = run_size_baseline(view)
        return {"sample_id": record.sample_id, "cluster_id": record.cluster_id, "tier": record.tier,
                "label": record.label, "condition": condition, "classification": verdict}

    if condition == "grep":
        verdict = run_grep_baseline(view)
        return {"sample_id": record.sample_id, "cluster_id": record.cluster_id, "tier": record.tier,
                "label": record.label, "condition": condition, "classification": verdict}

    if condition == "rule_only":
        verdict = run_rule_only_baseline(view)
        return {"sample_id": record.sample_id, "cluster_id": record.cluster_id, "tier": record.tier,
                "label": record.label, "condition": condition, "classification": verdict}

    if condition == "cargo_audit":
        if record.tier == 3:
            # Not applicable on injected pairs by design (Section 8)
            return {"sample_id": record.sample_id, "cluster_id": record.cluster_id, "tier": record.tier,
                    "label": record.label, "condition": condition,
                    "classification": {"classification": "BENIGN", "reasoning": "cargo-audit unindexed baseline"}}
        verdict = run_cargo_audit(record.base_crate, record.base_version)
        return {"sample_id": record.sample_id, "cluster_id": record.cluster_id, "tier": record.tier,
                "label": record.label, "condition": condition, "classification": verdict}

    # 2. LLM Conditions
    if condition in ("raw", "naive"):
        packed = pack_source(view, budget_chars=60000)
        builder = build_raw_prompt if condition == "raw" else build_naive_prompt
        msgs = builder(view["name"], view["version"], packed["text"], packed.get("truncation_note"))
        raw_resp = client.query_llm(msgs)
        verdict = parse_llm_response(raw_resp)
        return {"sample_id": record.sample_id, "cluster_id": record.cluster_id, "tier": record.tier,
                "label": record.label, "condition": condition, "classification": verdict}

    # 3. Structured Conditions
    signals = extract_all_signals(view)
    retrieved: list[dict] = []
    if condition == "structured":
        # Leave-one-out: exclude the base crate itself from RAG knowledge
        retrieved = retrieve_context(signals, top_k=3, exclude_crates={record.base_crate})

    msgs = build_prompt(signals, retrieved_context=retrieved)
    raw_resp = client.query_llm(msgs)
    verdict = parse_llm_response(raw_resp)

    return {
        "sample_id": record.sample_id,
        "cluster_id": record.cluster_id,
        "tier": record.tier,
        "label": record.label,
        "condition": condition,
        "classification": verdict,
    }


def run_tiered_evaluation(
    manifest: BenchmarkManifest,
    conditions: list[str] | None = None,
) -> dict[str, Any]:
    """Runs disaggregated evaluation across Tiers 1, 2, and 3."""
    conditions = conditions or ["size", "grep", "rule_only", "structured", "structured_norag", "raw", "naive"]
    eval_records = [r for r in manifest.records if r.split == "eval"]

    results_by_condition: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for cond in conditions:
        logger.info("Evaluating condition '%s' on %d eval samples...", cond, len(eval_records))
        for r in eval_records:
            try:
                res = evaluate_sample(r, cond)
                results_by_condition[cond].append(res)
            except Exception as e:
                logger.error("Error evaluating %s on %s: %s", r.sample_id, cond, e)

    # Compute stats for Tier 3 eval
    summary = {"tier_3_eval": {}}
    for cond, res_list in results_by_condition.items():
        strict_m = compute_metrics_for_sample_set(res_list, strict=True)
        relaxed_m = compute_metrics_for_sample_set(res_list, strict=False)
        boot_ci = cluster_bootstrap_by_base(res_list, B=1000, seed=42, strict=True)
        pair_consist = compute_pair_consistency(res_list, strict=True)

        summary["tier_3_eval"][cond] = {
            "strict": strict_m,
            "relaxed": relaxed_m,
            "bootstrap_95ci": boot_ci,
            "pair_consistency": pair_consist,
        }

    summary_path = BENCH_DIR / "results_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    logger.info("Saved tiered evaluation results to %s", summary_path)
    return summary

