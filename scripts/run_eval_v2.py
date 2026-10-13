"""Single-Run Sealed Evaluation Benchmark Runner (Phase 5).

Evaluates the sealed eval split (60 samples) and historical tiers (Tier 1 n=3, Tier 2 n=8)
across all conditions:
- Baselines: size, grep, rule_only, cargo_audit
- LLM conditions: structured, structured_norag, hybrid, hybrid_norag, raw, naive
Saves results incrementally to data/bench_v2/eval_cache.json.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
import sys
import time

sys.path.extend(["src", "."])

from crateshield.config import DATA_DIR
from harness.eval_v2 import (
    CACHE_FILE,
    evaluate_sample_v2,
    load_eval_cache,
    save_eval_cache,
)
from harness.manifest import BenchmarkManifest, SampleRecord, load_manifest

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("run_eval_v2")

BENCH_V2_DIR = DATA_DIR / "bench_v2"
MANIFEST_PATH = BENCH_V2_DIR / "manifest.json"
EXTRACTED_DIR = DATA_DIR / "extracted"

TIER1_SAMPLES = [
    {"sample_id": "tier1_logs_update_0.0.1", "name": "logs-update", "version": "0.0.1", "label": "MALICIOUS", "tier": 1},
    {"sample_id": "tier1_logs_update_0.0.2", "name": "logs-update", "version": "0.0.2", "label": "MALICIOUS", "tier": 1},
    {"sample_id": "tier1_logs_update_0.0.3", "name": "logs-update", "version": "0.0.3", "label": "MALICIOUS", "tier": 1},
]

TIER2_SAMPLES = [
    {"sample_id": "tier2_proc-macro1_0.1.0", "name": "proc-macro1", "version": "0.1.0", "label": "MALICIOUS", "tier": 2},
    {"sample_id": "tier2_amzn-codewhisperer-streaming-client_99.0.1", "name": "amzn-codewhisperer-streaming-client", "version": "99.0.1", "label": "MALICIOUS", "tier": 2},
    {"sample_id": "tier2_amzn-consolas-client_99.0.1", "name": "amzn-consolas-client", "version": "99.0.1", "label": "MALICIOUS", "tier": 2},
    {"sample_id": "tier2_arrayref_0.3.10", "name": "arrayref", "version": "0.3.10", "label": "MALICIOUS", "tier": 2},
    {"sample_id": "tier2_tinymember_0.1.0", "name": "tinymember", "version": "0.1.0", "label": "MALICIOUS", "tier": 2},
    {"sample_id": "tier2_xrvrv_0.1.0", "name": "xrvrv", "version": "0.1.0", "label": "MALICIOUS", "tier": 2},
    {"sample_id": "tier2_rustdecimal_1.0.0", "name": "rustdecimal", "version": "1.0.0", "label": "MALICIOUS", "tier": 2},
    {"sample_id": "tier2_faster_log_0.1.2", "name": "faster_log", "version": "0.1.2", "label": "MALICIOUS", "tier": 2},
]


def run_eval():
    manifest = load_manifest(MANIFEST_PATH)
    eval_records = [r for r in manifest.records if r.split == "eval"]
    cache = load_eval_cache()

    logger.info("Total eval split samples: %d", len(eval_records))

    # All 10 conditions
    conditions = [
        "size",
        "grep",
        "rule_only",
        "cargo_audit",
        "structured",
        "structured_norag",
        "hybrid",
        "hybrid_norag",
        "raw",
        "naive",
    ]

    for cond in conditions:
        logger.info("=== Starting condition: %s on %d eval samples ===", cond, len(eval_records))
        for idx, r in enumerate(eval_records, 1):
            try:
                res = evaluate_sample_v2(r, cond, cache)
                save_eval_cache(cache)
                logger.info("[%s %d/%d] %s -> %s (calls: %d, tokens: %d)",
                            cond, idx, len(eval_records), r.sample_id,
                            res["classification"]["classification"],
                            res["usage"].get("calls", 0),
                            res["usage"].get("tokens_in", 0) + res["usage"].get("tokens_out", 0))
            except Exception as e:
                logger.error("Error evaluating %s on %s: %s", r.sample_id, cond, e)
                raise

    # Also evaluate Tier 1 and Tier 2 on all conditions
    extra_tiers = [("Tier 1", TIER1_SAMPLES), ("Tier 2", TIER2_SAMPLES)]
    for tier_name, sample_list in extra_tiers:
        logger.info("=== Evaluating %s (%d samples) ===", tier_name, len(sample_list))
        for sample_meta in sample_list:
            crate_dir = EXTRACTED_DIR / f"{sample_meta['name']}-{sample_meta['version']}"
            if not crate_dir.exists():
                crate_dir = EXTRACTED_DIR / sample_meta["name"]
            if not crate_dir.exists():
                logger.warning("Crate dir not found for %s, skipping", sample_meta["sample_id"])
                continue

            rec = SampleRecord(
                sample_id=sample_meta["sample_id"],
                view_id=sample_meta["sample_id"],
                pair_id=f"pair_{sample_meta['name']}",
                cluster_id=sample_meta["name"],
                tier=sample_meta["tier"],
                split="eval",
                label=sample_meta["label"],
                label_evidence="known-incident",
                base_crate=sample_meta["name"],
                base_version=sample_meta["version"],
                dump_date="2026-10-09",
            )
            for cond in conditions:
                try:
                    res = evaluate_sample_v2(rec, cond, cache, crate_dir=crate_dir)
                    save_eval_cache(cache)
                except Exception as e:
                    logger.warning("Error evaluating extra sample %s on %s: %s", sample_meta["sample_id"], cond, e)

    save_eval_cache(cache)
    logger.info("=== Evaluation Run Complete! Cached %d entries ===", len(cache))


if __name__ == "__main__":
    run_eval()
