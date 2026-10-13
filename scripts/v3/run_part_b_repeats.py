"""Runner for Part B: Repeat runs for noise floor estimation (v3.5).

Evaluates the fixed 24-sample reproducibility subset across 3 repeats at T=0.0 and 3 repeats at T=0.7.
Only fills missing entries in data/bench_v3/eval_cache.json without re-running existing complete conditions.
Uses dedicated Gemini key for Part B.
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
from pathlib import Path
import sys
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from harness.gen_v3.config import PRICE_TABLE, TRACKER
from scripts.v3.run_eval import (
    MANIFEST_PATH, CACHE_PATH, load_eval_cache, save_eval_cache, evaluate_sample_v3, make_cache_key, compute_prompt_hash
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("part_b_repeats")

FIXED_REPEAT_SUBSET_IDS = {
    's3_0034_clean', 's3_0035_malicious', 's3_0042_lookalike_benign', 's3_0044_malicious',
    's3_0045_lookalike_benign', 's3_0048_lookalike_benign', 's3_0058_clean', 's3_0059_malicious',
    's3_0060_lookalike_benign', 's3_0062_malicious', 's3_0066_lookalike_benign', 's3_0085_clean',
    's3_0095_malicious', 's3_0100_clean', 's3_0106_clean', 's3_0108_lookalike_benign',
    's3_0112_clean', 's3_0117_lookalike_benign', 's3_0125_malicious', 's3_0133_clean',
    's3_0137_malicious', 's3_0142_clean', 's3_0147_lookalike_benign', 's3_0148_clean'
}


def safe_save_eval_cache(cache: dict[str, Any]) -> None:
    disk = load_eval_cache()
    disk.update(cache)
    cache.update(disk)
    save_eval_cache(cache, dry_run=False)


def run_part_b(
    api_key: str,
    dry_run: bool = False,
    sleep_delay: float = 3.0,
) -> dict[str, Any]:
    # Temporarily set GEMINI_API_KEY environment variable for this run
    import os
    os.environ["GEMINI_API_KEY"] = api_key
    # Also update module-level import if needed
    import crateshield.config
    crateshield.config.GEMINI_API_KEY = api_key
    import scripts.v3.run_eval
    scripts.v3.run_eval.GEMINI_API_KEY = api_key

    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    eval_samples = [s for s in manifest["samples"] if s["split"] == "eval" and s["sample_id"] in FIXED_REPEAT_SUBSET_IDS]
    assert len(eval_samples) == 24, f"Expected exactly 24 samples in repeat subset, got {len(eval_samples)}"

    cache = load_eval_cache()
    logger.info("Loaded cache with %d entries.", len(cache))

    # Identify which conditions need repeats
    conditions = ["hybrid_taint", "contextual_purpose_consistency", "naive_full"]
    model = "gemini-3.5-flash-lite"

    total_planned = 0
    total_calls_made = 0
    total_cost = 0.0

    for cond in conditions:
        for temp in (0.0, 0.7):
            for rep in (1, 2, 3):
                # Quick cache audit for this block
                cached_count = sum(
                    1 for k, v in cache.items()
                    if v.get("split") == "eval" and v.get("sample_id") in FIXED_REPEAT_SUBSET_IDS
                    and v.get("condition") == cond and v.get("model") == model
                    and abs(v.get("temperature", 0.0) - temp) < 1e-4 and v.get("repeat") == rep
                    and not v.get("dry_run", False) and v.get("finish_reason") != "dry_run"
                )
                if cached_count == 24:
                    logger.info("Condition %s, rep=%d, temp=%.1f already fully cached (24/24). Skipping.", cond, rep, temp)
                    continue

                logger.info("Evaluating condition %s, rep=%d, temp=%.1f (cached: %d/24)...", cond, rep, temp, cached_count)
                for idx, sample in enumerate(eval_samples, 1):
                    s_id = sample["sample_id"]
                    total_planned += 1

                    # Fast cache lookup to bypass prompt reconstruction if already cached live
                    fast_cached = any(
                        v.get("sample_id") == s_id
                        and v.get("condition") == cond
                        and v.get("model") == model
                        and abs(v.get("temperature", 0.0) - temp) < 1e-4
                        and v.get("repeat") == rep
                        and not v.get("dry_run", False)
                        and v.get("finish_reason") != "dry_run"
                        for v in cache.values()
                    )
                    if fast_cached:
                        continue

                    # Check if already cached (live entry)
                    t0 = time.time()
                    res = evaluate_sample_v3(
                        sample_meta=sample,
                        condition=cond,
                        model=model,
                        cache=cache,
                        repeat=rep,
                        temperature=temp,
                        dry_run=dry_run,
                    )
                    elapsed = time.time() - t0

                    if not dry_run and res.get("usage", {}).get("calls", 0) > 0:
                        total_calls_made += 1
                        total_cost += res.get("usage", {}).get("cost_usd", 0.0)

                        if total_calls_made % 5 == 0:
                            safe_save_eval_cache(cache)
                            logger.info("  [Checkpoint] Saved eval cache (calls made: %d)", total_calls_made)

                        t_in = res.get("usage", {}).get("tokens_in", 0)
                        if t_in > 250000:
                            logger.info("Large input prompt (%d tokens). Sleeping 60s to drain rolling TPM window...", t_in)
                            time.sleep(60.0)
                        elif sleep_delay > 0:
                            time.sleep(sleep_delay)

    if not dry_run:
        safe_save_eval_cache(cache)
        logger.info("Final eval cache saved. Total new calls made: %d, Cost: $%.6f", total_calls_made, total_cost)

    return {
        "total_planned": total_planned,
        "total_calls_made": total_calls_made,
        "total_cost": total_cost,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Part B repeat evaluation")
    parser.add_argument("--api-key", type=str, default=None, help="Gemini API Key")
    parser.add_argument("--dry-run", action="store_true", help="Perform dry run without live calls")
    parser.add_argument("--sleep", type=float, default=1.0, help="Sleep between calls")
    args = parser.parse_args()

    run_part_b(api_key=args.api_key, dry_run=args.dry_run, sleep_delay=args.sleep)
