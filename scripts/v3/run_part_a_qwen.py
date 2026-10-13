"""Runner for Part A: Complete Qwen Cross-Model Coverage on Sealed Eval Split (v3.5).

Evaluates qwen/qwen3.8-27b across all LLM conditions on the 120-sample sealed eval split.
Strictly fills gaps without re-running existing complete results:
- hybrid_taint (skips existing 40, runs remaining 80)
- contextual_purpose_consistency (120)
- hybrid_fallback (120)
- raw_full (120, handling exceeds_context)
- naive_full (120)
- raw (120)
- structured (120)
- hybrid (120)

Uses dynamic token-bucket pacing and Retry-After handling to respect Groq's 7,000 ITPM limit.
Saves incrementally to data/bench_v3/eval_cache.json every 5 calls.
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

from dotenv import load_dotenv
load_dotenv(override=True)

from scripts.v3.run_eval import (
    MANIFEST_PATH, CACHE_PATH, load_eval_cache, save_eval_cache, evaluate_sample_v3
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("part_a_qwen")


def safe_save_eval_cache(cache: dict[str, Any]) -> None:
    disk = load_eval_cache()
    disk.update(cache)
    cache.update(disk)
    save_eval_cache(cache, dry_run=False)


def run_part_a(
    conditions: list[str] | None = None,
    dry_run: bool = False,
    sleep_delay: float = 6.0,
) -> dict[str, Any]:
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    eval_samples = [s for s in manifest["samples"] if s["split"] == "eval"]
    assert len(eval_samples) == 120, f"Expected 120 eval samples, got {len(eval_samples)}"

    cache = load_eval_cache()
    logger.info("Loaded eval cache with %d entries.", len(cache))

    target_conditions = conditions or [
        "hybrid_taint",
        "contextual_purpose_consistency",
        "hybrid_fallback",
        "raw_full",
        "naive_full",
        "raw",
        "structured",
        "hybrid",
    ]
    model = "qwen/qwen3.8-27b"

    total_planned = 0
    total_calls_made = 0
    total_cost = 0.0

    for cond in target_conditions:
        logger.info("=== Starting condition: %s on %s ===", cond, model)
        cond_calls = 0
        cond_skipped = 0

        for idx, sample in enumerate(eval_samples, 1):
            s_id = sample["sample_id"]
            total_planned += 1

            # Fast cache lookup to bypass prompt reconstruction if already cached live
            fast_cached = any(
                v.get("sample_id") == s_id
                and v.get("condition") == cond
                and v.get("model") == model
                and v.get("repeat") == 0
                and not v.get("dry_run", False)
                and v.get("finish_reason") != "dry_run"
                for v in cache.values()
            )
            if fast_cached:
                cond_skipped += 1
                continue

            t0 = time.time()
            res = evaluate_sample_v3(
                sample_meta=sample,
                condition=cond,
                model=model,
                cache=cache,
                repeat=0,
                temperature=0.0,
                dry_run=dry_run,
            )
            elapsed = time.time() - t0

            calls_in_res = res.get("usage", {}).get("calls", 0)
            if not dry_run and calls_in_res > 0:
                cond_calls += 1
                total_calls_made += 1
                total_cost += res.get("usage", {}).get("cost_usd", 0.0)
                logger.info("  [%d/120] %s evaluated in %.2fs (calls made: %d)", idx, s_id, elapsed, total_calls_made)
            else:
                cond_skipped += 1
                logger.info("  [%d/120] %s cached/skipped (reason: %s)", idx, s_id, res.get("finish_reason"))

            # Save checkpoint every 5 live calls
            if not dry_run and total_calls_made % 5 == 0 and total_calls_made > 0 and calls_in_res > 0:
                safe_save_eval_cache(cache)
                logger.info("  [Checkpoint] Saved eval cache (total calls made: %d)", total_calls_made)

            # Pacing sleep between live calls
            if not dry_run and calls_in_res > 0 and sleep_delay > 0:
                time.sleep(sleep_delay)

        logger.info("Finished %s: %d live calls made, %d skipped from cache.", cond, cond_calls, cond_skipped)
        if not dry_run:
            safe_save_eval_cache(cache)

    logger.info("=== Part A Evaluation Pass Completed ===")
    logger.info("Total live calls made: %d, Total cost: $%.6f", total_calls_made, total_cost)

    return {
        "model": model,
        "total_planned": total_planned,
        "total_calls_made": total_calls_made,
        "total_cost": total_cost,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Part A Qwen evaluation")
    parser.add_argument("--dry-run", action="store_true", help="Perform dry run without live API calls")
    parser.add_argument("--sleep", type=float, default=6.0, help="Sleep delay between live calls (default: 6.0s)")
    parser.add_argument("--conditions", nargs="+", help="Specific conditions to run")
    args = parser.parse_args()

    run_part_a(conditions=args.conditions, dry_run=args.dry_run, sleep_delay=args.sleep)
