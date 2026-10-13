"""Execution Runner for hybrid_taint condition across sealed eval split (N=120).

Supports:
- --dry-run: Computes planned calls, tokens, and USD estimates without making API calls.
- --model <model_name>: e.g. gemini-3.5-flash-lite or qwen/qwen3.8-27b.
- Rate-limit pacing for Groq to strictly respect 7,000 ITPM and 30 RPM limits.
- Incremental caching every 5 samples to ensure resumability.
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import os
from pathlib import Path
import sys
import time
from typing import Any

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

load_dotenv(override=True)

from crateshield.config import GEMINI_API_KEY
from harness.gen_v3.config import PRICE_TABLE, TRACKER
from scripts.v3.run_eval import (
    MANIFEST_PATH, CACHE_PATH, DISCARDED_PATH,
    load_eval_cache, save_eval_cache, evaluate_sample_v3,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("eval_taint")


def run_taint_evaluation(
    model: str = "gemini-3.5-flash-lite",
    dry_run: bool = False,
    sleep_between_calls: float = 0.5,
) -> dict[str, Any]:
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    eval_samples = [s for s in manifest["samples"] if s["split"] == "eval"]
    assert len(eval_samples) == 120, f"Expected 120 eval samples, got {len(eval_samples)}"

    cache = load_eval_cache()
    logger.info("Loaded cache with %d entries. Target: 120 eval samples for hybrid_taint x %s (dry_run=%s)", len(cache), model, dry_run)

    # Groq pacing adjustment
    is_groq = "qwen" in model.lower() or "groq" in model.lower()
    pace_delay = 6.0 if is_groq else sleep_between_calls

    total_planned = 0
    total_tokens_in = 0
    total_tokens_out = 0
    total_cost = 0.0

    completed_entries = []

    for idx, sample in enumerate(eval_samples, 1):
        s_id = sample["sample_id"]
        logger.info("[%d/120] Evaluating %s (%s, %s)...", idx, s_id, sample.get("twin_type"), sample.get("ladder_level"))

        t0 = time.time()
        res = evaluate_sample_v3(
            sample_meta=sample,
            condition="hybrid_taint",
            model=model,
            cache=cache,
            repeat=0,
            temperature=0.0,
            dry_run=dry_run,
        )
        elapsed = time.time() - t0

        u = res.get("usage", {})
        total_planned += 1
        total_tokens_in += u.get("tokens_in", 0)
        total_tokens_out += u.get("tokens_out", 0)
        total_cost += u.get("cost_usd", 0.0)
        completed_entries.append(res)

        # Save incrementally
        if not dry_run and idx % 5 == 0:
            save_eval_cache(cache, dry_run=False)
            logger.info("  Saved cache checkpoint (%d/120 entries).", idx)

        # Pace calls
        if not dry_run and pace_delay > 0 and idx < len(eval_samples):
            time.sleep(pace_delay)

    # Final save
    save_eval_cache(cache, dry_run=dry_run)

    logger.info("Evaluation pass completed.")
    logger.info("  Total Calls: %d", total_planned)
    logger.info("  Total Tokens In: %d", total_tokens_in)
    logger.info("  Total Tokens Out: %d", total_tokens_out)
    logger.info("  Total Cost (USD): $%.6f", total_cost)

    return {
        "model": model,
        "dry_run": dry_run,
        "total_calls": total_planned,
        "total_tokens_in": total_tokens_in,
        "total_tokens_out": total_tokens_out,
        "total_cost_usd": total_cost,
        "completed_count": len(completed_entries),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run hybrid_taint evaluation")
    parser.add_argument("--dry-run", action="store_true", help="Perform dry run without live API calls")
    parser.add_argument("--model", type=str, default="gemini-3.5-flash-lite", help="Model name to evaluate")
    parser.add_argument("--sleep", type=float, default=0.5, help="Sleep between calls")
    args = parser.parse_args()

    run_taint_evaluation(model=args.model, dry_run=args.dry_run, sleep_between_calls=args.sleep)
