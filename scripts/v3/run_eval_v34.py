"""Execution Runner for Benchmark v3.4: contextual_purpose_consistency condition across sealed eval split (N=120).

Supports:
- --dry-run: Computes planned calls, tokens, and USD estimates without making API calls.
- --model <model_name>: e.g. gemini-3.5-flash-lite.
- Rate-limit pacing and incremental caching every 5 samples to ensure resumability.
- Strict accounting and verification against PREREGISTRATION_V34.md.
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
logger = logging.getLogger("eval_v34")


def run_v34_evaluation(
    model: str = "gemini-3.5-flash-lite",
    dry_run: bool = False,
    sleep_between_calls: float = 1.0,
) -> dict[str, Any]:
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    eval_samples = [s for s in manifest["samples"] if s["split"] == "eval"]
    assert len(eval_samples) == 120, f"Expected 120 eval samples, got {len(eval_samples)}"

    cache = load_eval_cache()
    logger.info("Loaded cache with %d entries. Target: 120 eval samples for contextual_purpose_consistency x %s (dry_run=%s)", len(cache), model, dry_run)

    # Groq pacing adjustment if applicable
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
            condition="contextual_purpose_consistency",
            model=model,
            cache=cache,
            repeat=0,
            temperature=0.0,
            dry_run=dry_run,
        )
        elapsed = time.time() - t0

        u = res.get("usage", {})
        total_planned += 1
        t_in = u.get("tokens_in", 0)
        t_out = u.get("tokens_out", 0)
        total_tokens_in += t_in
        total_tokens_out += t_out

        # Compute cost accurately even during dry run
        prices = PRICE_TABLE.get(model, PRICE_TABLE["default"])
        call_cost = (t_in / 1_000_000.0) * prices["prompt"] + (t_out / 1_000_000.0) * prices["completion"]
        total_cost += call_cost if dry_run else u.get("cost_usd", call_cost)
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
    logger.info("  Total Tokens In: %d (avg: %.1f/call)", total_tokens_in, total_tokens_in / max(1, total_planned))
    logger.info("  Total Tokens Out: %d (avg: %.1f/call)", total_tokens_out, total_tokens_out / max(1, total_planned))
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
    parser = argparse.ArgumentParser(description="Run contextual_purpose_consistency evaluation")
    parser.add_argument("--dry-run", action="store_true", help="Perform dry run without live API calls")
    parser.add_argument("--model", type=str, default="gemini-3.5-flash-lite", help="Model name to evaluate")
    parser.add_argument("--sleep", type=float, default=1.0, help="Sleep between calls")
    args = parser.parse_args()

    run_v34_evaluation(model=args.model, dry_run=args.dry_run, sleep_between_calls=args.sleep)
