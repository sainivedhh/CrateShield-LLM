"""Execution Runner for v3.3 Pilot on TUNE split (N=30: 10 mal, 10 clean, 10 lookalike).

Supports:
- candidate_a (hybrid_taint_contextual)
- candidate_b (purpose_consistency)
- hybrid_taint (tune baseline)
- raw (tune baseline)

Saves strictly to data/bench_v3/pilot_v33_cache.json, isolating all pilot data from sealed eval.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import logging
from pathlib import Path
import sys
import time
from typing import Any

from dotenv import load_dotenv
load_dotenv(override=True)

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from crateshield.config import GEMINI_API_KEY
from crateshield.ingestion.downloader import preprocess_crate
from crateshield.llm.packing import pack_source
from crateshield.llm.parser import parse_llm_response
from crateshield.llm.prompt import build_raw_prompt
from crateshield.rag.retriever import retrieve_context
from crateshield.signals.extractor import extract_all_signals
from crateshield.taintflow.extractor import extract_taint_context
from crateshield.taintflow.contextual_extractor import extract_taint_contextual
from harness.hybrid_taint import build_hybrid_taint_prompt
from harness.pilot_v33.candidate_a import build_candidate_a_prompt
from harness.pilot_v33.candidate_b import (
    extract_crate_declared_purpose, build_candidate_b_prompt,
)
from harness.view import build_anonymized_view
from scripts.v3.run_eval import call_model_api

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("pilot_v33")

MANIFEST_PATH = ROOT / "data" / "bench_v3" / "manifest.json"
CORPUS_DIR = ROOT / "data" / "bench_v3" / "corpus_private"
PILOT_CACHE_PATH = ROOT / "data" / "bench_v3" / "pilot_v33_cache.json"


def compute_prompt_hash(messages: list[dict[str, str]]) -> str:
    content = json.dumps(messages, sort_keys=True)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


def load_pilot_cache() -> dict[str, Any]:
    if PILOT_CACHE_PATH.exists():
        try:
            return json.loads(PILOT_CACHE_PATH.read_text("utf-8"))
        except Exception:
            return {}
    return {}


def save_pilot_cache(cache: dict[str, Any]) -> None:
    PILOT_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    PILOT_CACHE_PATH.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def evaluate_tune_sample(
    sample_meta: dict[str, Any],
    condition: str,
    model: str = "gemini-3.5-flash-lite",
    cache: dict[str, Any] | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    sample_id = sample_meta["sample_id"]
    crate_dir = CORPUS_DIR / sample_id
    if not crate_dir.exists():
        raise FileNotFoundError(f"Crate directory not found: {crate_dir}")

    preprocessed = preprocess_crate(
        name=sample_meta["cluster_id"],
        version="1.0.0",
        crate_dir=crate_dir,
    )
    view = build_anonymized_view(preprocessed=preprocessed, salt="crateshield-v3")

    messages: list[dict[str, str]] = []
    meta_info: dict[str, Any] = {}

    if condition == "raw":
        packed = pack_source(view, budget_chars=60000)
        messages = build_raw_prompt(view["name"], view["version"], packed["text"], packed.get("truncation_note"))

    elif condition == "hybrid_taint":
        signals = extract_all_signals(view)
        signals.pop("analysis_timestamp", None)
        taint_context = extract_taint_context(view, manifest_sample=sample_meta)
        retrieved = retrieve_context(signals, top_k=3, exclude_crates={sample_meta["cluster_id"]})
        messages = build_hybrid_taint_prompt(signals, taint_context, retrieved_context=retrieved)
        meta_info["paths_found"] = taint_context.get("paths_found", 0)
        meta_info["fallback_used"] = taint_context.get("fallback_used", False)
        meta_info["context_chars"] = taint_context.get("total_chars", 0)

    elif condition == "candidate_a":  # hybrid_taint_contextual
        signals = extract_all_signals(view)
        signals.pop("analysis_timestamp", None)
        taint_context = extract_taint_contextual(view, manifest_sample=sample_meta)
        retrieved = retrieve_context(signals, top_k=3, exclude_crates={sample_meta["cluster_id"]})
        messages = build_candidate_a_prompt(signals, taint_context, retrieved_context=retrieved)
        meta_info["paths_found"] = taint_context.get("paths_found", 0)
        meta_info["fallback_used"] = taint_context.get("fallback_used", False)
        meta_info["context_chars"] = taint_context.get("total_chars", 0)

    elif condition == "candidate_b":  # purpose_consistency
        signals = extract_all_signals(view)
        signals.pop("analysis_timestamp", None)
        purpose_info = extract_crate_declared_purpose(crate_dir, view, sample_meta)
        taint_context = extract_taint_context(view, manifest_sample=sample_meta)
        retrieved = retrieve_context(signals, top_k=3, exclude_crates={sample_meta["cluster_id"]})
        messages = build_candidate_b_prompt(signals, taint_context, purpose_info, retrieved_context=retrieved)
        meta_info["purpose_fallback_used"] = purpose_info.get("fallback_used", False)
        meta_info["has_readme"] = bool(purpose_info.get("readme_snippet") and purpose_info["readme_snippet"] != "(No README provided)")
        meta_info["context_chars"] = taint_context.get("total_chars", 0)

    else:
        raise ValueError(f"Unknown condition: {condition}")

    prompt_hash = compute_prompt_hash(messages)
    cache_key = f"{sample_id}:{condition}:{prompt_hash}:{model}:temp0.0:rep0"

    if cache and cache_key in cache:
        cached = cache[cache_key]
        if not dry_run and not cached.get("dry_run", False):
            return cached

    raw_resp, t_in, t_out, call_cost, finish_reason = call_model_api(
        model=model, messages=messages, temperature=0.0, dry_run=dry_run
    )
    verdict = parse_llm_response(raw_resp) if not dry_run else {
        "classification": "BENIGN",
        "verdict": "BENIGN",
        "confidence": 0.0,
        "malware_score": 0.0,
        "obfuscation_score": 0.0,
        "security_risk_score": 0.0,
        "primary_signals": [],
        "reasoning": "[DRY RUN]",
        "recommended_action": "ALLOW",
    }

    res = {
        "sample_id": sample_id,
        "pair_id": sample_meta["pair_id"],
        "cluster_id": sample_meta["cluster_id"],
        "split": "tune",
        "twin_type": sample_meta["twin_type"],
        "label": sample_meta["label"],
        "ladder_level": sample_meta["ladder_level"],
        "condition": condition,
        "model": model,
        "prompt_hash": prompt_hash,
        "classification": verdict,
        "reasoning": verdict.get("reasoning", ""),
        "raw_response": raw_resp if not dry_run else "",
        "dry_run": dry_run,
        "finish_reason": finish_reason,
        "usage": {
            "calls": 1 if not dry_run else 0,
            "tokens_in": t_in,
            "tokens_out": t_out,
            "cost_usd": call_cost,
        },
        "meta": meta_info,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    if cache is not None:
        cache[cache_key] = res

    return res


def run_pilot(
    conditions: list[str],
    model: str = "gemini-3.5-flash-lite",
    dry_run: bool = False,
    sleep_between_calls: float = 1.0,
) -> dict[str, Any]:
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    tune_samples = [s for s in manifest["samples"] if s.get("split") == "tune"]
    assert len(tune_samples) == 30, f"Expected 30 tune samples, got {len(tune_samples)}"

    cache = load_pilot_cache() if not dry_run else {}

    summary = {
        "total_calls": 0,
        "total_tokens_in": 0,
        "total_tokens_out": 0,
        "total_cost_usd": 0.0,
        "conditions": {},
    }

    logger.info("Starting Pilot v3.3 Run on TUNE split (N=30 x %d conditions, dry_run=%s)", len(conditions), dry_run)

    for cond in conditions:
        logger.info("=== Running Condition: %s ===", cond)
        cond_entries = []
        c_tin = 0
        c_tout = 0
        c_cost = 0.0

        for idx, sample in enumerate(tune_samples, 1):
            s_id = sample["sample_id"]
            res = evaluate_tune_sample(
                sample_meta=sample,
                condition=cond,
                model=model,
                cache=cache,
                dry_run=dry_run,
            )
            u = res.get("usage", {})
            c_tin += u.get("tokens_in", 0)
            c_tout += u.get("tokens_out", 0)
            c_cost += u.get("cost_usd", 0.0)
            cond_entries.append(res)

            v = res.get("classification", {}).get("classification") or res.get("classification", {}).get("verdict")
            logger.info("  [%d/30] %s (%s, %s) -> %s (in: %d, out: %d)",
                        idx, s_id, sample["twin_type"], sample["ladder_level"], v, u.get("tokens_in", 0), u.get("tokens_out", 0))

            if not dry_run:
                if idx % 5 == 0:
                    save_pilot_cache(cache)
                if sleep_between_calls > 0 and idx < len(tune_samples):
                    time.sleep(sleep_between_calls)

        if not dry_run:
            save_pilot_cache(cache)

        summary["total_calls"] += len(tune_samples)
        summary["total_tokens_in"] += c_tin
        summary["total_tokens_out"] += c_tout
        summary["total_cost_usd"] += c_cost
        summary["conditions"][cond] = {
            "samples": len(cond_entries),
            "tokens_in": c_tin,
            "tokens_out": c_tout,
            "cost_usd": c_cost,
        }

    logger.info("=== Pilot Run Completed ===")
    logger.info("Total Planned Calls: %d", summary["total_calls"])
    logger.info("Total Tokens In: %d", summary["total_tokens_in"])
    logger.info("Total Tokens Out: %d", summary["total_tokens_out"])
    logger.info("Total Estimated Cost (USD): $%.6f", summary["total_cost_usd"])

    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run v3.3 pilot on tune split")
    parser.add_argument("--dry-run", action="store_true", help="Perform dry run without making live LLM calls")
    parser.add_argument("--model", type=str, default="gemini-3.5-flash-lite", help="Model to evaluate")
    parser.add_argument("--conditions", type=str, default="candidate_a,candidate_b,hybrid_taint,raw",
                        help="Comma-separated conditions to run")
    parser.add_argument("--sleep", type=float, default=1.0, help="Sleep between calls")
    args = parser.parse_args()

    conds = [c.strip() for c in args.conditions.split(",") if c.strip()]
    run_pilot(conditions=conds, model=args.model, dry_run=args.dry_run, sleep_between_calls=args.sleep)
