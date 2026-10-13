"""Evaluation Engine v2 with strict caching, token accounting, and hybrid condition.

Implements Phase 4 and Phase 5 of CrateShield Spec v2:
1. Cache keyed by (sample_id, condition, prompt_hash, model, temperature).
2. Per-sample token accounting (tokens_in, tokens_out, calls, chars_in, chars_out).
3. Evaluates all conditions on identical anonymized twin pairs:
   - Baselines: size, grep, rule_only, cargo_audit
   - LLM conditions: structured, structured_norag, hybrid, hybrid_norag, raw, naive
4. Gate G1 leak audit enforcement on views.
5. Strict separation between Tune split development and sealed Eval split execution.
"""
from __future__ import annotations

from collections import defaultdict
import datetime
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from crateshield.config import DATA_DIR, GEMINI_MODEL, LLM_MODEL, LLM_PROVIDER
from crateshield.evaluation.baseline_cargo import run_cargo_audit
from crateshield.ingestion.downloader import preprocess_crate
from crateshield.llm import client
from crateshield.llm.packing import pack_source
from crateshield.llm.parser import parse_llm_response
from crateshield.llm.prompt import build_naive_prompt, build_prompt, build_raw_prompt
from crateshield.rag.retriever import retrieve_context
from crateshield.signals.extractor import extract_all_signals
from harness.audit import assert_gate_g1
from harness.baselines import run_grep_baseline, run_rule_only_baseline, run_size_baseline
from harness.hybrid import build_hybrid_prompt, extract_targeted_code_windows
from harness.manifest import BenchmarkManifest, SampleRecord, load_manifest
from harness.view import build_anonymized_view

logger = logging.getLogger("eval_v2")

BENCH_V2_DIR = DATA_DIR / "bench_v2"
PAIRS_DIR = BENCH_V2_DIR / "pairs"
CACHE_FILE = BENCH_V2_DIR / "eval_cache.json"


def compute_prompt_hash(messages: list[dict[str, str]]) -> str:
    """Computes SHA-256 fingerprint of the prompt messages."""
    content = json.dumps(messages, sort_keys=True)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


def make_cache_key(
    sample_id: str,
    condition: str,
    prompt_hash: str,
    model: str,
    temperature: float,
) -> str:
    """Creates a deterministic cache key."""
    return f"{sample_id}::{condition}::{prompt_hash}::{model}::{temperature:.2f}"


def load_eval_cache(cache_path: Path = CACHE_FILE) -> dict[str, Any]:
    if cache_path.exists():
        try:
            return json.loads(cache_path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning("Could not read eval cache at %s: %s", cache_path, e)
    return {}


def save_eval_cache(cache: dict[str, Any], cache_path: Path = CACHE_FILE) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def evaluate_sample_v2(
    record: SampleRecord,
    condition: str,
    cache: dict[str, Any],
    model: str | None = None,
    temperature: float = 0.0,
    crate_dir: Path | None = None,
) -> dict[str, Any]:
    """Evaluates a single v2 benchmark sample under a specific condition with caching and token metrics."""
    actual_model = model or (GEMINI_MODEL if LLM_PROVIDER.startswith("gemini") else LLM_MODEL)
    sample_dir = crate_dir or (PAIRS_DIR / f"{record.split}_{record.sample_id}")
    if not sample_dir.exists():
        raise FileNotFoundError(f"Sample directory not found: {sample_dir}")

    pre = preprocess_crate(record.base_crate, record.base_version, sample_dir)
    view = build_anonymized_view(pre)
    assert_gate_g1(view)

    # 1. Non-LLM Baselines (deterministic, no API calls or prompt hash)
    if condition in ("size", "grep", "rule_only", "cargo_audit"):
        cache_key = make_cache_key(record.sample_id, condition, "none", "baseline", 0.0)
        if cache_key in cache:
            return cache[cache_key]

        if condition == "size":
            verdict = run_size_baseline(view)
        elif condition == "grep":
            verdict = run_grep_baseline(view)
        elif condition == "rule_only":
            verdict = run_rule_only_baseline(view)
        elif condition == "cargo_audit":
            if record.tier == 3:
                verdict = {"classification": "BENIGN", "reasoning": "cargo-audit unindexed baseline"}
            else:
                verdict = run_cargo_audit(record.base_crate, record.base_version)

        res = {
            "sample_id": record.sample_id,
            "pair_id": record.pair_id,
            "split": record.split,
            "tier": record.tier,
            "label": record.label,
            "domain_type": record.domain_type,
            "payload_in_omitted_region": record.payload_in_omitted_region,
            "condition": condition,
            "model": "baseline",
            "temperature": 0.0,
            "classification": verdict,
            "usage": {"calls": 0, "tokens_in": 0, "tokens_out": 0, "chars_in": 0, "chars_out": 0},
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        cache[cache_key] = res
        return res

    # 2. Build Prompt for LLM Conditions
    messages: list[dict[str, str]] = []
    if condition in ("raw", "naive"):
        packed = pack_source(view, budget_chars=60000)
        builder = build_raw_prompt if condition == "raw" else build_naive_prompt
        messages = builder(view["name"], view["version"], packed["text"], packed.get("truncation_note"))

    elif condition in ("structured", "structured_norag"):
        signals = extract_all_signals(view)
        retrieved = []
        if condition == "structured":
            retrieved = retrieve_context(signals, top_k=3, exclude_crates={record.base_crate})
        messages = build_prompt(signals, retrieved_context=retrieved)

    elif condition in ("hybrid", "hybrid_norag"):
        signals = extract_all_signals(view)
        code_windows = extract_targeted_code_windows(view)
        retrieved = []
        if condition == "hybrid":
            retrieved = retrieve_context(signals, top_k=3, exclude_crates={record.base_crate})
        messages = build_hybrid_prompt(signals, code_windows, retrieved_context=retrieved)
    else:
        raise ValueError(f"Unknown condition: {condition}")

    prompt_hash = compute_prompt_hash(messages)
    cache_key = make_cache_key(record.sample_id, condition, prompt_hash, actual_model, temperature)

    if cache_key in cache:
        logger.debug("Cache hit for %s (%s)", record.sample_id, condition)
        return cache[cache_key]

    # Query LLM with fresh usage delta
    usage_before = client.get_usage()
    raw_resp = client.query_llm(messages, temperature=temperature)
    verdict = parse_llm_response(raw_resp)
    usage_after = client.get_usage()

    usage_delta = {k: usage_after[k] - usage_before[k] for k in usage_after}

    res = {
        "sample_id": record.sample_id,
        "pair_id": record.pair_id,
        "split": record.split,
        "tier": record.tier,
        "label": record.label,
        "domain_type": record.domain_type,
        "payload_in_omitted_region": record.payload_in_omitted_region,
        "condition": condition,
        "model": actual_model,
        "temperature": temperature,
        "prompt_hash": prompt_hash,
        "classification": verdict,
        "usage": usage_delta,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    cache[cache_key] = res
    return res


def run_split_evaluation(
    split: str = "tune",
    conditions: list[str] | None = None,
    manifest_path: Path = BENCH_V2_DIR / "manifest.json",
    cache_path: Path = CACHE_FILE,
    temperature: float = 0.0,
    model: str | None = None,
) -> dict[str, Any]:
    """Runs evaluation on a specified split (tune or eval) across conditions."""
    manifest = load_manifest(manifest_path)
    records = [r for r in manifest.records if r.split == split]
    cache = load_eval_cache(cache_path)

    default_conditions = [
        "size", "grep", "rule_only", "cargo_audit",
        "structured", "structured_norag", "hybrid", "hybrid_norag",
        "raw", "naive",
    ]
    conds = conditions or default_conditions

    results_by_cond: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for cond in conds:
        logger.info("Evaluating split '%s' condition '%s' on %d samples...", split, cond, len(records))
        for r in records:
            res = evaluate_sample_v2(
                record=r,
                condition=cond,
                cache=cache,
                model=model,
                temperature=temperature,
            )
            results_by_cond[cond].append(res)
            # Save cache incrementally
            save_eval_cache(cache, cache_path)

    return results_by_cond
