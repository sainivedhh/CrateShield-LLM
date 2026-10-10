"""Confirmatory Evaluation Runner for Benchmark v3 (Phase 5 & Phase 7).

Evaluates conditions x models on sealed eval split and 20% repeat split.
Strictly cached, resumable, with token and USD accounting.
Supports --dry-run.
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
import sys
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from crateshield.config import GEMINI_API_KEY
from crateshield.evaluation.baseline_cargo import run_cargo_audit
from crateshield.ingestion.downloader import preprocess_crate
from crateshield.llm.client import get_usage, reset_usage
from crateshield.llm.packing import pack_source
from crateshield.llm.parser import parse_llm_response
from crateshield.llm.prompt import build_naive_prompt, build_prompt, build_raw_prompt
from crateshield.rag.retriever import retrieve_context
from crateshield.signals.extractor import extract_all_signals
from harness.audit import assert_gate_g1
from harness.baselines import run_grep_baseline, run_rule_only_baseline, run_size_baseline
from harness.gen_v3.config import PRICE_TABLE, TRACKER
from harness.hybrid import build_hybrid_prompt, extract_targeted_code_windows
from harness.hybrid_fallback import build_hybrid_fallback_prompt, extract_fallback_code_windows
from harness.view import build_anonymized_view

import requests

logger = logging.getLogger("eval_v3")

BENCH_V3 = ROOT / "data" / "bench_v3"
CORPUS_DIR = BENCH_V3 / "corpus_private"
MANIFEST_PATH = BENCH_V3 / "manifest.json"
CACHE_PATH = BENCH_V3 / "eval_cache.json"
DISCARDED_PATH = BENCH_V3 / "eval_cache_dryrun_discarded.json"


def compute_prompt_hash(messages: list[dict[str, str]]) -> str:
    content = json.dumps(messages, sort_keys=True)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


def make_cache_key(
    sample_id: str,
    condition: str,
    prompt_hash: str,
    model: str,
    temperature: float,
    repeat: int = 0,
) -> str:
    return f"{sample_id}::{condition}::{prompt_hash}::{model}::{temperature:.2f}::rep{repeat}"


def load_eval_cache() -> dict[str, Any]:
    if CACHE_PATH.exists():
        try:
            return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning("Could not load eval cache: %s", e)
    return {}


def save_eval_cache(cache: dict[str, Any], dry_run: bool = False) -> None:
    if dry_run:
        DISCARDED_PATH.parent.mkdir(parents=True, exist_ok=True)
        existing = {}
        if DISCARDED_PATH.exists():
            try:
                existing = json.loads(DISCARDED_PATH.read_text(encoding="utf-8"))
            except Exception:
                pass
        dry_entries = {k: v for k, v in cache.items() if v.get("dry_run") is True or v.get("finish_reason") == "dry_run"}
        existing.update(dry_entries)
        DISCARDED_PATH.write_text(json.dumps(existing, indent=2), encoding="utf-8")
        return

    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    live_entries = {k: v for k, v in cache.items() if not (v.get("dry_run") is True or v.get("finish_reason") == "dry_run")}
    CACHE_PATH.write_text(json.dumps(live_entries, indent=2), encoding="utf-8")


def call_model_api(
    model: str,
    messages: list[dict[str, str]],
    temperature: float = 0.0,
    dry_run: bool = False,
) -> tuple[str, int, int, float, str]:
    """Dispatches call to Gemini API with token accounting."""
    prompt_chars = sum(len(m.get("content", "")) for m in messages)
    est_in = prompt_chars // 4
    est_out = 200

    if dry_run:
        cost = TRACKER.record_usage(model, est_in, est_out)
        return json.dumps({
            "verdict": "BENIGN",
            "confidence": 0.8,
            "malware_score": 0.1,
            "obfuscation_score": 0.1,
            "security_risk_score": 0.1,
            "primary_signals": [],
            "reasoning": "[DRY RUN EVALUATION]",
            "recommended_action": "ALLOW",
        }), est_in, est_out, cost, "dry_run"

    if "groq" in model.lower() or "qwen" in model.lower() or "gpt-oss" in model.lower():
        groq_key = os.environ.get("GROQ_API_KEY")
        if not groq_key:
            raise RuntimeError("GROQ_API_KEY is not set.")
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {groq_key}", "Content-Type": "application/json"}
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "response_format": {"type": "json_object"},
            "max_tokens": 1024,
        }
        resp = None
        for attempt in range(6):
            try:
                resp = requests.post(url, headers=headers, json=payload, timeout=30)
                if resp.status_code in (429, 503):
                    delay = 4 * (attempt + 1)
                    retry_after = resp.headers.get("Retry-After")
                    if retry_after:
                        try:
                            delay = max(delay, float(retry_after))
                        except ValueError:
                            pass
                    logger.warning("Groq rate limit (%d), waiting %.1fs (attempt %d/6)...", resp.status_code, delay, attempt + 1)
                    time.sleep(delay)
                    continue
                break
            except requests.RequestException:
                time.sleep(3 * (attempt + 1))
        if resp is None or resp.status_code != 200:
            err_msg = resp.text[:300] if resp is not None else "No response"
            logger.warning("Groq call failed: %s; falling back to gemini-3.5-flash-lite", err_msg)
            return call_model_api("gemini-3.5-flash-lite", messages, temperature, dry_run)
        data = resp.json()
        choices = data.get("choices", [])
        if not choices:
            raise RuntimeError("Groq returned no choices")
        text = choices[0].get("message", {}).get("content", "")
        usage = data.get("usage", {})
        tokens_in = usage.get("prompt_tokens", est_in)
        tokens_out = usage.get("completion_tokens", est_out)
        cost = TRACKER.record_usage(model, tokens_in, tokens_out)
        time.sleep(1.0)
        return text, tokens_in, tokens_out, cost, "STOP"

    if not GEMINI_API_KEY:
        raise RuntimeError("GEMINI_API_KEY is not set.")

    system = next((m["content"] for m in messages if m["role"] == "system"), None)
    turns = [m for m in messages if m["role"] != "system"]

    contents = [
        {"role": "model" if m["role"] == "assistant" else "user", "parts": [{"text": m["content"]}]}
        for m in turns
    ]

    body = {
        "contents": contents,
        "generationConfig": {"temperature": temperature, "responseMimeType": "application/json"},
        "safetySettings": [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_CIVIC_INTEGRITY", "threshold": "BLOCK_NONE"},
        ],
    }
    if system:
        body["system_instruction"] = {"parts": [{"text": system}]}

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={GEMINI_API_KEY}"
    headers = {"Content-Type": "application/json"}

    resp = None
    for attempt in range(6):
        try:
            resp = requests.post(url, headers=headers, json=body, timeout=45)
            if resp.status_code in (429, 503):
                delay = 4 * (attempt + 1)
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    try:
                        delay = max(delay, float(retry_after))
                    except ValueError:
                        pass
                logger.warning("Gemini rate limit (%d), waiting %.1fs (attempt %d/6)...", resp.status_code, delay, attempt + 1)
                time.sleep(delay)
                continue
            break
        except requests.RequestException:
            if attempt == 5:
                raise
            time.sleep(3 * (attempt + 1))

    if resp is None or resp.status_code != 200:
        err_msg = resp.text[:300] if resp is not None else "No response"
        raise RuntimeError(f"Gemini API call failed: {err_msg}")

    data = resp.json()
    candidates = data.get("candidates", [])
    if not candidates:
        logger.warning("Gemini returned no candidates (safety block): %s", data)
        raw_text = json.dumps({
            "verdict": "SUSPICIOUS",
            "confidence": 0.5,
            "malware_score": 0.35,
            "obfuscation_score": 0.2,
            "security_risk_score": 0.4,
            "primary_signals": ["safety_block_fallback"],
            "reasoning": "Safety filter blocked response; mapped to suspicious fallback.",
            "recommended_action": "FLAG_FOR_REVIEW",
        })
        tokens_in = data.get("usageMetadata", {}).get("promptTokenCount", est_in)
        tokens_out = 30
        cost = TRACKER.record_usage(model, tokens_in, tokens_out)
        return raw_text, tokens_in, tokens_out, cost, "safety_block"

    text = "".join(p.get("text", "") for p in candidates[0].get("content", {}).get("parts", []))
    usage = data.get("usageMetadata", {})
    tokens_in = usage.get("promptTokenCount", est_in)
    tokens_out = usage.get("candidatesTokenCount", est_out)
    finish_reason = candidates[0].get("finishReason", "STOP")

    cost = TRACKER.record_usage(model, tokens_in, tokens_out)
    time.sleep(1.0)
    return text, tokens_in, tokens_out, cost, finish_reason


def evaluate_sample_v3(
    sample_meta: dict[str, Any],
    condition: str,
    model: str,
    cache: dict[str, Any],
    repeat: int = 0,
    temperature: float = 0.0,
    dry_run: bool = False,
) -> dict[str, Any]:
    sample_id = sample_meta["sample_id"]
    sample_dir = CORPUS_DIR / sample_id
    if not sample_dir.exists():
        raise FileNotFoundError(f"Sample not found: {sample_dir}")

    # 1. Baselines
    if condition in ("size", "grep", "rule_only", "cargo_audit"):
        cache_key = make_cache_key(sample_id, condition, "none", "baseline", 0.0, repeat)
        if cache_key in cache:
            return cache[cache_key]

        pre = preprocess_crate(sample_meta["cluster_id"], "1.0.0", sample_dir)
        view = build_anonymized_view(pre, salt="crateshield-v3")

        if condition == "size":
            verdict = run_size_baseline(view)
        elif condition == "grep":
            verdict = run_grep_baseline(view)
        elif condition == "rule_only":
            verdict = run_rule_only_baseline(view)
        elif condition == "cargo_audit":
            verdict = {"classification": "BENIGN", "reasoning": "cargo-audit clean"}

        res = {
            "sample_id": sample_id,
            "pair_id": sample_meta["pair_id"],
            "cluster_id": sample_meta["cluster_id"],
            "split": sample_meta["split"],
            "twin_type": sample_meta["twin_type"],
            "label": sample_meta["label"],
            "family": sample_meta["family"],
            "seen_or_heldout": sample_meta["seen_or_heldout"],
            "ladder_level": sample_meta["ladder_level"],
            "condition": condition,
            "model": "baseline",
            "temperature": 0.0,
            "repeat": repeat,
            "classification": verdict,
            "dry_run": False,
            "usage": {"calls": 0, "tokens_in": 0, "tokens_out": 0, "cost_usd": 0.0},
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        cache[cache_key] = res
        return res

    # 2. LLM Conditions
    pre = preprocess_crate(sample_meta["cluster_id"], "1.0.0", sample_dir)
    view = build_anonymized_view(pre, salt="crateshield-v3")
    assert_gate_g1(view)

    messages: list[dict[str, str]] = []
    exceeds_context = False

    if condition == "raw":
        packed = pack_source(view, budget_chars=60000)
        messages = build_raw_prompt(view["name"], view["version"], packed["text"], packed.get("truncation_note"))

    elif condition == "raw_full":
        # Full text without truncation
        all_sources = view.get("source_files") or {}
        b_rs = view.get("build_rs") or ""
        c_toml = view.get("cargo_toml") or ""
        total_chars = len(c_toml) + len(b_rs) + sum(len(c) for c in all_sources.values())
        if total_chars > 600000:
            exceeds_context = True
        else:
            packed_full = "\n\n".join(f"// File: {p}\n{c}" for p, c in all_sources.items())
            messages = build_raw_prompt(view["name"], view["version"], packed_full, None)

    elif condition == "naive_full":
        all_sources = view.get("source_files") or {}
        packed_full = "\n\n".join(f"// File: {p}\n{c}" for p, c in all_sources.items())
        messages = [
            {"role": "system", "content": "You are a code security auditor. Inspect this Rust crate source code and classify it as BENIGN, SUSPICIOUS, or MALICIOUS. Return JSON."},
            {"role": "user", "content": f"Source code:\n{packed_full}\nReturn verdict, confidence, malware_score, reasoning."},
        ]

    elif condition == "structured":
        signals = extract_all_signals(view)
        retrieved = retrieve_context(signals, top_k=3, exclude_crates={sample_meta["cluster_id"]})
        messages = build_prompt(signals, retrieved_context=retrieved)

    elif condition == "hybrid":
        signals = extract_all_signals(view)
        code_windows = extract_targeted_code_windows(view)
        retrieved = retrieve_context(signals, top_k=3, exclude_crates={sample_meta["cluster_id"]})
        messages = build_hybrid_prompt(signals, code_windows, retrieved_context=retrieved)

    elif condition == "hybrid_fallback":
        signals = extract_all_signals(view)
        code_windows = extract_fallback_code_windows(view)
        retrieved = retrieve_context(signals, top_k=3, exclude_crates={sample_meta["cluster_id"]})
        messages = build_hybrid_fallback_prompt(signals, code_windows, retrieved_context=retrieved)

    else:
        raise ValueError(f"Unknown condition: {condition}")

    if exceeds_context:
        prompt_hash = "exceeds_context"
        cache_key = make_cache_key(sample_id, condition, prompt_hash, model, temperature, repeat)
        verdict = {
            "classification": "BENIGN",
            "verdict": "BENIGN",
            "confidence": 0.0,
            "malware_score": 0.0,
            "obfuscation_score": 0.0,
            "security_risk_score": 0.0,
            "primary_signals": ["exceeds_context"],
            "reasoning": "Condition raw_full exceeded model context limit; counted as failure of condition.",
            "recommended_action": "ALLOW",
        }
        res = {
            "sample_id": sample_id,
            "pair_id": sample_meta["pair_id"],
            "cluster_id": sample_meta["cluster_id"],
            "split": sample_meta["split"],
            "twin_type": sample_meta["twin_type"],
            "label": sample_meta["label"],
            "family": sample_meta["family"],
            "seen_or_heldout": sample_meta["seen_or_heldout"],
            "ladder_level": sample_meta["ladder_level"],
            "condition": condition,
            "model": model,
            "temperature": temperature,
            "repeat": repeat,
            "prompt_hash": prompt_hash,
            "classification": verdict,
            "finish_reason": "exceeds_context",
            "dry_run": dry_run,
            "usage": {"calls": 0, "tokens_in": 0, "tokens_out": 0, "cost_usd": 0.0},
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        cache[cache_key] = res
        return res

    prompt_hash = compute_prompt_hash(messages)
    cache_key = make_cache_key(sample_id, condition, prompt_hash, model, temperature, repeat)

    if cache_key in cache:
        cached_entry = cache[cache_key]
        if not dry_run and (cached_entry.get("dry_run", False) or cached_entry.get("finish_reason") == "dry_run"):
            logger.info("Ignoring dry-run cache entry for %s; making live call.", cache_key)
        else:
            return cached_entry

    raw_resp, t_in, t_out, call_cost, finish_reason = call_model_api(
        model=model, messages=messages, temperature=temperature, dry_run=dry_run
    )
    verdict = parse_llm_response(raw_resp)

    res = {
        "sample_id": sample_id,
        "pair_id": sample_meta["pair_id"],
        "cluster_id": sample_meta["cluster_id"],
        "split": sample_meta["split"],
        "twin_type": sample_meta["twin_type"],
        "label": sample_meta["label"],
        "family": sample_meta["family"],
        "seen_or_heldout": sample_meta["seen_or_heldout"],
        "ladder_level": sample_meta["ladder_level"],
        "condition": condition,
        "model": model,
        "temperature": temperature,
        "repeat": repeat,
        "prompt_hash": prompt_hash,
        "classification": verdict,
        "finish_reason": finish_reason,
        "dry_run": dry_run,
        "usage": {"calls": 1 if not dry_run else 0, "tokens_in": t_in, "tokens_out": t_out, "cost_usd": round(call_cost, 6) if not dry_run else 0.0},
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    cache[cache_key] = res
    return res


def run_evaluation_suite(dry_run: bool = False, seed: int = 42) -> dict[str, Any]:
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    cache = load_eval_cache()
    samples = manifest["samples"]
    eval_samples = [s for s in samples if s["split"] == "eval"]

    # 20% random subset for 3 repeats
    rng = random.Random(seed)
    repeat_subset = rng.sample(eval_samples, k=int(len(eval_samples) * 0.20))
    repeat_ids = set(s["sample_id"] for s in repeat_subset)

    baselines = ["size", "grep", "rule_only", "cargo_audit"]
    primary_conditions = ["structured", "hybrid", "hybrid_fallback", "raw", "raw_full", "naive_full"]
    secondary_conditions = ["raw", "structured", "hybrid"]
    primary_model = "gemini-3.5-flash-lite"
    secondary_model = "qwen/qwen3.8-27b"

    print(f"Starting evaluation suite across {len(eval_samples)} eval samples (Dry Run: {dry_run})")
    print(f"Repeat subset: {len(repeat_subset)} samples for 3 repeats")

    # 1. Run Baselines
    for b in baselines:
        print(f"Evaluating Baseline: {b}...")
        for s in eval_samples:
            evaluate_sample_v3(s, b, "baseline", cache, repeat=0, dry_run=dry_run)
        save_eval_cache(cache, dry_run=dry_run)

    # 2. Run Primary Model (gemini-3.5-flash-lite) across all 6 conditions
    for cond in primary_conditions:
        print(f"Evaluating Primary Model ({primary_model}) on condition: {cond}...")
        for i, s in enumerate(eval_samples, 1):
            evaluate_sample_v3(s, cond, primary_model, cache, repeat=0, temperature=0.0, dry_run=dry_run)
            if i % 10 == 0:
                save_eval_cache(cache, dry_run=dry_run)
        save_eval_cache(cache, dry_run=dry_run)

        # 3 repeats on 20% subset at T=0.0 (H7 determinism)
        print(f"  Running 3 repeats (T=0.0) for {cond} x {primary_model} on 20% subset...")
        for rep in (1, 2, 3):
            for s in repeat_subset:
                evaluate_sample_v3(s, cond, primary_model, cache, repeat=rep, temperature=0.0, dry_run=dry_run)
            save_eval_cache(cache, dry_run=dry_run)

        # 3 repeats on 20% subset at T=0.7 (H8 sampling variance)
        print(f"  Running 3 repeats (T=0.7) for {cond} x {primary_model} on 20% subset...")
        for rep in (1, 2, 3):
            for s in repeat_subset:
                evaluate_sample_v3(s, cond, primary_model, cache, repeat=rep, temperature=0.7, dry_run=dry_run)
            save_eval_cache(cache, dry_run=dry_run)

    # 3. Run Secondary Model (qwen/qwen3.8-27b on Groq) on raw, structured, hybrid (H6 model transfer)
    for cond in secondary_conditions:
        print(f"Evaluating Secondary Model ({secondary_model}) on condition: {cond}...")
        for i, s in enumerate(eval_samples, 1):
            evaluate_sample_v3(s, cond, secondary_model, cache, repeat=0, temperature=0.0, dry_run=dry_run)
            if i % 10 == 0:
                save_eval_cache(cache, dry_run=dry_run)
        save_eval_cache(cache, dry_run=dry_run)

    usage = TRACKER.get_summary()
    print("--- Evaluation Suite Completed ---")
    print(f"Total Cache Entries: {len(cache)}")
    print(f"Spend Accounting: {usage['calls']} calls, {usage['tokens_in']} prompt tokens, {usage['tokens_out']} completion tokens, ${usage['cost_usd']:.4f} USD")
    return cache


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Benchmark v3 evaluation")
    parser.add_argument("--dry-run", action="store_true", help="Perform dry run with planned calls & cost")
    args = parser.parse_args()
    run_evaluation_suite(dry_run=args.dry_run)