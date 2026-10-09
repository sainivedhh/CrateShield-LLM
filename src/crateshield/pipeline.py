"""End-to-end pipeline orchestrator. download -> (signals | packed source |
per-file workflow) -> LLM reasoning -> persisted result. The LLM call IS the
classification decision; nothing downstream re-scores it (the only
post-processing is the parser's score/label reconciliation, which can only
escalate a BENIGN verdict, and citation verification, which only annotates).

Conditions (see README "Ablation"):
  structured        signals + RAG + LLM                       (the system)
  structured_norag  signals + LLM, no retrieval               (isolates RAG)
  raw               packed raw source + domain prompt + LLM   (isolates the extractor)
  naive             packed raw source + bare "is it malicious?" prompt
"""
from __future__ import annotations

import json
import logging

from crateshield.config import ALL_CONDITIONS, RAW_SOURCE_CHAR_BUDGET, RESULTS_DIR
from crateshield.ingestion.downloader import (
    download_and_extract, get_crate_metadata, preprocess_crate,
)
from crateshield.llm import client
from crateshield.llm.packing import pack_source
from crateshield.llm.parser import parse_llm_response
from crateshield.llm.prompt import build_naive_prompt, build_prompt, build_raw_prompt
from crateshield.prescreen import decide_prescreen, skipped_classification
from crateshield.rag.retriever import retrieve_context
from crateshield.signals.extractor import extract_all_signals

logger = logging.getLogger(__name__)


def _verify_citations(classification: dict, retrieved: list[dict]) -> None:
    """The model's `retrieved_evidence_used` is self-reported. Keep only ids
    that were actually retrieved; record the rest so hallucinated citations
    are visible instead of silently trusted."""
    cited = classification.get("retrieved_evidence_used") or []
    if not isinstance(cited, list):
        cited = []
    valid_ids = {d["id"] for d in retrieved}
    classification["retrieved_evidence_used"] = [c for c in cited if c in valid_ids]
    classification["unverified_citations"] = [c for c in cited if c not in valid_ids]


def analyze_crate(name: str, version: str, ground_truth_label: str | None = None,
                  condition: str = "structured", prescreen: bool = False,
                  holdout: bool | None = None, reuse_cached: bool = False) -> dict:
    """prescreen: opt-in static pre-screen (structured conditions only); skips
    the LLM when no cheap signal fires.
    holdout: leave-one-out retrieval (a crate's own incident write-up is not
    retrievable for that crate). Defaults to True whenever a ground-truth
    label is supplied, i.e. during evaluation."""
    if condition not in ALL_CONDITIONS:
        raise ValueError(f"unknown condition {condition!r}; expected one of {ALL_CONDITIONS}")
    if not version:
        raise ValueError("a concrete version is required (dataset entries with version=None "
                         "are not analyzable)")
    if holdout is None:
        holdout = ground_truth_label is not None

    out_path = RESULTS_DIR / f"{name}-{version}-{condition}.json"
    if reuse_cached and out_path.exists():
        try:
            cached = json.loads(out_path.read_text(encoding="utf-8"))
            if cached.get("classification") and "classification" in cached["classification"]:
                cached_had_prescreen = bool(cached.get("prescreen"))
                if cached_had_prescreen == prescreen:
                    if ground_truth_label is not None:
                        cached["ground_truth"] = ground_truth_label
                        cached["correct"] = (cached["classification"]["classification"] == ground_truth_label)
                    logger.info("Reusing cached result for %s v%s (%s)", name, version, condition)
                    return cached
        except Exception:
            pass

    logger.info("Analyzing %s v%s (condition=%s, prescreen=%s, holdout=%s)",
                name, version, condition, prescreen, holdout)
    usage_before = client.get_usage()

    structured = condition in ("structured", "structured_norag")
    metadata = None
    if structured:
        try:
            metadata = get_crate_metadata(name)
        except Exception as e:
            logger.warning("Could not fetch crates.io metadata for %s: %s", name, e)

    crate_dir = download_and_extract(name, version, RESULTS_DIR)
    preprocessed = preprocess_crate(name, version, crate_dir)

    signals = None
    retrieved: list[dict] = []
    packing = None
    decision = None

    if structured:
        signals = extract_all_signals(preprocessed, metadata)
        if prescreen:
            decision = decide_prescreen(signals)
        if decision and decision["skip_llm"]:
            classification = skipped_classification(decision)
        else:
            if condition == "structured":
                retrieved = retrieve_context(signals, top_k=3,
                                             exclude_crates={name} if holdout else None)
            messages = build_prompt(signals, retrieved_context=retrieved)
            classification = parse_llm_response(client.query_llm(messages))
            _verify_citations(classification, retrieved)
    elif condition in ("raw", "naive"):
        packing = pack_source(preprocessed, RAW_SOURCE_CHAR_BUDGET)
        builder = build_raw_prompt if condition == "raw" else build_naive_prompt
        messages = builder(name, version, packing["text"], packing["truncation_note"])
        classification = parse_llm_response(client.query_llm(messages))
        packing = {k: v for k, v in packing.items() if k != "text"}
    else:
        raise ValueError(f"unsupported condition: {condition}")

    usage_after = client.get_usage()
    result = {
        "crate": name, "version": version, "condition": condition,
        "signals": signals, "classification": classification,
        "retrieved_context": retrieved,
        "prescreen": decision, "packing": packing,
        "holdout": holdout,
        "usage": {k: usage_after[k] - usage_before[k] for k in usage_after},
        "ground_truth": ground_truth_label,
        "correct": (
            classification["classification"] == ground_truth_label
            if ground_truth_label else None
        ),
    }

    out_path = RESULTS_DIR / f"{name}-{version}-{condition}.json"
    out_path.write_text(json.dumps(result, indent=2))
    return result
