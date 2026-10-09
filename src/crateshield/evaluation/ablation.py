"""Ablation over LLM conditions plus the cargo-audit baseline.

Conditions (each answers a specific question):
  structured        the full system (signals + RAG + LLM)
  structured_norag  same without retrieval          -> what does RAG add?
  raw               raw source + domain prompt      -> what do the signals add?
  naive             raw source + bare prompt        -> does any of it beat "just ask an LLM"?
  cargo_audit       advisory lookup                 -> status quo

Only dataset entries marked `analyzable` (a concrete version that is still
downloadable) are run; the rest are counted and reported, never dropped
silently. Leave-one-out retrieval is on for every evaluated crate.
"""
from __future__ import annotations

import json
import logging

from crateshield.config import ALL_CONDITIONS, RESULTS_DIR
from crateshield.evaluation.baseline_cargo import run_cargo_audit
from crateshield.evaluation.metrics import compute_metrics
from crateshield.llm import client
from crateshield.pipeline import analyze_crate

logger = logging.getLogger(__name__)


def split_dataset(dataset: list[dict]) -> tuple[list[dict], list[dict]]:
    from crateshield.ingestion.downloader import is_crate_available_locally
    runnable = [
        e for e in dataset
        if e.get("version") and (e.get("analyzable", True) or is_crate_available_locally(e["name"], e.get("version")))
    ]
    skipped = [e for e in dataset if e not in runnable]
    return runnable, skipped


class AblationRunner:
    def run_condition(self, dataset: list[dict], condition: str, prescreen: bool = False) -> list[dict]:
        out = []
        total = len(dataset)
        for i, entry in enumerate(dataset, 1):
            try:
                logger.info("[%d/%d] [%s] %s v%s (ground truth: %s)...",
                            i, total, condition, entry["name"], entry["version"], entry["label"])
                res = analyze_crate(entry["name"], entry["version"],
                                    ground_truth_label=entry["label"],
                                    condition=condition, prescreen=prescreen, holdout=True,
                                    reuse_cached=True)
                pred = res.get("classification", {}).get("classification")
                logger.info("   -> Result: %s (truth: %s)", pred, entry["label"])
                out.append(res)
            except client.LLMNotConfiguredError:
                raise
            except Exception as e:
                logger.error("Condition %s failed for %s@%s: %s", condition, entry["name"],
                             entry.get("version"), e)
        return out

    def run_cargo_audit(self, dataset: list[dict]) -> list[dict]:
        out = []
        for entry in dataset:
            verdict = run_cargo_audit(entry["name"], entry["version"])
            out.append({
                "crate": entry["name"], "version": entry["version"],
                "ground_truth": entry["label"], "classification": verdict,
            })
        return out


def run_full_ablation(dataset: list[dict], conditions: tuple[str, ...] | list[str] | None = None,
                      prescreen: bool = False, include_cargo_audit: bool = True) -> dict:
    conditions = tuple(conditions) if conditions else ALL_CONDITIONS
    unknown = [c for c in conditions if c not in ALL_CONDITIONS]
    if unknown:
        raise ValueError(f"unknown condition(s): {unknown}")

    runnable, skipped = split_dataset(dataset)
    runner = AblationRunner()
    metrics: dict = {}
    usage: dict = {}
    for cond in conditions:
        before = client.get_usage()
        results = runner.run_condition(runnable, cond, prescreen=prescreen and cond.startswith("structured"))
        after = client.get_usage()
        usage[cond] = {k: after[k] - before[k] for k in after}
        metrics[cond] = compute_metrics(results, n_skipped_unanalyzable=len(skipped))
        metrics[cond]["n_run"] = len(results)
        metrics[cond]["n_failed"] = len(runnable) - len(results)
    if include_cargo_audit:
        # cargo-audit is an advisory lookup, so it can be evaluated on every entry that has a name.
        metrics["cargo_audit"] = compute_metrics(runner.run_cargo_audit(
            [e for e in dataset if e.get("version")]), n_skipped_unanalyzable=len(skipped))
    metrics["_meta"] = {
        "n_dataset": len(dataset), "n_analyzable": len(runnable),
        "n_skipped_unanalyzable": len(skipped),
        "skipped": [{"name": e["name"], "version": e.get("version"),
                     "reason": e.get("note", "not analyzable")} for e in skipped],
        "prescreen": prescreen, "usage": usage,
        "note": ("cargo_audit matches RustSec malicious advisories by crate name. It is circular for "
                 "dataset entries whose label_source is itself a RustSec advisory (it will trivially "
                 "'detect' them), and it is an advisory lookup, not a behavioural detector."),
    }
    summary_path = RESULTS_DIR / "ablation_summary.json"
    summary_path.write_text(json.dumps(metrics, indent=2))
    logger.info("Saved ablation summary to %s", summary_path)
    return metrics
