"""Tune Split Evaluation & Prompt Tuning Runner (Phase 4).

Evaluates the 20 Tune samples under LLM conditions to test Hypothesis H1:
- strict recall >= raw - 0.10
- tokens <= 50% of raw mean tokens
- FPR <= 0.10
Logs metrics to TUNING_LOG.md.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.extend(["src", "."])

from harness.eval_v2 import run_split_evaluation


def evaluate_tune():
    conditions = ["hybrid", "hybrid_norag", "structured", "raw"]
    results = run_split_evaluation(split="tune", conditions=conditions)

    metrics = {}
    for cond, sample_results in results.items():
        tp = sum(1 for r in sample_results if r["label"] == "MALICIOUS" and r["classification"]["classification"] == "MALICIOUS")
        fn = sum(1 for r in sample_results if r["label"] == "MALICIOUS" and r["classification"]["classification"] != "MALICIOUS")
        fp = sum(1 for r in sample_results if r["label"] == "BENIGN" and r["classification"]["classification"] == "MALICIOUS")
        tn = sum(1 for r in sample_results if r["label"] == "BENIGN" and r["classification"]["classification"] != "MALICIOUS")

        relaxed_tp = sum(1 for r in sample_results if r["label"] == "MALICIOUS" and r["classification"]["classification"] in ("MALICIOUS", "SUSPICIOUS"))
        relaxed_fp = sum(1 for r in sample_results if r["label"] == "BENIGN" and r["classification"]["classification"] in ("MALICIOUS", "SUSPICIOUS"))

        strict_recall = tp / (tp + fn) if (tp + fn) else 0.0
        strict_fpr = fp / (fp + tn) if (fp + tn) else 0.0
        relaxed_recall = relaxed_tp / (tp + fn) if (tp + fn) else 0.0
        relaxed_fpr = relaxed_fp / (fp + tn) if (fp + tn) else 0.0

        tok_in = [r["usage"].get("tokens_in", 0) for r in sample_results]
        tok_out = [r["usage"].get("tokens_out", 0) for r in sample_results]

        mean_tok_in = sum(tok_in) / len(tok_in) if tok_in else 0
        mean_tok_out = sum(tok_out) / len(tok_out) if tok_out else 0
        mean_tok_total = mean_tok_in + mean_tok_out

        metrics[cond] = {
            "strict_recall": round(strict_recall, 3),
            "strict_fpr": round(strict_fpr, 3),
            "relaxed_recall": round(relaxed_recall, 3),
            "relaxed_fpr": round(relaxed_fpr, 3),
            "mean_tokens_in": round(mean_tok_in, 1),
            "mean_tokens_out": round(mean_tok_out, 1),
            "mean_total_tokens": round(mean_tok_total, 1),
            "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        }

    print("=== TUNE EVALUATION RESULTS ===")
    print(json.dumps(metrics, indent=2))
    return metrics


if __name__ == "__main__":
    evaluate_tune()
