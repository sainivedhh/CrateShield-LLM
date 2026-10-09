"""Precision/Recall/F1/FPR over LLM classification results. No trained
model is evaluated here -- this scores the LLM's own verdicts against
ground truth.

Undefined is not zero: with no benign examples in the evaluated set,
precision/F1/FPR are reported as None (with a warning) instead of the
misleading 1.0/0.0 that a division-guarded formula would give."""
from __future__ import annotations


def compute_metrics(results: list[dict], n_skipped_unanalyzable: int = 0) -> dict:
    """Treats MALICIOUS+SUSPICIOUS as positive class, BENIGN as negative,
    per Section 12.3 of the proposal (SUSPICIOUS counted for Recall).

    n_skipped_unanalyzable: dataset entries that could not be run (crate no
    longer downloadable, version unknown). Reported, never silently dropped."""
    tp = fp = fn = tn = 0
    llm_skipped = 0
    for r in results:
        if r.get("ground_truth") is None:
            continue
        y_true = 1 if r["ground_truth"] in ("MALICIOUS", "SUSPICIOUS") else 0
        cls = r["classification"]
        pred_label = cls["classification"]
        y_pred = 1 if pred_label in ("MALICIOUS", "SUSPICIOUS") else 0
        if cls.get("llm_skipped"):
            llm_skipped += 1

        if y_true == 1 and y_pred == 1:
            tp += 1
        elif y_true == 0 and y_pred == 1:
            fp += 1
        elif y_true == 1 and y_pred == 0:
            fn += 1
        else:
            tn += 1

    n_mal, n_ben = tp + fn, fp + tn
    recall = tp / n_mal if n_mal else None
    warnings = []
    if n_ben == 0:
        precision = f1 = fpr = None
        warnings.append("no benign examples evaluated: precision, F1 and FPR are undefined")
    else:
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        fpr = fp / n_ben
        f1 = (2 * precision * recall / (precision + recall)) if (recall is not None and (precision + recall)) else 0.0
    if n_mal == 0:
        warnings.append("no malicious examples evaluated: recall is undefined")
    if n_mal + n_ben < 30:
        warnings.append(f"only {n_mal + n_ben} evaluated example(s): results are anecdotal, not statistical")

    def r3(x):
        return None if x is None else round(x, 3)

    return {
        "precision": r3(precision), "recall": r3(recall), "f1": r3(f1), "fpr": r3(fpr),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "n_malicious": n_mal, "n_benign": n_ben,
        "n_llm_skipped_by_prescreen": llm_skipped,
        "n_skipped_unanalyzable": n_skipped_unanalyzable,
        "warnings": warnings,
    }


CONDITION_LABELS = {
    "structured": "Signals + RAG + LLM",
    "structured_norag": "Signals + LLM (no RAG)",
    "raw": "Raw source + domain prompt",
    "naive": "Naive prompt (baseline)",
    "cargo_audit": "cargo-audit (advisory lookup)",
}


def _fmt(x) -> str:
    return "n/a" if x is None else f"{x:.3f}"


def print_ablation_table(metrics: dict) -> str:
    lines = [f"{'Condition':<38} {'Precision':>10} {'Recall':>10} {'F1':>10} {'FPR':>10} {'LLM calls':>10}",
             "-" * 92]
    usage = metrics.get("_meta", {}).get("usage", {})
    for key, label in CONDITION_LABELS.items():
        if key not in metrics:
            continue
        m = metrics[key]
        calls = usage.get(key, {}).get("calls")
        lines.append(f"{label:<38} {_fmt(m['precision']):>10} {_fmt(m['recall']):>10} "
                     f"{_fmt(m['f1']):>10} {_fmt(m['fpr']):>10} {('-' if calls is None else calls):>10}")
    meta = metrics.get("_meta", {})
    if meta:
        lines.append("")
        lines.append(f"dataset entries: {meta.get('n_dataset')} | analyzable: {meta.get('n_analyzable')} | "
                     f"skipped (not downloadable / no version): {meta.get('n_skipped_unanalyzable')}")
    warns = sorted({w for k, v in metrics.items() if isinstance(v, dict) and k != "_meta"
                    for w in v.get("warnings", [])})
    for w in warns:
        lines.append(f"WARNING: {w}")
    table = "\n".join(lines)
    print(table)
    return table
