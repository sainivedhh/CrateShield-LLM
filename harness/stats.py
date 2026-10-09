"""Statistical Evaluation Engine implementing Section 11 of the CrateShield Harness Spec.

Features:
1. Dual-Threshold Reporting:
   - Strict: MALICIOUS only (primary)
   - Relaxed: MALICIOUS + SUSPICIOUS (secondary)
2. Statistical Confidence Intervals:
   - Cluster bootstrap by base crate (B = 10,000) for Tier 3 paired samples.
   - Wilson score intervals for binomial metrics on small/unpaired sets (Tiers 1 & 2).
3. Paired Condition Testing:
   - McNemar's exact test on paired per-sample outcomes.
4. Stratifications & Consistency:
   - Pair consistency rate (percentage of base crates where both twins were classified correctly).
   - Recall breakdown by attack category (C1..C8), placement (P1..P5), and obfuscation level.
"""
from __future__ import annotations

import math
from collections import defaultdict
import random
from typing import Any


def wilson_score_interval(k: int, n: int, confidence: float = 0.95) -> tuple[float, float]:
    """Computes Wilson score interval for a binomial proportion k/n."""
    if n == 0:
        return 0.0, 0.0
    z = 1.95996  # 95% confidence level
    p_hat = k / n
    denom = 1 + (z**2) / n
    center = (p_hat + (z**2) / (2 * n)) / denom
    margin = (z * math.sqrt((p_hat * (1 - p_hat) + (z**2) / (4 * n)) / n)) / denom
    lower = max(0.0, center - margin)
    upper = min(1.0, center + margin)
    return round(lower, 3), round(upper, 3)


def mcnemar_exact_test(b: int, c: int) -> float:
    """Computes exact two-tailed McNemar test p-value for discordant pairs (b, c).
    b: condition 1 correct, condition 2 incorrect
    c: condition 1 incorrect, condition 2 correct
    """
    n = b + c
    if n == 0:
        return 1.0

    # If small sample, exact binomial
    k = min(b, c)
    # Binomial sum for p=0.5
    prob_less = sum(math.comb(n, i) * (0.5**n) for i in range(k + 1))
    p_value = min(1.0, 2 * prob_less)
    return round(p_value, 4)


def paired_mcnemar(
    res1: list[dict[str, Any]],
    res2: list[dict[str, Any]],
    strict: bool = True,
) -> dict[str, Any]:
    """Computes discordant pairs and McNemar exact p-value between two evaluated conditions."""
    map1 = {r["sample_id"]: r for r in res1}
    map2 = {r["sample_id"]: r for r in res2}
    common_ids = sorted(set(map1.keys()) & set(map2.keys()))

    b = 0  # c1 correct, c2 incorrect
    c = 0  # c1 incorrect, c2 correct

    for sid in common_ids:
        r1, r2 = map1[sid], map2[sid]
        gt = r1.get("ground_truth") or r1.get("label")
        exp_mal = (gt in ("MALICIOUS", "SUSPICIOUS"))

        pred1 = (r1.get("classification") or {}).get("classification")
        c1_mal = (pred1 == "MALICIOUS") if strict else (pred1 in ("MALICIOUS", "SUSPICIOUS"))
        ok1 = (c1_mal == exp_mal)

        pred2 = (r2.get("classification") or {}).get("classification")
        c2_mal = (pred2 == "MALICIOUS") if strict else (pred2 in ("MALICIOUS", "SUSPICIOUS"))
        ok2 = (c2_mal == exp_mal)

        if ok1 and not ok2:
            b += 1
        elif not ok1 and ok2:
            c += 1

    p_val = mcnemar_exact_test(b, c)
    return {
        "n_discordant": b + c,
        "cond1_wins": b,
        "cond2_wins": c,
        "p_value": p_val,
        "significant_p05": p_val < 0.05,
    }


def compute_metrics_for_sample_set(
    results: list[dict[str, Any]],
    strict: bool = True,
) -> dict[str, Any]:
    """Computes point estimate metrics under strict or relaxed threshold.

    strict=True: MALICIOUS is positive, SUSPICIOUS and BENIGN are negative.
    strict=False: MALICIOUS and SUSPICIOUS are positive, BENIGN is negative.
    """
    tp = fp = fn = tn = 0

    for r in results:
        ground_truth = r.get("ground_truth") or r.get("label")
        if not ground_truth:
            continue
        y_true = 1 if ground_truth in ("MALICIOUS", "SUSPICIOUS") else 0

        pred = (r.get("classification") or {}).get("classification")
        if strict:
            y_pred = 1 if pred == "MALICIOUS" else 0
        else:
            y_pred = 1 if pred in ("MALICIOUS", "SUSPICIOUS") else 0

        if y_true == 1 and y_pred == 1:
            tp += 1
        elif y_true == 0 and y_pred == 1:
            fp += 1
        elif y_true == 1 and y_pred == 0:
            fn += 1
        else:
            tn += 1

    n_pos = tp + fn
    n_neg = fp + tn

    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / n_pos) if n_pos > 0 else 0.0
    fpr = (fp / n_neg) if n_neg > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return {
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "fpr": round(fpr, 3),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "n_pos": n_pos, "n_neg": n_neg,
        "strict": strict,
    }


def cluster_bootstrap_by_base(
    results: list[dict[str, Any]],
    B: int = 1000,
    seed: int = 42,
    strict: bool = True,
) -> dict[str, tuple[float, float]]:
    """Performs cluster bootstrap resampling by base crate (cluster_id) to compute 95% CIs."""
    clusters: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in results:
        cluster_id = r.get("cluster_id") or r.get("base_crate") or r.get("crate")
        clusters[cluster_id].append(r)

    cluster_keys = list(clusters.keys())
    if not cluster_keys:
        return {}

    rng = random.Random(seed)
    n_clusters = len(cluster_keys)

    recalls, precisions, f1s, fprs = [], [], [], []

    for _ in range(B):
        sampled_keys = [cluster_keys[rng.randint(0, n_clusters - 1)] for _ in range(n_clusters)]
        sample_records = [record for k in sampled_keys for record in clusters[k]]
        m = compute_metrics_for_sample_set(sample_records, strict=strict)
        recalls.append(m["recall"])
        precisions.append(m["precision"])
        f1s.append(m["f1"])
        fprs.append(m["fpr"])

    def percentile_ci(values: list[float]) -> tuple[float, float]:
        values.sort()
        low = values[int(0.025 * len(values))]
        high = values[int(0.975 * len(values))]
        return round(low, 3), round(high, 3)

    return {
        "recall_ci": percentile_ci(recalls),
        "precision_ci": percentile_ci(precisions),
        "f1_ci": percentile_ci(f1s),
        "fpr_ci": percentile_ci(fprs),
    }


def compute_pair_consistency(results: list[dict[str, Any]], strict: bool = True) -> float:
    """Computes pair consistency: percentage of base crates where both twins were classified correctly.
    
    Definition: A pair is consistent iff the malicious twin is classified MALICIOUS (or SUSPICIOUS under relaxed)
    AND the benign twin is classified BENIGN.
    """
    pairs: dict[str, dict[str, str]] = defaultdict(dict)
    for r in results:
        pair_key = r.get("pair_id") or r.get("cluster_id") or r.get("base_crate")
        lbl = r.get("ground_truth") or r.get("label")
        pred = (r.get("classification") or {}).get("classification")
        if pair_key and lbl and pred:
            pairs[pair_key][lbl] = pred

    perfect_pairs = 0
    total_valid_pairs = 0

    for cluster_id, twins in pairs.items():
        if "MALICIOUS" not in twins or "BENIGN" not in twins:
            continue
        total_valid_pairs += 1
        mal_pred = twins["MALICIOUS"]
        ben_pred = twins["BENIGN"]
        
        mal_ok = (mal_pred == "MALICIOUS") if strict else (mal_pred in ("MALICIOUS", "SUSPICIOUS"))
        ben_ok = (ben_pred == "BENIGN")
        
        if mal_ok and ben_ok:
            perfect_pairs += 1

    return round((perfect_pairs / total_valid_pairs), 3) if total_valid_pairs > 0 else 0.0


def compute_pair_consistency_stats(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Returns detailed pair consistency statistics including counts and fractions."""
    pairs: dict[str, dict[str, str]] = defaultdict(dict)
    for r in results:
        pair_key = r.get("pair_id") or r.get("cluster_id") or r.get("base_crate")
        lbl = r.get("ground_truth") or r.get("label")
        pred = (r.get("classification") or {}).get("classification")
        if pair_key and lbl and pred:
            pairs[pair_key][lbl] = pred

    strict_count = 0
    relaxed_count = 0
    total_pairs = 0

    for cluster_id, twins in pairs.items():
        if "MALICIOUS" not in twins or "BENIGN" not in twins:
            continue
        total_pairs += 1
        mal_pred = twins["MALICIOUS"]
        ben_pred = twins["BENIGN"]
        
        if mal_pred == "MALICIOUS" and ben_pred == "BENIGN":
            strict_count += 1
        if mal_pred in ("MALICIOUS", "SUSPICIOUS") and ben_pred == "BENIGN":
            relaxed_count += 1

    return {
        "total_pairs": total_pairs,
        "strict_count": strict_count,
        "strict_fraction": round(strict_count / total_pairs, 3) if total_pairs > 0 else 0.0,
        "relaxed_count": relaxed_count,
        "relaxed_fraction": round(relaxed_count / total_pairs, 3) if total_pairs > 0 else 0.0,
    }
