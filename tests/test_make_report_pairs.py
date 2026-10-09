"""Unit tests for pair consistency calculation in reporting (Task 1)."""
import pytest
from harness.stats import compute_pair_consistency, compute_pair_consistency_stats


def test_synthetic_pair_consistency():
    # 4 synthetic pairs:
    # p1: mal=MALICIOUS, ben=BENIGN -> strict=True, relaxed=True
    # p2: mal=SUSPICIOUS, ben=BENIGN -> strict=False, relaxed=True
    # p3: mal=MALICIOUS, ben=SUSPICIOUS -> strict=False, relaxed=False (benign not BENIGN)
    # p4: mal=BENIGN, ben=BENIGN -> strict=False, relaxed=False (mal missed)
    records = [
        {"pair_id": "p1", "label": "MALICIOUS", "classification": {"classification": "MALICIOUS"}},
        {"pair_id": "p1", "label": "BENIGN", "classification": {"classification": "BENIGN"}},
        {"pair_id": "p2", "label": "MALICIOUS", "classification": {"classification": "SUSPICIOUS"}},
        {"pair_id": "p2", "label": "BENIGN", "classification": {"classification": "BENIGN"}},
        {"pair_id": "p3", "label": "MALICIOUS", "classification": {"classification": "MALICIOUS"}},
        {"pair_id": "p3", "label": "BENIGN", "classification": {"classification": "SUSPICIOUS"}},
        {"pair_id": "p4", "label": "MALICIOUS", "classification": {"classification": "BENIGN"}},
        {"pair_id": "p4", "label": "BENIGN", "classification": {"classification": "BENIGN"}},
    ]

    strict_rate = compute_pair_consistency(records, strict=True)
    assert strict_rate == 0.25  # 1/4

    relaxed_rate = compute_pair_consistency(records, strict=False)
    assert relaxed_rate == 0.50  # 2/4

    stats = compute_pair_consistency_stats(records)
    assert stats["total_pairs"] == 4
    assert stats["strict_count"] == 1
    assert stats["strict_fraction"] == 0.25
    assert stats["relaxed_count"] == 2
    assert stats["relaxed_fraction"] == 0.50


def test_pair_consistency_lower_bound():
    # Lower bound assertion: pair_consistent_count >= max(0, TP + TN - n_pairs)
    # Case with high overlap: TP=8/10, TN=9/10, n_pairs=10 -> lower bound is 8+9-10 = 7.
    records = []
    # 7 pairs where both correct:
    for i in range(7):
        records.extend([
            {"pair_id": f"pair_{i}", "label": "MALICIOUS", "classification": {"classification": "MALICIOUS"}},
            {"pair_id": f"pair_{i}", "label": "BENIGN", "classification": {"classification": "BENIGN"}},
        ])
    # 1 pair where mal correct, ben incorrect:
    records.extend([
        {"pair_id": "pair_7", "label": "MALICIOUS", "classification": {"classification": "MALICIOUS"}},
        {"pair_id": "pair_7", "label": "BENIGN", "classification": {"classification": "MALICIOUS"}},
    ])
    # 2 pairs where ben correct, mal incorrect:
    for i in (8, 9):
        records.extend([
            {"pair_id": f"pair_{i}", "label": "MALICIOUS", "classification": {"classification": "BENIGN"}},
            {"pair_id": f"pair_{i}", "label": "BENIGN", "classification": {"classification": "BENIGN"}},
        ])

    stats = compute_pair_consistency_stats(records)
    tp = sum(1 for r in records if r["label"] == "MALICIOUS" and r["classification"]["classification"] == "MALICIOUS")
    tn = sum(1 for r in records if r["label"] == "BENIGN" and r["classification"]["classification"] == "BENIGN")
    n_pairs = 10
    lower_bound = max(0, tp + tn - n_pairs)

    assert tp == 8
    assert tn == 9
    assert lower_bound == 7
    assert stats["strict_count"] >= lower_bound
    assert stats["strict_count"] == 7
