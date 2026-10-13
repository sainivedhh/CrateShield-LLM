"""Statistical analysis for Part B repeatability / noise floor estimation (v3.5).

Computes:
1. Pairwise Cohen's kappa and discordance counts across 3 repeats at T=0.0 and T=0.7 for all 8 conditions (strict and relaxed).
2. Recall spread (min, mean, max) on malicious samples in the 24-sample subset at T=0.7.
3. Deterministic jitter check at T=0.0 (verifies whether discordance is truly 0).
4. Direct noise comparison: contextual_purpose_consistency vs hybrid_taint vs raw.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
CACHE_PATH = ROOT / "data" / "bench_v3" / "eval_cache.json"
MANIFEST_PATH = ROOT / "data" / "bench_v3" / "manifest.json"

FIXED_REPEAT_SUBSET_IDS = {
    's3_0034_clean', 's3_0035_malicious', 's3_0042_lookalike_benign', 's3_0044_malicious',
    's3_0045_lookalike_benign', 's3_0048_lookalike_benign', 's3_0058_clean', 's3_0059_malicious',
    's3_0060_lookalike_benign', 's3_0062_malicious', 's3_0066_lookalike_benign', 's3_0085_clean',
    's3_0095_malicious', 's3_0100_clean', 's3_0106_clean', 's3_0108_lookalike_benign',
    's3_0112_clean', 's3_0117_lookalike_benign', 's3_0125_malicious', 's3_0133_clean',
    's3_0137_malicious', 's3_0142_clean', 's3_0147_lookalike_benign', 's3_0148_clean'
}


def is_malicious_strict(entry: dict[str, Any]) -> bool:
    if not entry:
        return False
    cls_obj = entry.get("classification", {})
    val = cls_obj.get("classification") or cls_obj.get("verdict")
    return str(val).upper() == "MALICIOUS"


def is_malicious_relaxed(entry: dict[str, Any]) -> bool:
    if not entry:
        return False
    cls_obj = entry.get("classification", {})
    val = cls_obj.get("classification") or cls_obj.get("verdict")
    if str(val).upper() in ("MALICIOUS", "SUSPICIOUS"):
        return True
    score = cls_obj.get("malware_score", 0.0)
    return (score or 0.0) >= 0.25


def cohen_kappa(y1: list[bool], y2: list[bool]) -> float:
    assert len(y1) == len(y2)
    n = len(y1)
    if n == 0:
        return 1.0
    po = sum(1 for a, b in zip(y1, y2) if a == b) / n
    p1_pos = sum(1 for a in y1 if a) / n
    p2_pos = sum(1 for b in y2 if b) / n
    pe = (p1_pos * p2_pos) + ((1 - p1_pos) * (1 - p2_pos))
    if abs(1.0 - pe) < 1e-9:
        return 1.0 if po == 1.0 else 0.0
    return (po - pe) / (1.0 - pe)


def main() -> None:
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    repeat_samples = [s for s in manifest["samples"] if s["sample_id"] in FIXED_REPEAT_SUBSET_IDS]
    mal_sample_ids = {s["sample_id"] for s in repeat_samples if s["twin_type"] == "malicious"}
    clean_sample_ids = {s["sample_id"] for s in repeat_samples if s["twin_type"] == "clean"}
    look_sample_ids = {s["sample_id"] for s in repeat_samples if s["twin_type"] == "lookalike_benign"}
    all_sids = sorted(list(FIXED_REPEAT_SUBSET_IDS))

    with open(CACHE_PATH, "r", encoding="utf-8") as f:
        cache = json.load(f)

    conditions = [
        "raw",
        "structured",
        "hybrid",
        "hybrid_fallback",
        "raw_full",
        "hybrid_taint",
        "contextual_purpose_consistency",
        "naive_full",
    ]

    print(f"==========================================================================================")
    print(f"PART B: REPEATABILITY & NOISE FLOOR ANALYSIS (N=24 samples: {len(mal_sample_ids)} malicious, {len(clean_sample_ids)} clean, {len(look_sample_ids)} lookalike)")
    print(f"==========================================================================================\n")

    results_table = []

    for cond in conditions:
        cond_row = {"condition": cond}
        for temp in (0.0, 0.7):
            rep_entries = {}
            for rep in (1, 2, 3):
                entries = {}
                for k, v in cache.items():
                    if (
                        v.get("sample_id") in FIXED_REPEAT_SUBSET_IDS
                        and v.get("condition") == cond
                        and v.get("repeat") == rep
                        and abs(v.get("temperature", 0.0) - temp) < 1e-4
                        and v.get("model") == "gemini-3.5-flash-lite"
                        and not v.get("dry_run", False)
                        and v.get("finish_reason") != "dry_run"
                    ):
                        entries[v["sample_id"]] = v
                rep_entries[rep] = entries

            # Strict
            v1_strict = [is_malicious_strict(rep_entries[1].get(s)) for s in all_sids]
            v2_strict = [is_malicious_strict(rep_entries[2].get(s)) for s in all_sids]
            v3_strict = [is_malicious_strict(rep_entries[3].get(s)) for s in all_sids]

            k12_s = cohen_kappa(v1_strict, v2_strict)
            k23_s = cohen_kappa(v2_strict, v3_strict)
            k13_s = cohen_kappa(v1_strict, v3_strict)
            mean_k_s = float(np.mean([k12_s, k23_s, k13_s]))

            d12_s = sum(1 for a, b in zip(v1_strict, v2_strict) if a != b)
            d23_s = sum(1 for a, b in zip(v2_strict, v3_strict) if a != b)
            d13_s = sum(1 for a, b in zip(v1_strict, v3_strict) if a != b)
            mean_d_s = float(np.mean([d12_s, d23_s, d13_s]))

            # Relaxed
            v1_rel = [is_malicious_relaxed(rep_entries[1].get(s)) for s in all_sids]
            v2_rel = [is_malicious_relaxed(rep_entries[2].get(s)) for s in all_sids]
            v3_rel = [is_malicious_relaxed(rep_entries[3].get(s)) for s in all_sids]

            k12_r = cohen_kappa(v1_rel, v2_rel)
            k23_r = cohen_kappa(v2_rel, v3_rel)
            k13_r = cohen_kappa(v1_rel, v3_rel)
            mean_k_r = float(np.mean([k12_r, k23_r, k13_r]))

            d12_r = sum(1 for a, b in zip(v1_rel, v2_rel) if a != b)
            d23_r = sum(1 for a, b in zip(v2_rel, v3_rel) if a != b)
            d13_r = sum(1 for a, b in zip(v1_rel, v3_rel) if a != b)
            mean_d_r = float(np.mean([d12_r, d23_r, d13_r]))

            # Malicious recall on the 7 malicious samples
            recalls_strict = []
            recalls_rel = []
            for v_s, v_r in zip((v1_strict, v2_strict, v3_strict), (v1_rel, v2_rel, v3_rel)):
                rec_s = sum(1 for sid, verd in zip(all_sids, v_s) if sid in mal_sample_ids and verd) / len(mal_sample_ids)
                rec_r = sum(1 for sid, verd in zip(all_sids, v_r) if sid in mal_sample_ids and verd) / len(mal_sample_ids)
                recalls_strict.append(rec_s)
                recalls_rel.append(rec_r)

            prefix = f"T_{temp:.1f}"
            cond_row[f"{prefix}_kappa_strict"] = mean_k_s
            cond_row[f"{prefix}_discordance_strict"] = mean_d_s
            cond_row[f"{prefix}_kappa_relaxed"] = mean_k_r
            cond_row[f"{prefix}_discordance_relaxed"] = mean_d_r

            cond_row[f"{prefix}_rec_strict_min"] = min(recalls_strict)
            cond_row[f"{prefix}_rec_strict_mean"] = float(np.mean(recalls_strict))
            cond_row[f"{prefix}_rec_strict_max"] = max(recalls_strict)
            cond_row[f"{prefix}_rec_strict_spread"] = max(recalls_strict) - min(recalls_strict)

            cond_row[f"{prefix}_rec_rel_min"] = min(recalls_rel)
            cond_row[f"{prefix}_rec_rel_mean"] = float(np.mean(recalls_rel))
            cond_row[f"{prefix}_rec_rel_max"] = max(recalls_rel)
            cond_row[f"{prefix}_rec_rel_spread"] = max(recalls_rel) - min(recalls_rel)

        results_table.append(cond_row)

    # Print markdown table
    print("### Table 1: Deterministic Jitter (T=0.0) Across 3 Repeats (N=24)")
    print("| Condition | Strict Mean Kappa | Strict Discordance | Relaxed Mean Kappa | Relaxed Discordance |")
    print("| :--- | :---: | :---: | :---: | :---: |")
    for r in results_table:
        print(f"| `{r['condition']}` | {r['T_0.0_kappa_strict']:.4f} | {r['T_0.0_discordance_strict']:.1f}/24 | {r['T_0.0_kappa_relaxed']:.4f} | {r['T_0.0_discordance_relaxed']:.1f}/24 |")

    print("\n### Table 2: Stochastic Noise Floor (T=0.7) Across 3 Repeats (N=24)")
    print("| Condition | Strict Kappa | Strict Discordance | Strict Mal Recall (Min / Mean / Max) | Spread | Relaxed Kappa | Relaxed Mal Recall (Min / Mean / Max) |")
    print("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |")
    for r in results_table:
        print(
            f"| `{r['condition']}` | "
            f"{r['T_0.7_kappa_strict']:.4f} | "
            f"{r['T_0.7_discordance_strict']:.1f}/24 | "
            f"{r['T_0.7_rec_strict_min']:.1%} / {r['T_0.7_rec_strict_mean']:.1%} / {r['T_0.7_rec_strict_max']:.1%} | "
            f"±{r['T_0.7_rec_strict_spread']/2:.1%} | "
            f"{r['T_0.7_kappa_relaxed']:.4f} | "
            f"{r['T_0.7_rec_rel_min']:.1%} / {r['T_0.7_rec_rel_mean']:.1%} / {r['T_0.7_rec_rel_max']:.1%} |"
        )

    print("\n--- Key Noise Observations ---")
    raw_r = next(r for r in results_table if r["condition"] == "raw")
    ht_r = next(r for r in results_table if r["condition"] == "hybrid_taint")
    cpc_r = next(r for r in results_table if r["condition"] == "contextual_purpose_consistency")

    print("1. Deterministic Jitter at T=0.0:")
    all_zero_jitter = all(r["T_0.0_discordance_strict"] == 0.0 for r in results_table)
    if all_zero_jitter:
        print("   CONFIRMED: Exactly 0.0 discordance across all 3 repeats at T=0.0 across ALL 8 conditions (Kappa = 1.0000).")
    else:
        for r in results_table:
            if r["T_0.0_discordance_strict"] > 0.0:
                print(f"   NOTICE: `{r['condition']}` has T=0.0 strict discordance: {r['T_0.0_discordance_strict']:.1f}/24 (Kappa = {r['T_0.0_kappa_strict']:.4f})")

    print("\n2. Stochastic Noise Comparison at T=0.7:")
    print(f"   - raw: Strict Discordance = {raw_r['T_0.7_discordance_strict']:.1f}/24, Kappa = {raw_r['T_0.7_kappa_strict']:.4f}, Recall Spread = {raw_r['T_0.7_rec_strict_spread']:.1%}")
    print(f"   - hybrid_taint: Strict Discordance = {ht_r['T_0.7_discordance_strict']:.1f}/24, Kappa = {ht_r['T_0.7_kappa_strict']:.4f}, Recall Spread = {ht_r['T_0.7_rec_strict_spread']:.1%}")
    print(f"   - contextual_purpose_consistency: Strict Discordance = {cpc_r['T_0.7_discordance_strict']:.1f}/24, Kappa = {cpc_r['T_0.7_kappa_strict']:.4f}, Recall Spread = {cpc_r['T_0.7_rec_strict_spread']:.1%}")

    # Save summary json
    out_path = ROOT / "data" / "bench_v3" / "part_b_repeats_summary.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results_table, f, indent=2)
    print(f"\nSaved Part B results summary to {out_path}")


if __name__ == "__main__":
    main()
