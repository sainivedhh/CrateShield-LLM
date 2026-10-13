"""Cross-model validation comparison: Gemini-3.5-flash-lite vs Qwen/qwen3.8-27b on Benchmark v3.5."""
from __future__ import annotations

import json
from pathlib import Path
import numpy as np
from scipy.stats import binomtest

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "data/bench_v3/manifest.json"
CACHE_PATH = ROOT / "data/bench_v3/eval_cache.json"

with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
    manifest = json.load(f)

with open(CACHE_PATH, "r", encoding="utf-8") as f:
    cache = json.load(f)

eval_samples = {s["sample_id"]: s for s in manifest["samples"] if s["split"] == "eval"}
mal_ids = [k for k, s in eval_samples.items() if s["twin_type"] == "malicious"]
clean_ids = [k for k, s in eval_samples.items() if s["twin_type"] == "clean"]
look_ids = [k for k, s in eval_samples.items() if s["twin_type"] == "lookalike_benign"]
benign_ids = clean_ids + look_ids

assert len(mal_ids) == 40
assert len(clean_ids) == 40
assert len(look_ids) == 40

def is_mal_strict(entry):
    if not entry:
        return False
    c = entry.get("classification", {})
    val = c.get("classification") or c.get("verdict")
    return str(val).upper() == "MALICIOUS"

def is_mal_relaxed(entry):
    if not entry:
        return False
    c = entry.get("classification", {})
    val = c.get("classification") or c.get("verdict")
    if str(val).upper() in ("MALICIOUS", "SUSPICIOUS"):
        return True
    score = c.get("malware_score", 0.0)
    return (score or 0.0) >= 0.25

# Get deduplicated latest entries
entries = {}
for e in cache.values():
    if e.get("split") == "eval" and e.get("repeat", 0) == 0 and e.get("temperature", 0.0) == 0.0 and not e.get("dry_run", False) and e.get("finish_reason") != "dry_run":
        k = (e["condition"], e["model"], e["sample_id"])
        if k not in entries or e.get("timestamp", "") > entries[k].get("timestamp", ""):
            entries[k] = e

ladder_levels = ["L0", "L1", "L2", "L3", "L4"]

def analyze_cond_model(cond, model):
    sample_map = {s_id: entries.get((cond, model, s_id)) for s_id in eval_samples}
    
    # Recall
    mal_s = {s: is_mal_strict(sample_map[s]) for s in mal_ids}
    mal_r = {s: is_mal_relaxed(sample_map[s]) for s in mal_ids}
    rec_s = sum(mal_s.values()) / len(mal_ids)
    rec_r = sum(mal_r.values()) / len(mal_ids)
    
    # FPR
    clean_fp_s = sum(1 for s in clean_ids if is_mal_strict(sample_map[s]))
    clean_fp_r = sum(1 for s in clean_ids if is_mal_relaxed(sample_map[s]))
    look_fp_s = sum(1 for s in look_ids if is_mal_strict(sample_map[s]))
    look_fp_r = sum(1 for s in look_ids if is_mal_relaxed(sample_map[s]))
    
    fpr_clean_s = clean_fp_s / len(clean_ids)
    fpr_look_s = look_fp_s / len(look_ids)
    fpr_total_s = (clean_fp_s + look_fp_s) / (len(clean_ids) + len(look_ids))
    
    fpr_clean_r = clean_fp_r / len(clean_ids)
    fpr_look_r = look_fp_r / len(look_ids)
    fpr_total_r = (clean_fp_r + look_fp_r) / (len(clean_ids) + len(look_ids))
    
    # Tokens
    tokens_in = [sample_map[s].get("usage", {}).get("tokens_in", 0) for s in eval_samples if sample_map[s]]
    mean_tokens = float(np.mean(tokens_in)) if tokens_in else 0.0
    
    # Ladder L2-L4
    l2_4_ids = [s for s in mal_ids if eval_samples[s]["ladder_level"] in ("L2", "L3", "L4")]
    l2_4_rec_s = sum(1 for s in l2_4_ids if mal_s[s]) / len(l2_4_ids)
    l2_4_rec_r = sum(1 for s in l2_4_ids if mal_r[s]) / len(l2_4_ids)

    return {
        "cond": cond,
        "model": model,
        "rec_strict": rec_s,
        "rec_strict_cnt": sum(mal_s.values()),
        "rec_rel": rec_r,
        "rec_rel_cnt": sum(mal_r.values()),
        "fpr_clean_s": fpr_clean_s,
        "fpr_look_s": fpr_look_s,
        "fpr_total_s": fpr_total_s,
        "fpr_clean_r": fpr_clean_r,
        "fpr_look_r": fpr_look_r,
        "fpr_total_r": fpr_total_r,
        "l2_4_rec_s": l2_4_rec_s,
        "l2_4_rec_r": l2_4_rec_r,
        "mean_tokens": mean_tokens,
        "mal_s": mal_s,
        "mal_r": mal_r,
    }

def mcnemar_test(dict_a, dict_b, keys):
    b = sum(1 for k in keys if dict_a[k] and not dict_b[k])
    c = sum(1 for k in keys if not dict_a[k] and dict_b[k])
    n = b + c
    if n == 0:
        return b, c, 1.0
    res = binomtest(b, n, 0.5, alternative="two-sided")
    return b, c, float(res.pvalue)

# Conditions to compare
target_conds = [
    ("contextual_purpose_consistency", "gemini-3.5-flash-lite"),
    ("contextual_purpose_consistency", "qwen/qwen3.8-27b"),
    ("hybrid_taint", "gemini-3.5-flash-lite"),
    ("hybrid_taint", "qwen/qwen3.8-27b"),
]

reports = {}
for c, m in target_conds:
    reports[(c, m)] = analyze_cond_model(c, m)

# Also get Gemini conditions for Pareto comparison
all_gemini_conds = [
    "contextual_purpose_consistency",
    "hybrid_taint",
    "hybrid_fallback",
    "hybrid",
    "structured",
    "raw",
    "naive_full",
    "raw_full",
]

for c in all_gemini_conds:
    if (c, "gemini-3.5-flash-lite") not in reports:
        reports[(c, "gemini-3.5-flash-lite")] = analyze_cond_model(c, "gemini-3.5-flash-lite")

print("=" * 80)
print("GEMINI VS QWEN DIRECT COMPARISON (N=120 eval split)")
print("=" * 80)
print(f"{'Condition':32s} | {'Model':22s} | {'Strict Rec':10s} | {'Rel Rec':10s} | {'Clean FPR':10s} | {'Look FPR':10s} | {'Tokens':8s}")
print("-" * 115)
for (c, m), r in sorted(reports.items()):
    if m in ("gemini-3.5-flash-lite", "qwen/qwen3.8-27b") and c in ("contextual_purpose_consistency", "hybrid_taint"):
        s_rec = f"{r['rec_strict_cnt']}/40 ({r['rec_strict']*100:.1f}%)"
        r_rec = f"{r['rec_rel_cnt']}/40 ({r['rec_rel']*100:.1f}%)"
        c_fpr = f"{r['fpr_clean_s']*100:.1f}%"
        l_fpr = f"{r['fpr_look_s']*100:.1f}%"
        tok = f"{r['mean_tokens']:.0f}"
        print(f"{c:32s} | {m:22s} | {s_rec:10s} | {r_rec:10s} | {c_fpr:10s} | {l_fpr:10s} | {tok:8s}")

print("\n" + "=" * 80)
print("MCNEMAR TESTS (Cross-Model Concordance)")
print("=" * 80)

# McNemar 1: contextual_purpose_consistency (Gemini vs Qwen)
cpc_g = reports[("contextual_purpose_consistency", "gemini-3.5-flash-lite")]
cpc_q = reports[("contextual_purpose_consistency", "qwen/qwen3.8-27b")]
b_s, c_s, p_s = mcnemar_test(cpc_g["mal_s"], cpc_q["mal_s"], mal_ids)
b_r, c_r, p_r = mcnemar_test(cpc_g["mal_r"], cpc_q["mal_r"], mal_ids)

print(f"contextual_purpose_consistency (Gemini vs Qwen):")
print(f"  Strict Recall Concordance: Gemini-only={b_s}, Qwen-only={c_s}, p={p_s:.4f}")
print(f"  Relaxed Recall Concordance: Gemini-only={b_r}, Qwen-only={c_r}, p={p_r:.4f}")

# McNemar 2: hybrid_taint (Gemini vs Qwen)
ht_g = reports[("hybrid_taint", "gemini-3.5-flash-lite")]
ht_q = reports[("hybrid_taint", "qwen/qwen3.8-27b")]
b_ht_s, c_ht_s, p_ht_s = mcnemar_test(ht_g["mal_s"], ht_q["mal_s"], mal_ids)
b_ht_r, c_ht_r, p_ht_r = mcnemar_test(ht_g["mal_r"], ht_q["mal_r"], mal_ids)

print(f"\nhybrid_taint (Gemini vs Qwen):")
print(f"  Strict Recall Concordance: Gemini-only={b_ht_s}, Qwen-only={c_ht_s}, p={p_ht_s:.4f}")
print(f"  Relaxed Recall Concordance: Gemini-only={b_ht_r}, Qwen-only={c_ht_r}, p={p_ht_r:.4f}")

# McNemar 3: On Qwen: contextual_purpose_consistency vs hybrid_taint
b_q_s, c_q_s, p_q_s = mcnemar_test(cpc_q["mal_s"], ht_q["mal_s"], mal_ids)
b_q_r, c_q_r, p_q_r = mcnemar_test(cpc_q["mal_r"], ht_q["mal_r"], mal_ids)

print(f"\nWithin Qwen: contextual_purpose_consistency vs hybrid_taint:")
print(f"  Strict Recall: CPC-only={b_q_s}, HT-only={c_q_s}, p={p_q_s:.4f}")
print(f"  Relaxed Recall: CPC-only={b_q_r}, HT-only={c_q_r}, p={p_q_r:.4f}")

# Pareto Comparison
print("\n" + "=" * 80)
print("PARETO EFFICIENCY COMPARISON (Tokens vs Recall)")
print("=" * 80)
print(f"{'Condition':32s} | {'Model':22s} | {'Mean Tokens':11s} | {'Rel Recall':10s} | {'Recall/1K Tokens':16s}")
print("-" * 105)
for (c, m) in [
    ("contextual_purpose_consistency", "gemini-3.5-flash-lite"),
    ("contextual_purpose_consistency", "qwen/qwen3.8-27b"),
    ("hybrid_taint", "gemini-3.5-flash-lite"),
    ("hybrid_taint", "qwen/qwen3.8-27b"),
    ("hybrid", "gemini-3.5-flash-lite"),
    ("raw", "gemini-3.5-flash-lite"),
    ("raw_full", "gemini-3.5-flash-lite"),
]:
    r = reports[(c, m)]
    tokens_k = r["mean_tokens"] / 1000.0
    rec_per_k = (r["rec_rel"] * 100.0) / tokens_k if tokens_k > 0 else 0.0
    print(f"{c:32s} | {m:22s} | {r['mean_tokens']:11.1f} | {r['rec_rel']*100:9.1f}% | {rec_per_k:16.2f}%")

with open(ROOT / "data/bench_v3/part_a_qwen_summary.json", "w", encoding="utf-8") as f:
    # Save serializable summary
    clean_summary = {}
    for (c, m), r in reports.items():
        clean_summary[f"{c}__{m}"] = {k: v for k, v in r.items() if k not in ("mal_s", "mal_r")}
    json.dump(clean_summary, f, indent=2)

print("\nSummary saved to data/bench_v3/part_a_qwen_summary.json")
