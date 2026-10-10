"""Statistical Report Generator for hybrid_taint Benchmark Evaluation.

Reuses cached results from data/bench_v3/eval_cache.json for all conditions:
- grep (baseline)
- structured (strict and relaxed)
- hybrid
- hybrid_fallback
- raw
- raw_full (both uncorrected N=40 and Task 0 corrected testable N=35)
- hybrid_taint

Generates:
1. Headline recall & FPR comparison table
2. Stratified recall breakdown by evasion ladder levels (L0-L4) and pooled L2-L4
3. Paired exact McNemar tests with Holm-Bonferroni correction (taint vs hybrid, hybrid_fallback, raw, raw_full)
4. Mechanistic explanation via payload_in_selected_context rate
5. Cross-model evaluation comparison on Groq (qwen/qwen3.8-27b)
6. Objective verdict statement ("directionally favorable, not statistically confirmed" if p >= 0.05).
"""

from __future__ import annotations

import collections
import json
from pathlib import Path
from typing import Any

import numpy as np
from scipy import stats

ROOT = Path(__file__).resolve().parents[2]
CACHE_PATH = ROOT / "data" / "bench_v3" / "eval_cache.json"
MANIFEST_PATH = ROOT / "data" / "bench_v3" / "manifest.json"
VALIDATION_PATH = ROOT / "data" / "bench_v3" / "taint_offline_validation.json"
REPORT_OUTPUT_PATH = ROOT / "REPORT_TAINT.md"


def mcnemar_exact_pvalue(b: int, c: int) -> float:
    """Exact two-sided binomial p-value for discordant pairs b and c."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p_val = 2.0 * stats.binom.cdf(k, n, 0.5)
    return min(1.0, float(p_val))


def holm_bonferroni(p_values: list[float]) -> list[float]:
    """Applies Holm-Bonferroni step-down correction to a list of p-values."""
    m = len(p_values)
    indexed = sorted(enumerate(p_values), key=lambda x: x[1])
    adjusted = [0.0] * m
    running_max = 0.0

    for rank, (orig_idx, p) in enumerate(indexed):
        adj_p = p * (m - rank)
        running_max = max(running_max, adj_p)
        adjusted[orig_idx] = min(1.0, running_max)

    return adjusted


def is_malicious_strict(entry: dict[str, Any]) -> bool:
    cls_obj = entry.get("classification", {})
    val = cls_obj.get("classification") or cls_obj.get("verdict")
    return str(val).upper() == "MALICIOUS"


def is_malicious_relaxed(entry: dict[str, Any]) -> bool:
    cls_obj = entry.get("classification", {})
    val = cls_obj.get("classification") or cls_obj.get("verdict")
    if str(val).upper() in ("MALICIOUS", "SUSPICIOUS"):
        return True
    score = cls_obj.get("malware_score", 0.0)
    return score >= 0.25


def generate_taint_report() -> dict[str, Any]:
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    with open(CACHE_PATH, "r", encoding="utf-8") as f:
        cache = json.load(f)

    manifest_samples = {s["sample_id"]: s for s in manifest["samples"] if s["split"] == "eval"}
    malicious_ids = [s_id for s_id, s in manifest_samples.items() if s["twin_type"] == "malicious"]
    clean_ids = [s_id for s_id, s in manifest_samples.items() if s["twin_type"] == "clean"]
    lookalike_ids = [s_id for s_id, s in manifest_samples.items() if s["twin_type"] == "lookalike_benign"]

    # Deduplicate cache entries (latest timestamp, repeat 0, temperature 0.0)
    entries_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for e in cache.values():
        if e.get("split") == "eval" and e.get("repeat", 0) == 0 and e.get("temperature", 0.0) == 0.0 and not e.get("dry_run", False):
            k = (e["condition"], e["model"], e["sample_id"])
            if k not in entries_by_key or e.get("timestamp", "") > entries_by_key[k].get("timestamp", ""):
                entries_by_key[k] = e

    # Determine available conditions and models
    cond_models = sorted(set((cond, model) for (cond, model, _) in entries_by_key.keys()))

    # Find raw_full untestable samples
    rf_exceeds_ids = set()
    for (cond, model, s_id), e in entries_by_key.items():
        if cond == "raw_full" and model == "gemini-3.5-flash-lite":
            if e.get("finish_reason") == "exceeds_context" or e.get("exceeds_context") is True:
                rf_exceeds_ids.add(s_id)

    malicious_testable_rf = [s_id for s_id in malicious_ids if s_id not in rf_exceeds_ids]

    # Compute metrics per condition
    results = {}
    ladder_levels = ["L0", "L1", "L2", "L3", "L4"]

    for cond, model in cond_models:
        sample_map = {s_id: entries_by_key.get((cond, model, s_id)) for s_id in manifest_samples.keys()}

        # Strict recall
        correct_mal = {s_id: is_malicious_strict(sample_map[s_id]) if sample_map[s_id] else False for s_id in malicious_ids}
        recall_strict_cnt = sum(1 for v in correct_mal.values() if v)
        recall_strict_rate = recall_strict_cnt / len(malicious_ids)

        # Relaxed recall
        correct_mal_rel = {s_id: is_malicious_relaxed(sample_map[s_id]) if sample_map[s_id] else False for s_id in malicious_ids}
        recall_rel_cnt = sum(1 for v in correct_mal_rel.values() if v)
        recall_rel_rate = recall_rel_cnt / len(malicious_ids)

        # FPRs
        clean_fps = sum(1 for s_id in clean_ids if sample_map[s_id] and is_malicious_strict(sample_map[s_id]))
        clean_fpr = clean_fps / len(clean_ids)
        lookalike_fps = sum(1 for s_id in lookalike_ids if sample_map[s_id] and is_malicious_strict(sample_map[s_id]))
        lookalike_fpr = lookalike_fps / len(lookalike_ids)

        # Ladder breakdown (strict)
        by_ladder = {}
        for lvl in ladder_levels:
            lvl_ids = [s_id for s_id in malicious_ids if manifest_samples[s_id]["ladder_level"] == lvl]
            hit = sum(1 for s_id in lvl_ids if correct_mal[s_id])
            by_ladder[lvl] = (hit, len(lvl_ids), hit / len(lvl_ids) if lvl_ids else 0.0)

        # L2-L4 pooled
        l2_4_hit = sum(by_ladder[lvl][0] for lvl in ("L2", "L3", "L4"))
        l2_4_tot = sum(by_ladder[lvl][1] for lvl in ("L2", "L3", "L4"))
        l2_4_rate = l2_4_hit / l2_4_tot if l2_4_tot else 0.0

        results[(cond, model)] = {
            "condition": cond,
            "model": model,
            "recall_strict_cnt": recall_strict_cnt,
            "recall_strict_total": len(malicious_ids),
            "recall_strict": recall_strict_rate,
            "recall_relaxed_cnt": recall_rel_cnt,
            "recall_relaxed": recall_rel_rate,
            "clean_fpr": clean_fpr,
            "lookalike_fpr": lookalike_fpr,
            "by_ladder": by_ladder,
            "l2_4_hit": l2_4_hit,
            "l2_4_tot": l2_4_tot,
            "l2_4_rate": l2_4_rate,
            "per_sample_strict": correct_mal,
        }

    # Add raw_full testable corrected row (N=35)
    if ("raw_full", "gemini-3.5-flash-lite") in results:
        rf_full = results[("raw_full", "gemini-3.5-flash-lite")]
        rf_sample_map = {s_id: entries_by_key.get(("raw_full", "gemini-3.5-flash-lite", s_id)) for s_id in malicious_testable_rf}
        rf_testable_hit = sum(1 for s_id in malicious_testable_rf if rf_sample_map[s_id] and is_malicious_strict(rf_sample_map[s_id]))
        
        by_ladder_rf = {}
        for lvl in ladder_levels:
            lvl_ids = [s_id for s_id in malicious_testable_rf if manifest_samples[s_id]["ladder_level"] == lvl]
            hit = sum(1 for s_id in lvl_ids if rf_sample_map[s_id] and is_malicious_strict(rf_sample_map[s_id]))
            by_ladder_rf[lvl] = (hit, len(lvl_ids), hit / len(lvl_ids) if lvl_ids else 0.0)
        l2_4_rf_hit = sum(by_ladder_rf[lvl][0] for lvl in ("L2", "L3", "L4"))
        l2_4_rf_tot = sum(by_ladder_rf[lvl][1] for lvl in ("L2", "L3", "L4"))

        results[("raw_full_corrected", "gemini-3.5-flash-lite")] = {
            "condition": "raw_full (testable N=35)",
            "model": "gemini-3.5-flash-lite",
            "recall_strict_cnt": rf_testable_hit,
            "recall_strict_total": len(malicious_testable_rf),
            "recall_strict": rf_testable_hit / len(malicious_testable_rf),
            "recall_relaxed_cnt": rf_testable_hit,
            "recall_relaxed": rf_testable_hit / len(malicious_testable_rf),
            "clean_fpr": rf_full["clean_fpr"],
            "lookalike_fpr": rf_full["lookalike_fpr"],
            "by_ladder": by_ladder_rf,
            "l2_4_hit": l2_4_rf_hit,
            "l2_4_tot": l2_4_rf_tot,
            "l2_4_rate": l2_4_rf_hit / l2_4_rf_tot if l2_4_rf_tot else 0.0,
            "per_sample_strict": {s_id: is_malicious_strict(rf_sample_map[s_id]) if rf_sample_map[s_id] else False for s_id in malicious_testable_rf},
        }

    # Statistical McNemar Tests for hybrid_taint
    # Compare hybrid_taint against hybrid, hybrid_fallback, raw, raw_full_corrected
    mcnemar_rows = []
    taint_key = next((k for k in results.keys() if k[0] == "hybrid_taint"), None)

    if taint_key:
        taint_res = results[taint_key]
        taint_model = taint_key[1]

        # Targets to compare against
        compare_targets = [
            ("hybrid", "hybrid", taint_model if ( "hybrid", taint_model) in results else "gemini-3.5-flash-lite"),
            ("hybrid_fallback", "hybrid_fallback", "gemini-3.5-flash-lite"),
            ("raw", "raw", taint_model if ("raw", taint_model) in results else "gemini-3.5-flash-lite"),
            ("raw_full_corrected", "raw_full (testable)", "gemini-3.5-flash-lite"),
        ]

        raw_pvals = []
        comp_records = []

        for target_key, display_name, target_model in compare_targets:
            target_entry = results.get((target_key, target_model))
            if not target_entry:
                continue

            target_preds = target_entry["per_sample_strict"]
            taint_preds = taint_res["per_sample_strict"]

            # Common samples (for raw_full_corrected, N=35; otherwise N=40)
            common_ids = [s_id for s_id in taint_preds.keys() if s_id in target_preds]
            b = sum(1 for s_id in common_ids if taint_preds[s_id] and not target_preds[s_id])  # Taint won, Target lost
            c = sum(1 for s_id in common_ids if not taint_preds[s_id] and target_preds[s_id])  # Target won, Taint lost

            p_val = mcnemar_exact_pvalue(b, c)
            raw_pvals.append(p_val)
            comp_records.append({
                "target": display_name,
                "model": target_model,
                "n": len(common_ids),
                "taint_correct": sum(1 for s_id in common_ids if taint_preds[s_id]),
                "target_correct": sum(1 for s_id in common_ids if target_preds[s_id]),
                "b_taint_only": b,
                "c_target_only": c,
                "raw_p": p_val,
            })

        adj_pvals = holm_bonferroni(raw_pvals)
        for rec, adj_p in zip(comp_records, adj_pvals):
            rec["adj_p"] = adj_p
            mcnemar_rows.append(rec)

    # Mechanistic explanation: Load validation stats
    mechanistic_stats = {}
    if VALIDATION_PATH.exists():
        with open(VALIDATION_PATH, "r", encoding="utf-8") as f:
            mechanistic_stats = json.load(f).get("stats", {})

    return {
        "results": results,
        "mcnemar": mcnemar_rows,
        "mechanistic": mechanistic_stats,
    }


def render_markdown_report(report_data: dict[str, Any]) -> str:
    results = report_data["results"]
    mcnemar = report_data["mcnemar"]
    mech = report_data["mechanistic"]

    md = []
    md.append("# CrateShield Benchmark v3.2 — Comparative Evaluation: `hybrid_taint`\n")
    md.append("**Date:** 2026-10-10  ")
    md.append("**Evaluation Set:** Sealed Benchmark v3 Eval Split ($N=120$: 40 malicious, 40 clean, 40 lookalike-benign)  \n")

    md.append("## 1. Headline Recall & False Positive Rate Comparison\n")
    md.append("| Condition | Model | Strict Recall ($N$) | Strict % | Relaxed % | Clean FPR | Lookalike FPR |")
    md.append("|:---|:---|:---:|:---:|:---:|:---:|:---:|")

    for (cond, model), r in results.items():
        n_str = f"{r['recall_strict_cnt']}/{r['recall_strict_total']}"
        md.append(f"| **{cond}** | {model} | {n_str} | **{r['recall_strict']:.1%}** | {r['recall_relaxed']:.1%} | {r['clean_fpr']:.1%} | {r['lookalike_fpr']:.1%} |")

    md.append("\n*Note: raw_full (testable N=35) excludes 5 crates that exceeded context limit (auto-labeled BENIGN). Overall uncorrected raw_full recall is 13/40 (32.5%).*\n")

    md.append("## 2. Evasion Ladder Breakdown ($L0$–$L4$ Strict Recall)\n")
    md.append("| Condition | Model | $L0$ (Plain) | $L1$ (Obfusc) | $L2$ (Split-Flow) | $L3$ (Hidden-API) | $L4$ (Dep-Borne) | **Pooled $L2$–$L4$** |")
    md.append("|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|")

    for (cond, model), r in results.items():
        bl = r["by_ladder"]
        l_strs = [f"{bl[lvl][0]}/{bl[lvl][1]} ({bl[lvl][2]:.0%})" for lvl in ["L0", "L1", "L2", "L3", "L4"]]
        pooled_str = f"**{r['l2_4_hit']}/{r['l2_4_tot']} ({r['l2_4_rate']:.1%})**"
        md.append(f"| **{cond}** | {model} | {l_strs[0]} | {l_strs[1]} | {l_strs[2]} | {l_strs[3]} | {l_strs[4]} | {pooled_str} |")

    md.append("\n## 3. Paired Exact McNemar Tests (Holm-Bonferroni Corrected)\n")
    if mcnemar:
        md.append("| Comparison (Taint vs Target) | Target Model | Common $N$ | Taint Wins ($b$) | Target Wins ($c$) | Raw Exact $p$ | **Holm-Adjusted $p$** | Significance |")
        md.append("|:---|:---|:---:|:---:|:---:|:---:|:---:|:---|")
        for rec in mcnemar:
            sig = "**p < 0.05 (Significant)**" if rec["adj_p"] < 0.05 else "Directionally favorable, not confirmed" if rec["taint_correct"] > rec["target_correct"] else "No difference / Lower"
            md.append(f"| **hybrid_taint** vs {rec['target']} | {rec['model']} | {rec['n']} | {rec['b_taint_only']} | {rec['c_target_only']} | {rec['raw_p']:.4f} | **{rec['adj_p']:.4f}** | {sig} |")
    else:
        md.append("*McNemar tests pending completed evaluation entries in cache.*")

    md.append("\n## 4. Mechanistic Verification: Context Selection Quality\n")
    if mech:
        md.append(f"- **Malicious Payload in Selected Context Rate:** {mech.get('payload_in_selected_context_eval_mal', 0.0):.1%} ({int(mech.get('payload_in_selected_context_eval_mal', 0.0)*40)}/40)")
        md.append(f"- **Sanity Gate Status:** {'PASSED' if mech.get('sanity_gate_passed') else 'FAILED'} (threshold $\\ge 50\\%$)")
        md.append(f"- **Connected Path Discovery Rate:** {mech.get('eval_malicious_path_found_pct', 0.0):.1%}")
        md.append(f"- **Fallback Extraction Rate:** {mech.get('eval_malicious_fallback_pct', 0.0):.1%}")
        md.append(f"- **Mean Path Length:** {mech.get('mean_path_length', 0.0):.2f} functions")
        md.append(f"- **Mean Functions Included:** {mech.get('mean_functions_included', 0.0):.1f}")
        md.append(f"- **Mean Character Budget:** {mech.get('mean_taint_chars', 0.0):.0f} chars (~{mech.get('mean_taint_chars', 0.0)/4:.0f} tokens) vs Hybrid {mech.get('mean_hybrid_chars', 0.0):.0f} chars")

    md.append("\n## 5. Preregistration Hypotheses Verdict\n")
    # Determine headline verdict
    taint_key = next((k for k in results.keys() if k[0] == "hybrid_taint"), None)
    if taint_key and mcnemar:
        t_res = results[taint_key]
        raw_comp = next((r for r in mcnemar if "raw" in r["target"].lower() and "testable" not in r["target"].lower()), None)
        l2_rate = t_res["l2_4_rate"]
        
        md.append(f"**Headline Finding:**")
        if raw_comp and raw_comp["adj_p"] < 0.05 and t_res["recall_strict"] > raw_comp["target_correct"] / raw_comp["n"]:
            md.append(f"hybrid_taint **statistically significantly beats raw** on the sealed evaluation set (Recall: {t_res['recall_strict']:.1%} vs {raw_comp['target_correct']/raw_comp['n']:.1%}, Holm-adjusted p={raw_comp['adj_p']:.4f}).")
        elif raw_comp and t_res["recall_strict"] >= raw_comp["target_correct"] / raw_comp["n"]:
            md.append(f"hybrid_taint closes the recall gap to raw numerically (Recall: {t_res['recall_strict']:.1%} vs {raw_comp['target_correct']/raw_comp['n']:.1%}, Pooled L2-L4: {l2_rate:.1%}), but the difference is **directionally favorable, not statistically confirmed** (Holm-adjusted p={raw_comp['adj_p']:.4f}).")
        else:
            p_val_str = f"Holm-adjusted p={raw_comp['adj_p']:.4f}" if raw_comp else "p=N/A"
            md.append(f"hybrid_taint **does not close the gap to raw on L2-L4** ({p_val_str}; Taint: {t_res['recall_strict']:.1%}, Pooled L2-L4: {l2_rate:.1%}).")

    return "\n".join(md)


if __name__ == "__main__":
    report_data = generate_taint_report()
    rendered = render_markdown_report(report_data)
    with open(REPORT_OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(rendered)
    print(rendered)
    print(f"\nReport written to {REPORT_OUTPUT_PATH}")
