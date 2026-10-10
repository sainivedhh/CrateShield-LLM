"""Report and qualitative analysis generator for Pilot v3.3 on TUNE split.

Analyzes data/bench_v3/pilot_v33_cache.json:
1. Aggregate metrics table (Candidate A, Candidate B, hybrid_taint, raw) on 10 mal + 10 clean + 10 lookalike
2. Evasion ladder breakdown (L0-L4) on the 10 malicious tune samples
3. Mechanism spot-check comparing reasoning text across conditions
4. Spot-check on L2 split-flow samples (s3_0008, s3_0023)
5. Go / No-Go recommendations
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
PILOT_CACHE_PATH = ROOT / "data" / "bench_v3" / "pilot_v33_cache.json"
MANIFEST_PATH = ROOT / "data" / "bench_v3" / "manifest.json"
PILOT_LOG_PATH = ROOT / "PILOT_LOG_V33.md"


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


def generate_pilot_report() -> dict[str, Any]:
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    cache = json.loads(PILOT_CACHE_PATH.read_text("utf-8")) if PILOT_CACHE_PATH.exists() else {}

    tune_samples = {s["sample_id"]: s for s in manifest["samples"] if s.get("split") == "tune"}
    malicious_ids = [s_id for s_id, s in tune_samples.items() if s["twin_type"] == "malicious"]
    clean_ids = [s_id for s_id, s in tune_samples.items() if s["twin_type"] == "clean"]
    lookalike_ids = [s_id for s_id, s in tune_samples.items() if s["twin_type"] == "lookalike_benign"]

    # Index cache entries by (condition, sample_id)
    by_cond_sample: dict[tuple[str, str], dict[str, Any]] = {}
    for e in cache.values():
        if e.get("split") == "tune" and not e.get("dry_run", False):
            by_cond_sample[(e["condition"], e["sample_id"])] = e

    conditions = ["raw", "hybrid_taint", "candidate_a", "candidate_b"]
    cond_names = {
        "raw": "raw (60k budget)",
        "hybrid_taint": "hybrid_taint (baseline)",
        "candidate_a": "Candidate A: hybrid_taint_contextual",
        "candidate_b": "Candidate B: purpose_consistency",
    }

    metrics = {}
    ladder_levels = ["L0", "L1", "L2", "L3", "L4"]

    for cond in conditions:
        sample_map = {s_id: by_cond_sample.get((cond, s_id)) for s_id in tune_samples.keys()}
        
        # Strict recall (10 mal)
        strict_hits = [s_id for s_id in malicious_ids if sample_map[s_id] and is_malicious_strict(sample_map[s_id])]
        strict_cnt = len(strict_hits)
        strict_rate = strict_cnt / len(malicious_ids)

        # Relaxed recall (10 mal)
        rel_hits = [s_id for s_id in malicious_ids if sample_map[s_id] and is_malicious_relaxed(sample_map[s_id])]
        rel_cnt = len(rel_hits)
        rel_rate = rel_cnt / len(malicious_ids)

        # FPRs (10 clean, 10 lookalike)
        clean_fps = [s_id for s_id in clean_ids if sample_map[s_id] and is_malicious_strict(sample_map[s_id])]
        clean_fpr = len(clean_fps) / len(clean_ids)

        lookalike_fps = [s_id for s_id in lookalike_ids if sample_map[s_id] and is_malicious_strict(sample_map[s_id])]
        lookalike_fpr = len(lookalike_fps) / len(lookalike_ids)

        # Token usage
        all_entries = [sample_map[s_id] for s_id in tune_samples.keys() if sample_map[s_id]]
        mean_tin = sum(e.get("usage", {}).get("tokens_in", 0) for e in all_entries) / len(all_entries) if all_entries else 0
        mean_tout = sum(e.get("usage", {}).get("tokens_out", 0) for e in all_entries) / len(all_entries) if all_entries else 0

        # By ladder level
        ladder_breakdown = {}
        for lvl in ladder_levels:
            lvl_ids = [s_id for s_id in malicious_ids if tune_samples[s_id]["ladder_level"] == lvl]
            hit = sum(1 for s_id in lvl_ids if s_id in strict_hits)
            ladder_breakdown[lvl] = (hit, len(lvl_ids))

        metrics[cond] = {
            "name": cond_names[cond],
            "strict_cnt": strict_cnt,
            "strict_total": len(malicious_ids),
            "strict_rate": strict_rate,
            "rel_cnt": rel_cnt,
            "rel_total": len(malicious_ids),
            "rel_rate": rel_rate,
            "clean_fps": len(clean_fps),
            "clean_fpr": clean_fpr,
            "lookalike_fps": len(lookalike_fps),
            "lookalike_fpr": lookalike_fpr,
            "mean_tokens_in": mean_tin,
            "mean_tokens_out": mean_tout,
            "ladder": ladder_breakdown,
            "sample_map": sample_map,
        }

    # Mechanism spot-checks
    # Compare Candidate A vs hybrid_taint, and Candidate B vs hybrid_taint
    flips_a = []
    flips_b = []
    l2_spotchecks = []

    for s_id in malicious_ids:
        base_e = by_cond_sample.get(("hybrid_taint", s_id))
        ca_e = by_cond_sample.get(("candidate_a", s_id))
        cb_e = by_cond_sample.get(("candidate_b", s_id))

        base_v = (base_e.get("classification", {}).get("classification") or base_e.get("classification", {}).get("verdict")) if base_e else "NONE"
        ca_v = (ca_e.get("classification", {}).get("classification") or ca_e.get("classification", {}).get("verdict")) if ca_e else "NONE"
        cb_v = (cb_e.get("classification", {}).get("classification") or cb_e.get("classification", {}).get("verdict")) if cb_e else "NONE"

        if ca_e and base_e and str(ca_v).upper() != str(base_v).upper():
            flips_a.append({
                "sample_id": s_id,
                "ladder": tune_samples[s_id]["ladder_level"],
                "base_verdict": base_v,
                "base_score": base_e.get("classification", {}).get("malware_score", 0.0),
                "base_reasoning": base_e.get("reasoning", ""),
                "new_verdict": ca_v,
                "new_score": ca_e.get("classification", {}).get("malware_score", 0.0),
                "new_reasoning": ca_e.get("reasoning", ""),
            })

        if cb_e and base_e and str(cb_v).upper() != str(base_v).upper():
            flips_b.append({
                "sample_id": s_id,
                "ladder": tune_samples[s_id]["ladder_level"],
                "base_verdict": base_v,
                "base_score": base_e.get("classification", {}).get("malware_score", 0.0),
                "base_reasoning": base_e.get("reasoning", ""),
                "new_verdict": cb_v,
                "new_score": cb_e.get("classification", {}).get("malware_score", 0.0),
                "new_reasoning": cb_e.get("reasoning", ""),
            })

        if tune_samples[s_id]["ladder_level"] == "L2":
            l2_spotchecks.append({
                "sample_id": s_id,
                "base_verdict": base_v,
                "base_reasoning": base_e.get("reasoning", "") if base_e else "",
                "ca_verdict": ca_v,
                "ca_reasoning": ca_e.get("reasoning", "") if ca_e else "",
                "cb_verdict": cb_v,
                "cb_reasoning": cb_e.get("reasoning", "") if cb_e else "",
            })

    return {
        "metrics": metrics,
        "flips_a": flips_a,
        "flips_b": flips_b,
        "l2_spotchecks": l2_spotchecks,
    }


def format_markdown(report: dict[str, Any]) -> str:
    metrics = report["metrics"]
    flips_a = report["flips_a"]
    flips_b = report["flips_b"]
    l2_spots = report["l2_spotchecks"]

    lines = []
    lines.append("# CrateShield Benchmark v3.3 — Tune-Split Pilot Evaluation Report\n")
    lines.append("**Date:** 2026-10-11  ")
    lines.append("**Split:** TUNE Split Only ($N=30$: 10 Malicious, 10 Clean, 10 Lookalike-Benign)  ")
    lines.append("**Purpose:** Exploratory pilot to test Candidate A (contextual taint) and Candidate B (purpose consistency).  ")
    lines.append("**Note on Sample Size:** $n=10$ per class is descriptive/developmental. It does not support inferential statistical significance claims.\n")

    lines.append("## 1. Comparative Metrics on Tune Split\n")
    lines.append("| Condition | Strict Recall ($N=10$) | Relaxed Recall ($N=10$) | Clean FPR ($N=10$) | Lookalike FPR ($N=10$) | Mean Tokens In | Mean Tokens Out |")
    lines.append("|:---|:---:|:---:|:---:|:---:|:---:|:---:|")

    for cond, m in metrics.items():
        lines.append(f"| **{m['name']}** | {m['strict_cnt']}/10 (**{m['strict_rate']:.0%}**) | {m['rel_cnt']}/10 ({m['rel_rate']:.0%}) | {m['clean_fps']}/10 ({m['clean_fpr']:.0%}) | {m['lookalike_fps']}/10 ({m['lookalike_fpr']:.0%}) | {m['mean_tokens_in']:.0f} | {m['mean_tokens_out']:.0f} |")

    lines.append("\n## 2. Evasion Ladder Breakdown ($L0$–$L4$ Strict Recall on Tune Malicious)\n")
    lines.append("| Condition | $L0$ (Plain) | $L1$ (Obfusc) | $L2$ (Split-Flow) | $L3$ (Hidden-API) | $L4$ (Dep-Borne) | Pooled $L2$–$L4$ |")
    lines.append("|:---|:---:|:---:|:---:|:---:|:---:|:---:|")

    for cond, m in metrics.items():
        lad = m["ladder"]
        l_strs = [f"{lad[lvl][0]}/{lad[lvl][1]}" for lvl in ["L0", "L1", "L2", "L3", "L4"]]
        pooled_hit = lad["L2"][0] + lad["L3"][0] + lad["L4"][0]
        pooled_tot = lad["L2"][1] + lad["L3"][1] + lad["L4"][1]
        lines.append(f"| **{m['name']}** | {l_strs[0]} | {l_strs[1]} | {l_strs[2]} | {l_strs[3]} | {l_strs[4]} | **{pooled_hit}/{pooled_tot} ({pooled_hit/pooled_tot:.0%})** |")

    lines.append("\n## 3. Mechanism Spot-Checks (Flipped Verdicts)\n")
    lines.append(f"### Candidate A vs hybrid_taint ({len(flips_a)} flipped verdict(s))\n")
    if not flips_a:
        lines.append("*No malicious samples had their strict verdict flipped by Candidate A.*")
    for f in flips_a:
        lines.append(f"#### Sample {f['sample_id']} ({f['ladder']}): {f['base_verdict']} -> {f['new_verdict']}")
        lines.append(f"- **hybrid_taint (score: {f['base_score']:.2f}):**\n  > {f['base_reasoning']}")
        lines.append(f"- **Candidate A (score: {f['new_score']:.2f}):**\n  > {f['new_reasoning']}\n")

    lines.append(f"\n### Candidate B vs hybrid_taint ({len(flips_b)} flipped verdict(s))\n")
    if not flips_b:
        lines.append("*No malicious samples had their strict verdict flipped by Candidate B.*")
    for f in flips_b:
        lines.append(f"#### Sample {f['sample_id']} ({f['ladder']}): {f['base_verdict']} -> {f['new_verdict']}")
        lines.append(f"- **hybrid_taint (score: {f['base_score']:.2f}):**\n  > {f['base_reasoning']}")
        lines.append(f"- **Candidate B (score: {f['new_score']:.2f}):**\n  > {f['new_reasoning']}\n")

    lines.append("\n## 4. L2 Split-Flow In-Depth Qualitative Spot-Check\n")
    for spot in l2_spots:
        lines.append(f"### Sample `{spot['sample_id']}` ($L2$ Split-Flow)")
        lines.append(f"- **hybrid_taint ({spot['base_verdict']}):** {spot['base_reasoning'][:300]}...")
        lines.append(f"- **Candidate A ({spot['ca_verdict']}):** {spot['ca_reasoning'][:300]}...")
        lines.append(f"- **Candidate B ({spot['cb_verdict']}):** {spot['cb_reasoning'][:300]}...\n")

    return "\n".join(lines)


if __name__ == "__main__":
    rep = generate_pilot_report()
    md = format_markdown(rep)
    PILOT_LOG_PATH.write_text(md, encoding="utf-8")
    print(md)
