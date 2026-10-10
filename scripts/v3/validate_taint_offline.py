"""Task 3: Offline Validation of Taintflow Module without LLM Calls.

Evaluates taint context extraction across:
- 120 sealed eval samples (40 malicious, 40 clean, 40 lookalike-benign)
- 30 tune samples (10 malicious, 10 clean, 10 lookalike-benign)

Measures:
1. % malicious samples with path found vs fallback
2. Mean path length
3. Mean functions per sample
4. Character / estimated token counts vs hybrid's recorded counts
5. Sanity gate: payload_in_selected_context rate on malicious eval samples
"""

import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from crateshield.ingestion.downloader import preprocess_crate
from harness.view import build_anonymized_view
from crateshield.taintflow.extractor import extract_taint_context
from harness.hybrid import extract_targeted_code_windows

MANIFEST_PATH = Path("data/bench_v3/manifest.json")
CORPUS_DIR = Path("data/bench_v3/corpus_private")
CACHE_PATH = Path("data/bench_v3/eval_cache.json")


def validate_taint_offline() -> dict[str, Any]:
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    # Load cache for hybrid token comparisons if available
    cache = {}
    if CACHE_PATH.exists():
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            cache = json.load(f)

    eval_samples = [s for s in manifest["samples"] if s["split"] == "eval"]
    tune_samples = [s for s in manifest["samples"] if s["split"] == "tune"]
    all_samples = eval_samples + tune_samples

    print(f"Loaded {len(eval_samples)} eval samples and {len(tune_samples)} tune samples ({len(all_samples)} total).")

    stats = {
        "eval_malicious": {"total": 0, "path_found": 0, "fallback": 0, "payload_in_context": 0, "chars": [], "funcs": [], "path_lens": []},
        "eval_clean": {"total": 0, "path_found": 0, "fallback": 0, "chars": [], "funcs": []},
        "eval_lookalike": {"total": 0, "path_found": 0, "fallback": 0, "chars": [], "funcs": []},
        "tune_malicious": {"total": 0, "path_found": 0, "fallback": 0, "payload_in_context": 0, "chars": [], "funcs": [], "path_lens": []},
        "hybrid_eval_mal_chars": [],
    }

    per_sample_results = []

    for idx, s in enumerate(all_samples, 1):
        sample_id = s["sample_id"]
        split = s["split"]
        twin = s["twin_type"]
        sample_dir = CORPUS_DIR / sample_id

        if not sample_dir.exists():
            print(f"Warning: sample directory {sample_dir} not found!")
            continue

        pre = preprocess_crate(s["cluster_id"], "1.0.0", sample_dir)
        view = build_anonymized_view(pre, salt="crateshield-v3")

        taint_res = extract_taint_context(view, manifest_sample=s)
        hybrid_res = extract_targeted_code_windows(view)

        entry_record = {
            "sample_id": sample_id,
            "split": split,
            "twin_type": twin,
            "ladder_level": s.get("ladder_level"),
            "paths_found": taint_res["paths_found"],
            "fallback_used": taint_res["fallback_used"],
            "total_chars": taint_res["total_chars"],
            "hybrid_chars": hybrid_res["total_chars"],
            "functions_count": len(taint_res["functions_included"]),
            "payload_in_context": taint_res.get("payload_in_selected_context", False),
        }
        per_sample_results.append(entry_record)

        if split == "eval":
            if twin == "malicious":
                st = stats["eval_malicious"]
                st["total"] += 1
                if taint_res["fallback_used"]:
                    st["fallback"] += 1
                else:
                    st["path_found"] += 1
                if taint_res.get("payload_in_selected_context"):
                    st["payload_in_context"] += 1
                st["chars"].append(taint_res["total_chars"])
                st["funcs"].append(len(taint_res["functions_included"]))
                if taint_res["path_lengths"]:
                    st["path_lens"].extend(taint_res["path_lengths"])
                stats["hybrid_eval_mal_chars"].append(hybrid_res["total_chars"])

            elif twin == "clean":
                st = stats["eval_clean"]
                st["total"] += 1
                if taint_res["fallback_used"]:
                    st["fallback"] += 1
                else:
                    st["path_found"] += 1
                st["chars"].append(taint_res["total_chars"])
                st["funcs"].append(len(taint_res["functions_included"]))

            elif twin == "lookalike_benign":
                st = stats["eval_lookalike"]
                st["total"] += 1
                if taint_res["fallback_used"]:
                    st["fallback"] += 1
                else:
                    st["path_found"] += 1
                st["chars"].append(taint_res["total_chars"])
                st["funcs"].append(len(taint_res["functions_included"]))

        elif split == "tune":
            if twin == "malicious":
                st = stats["tune_malicious"]
                st["total"] += 1
                if taint_res["fallback_used"]:
                    st["fallback"] += 1
                else:
                    st["path_found"] += 1
                if taint_res.get("payload_in_selected_context"):
                    st["payload_in_context"] += 1
                st["chars"].append(taint_res["total_chars"])
                st["funcs"].append(len(taint_res["functions_included"]))
                if taint_res["path_lengths"]:
                    st["path_lens"].extend(taint_res["path_lengths"])

        if idx % 25 == 0 or idx == len(all_samples):
            print(f"Processed {idx}/{len(all_samples)} samples...")

    # Compute summaries
    em = stats["eval_malicious"]
    mean_path_len = sum(em["path_lens"]) / len(em["path_lens"]) if em["path_lens"] else 0.0
    mean_funcs = sum(em["funcs"]) / len(em["funcs"]) if em["funcs"] else 0.0
    mean_chars = sum(em["chars"]) / len(em["chars"]) if em["chars"] else 0.0
    mean_hybrid_chars = sum(stats["hybrid_eval_mal_chars"]) / len(stats["hybrid_eval_mal_chars"]) if stats["hybrid_eval_mal_chars"] else 0.0
    payload_rate = em["payload_in_context"] / em["total"] if em["total"] else 0.0

    print("\n" + "=" * 60)
    print("TASK 3 OFFLINE VALIDATION RESULTS (SEALED EVAL MALICIOUS, N=40):")
    print("=" * 60)
    print(f"Path Found: {em['path_found']}/{em['total']} ({em['path_found']/em['total']:.1%})")
    print(f"Fallback Used: {em['fallback']}/{em['total']} ({em['fallback']/em['total']:.1%})")
    print(f"Mean Path Length (when path found): {mean_path_len:.2f}")
    print(f"Mean Functions Included: {mean_funcs:.1f}")
    print(f"Mean Chars (taint): {mean_chars:.0f} chars (~{mean_chars/4:.0f} tokens)")
    print(f"Mean Chars (hybrid): {mean_hybrid_chars:.0f} chars (~{mean_hybrid_chars/4:.0f} tokens)")
    print(f"Payload in Selected Context Rate: {em['payload_in_context']}/{em['total']} ({payload_rate:.1%})")

    sanity_gate_passed = payload_rate >= 0.50
    print(f"\nSANITY GATE STATUS: {'PASSED' if sanity_gate_passed else 'FAILED'} (Threshold >= 50.0%)")

    # Clean / Lookalike summary
    ec = stats["eval_clean"]
    el = stats["eval_lookalike"]
    print(f"\nEval Clean (N={ec['total']}): Path Found={ec['path_found']}, Fallback={ec['fallback']}, Mean Chars={sum(ec['chars'])/len(ec['chars']):.0f}")
    print(f"Eval Lookalike (N={el['total']}): Path Found={el['path_found']}, Fallback={el['fallback']}, Mean Chars={sum(el['chars'])/len(el['chars']):.0f}")

    # Tune Malicious summary
    tm = stats["tune_malicious"]
    print(f"\nTune Malicious (N={tm['total']}): Path Found={tm['path_found']}, Fallback={tm['fallback']}, Payload in Context={tm['payload_in_context']}/{tm['total']} ({tm['payload_in_context']/tm['total']:.1%})")

    # Ladder breakdown for payload_in_context on eval malicious
    print("\nPayload in Context by Ladder Level (Eval Malicious):")
    for lvl in ["L0", "L1", "L2", "L3", "L4"]:
        lvl_samples = [r for r in per_sample_results if r["split"] == "eval" and r["twin_type"] == "malicious" and r["ladder_level"] == lvl]
        hit_cnt = sum(1 for r in lvl_samples if r["payload_in_context"])
        print(f"  {lvl}: {hit_cnt}/{len(lvl_samples)} ({hit_cnt/len(lvl_samples):.1%})")

    out_file = Path("data/bench_v3/taint_offline_validation.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({
            "stats": {
                "eval_malicious_path_found_pct": em["path_found"] / em["total"],
                "eval_malicious_fallback_pct": em["fallback"] / em["total"],
                "mean_path_length": mean_path_len,
                "mean_functions_included": mean_funcs,
                "mean_taint_chars": mean_chars,
                "mean_hybrid_chars": mean_hybrid_chars,
                "payload_in_selected_context_eval_mal": payload_rate,
                "sanity_gate_passed": sanity_gate_passed,
            },
            "per_sample": per_sample_results,
        }, f, indent=2)
    print(f"\nDetailed validation saved to {out_file}")

    return stats


if __name__ == "__main__":
    validate_taint_offline()
