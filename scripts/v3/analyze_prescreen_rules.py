"""Detailed rule-by-rule breakdown of the Stage 1 static pre-screen across 1,300 crates.io crates.

Analyzes:
1. Overall flag rate across cohorts (popular 300 vs random 1,000).
2. Frequency of each individual pre-screen rule across all 1,300 crates and among the 494 flagged crates.
3. Sole-culprit analysis: how many crates tripped ONLY on that single rule.
4. Co-occurrence / multi-signal patterns.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STAGE1_PATH = ROOT / "data" / "prod_v2" / "stage1_results.json"
MANIFEST_PATH = ROOT / "data" / "prod_v2" / "manifest_prod.json"


def main() -> None:
    with open(STAGE1_PATH, "r", encoding="utf-8") as f:
        stage1 = json.load(f)

    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    crate_meta = {c["sample_id"]: c for c in manifest["popular_sample"] + manifest["random_sample"]}

    total_crates = len(stage1)
    flagged_crates = {sid: data for sid, data in stage1.items() if not data.get("prescreen", {}).get("skip_llm", True)}
    skipped_crates = {sid: data for sid, data in stage1.items() if data.get("prescreen", {}).get("skip_llm", True)}

    pop_total = sum(1 for sid in stage1 if crate_meta.get(sid, {}).get("sample_type") == "popular_300")
    rand_total = sum(1 for sid in stage1 if crate_meta.get(sid, {}).get("sample_type") != "popular_300")

    pop_flagged = sum(1 for sid in flagged_crates if crate_meta.get(sid, {}).get("sample_type") == "popular_300")
    rand_flagged = sum(1 for sid in flagged_crates if crate_meta.get(sid, {}).get("sample_type") != "popular_300")

    print(f"==========================================================================================")
    print(f"STAGE 1 PRE-SCREEN RULE BREAKDOWN (Total: {total_crates} crates, Flagged: {len(flagged_crates)})")
    print(f"==========================================================================================\n")
    print(f"Cohorts:")
    print(f"  Popular (top 300): {pop_flagged} / {pop_total} flagged ({pop_flagged/pop_total:.1%})")
    print(f"  Random (1,000):    {rand_flagged} / {rand_total} flagged ({rand_flagged/rand_total:.1%})")
    print(f"  Combined (1,300):  {len(flagged_crates)} / {total_crates} flagged ({len(flagged_crates)/total_crates:.1%})\n")

    # Collect rule activations
    rule_counts_all = Counter()
    rule_counts_pop = Counter()
    rule_counts_rand = Counter()
    rule_sole_culprit = Counter()
    rule_sets = []

    for sid, data in flagged_crates.items():
        fired = data.get("prescreen", {}).get("fired", [])
        stype = crate_meta.get(sid, {}).get("sample_type", "random")
        rule_sets.append(set(fired))
        for r in fired:
            rule_counts_all[r] += 1
            if stype == "popular_300":
                rule_counts_pop[r] += 1
            else:
                rule_counts_rand[r] += 1

        if len(fired) == 1:
            rule_sole_culprit[fired[0]] += 1

    # Format into markdown table
    all_rules_sorted = sorted(rule_counts_all.keys(), key=lambda r: rule_counts_all[r], reverse=True)

    print("### Table 1: Individual Rule Flag-Rate Contribution")
    print("| Pre-Screen Rule | Total Times Fired (of 494 flagged) | % of Flagged Crates | % of All 1,300 Crates | Popular (N=300) | Random (N=1,000) | Sole Culprit (Only this rule) |")
    print("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |")

    for r in all_rules_sorted:
        cnt = rule_counts_all[r]
        pct_flagged = cnt / len(flagged_crates) * 100.0
        pct_all = cnt / total_crates * 100.0
        p_cnt = rule_counts_pop[r]
        r_cnt = rule_counts_rand[r]
        sole = rule_sole_culprit[r]
        print(f"| `{r}` | {cnt} | {pct_flagged:.1f}% | {pct_all:.1f}% | {p_cnt} ({p_cnt/pop_total:.1%}) | {r_cnt} ({r_cnt/rand_total:.1%}) | **{sole}** ({sole/len(flagged_crates):.1%}) |")

    # Multi-rule complexity
    fired_len_dist = Counter(len(s) for s in rule_sets)
    print("\n### Table 2: Signal Multiplicity (Number of Rules Tripped per Flagged Crate)")
    print("| Number of Rules Fired | Crate Count | % of Flagged Crates | Cumulative % |")
    print("| :---: | :---: | :---: | :---: |")
    cum = 0
    for n_rules in sorted(fired_len_dist.keys()):
        c = fired_len_dist[n_rules]
        cum += c
        print(f"| {n_rules} rule(s) | {c} | {c/len(flagged_crates):.1%} | {cum/len(flagged_crates):.1%} |")

    # High-level Rule Groupings
    print("\n### Table 3: Rule Families / High-Level Categories")
    family_counts = Counter()
    family_sole = Counter()
    for sid, data in flagged_crates.items():
        fired = data.get("prescreen", {}).get("fired", [])
        fams = set()
        for r in fired:
            if r.startswith("source_scan."):
                fams.add(r)  # Keep individual source_scan or category
            elif r.startswith("unsafe_ffi"):
                fams.add("unsafe_ffi (any)")
            elif r == "build_rs":
                fams.add("build_rs")
            elif r == "proc_macro":
                fams.add("proc_macro")
            elif r == "prompt_injection":
                fams.add("prompt_injection")
            else:
                fams.add(r.split(".")[0])
        for fam in fams:
            family_counts[fam] += 1
        if len(fams) == 1:
            family_sole[list(fams)[0]] += 1

    print("| Rule Family | Total Crates | % of Flagged Crates | Sole Family Tripped |")
    print("| :--- | :---: | :---: | :---: |")
    for fam, cnt in family_counts.most_common():
        sole = family_sole[fam]
        print(f"| `{fam}` | {cnt} | {cnt/len(flagged_crates):.1%} | **{sole}** ({sole/len(flagged_crates):.1%}) |")

    # Top co-occurring pairs
    pair_counts = Counter()
    for rset in rule_sets:
        rlist = sorted(list(rset))
        for i in range(len(rlist)):
            for j in range(i + 1, len(rlist)):
                pair_counts[(rlist[i], rlist[j])] += 1

    print("\n### Table 4: Top Co-Occurring Rule Pairs")
    print("| Rule A | Rule B | Co-occurrence Count | % of Flagged Crates |")
    print("| :--- | :--- | :---: | :---: |")
    for (ra, rb), cnt in pair_counts.most_common(10):
        print(f"| `{ra}` | `{rb}` | {cnt} | {cnt/len(flagged_crates):.1%} |")


if __name__ == "__main__":
    main()
