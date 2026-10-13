# CrateShield-LLM v2: Evaluation Deviations Log

This document records any post-preregistration deviations, anomalies, unexpected behaviors, and reporting corrections encountered during CrateShield v2.

---

## Deviations Record

### Deviation 1: Tier 2 Historical Reconstructions Discrepancy Resolution
- **Description:** In the v1 benchmark snapshot, `ABLATION_RESULTS.md` and `results_summary.json` reported $n=8$ historical reconstructions, whereas `data/bench_v1/eval_cache.json` only contained $n=6$ entries (`rustdecimal` and `faster_log` were missing).
- **Root Cause:** The most likely cause (not independently verified in the original v1 execution environment): `harness/run.py` (lines 322, 397-398) and `scripts/run_eval_v2.py` (lines 115-119) execute `assert_gate_g1(view)`. When forbidden leak terms are encountered, an `AssertionError` is raised and caught by the evaluation loop, skipping the cache write. In v1, reconstructed test fixtures for `rustdecimal` and `faster_log` contained legacy comments (`// Defanged: Mock telemetry C2 connection` and `// Defanged: Mock exfiltration of wallet data`) containing forbidden leak terms (`defanged`, `exfiltration`), which would trigger this skip mechanism.
- **Resolution in v2:** Rather than silently rewriting historical records or forcing unverified entries, `scripts/make_report.py` strictly asserts and reports the true cached $n=6$ historical reconstructions, fully resolving Problem F. Gate G1 integrity was strictly preserved.

### Deviation 2: Pair-Consistency Calculation Bug Found Post-Evaluation and Corrected in Reporting Only (2026-10-10)
- **Description:** In the initial v2 report, pair consistency was reported as `0.0%` across all conditions despite high accuracy (e.g. hybrid recall 0.933, FPR 0.0).
- **Root Cause:** `compute_pair_consistency` in `harness/stats.py` attempted to group by `r.get("cluster_id") or r.get("base_crate")`. These keys were not stored in the evaluation cache (which stores `pair_id`), causing `clusters` to be empty and returning `0.0`. In addition, binary thresholding logic improperly counted `SUSPICIOUS` benign twin predictions as negatives rather than requiring explicit `BENIGN` classification.
- **Resolution:** Updated `compute_pair_consistency` and added `compute_pair_consistency_stats` in `harness/stats.py` to group by `pair_id` and enforce the exact definition: a pair is consistent iff the malicious twin is classified positive (MALICIOUS for strict; MALICIOUS or SUSPICIOUS for relaxed) AND the benign twin is classified BENIGN. Added unit tests in `tests/test_make_report_pairs.py` and a Fréchet lower-bound assertion `strict_pairs >= max(0, TP_mal + TN_ben - n_pairs)`.
- **Confirmation:** No cache data or model classifications were modified. Strict pair consistency regenerated and verified at: hybrid 28/30, grep 25/30, raw 23/30, structured 21/30, size 0/30.

### Deviation 3: H2 (Defanging Confounder) Reclassified as Not Testable as Executed (2026-10-10)
- **Description:** Hypothesis H2 intended to isolate whether `.invalid` reserved domains caused false negatives compared to plausible fabricated hostnames.
- **Root Cause:** In `data/bench_v2/manifest.json`, `domain_type` was perfectly confounded with threat category (`fabricated` = C1, C3, C5, C7; `invalid` = C2, C4, C6, C8). Furthermore, only 21/30 malicious twins contained network hostnames, with `.invalid` appearing in exactly 11/30 eval twins.
- **Resolution:** Reclassified H2 verdict to "NOT TESTABLE AS EXECUTED (design confound)". Removed claims that Fisher $p=1.0000$ demonstrates "no defanging effect"; relegated Fisher p to a footnote as a category-level comparison. Added formal limitations note that testing this question requires crossing domain style with category on identical crates.
- **Confirmation:** No data or classifications were modified.

### Deviation 4: H3 (Scale/Truncation) Reclassified as Confirmed by Construction (2026-10-10)
- **Description:** Raw recall on the 7 omitted-region samples dropped to 0/7.
- **Root Cause:** Analysis with the real packer (`src/crateshield/llm/packing.py`) confirmed that all 7 samples sat in files omitted from the prompt or truncated prior to the payload's character offset due to the 60,000-character budget.
- **Resolution:** Reclassified H3 verdict to "CONFIRMED BY CONSTRUCTION", stating this as a demonstration of a failure mode of truncating baselines rather than an empirical model capability finding. Added exact packer diagnostics (file, size, payload offset) and disclosed the limitation that payloads were placed at the end of files.
- **Confirmation:** No data or classifications were modified.

### Deviation 5: H1 Reporting Augmented with Visible vs. Blinded Decomposition (2026-10-10)
- **Description:** Across all 30 eval samples, hybrid (28/30) vs raw (23/30) difference was not statistically significant ($p=0.1797$, Holm $p=0.8985$). On the visible 23 samples where raw actually saw the code, raw achieved 23/23 (1.000) vs hybrid 21/23 (0.913) ($p=0.5000$).
- **Root Cause:** Raw's overall lower recall was driven entirely by the 7 blinded samples where raw cannot see the payload by construction.
- **Resolution:** Added mandatory "Visible vs Blinded Decomposition" table directly beneath H1. Replaced overstatements with: "Preregistered criterion met; accuracy parity with raw on visible payloads (not significantly different); advantage is cost (about 36% of raw tokens) and robustness to truncation." Included exploratory paired McNemar on visible samples only.
- **Confirmation:** No data or classifications were modified.

### Deviation 6: False Claims Removed (Grep Obfuscation & Placement P1-P5) (2026-10-10)
- **Description:** 
  1. Stating that "Obfuscation levels >= 1 degrade keyword grep detection" was factually incorrect based on benchmark data (grep recall: Level 0 = 8/9, Level 1 = 10/12, Level 2 = 8/9).
  2. Stating that all placements P1-P5 were exercised in v2 was inaccurate (P2 and P5 had zero samples).
- **Resolution:** Replaced grep statement with exact breakdown table and explanation that obfuscation masked literals while leaving API names plaintext. Explicitly documented that P2 and P5 were not exercised in v2 across `README.md` and `REPORT_v2.md`. Added residual tell disclosure for `.invalid` hostnames (11/30 malicious vs 0/30 benign).
- **Confirmation:** No data or classifications were modified.
