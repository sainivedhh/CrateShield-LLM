# Changelog v2.1 (Correction Pass)

This document details the modifications made to `REPORT_v2.md`, analysis scripts, and documentation as part of the `v2.1-corrected` milestone. In accordance with the preregistration and non-intervention rules, **no model evaluations were re-run, and no cache or benchmark datasets were modified**. All numerical updates were deterministically regenerated from `data/bench_v2/eval_cache.json` using `scripts/make_report.py`.

---

## 1. Summary of Changes to `REPORT_v2.md`

### Executive Summary
- **H1 Takeaway Wording:** Replaced "CONFIRMED ... Hybrid beats raw" overstatements with:
  > *"Preregistered criterion met; accuracy parity with raw on visible payloads (not significantly different); advantage is cost (about 36% of raw tokens) and robustness to truncation."*
  Ensures no claim of superiority over raw is made unless supported by Holm-adjusted $p < 0.05$.
- **H2 Takeaway Wording:** Reclassified verdict to `NOT TESTABLE AS EXECUTED (design confound)`.
- **H3 Takeaway Wording:** Reclassified verdict to `CONFIRMED BY CONSTRUCTION`.

### Section 2: Preregistered Hypothesis Verdicts
- **H1 (Hybrid Efficiency & Recall):**
  - Retained preregistered verdict calculation over all 30 eval samples: `PREREGISTERED CRITERION MET`.
  - Added mandatory **Visible vs Blinded Decomposition Table** ($n=23$ visible, $n=7$ blinded) with Wilson 95% confidence intervals across `hybrid`, `hybrid_norag`, `raw`, `naive`, `structured`, `structured_norag`, and `grep`.
  - Added explicit generated text: on the visible subset, raw achieves 23/23 (100%) and hybrid achieves 21/23 (91.3%), showing that raw's overall deficit was driven entirely by the 7 blinded samples where raw cannot see the payload by construction.
  - Added paired McNemar test reporting for both all 30 ($p=0.1797$, Holm $p=0.8985$) and the visible 23 only ($p=0.5000$, Holm $p=1.0000$), explicitly labelling the visible subset comparison as **EXPLORATORY**.
- **H2 (Defanging Confounder):**
  - Changed verdict to `NOT TESTABLE AS EXECUTED (design confound)`.
  - Documented that eval-split `domain_type` is perfectly confounded with `category` (`fabricated` = C1, C3, C5, C7; `invalid` = C2, C4, C6, C8).
  - Documented network hostname prevalence: only 21/30 malicious twins contain network hostnames, and `.invalid` appears in 11/30 twins.
  - Removed claim that Fisher exact $p=1.0000$ demonstrates lack of a defanging effect; relegated Fisher p to a footnote as a category-level comparison. Added formal limitations note that evaluating defanging requires crossing domain style with category on identical crates.
- **H3 (Scale & Truncation):**
  - Reclassified verdict to `CONFIRMED BY CONSTRUCTION`.
  - Formulated raw's 0/7 recall on omitted samples as a demonstration of a failure mode of truncating baselines rather than an empirical finding about model reasoning.
  - Added deterministic packer diagnostic table (`src/crateshield/llm/packing.py`) for all 7 omitted samples: file name, file size in characters, payload character offset, and packer omission status.
  - Added limitation statement disclosing that payloads were placed at the end of files, maximizing truncation sensitivity.

### Section 3: Primary Benchmark Performance Table
- **Pair Consistency Bug Fixed:**
  - Corrected calculation in `harness/stats.py` and `scripts/make_report.py` (matching on `pair_id` and requiring strictly `MALICIOUS` for malicious twin and `BENIGN` for benign twin).
  - Regenerated exact strict pair consistency counts:
    - **hybrid:** 28/30 (93.3%)
    - **grep:** 25/30 (83.3%)
    - **raw:** 23/30 (76.7%)
    - **structured:** 21/30 (70.0%)
    - **size:** 0/30 (0.0%)
  - Included relaxed pair consistency counts alongside strict counts.
  - Enforced Fréchet lower-bound assertion in report generation: `strict_pairs >= max(0, TP_mal + TN_ben - n_pairs)`.

### Section 4: Subgroup & Threat Category Breakdown
- **Grep Obfuscation Performance:**
  - Removed unsupported claim that "Obfuscation levels >= 1 degrade keyword grep detection".
  - Added exact recall breakdown table for grep across obfuscation levels (Level 0: 8/9, Level 1: 10/12, Level 2: 8/9).
  - Added explanation that keyword grep remained effective across obfuscation levels because underlying Rust API calls (e.g. `TcpStream::connect`, `std::process::Command`) were preserved in plaintext even when string literals were split or encoded.
- **Payload Placement & Visible/Blinded Breakdown:**
  - Separated visible from blinded samples in obfuscation and placement tables.
  - Added explicit note that placements P2 (test files) and P5 (submodules) were not exercised in v2 ($n=0$).
- **Residual Tell Disclosure:**
  - Added explicit disclosure that `.invalid` domains appeared in 11/30 malicious twins and 0/30 benign twins, constituting a residual syntactic tell.

### Section 5: Historical Reconstruction & Methodological Notes
- **Tier 2 Reconstruction Count (Problem F):**
  - Documented that `data/bench_v1/eval_cache.json` contained $n=6$ samples (`rustdecimal` and `faster_log` missing).
  - Clarified that the most likely cause (not independently verified in the original v1 execution environment) was the Gate G1 assertion in `harness/run.py` lines 322, 397-398 and `scripts/run_eval_v2.py` lines 115-119 triggering on legacy comments (`// Defanged: Mock telemetry C2 connection`).

---

## 2. Code and Harness Changes

- `harness/stats.py`:
  - Updated `compute_pair_consistency` to group samples by `pair_id` rather than missing `cluster_id` / `base_crate`.
  - Added `compute_pair_consistency_stats` returning strict and relaxed counts and fractions.
  - Enforced strict condition: `malicious_pred == MALICIOUS and benign_pred == BENIGN`.
- `scripts/make_report.py`:
  - Added visible vs blinded decomposition table calculation.
  - Added exploratory paired McNemar on visible subset.
  - Added packer diagnostic calculation using `src/crateshield/llm/packing.py`.
  - Added Fréchet lower-bound assertion for pair consistency.
  - Updated all report narrative templates to conform to preregistered guidelines and unbiased phrasing.
- `scripts/verify_reproduction.py`:
  - Added strict programmatic assertion verifying exact pair-consistency numbers (hybrid 28/30, grep 25/30, raw 23/30, structured 21/30, size 0/30).
- `tests/test_make_report_pairs.py`:
  - Added unit tests with synthetic cache fixtures testing strict/relaxed pair consistency and boundary conditions.
- `README.md` & `DEVIATIONS.md`:
  - Updated to reflect placement coverage (P1, P3, P4) and all 6 dated deviations.
