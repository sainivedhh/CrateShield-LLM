# CrateShield-LLM v2: Benchmark Evaluation Report

**Date:** 2026-10-09T19:49:02.434199+00:00  
**Model:** `gemini-3.5-flash-lite` (temperature 0.0)  
**Git Snapshot:** `freeze-v2` / `prereg-v2` (v2.1-corrected)  

## 1. Executive Summary & Preregistered Hypotheses

| Hypothesis | Preregistered Condition | Result | Finding |
| :--- | :--- | :---: | :--- |
| **H1 (Primary)** | `hybrid` recall $\ge$ `raw` - 0.10 at $\le 50%$ tokens, FPR $\le 0.10$ | **PREREGISTERED CRITERION MET** | Preregistered criterion met; accuracy parity with raw on visible payloads (not significantly different); advantage is cost (about 36.3% of raw tokens) and robustness to truncation. |
| **H2 (Defanging)** | `structured` recall rises on `fabricated` vs `.invalid` | **NOT TESTABLE AS EXECUTED (design confound)** | In eval split, domain_type is perfectly confounded with category (fabricated = C1,C3,C5,C7; invalid = C2,C4,C6,C8); `.invalid` appears in 11/30 malicious twins.* |
| **H3 (Scale-test)** | Payload in omitted region drops `raw` recall; `hybrid` resilient | **CONFIRMED BY CONSTRUCTION** | Raw dropped from 1.00 (visible 23/23) to 0.00 (blinded 0/7) due to packer character limit; Hybrid retained 1.00 (7/7). |
| **H4 (RAG)** | `structured` vs `structured_norag` paired difference | **NO DIFF** | Exact McNemar Holm-adjusted $p=1.0000$ (0.733 vs 0.767). |

*\*Footnote: The Fisher exact p=1.0000 compares categories, not domain styles, due to the category-domain confound.*

### Visible vs Blinded Decomposition (Task 2)

Decomposition of strict recall across visible payloads ($n=23$, fully included in raw context budget) and blinded payloads ($n=7$, omitted or truncated by character packing limit). All confidence intervals are Wilson 95% score intervals.

| Condition | Visible Recall (n=23) [95% CI] | Blinded Recall (n=7) [95% CI] | Total Recall (n=30) [95% CI] |
| :--- | :---: | :---: | :---: |
| **hybrid** | 21/23 (0.913) [0.73, 0.98] | 7/7 (1.000) [0.65, 1.00] | 28/30 (0.933) [0.79, 0.98] |
| hybrid_norag | 21/23 (0.913) [0.73, 0.98] | 7/7 (1.000) [0.65, 1.00] | 28/30 (0.933) [0.79, 0.98] |
| **raw** | 23/23 (1.000) [0.86, 1.00] | 0/7 (0.000) [0.00, 0.35] | 23/30 (0.767) [0.59, 0.88] |
| naive | 23/23 (1.000) [0.86, 1.00] | 0/7 (0.000) [0.00, 0.35] | 23/30 (0.767) [0.59, 0.88] |
| structured | 15/23 (0.652) [0.45, 0.81] | 7/7 (1.000) [0.65, 1.00] | 22/30 (0.733) [0.56, 0.86] |
| structured_norag | 16/23 (0.696) [0.49, 0.84] | 7/7 (1.000) [0.65, 1.00] | 23/30 (0.767) [0.59, 0.88] |
| grep | 20/23 (0.870) [0.68, 0.95] | 6/7 (0.857) [0.49, 0.97] | 26/30 (0.867) [0.70, 0.95] |

**Critical Decomposition Finding:** On the visible subset, raw's recall is 23/23 (1.000) and hybrid's is 21/23 (0.913); the preregistered pass depends on the blinded subset where raw cannot see the payload by construction.

- **Paired McNemar (All 30 Malicious):** Discordant = 7 / 2 (hybrid wins 7, raw wins 2), Raw McNemar $p = 0.1797$, Holm-adjusted $p = 0.8985$ (not statistically significant).
- **Paired McNemar (Visible 23 Only - EXPLORATORY):** Discordant = 0 / 2 (hybrid wins 0, raw wins 2), Raw McNemar $p = 0.5000$, Holm-adjusted $p = 0.5000$ (not statistically significant).

## 2. Tier 3 Primary Benchmark Results (Eval Split, n=60)

All metrics reported with Wilson 95% score intervals. Bootstrapped F1 computed via cluster bootstrap by base crate ($B=2000$). Pair consistency definition: a pair is consistent iff the malicious twin is classified positive (MALICIOUS for strict; MALICIOUS or SUSPICIOUS for relaxed) AND the benign twin is classified BENIGN.

| Condition | Strict Recall [95% CI] | Strict FPR [95% CI] | Relaxed Recall | Relaxed FPR | Pair Consistency (Strict) | Pair Consistency (Relaxed) | Mean Tokens | Cost Efficiency (Recall/1k tok) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| size | 0.067 [0.02, 0.21] | 0.100 [0.04, 0.26] | 0.067 | 0.100 | 0/30 (0.0%) | 0/30 (0.0%) | 0 | 0.0000 |
| grep | 0.867 [0.70, 0.95] | 0.033 [0.01, 0.17] | 0.867 | 0.033 | 25/30 (83.3%) | 25/30 (83.3%) | 0 | 0.0000 |
| rule_only | 0.133 [0.05, 0.30] | 0.000 [0.00, 0.11] | 0.133 | 0.000 | 4/30 (13.3%) | 4/30 (13.3%) | 0 | 0.0000 |
| cargo_audit | 0.000 [0.00, 0.11] | 0.000 [0.00, 0.11] | 0.000 | 0.000 | 0/30 (0.0%) | 0/30 (0.0%) | 0 | 0.0000 |
| structured | 0.733 [0.56, 0.86] | 0.000 [0.00, 0.11] | 0.867 | 0.033 | 21/30 (70.0%) | 25/30 (83.3%) | 3885 | 0.1887 |
| structured_norag | 0.767 [0.59, 0.88] | 0.000 [0.00, 0.11] | 0.933 | 0.033 | 23/30 (76.7%) | 27/30 (90.0%) | 3208 | 0.2391 |
| **hybrid** | 0.933 [0.79, 0.98] | 0.000 [0.00, 0.11] | 0.967 | 0.033 | 28/30 (93.3%) | 28/30 (93.3%) | 5239 | 0.1781 |
| hybrid_norag | 0.933 [0.79, 0.98] | 0.000 [0.00, 0.11] | 0.933 | 0.000 | 28/30 (93.3%) | 28/30 (93.3%) | 4565 | 0.2044 |
| **raw** | 0.767 [0.59, 0.88] | 0.000 [0.00, 0.11] | 0.767 | 0.000 | 23/30 (76.7%) | 23/30 (76.7%) | 14419 | 0.0532 |
| naive | 0.767 [0.59, 0.88] | 0.000 [0.00, 0.11] | 0.767 | 0.000 | 23/30 (76.7%) | 23/30 (76.7%) | 13496 | 0.0568 |

## 3. Paired Hypothesis Testing (Holm-Bonferroni Corrected)

| Comparison | Discordant (c1 wins / c2 wins) | Raw McNemar $p$ | Holm-Adjusted $p$ | Statistically Significant? |
| :--- | :---: | :---: | :---: | :---: |
| hybrid vs raw | 7 / 2 | 0.1797 | 0.8985 | **NO** |
| hybrid vs structured | 7 / 1 | 0.0703 | 0.4218 | **NO** |
| hybrid vs hybrid_norag | 0 / 0 | 1.0000 | 1.0000 | **NO** |
| structured vs structured_norag | 1 / 2 | 1.0000 | 1.0000 | **NO** |
| structured vs raw | 7 / 8 | 1.0000 | 1.0000 | **NO** |
| raw vs naive | 0 / 0 | 1.0000 | 1.0000 | **NO** |

## 4. Diagnostics & Baseline Analysis

- **Size Baseline Threshold-Free AUC**: `0.500`
- **Paired Size-Delta Leak**: Within matched twin pairs, malicious twins were on average `415.8` bytes larger than base twins (100% of pairs). This confirms size is a twin artifact, motivating threshold-free AUC reporting.
- **Residual Tell Disclosure**: `.invalid` hostnames appear in 11/30 malicious twins and 0 benign twins by design (domain-style arm) and are therefore a residual token-level tell for those samples.

### Grep Baseline by Obfuscation Level (Task 4)
The obfuscation transforms hide strings and URLs but leave API names plaintext, so they do not meaningfully evade the frozen grep patterns:

| Obfuscation Level | Description | Grep Detections | Strict Recall | Wilson 95% CI |
| :--- | :--- | :---: | :---: | :---: |
| Level 0 | Plaintext / Standard APIs | 8/9 | 0.889 | [0.56, 0.98] |
| Level 1 | Split strings / Base64 | 10/12 | 0.833 | [0.55, 0.95] |
| Level 2 | Byte arrays / XOR masking | 8/9 | 0.889 | [0.56, 0.98] |

## 5. Stratified Performance Breakdown

### By Threat Category (Strict Recall)
| Threat Category | Hybrid | Raw | Structured |
| :--- | :---: | :---: | :---: |
| C1 | 3/3 (1.00) | 1/3 (0.33) | 2/3 (0.67) |
| C2 | 4/4 (1.00) | 4/4 (1.00) | 4/4 (1.00) |
| C3 | 4/4 (1.00) | 3/4 (0.75) | 2/4 (0.50) |
| C4 | 3/3 (1.00) | 3/3 (1.00) | 1/3 (0.33) |
| C5 | 2/4 (0.50) | 3/4 (0.75) | 3/4 (0.75) |
| C6 | 4/4 (1.00) | 3/4 (0.75) | 3/4 (0.75) |
| C7 | 4/4 (1.00) | 2/4 (0.50) | 4/4 (1.00) |
| C8 | 4/4 (1.00) | 4/4 (1.00) | 3/4 (0.75) |

### By Obfuscation Level (Strict Recall: Visible vs Blinded)
| Level | Description | Hybrid (Total) | Raw (Total) | Raw (Visible Only) | Structured (Total) | Blinded Count |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| Level 0 | Plaintext / Standard APIs | 9/9 (1.00) | 4/9 (0.44) | 4/4 (1.00) | 8/9 (0.89) | 5 blinded |
| Level 1 | Split strings / Base64 | 10/12 (0.83) | 10/12 (0.83) | 10/10 (1.00) | 8/12 (0.67) | 2 blinded |
| Level 2 | Byte arrays / XOR masking | 9/9 (1.00) | 9/9 (1.00) | 9/9 (1.00) | 6/9 (0.67) | 0 blinded |

### By Placement Strategy (Strict Recall: Visible vs Blinded)
| Placement | Location Description | Hybrid (Total) | Raw (Total) | Raw (Visible Only) | Structured (Total) | Blinded Count |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| P1 | main() entry point | 14/14 (1.00) | 14/14 (1.00) | 14/14 (1.00) | 10/14 (0.71) | 0 blinded |
| P2 | Helper function in lib.rs | 0/0 (N/A) | 0/0 (N/A) | 0/0 (N/A) | 0/0 (N/A) | *Not exercised in v2* |
| P3 | build.rs top-level | 6/6 (1.00) | 0/6 (0.00) | 0/0 (N/A) | 6/6 (1.00) | 6 blinded |
| P4 | Secondary crate module | 8/10 (0.80) | 9/10 (0.90) | 9/9 (1.00) | 6/10 (0.60) | 1 blinded |
| P5 | Static/lazy initializer | 0/0 (N/A) | 0/0 (N/A) | 0/0 (N/A) | 0/0 (N/A) | *Not exercised in v2* |

*Note on Placements: Placements P2 and P5 were not exercised in v2 (all v2 eval samples used P1, P3, or P4). The P3 raw recall of 0/6 is driven entirely by all 6 P3 samples sitting in omitted regions (blinded to the raw packer by construction). On visible samples alone, raw achieves 14/14 on P1 and 9/9 on P4.*

### Scale-Test Arm: Real Packer Omission Diagnostics (H3)

| Sample ID | Base Crate | Injected File | File Size (chars) | Payload Char Offset | Omitted by Packer? |
| :--- | :--- | :--- | :---: | :---: | :---: |
| `s_0022_malicious` | `discord-indexmap` | `src/map.rs` | 78,628 | 5,572 | **True (Omitted)** |
| `s_0034_malicious` | `signal-hook` | `src/iterator/backend.rs` | 17,817 | 17,393 | **True (Omitted)** |
| `s_0046_malicious` | `muter` | `src/lib/codec/helpers/codecs.rs` | 18,433 | 18,101 | **True (Omitted)** |
| `s_0058_malicious` | `crystals-rs` | `src/utils/unsafe_utils/flatten.rs` | 5,495 | 4,963 | **True (Omitted)** |
| `s_0064_malicious` | `matrixmultiply` | `src/sgemm_kernel.rs` | 33,593 | 8,521 | **True (Omitted)** |
| `s_0066_malicious` | `tikv-jemalloc-sys-0.7.1+5.3.1-0` | `src/lib.rs` | 40,883 | 40,429 | **True (Omitted)** |
| `s_0070_malicious` | `libsqlite3-sys` | `sqlcipher/bindgen_bundled_version.rs` | 125,014 | 124,545 | **True (Omitted)** |

**Limitation:** Payloads were placed at the end of the file, which maximizes truncation sensitivity; payload position within the file was not varied.

## 6. Historical Disaggregated Tiers

### Tier 1: Real In-the-Wild (`logs-update`, n=1 crate, 3 versions)
- Reported strictly disaggregated (not pooled into Tier 3 aggregate metrics).
- Detection rate across conditions: Hybrid: 3/3, Raw: 3/3, Structured: 3/3.

### Tier 2: Behavioral Reconstructions (n=6)
- **Historical discrepancy resolved:** v1 reported n=8 in `ABLATION_RESULTS.md` but only cached n=6 in `eval_cache.json`. The most likely cause (not independently verified in the original execution environment) is that `rustdecimal` and `faster_log` contained forbidden leak comments (`// Defanged: Mock...`) that triggered Gate G1 leak failures (`harness/run.py` lines 322, 397-398; `scripts/run_eval_v2.py` lines 115-119), causing the runner to skip cache writes. v2 adheres strictly to cache truth and reports the verified n=6 samples.

| Condition | Detections | Strict Recall | Wilson 95% CI |
| :--- | :---: | :---: | :---: |
| size | 6/6 | 1.000 | [0.61, 1.00] |
| grep | 3/6 | 0.500 | [0.19, 0.81] |
| rule_only | 4/6 | 0.667 | [0.30, 0.90] |
| cargo_audit | 4/6 | 0.667 | [0.30, 0.90] |
| structured | 4/6 | 0.667 | [0.30, 0.90] |
| structured_norag | 4/6 | 0.667 | [0.30, 0.90] |
| hybrid | 4/6 | 0.667 | [0.30, 0.90] |
| hybrid_norag | 4/6 | 0.667 | [0.30, 0.90] |
| raw | 3/6 | 0.500 | [0.19, 0.81] |
| naive | 2/6 | 0.333 | [0.10, 0.70] |

## 7. Limitations & Open Questions

1. **Defanging Confound (H2):** In the v2 split, `domain_type` was confounded with category (`fabricated` = C1, C3, C5, C7; `invalid` = C2, C4, C6, C8), and only 21/30 malicious twins contained a network hostname. The v1 defanging question remains open: a valid test requires the same payload template rendered with both domain styles on identical base crates (domain_type crossed with category), on a fresh split, preregistered separately.
2. **Truncation Position (H3):** Payloads sitting in secondary files were appended at the end of the file, maximizing truncation sensitivity. Model behavior when malicious payloads appear at the beginning or middle of omitted files remains uncharacterized.
3. **Synthetic Payloads:** Injected payloads represent synthetic twin artifacts rather than live malware in the wild.

---
*Report generated automatically by `scripts/make_report.py` from immutable cache `data/bench_v2/eval_cache.json`.*
