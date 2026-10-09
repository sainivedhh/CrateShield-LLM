# CrateShield-LLM v2: Benchmark Evaluation Report

**Date:** 2026-10-09T18:34:48.941002+00:00  
**Model:** `gemini-3.5-flash-lite` (temperature 0.0)  
**Git Snapshot:** `freeze-v2` / `prereg-v2`  

## 1. Executive Summary & Preregistered Hypotheses

| Hypothesis | Preregistered Condition | Result | Finding |
| :--- | :--- | :---: | :--- |
| **H1 (Primary)** | `hybrid` recall $\ge$ `raw` - 0.10 at $\le 50%$ tokens, FPR $\le 0.10$ | **CONFIRMED** | Strict recall 0.933 at **36.3% of raw tokens** (FPR=0.0) |
| **H2 (Defanging)** | `structured` recall rises on `fabricated` vs `.invalid` | **INCONCLUSIVE** | Fabricated: 11/15 vs Invalid: 11/15 ($p=1.0000$) |
| **H3 (Scale-test)** | Payload in omitted region drops `raw` recall; `hybrid` resilient | **CONFIRMED** | Raw dropped from 1.00 to 0.00; Hybrid retained 1.00 |
| **H4 (RAG)** | `structured` vs `structured_norag` paired difference | **NO DIFF** | Exact McNemar Holm-adjusted $p=1.0000$ |

## 2. Tier 3 Primary Benchmark Results (Eval Split, n=60)

All metrics reported with Wilson 95% score intervals. Bootstrapped F1 computed via cluster bootstrap by base crate ($B=2000$).

| Condition | Strict Recall [95% CI] | Strict FPR [95% CI] | Relaxed Recall | Relaxed FPR | Pair Consist | Mean Tokens | Cost Efficiency (Recall/1k tok) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| size | 0.067 [0.02, 0.21] | 0.100 [0.04, 0.26] | 0.067 | 0.100 | 0.0% | 0 | 0.0000 |
| grep | 0.867 [0.70, 0.95] | 0.033 [0.01, 0.17] | 0.867 | 0.033 | 0.0% | 0 | 0.0000 |
| rule_only | 0.133 [0.05, 0.30] | 0.000 [0.00, 0.11] | 0.133 | 0.000 | 0.0% | 0 | 0.0000 |
| cargo_audit | 0.000 [0.00, 0.11] | 0.000 [0.00, 0.11] | 0.000 | 0.000 | 0.0% | 0 | 0.0000 |
| structured | 0.733 [0.56, 0.86] | 0.000 [0.00, 0.11] | 0.867 | 0.033 | 0.0% | 3885 | 0.1887 |
| structured_norag | 0.767 [0.59, 0.88] | 0.000 [0.00, 0.11] | 0.933 | 0.033 | 0.0% | 3208 | 0.2391 |
| **hybrid** | 0.933 [0.79, 0.98] | 0.000 [0.00, 0.11] | 0.967 | 0.033 | 0.0% | 5239 | 0.1781 |
| hybrid_norag | 0.933 [0.79, 0.98] | 0.000 [0.00, 0.11] | 0.933 | 0.000 | 0.0% | 4565 | 0.2044 |
| **raw** | 0.767 [0.59, 0.88] | 0.000 [0.00, 0.11] | 0.767 | 0.000 | 0.0% | 14419 | 0.0532 |
| naive | 0.767 [0.59, 0.88] | 0.000 [0.00, 0.11] | 0.767 | 0.000 | 0.0% | 13496 | 0.0568 |

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
- **Grep Baseline**: Precision=0.96, Recall=0.87. Obfuscation levels $\ge 1$ degrade keyword grep detection.

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

### By Obfuscation Level (Strict Recall)
| Level | Description | Hybrid | Raw | Structured |
| :--- | :--- | :---: | :---: | :---: |
| Level 0 | Plaintext / Standard APIs | 9/9 (1.00) | 4/9 (0.44) | 8/9 (0.89) |
| Level 1 | Split strings / Base64 | 10/12 (0.83) | 10/12 (0.83) | 8/12 (0.67) |
| Level 2 | Byte arrays / XOR masking | 9/9 (1.00) | 9/9 (1.00) | 6/9 (0.67) |

### By Placement Strategy (Strict Recall)
| Placement | Location Description | Hybrid | Raw | Structured |
| :--- | :--- | :---: | :---: | :---: |
| P1 | main() entry point | 14/14 (1.00) | 14/14 (1.00) | 10/14 (0.71) |
| P2 | Helper function in lib.rs | N/A | N/A | N/A |
| P3 | build.rs top-level | 6/6 (1.00) | 0/6 (0.00) | 6/6 (1.00) |
| P4 | Secondary crate module | 8/10 (0.80) | 9/10 (0.90) | 6/10 (0.60) |
| P5 | Static/lazy initializer | N/A | N/A | N/A |

### Scale-Test Arm: Payload in Omitted Region (H3)
| Omitted by Packer? | Hybrid Strict Recall | Raw Strict Recall | Structured Strict Recall |
| :--- | :---: | :---: | :---: |
| False (Included in raw budget) | 21/23 (0.91) | 23/23 (1.00) | 15/23 (0.65) |
| **True (Omitted by raw budget)** | **7/7 (1.00)** | **0/7 (0.00)** | **7/7 (1.00)** |

## 6. Historical Disaggregated Tiers

### Tier 1: Real In-the-Wild (`logs-update`, n=1 crate, 3 versions)
- Reported strictly disaggregated (not pooled into Tier 3 aggregate metrics).
- Detection rate across conditions: Hybrid: 3/3, Raw: 3/3, Structured: 3/3.
### Tier 2: Behavioral Reconstructions (n=6)
- Historical discrepancy resolved: v1 reported n=8 in ABLATION_RESULTS.md but only cached n=6 in eval_cache.json because rustdecimal and faster_log contained forbidden leak comments ('// Defanged: Mock...') that failed Gate G1. v2 adheres strictly to cache truth and reports the n=6 valid samples.
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

---
*Report generated automatically by `scripts/make_report.py` from immutable cache `data/bench_v2/eval_cache.json`.*
