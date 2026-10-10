# CrateShield Benchmark v3.2 — Comparative Evaluation: `hybrid_taint`

**Date:** 2026-10-10  
**Evaluation Set:** Sealed Benchmark v3 Eval Split ($N=120$: 40 malicious, 40 clean, 40 lookalike-benign)  

## 1. Headline Recall & False Positive Rate Comparison

| Condition | Model | Strict Recall ($N$) | Strict % | Relaxed % | Clean FPR | Lookalike FPR |
|:---|:---|:---:|:---:|:---:|:---:|:---:|
| **cargo_audit** | baseline | 0/40 | **0.0%** | 0.0% | 0.0% | 0.0% |
| **grep** | baseline | 13/40 | **32.5%** | 32.5% | 12.5% | 12.5% |
| **hybrid** | gemini-3.5-flash-lite | 5/40 | **12.5%** | 15.0% | 0.0% | 2.5% |
| **hybrid_fallback** | gemini-3.5-flash-lite | 8/40 | **20.0%** | 32.5% | 0.0% | 10.0% |
| **naive_full** | gemini-3.5-flash-lite | 15/40 | **37.5%** | 47.5% | 0.0% | 25.0% |
| **raw** | gemini-3.5-flash-lite | 17/40 | **42.5%** | 50.0% | 0.0% | 10.0% |
| **raw_full** | gemini-3.5-flash-lite | 13/40 | **32.5%** | 35.0% | 0.0% | 2.5% |
| **rule_only** | baseline | 2/40 | **5.0%** | 5.0% | 5.0% | 5.0% |
| **size** | baseline | 0/40 | **0.0%** | 0.0% | 0.0% | 0.0% |
| **structured** | gemini-3.5-flash-lite | 0/40 | **0.0%** | 10.0% | 0.0% | 0.0% |
| **raw_full_corrected** | gemini-3.5-flash-lite | 13/35 | **37.1%** | 37.1% | 0.0% | 2.5% |

*Note: raw_full (testable N=35) excludes 5 crates that exceeded context limit (auto-labeled BENIGN). Overall uncorrected raw_full recall is 13/40 (32.5%).*

## 2. Evasion Ladder Breakdown ($L0$–$L4$ Strict Recall)

| Condition | Model | $L0$ (Plain) | $L1$ (Obfusc) | $L2$ (Split-Flow) | $L3$ (Hidden-API) | $L4$ (Dep-Borne) | **Pooled $L2$–$L4$** |
|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **cargo_audit** | baseline | 0/8 (0%) | 0/8 (0%) | 0/8 (0%) | 0/8 (0%) | 0/8 (0%) | **0/24 (0.0%)** |
| **grep** | baseline | 2/8 (25%) | 8/8 (100%) | 0/8 (0%) | 0/8 (0%) | 3/8 (38%) | **3/24 (12.5%)** |
| **hybrid** | gemini-3.5-flash-lite | 4/8 (50%) | 0/8 (0%) | 0/8 (0%) | 1/8 (12%) | 0/8 (0%) | **1/24 (4.2%)** |
| **hybrid_fallback** | gemini-3.5-flash-lite | 3/8 (38%) | 1/8 (12%) | 3/8 (38%) | 0/8 (0%) | 1/8 (12%) | **4/24 (16.7%)** |
| **naive_full** | gemini-3.5-flash-lite | 4/8 (50%) | 5/8 (62%) | 1/8 (12%) | 4/8 (50%) | 1/8 (12%) | **6/24 (25.0%)** |
| **raw** | gemini-3.5-flash-lite | 5/8 (62%) | 5/8 (62%) | 1/8 (12%) | 3/8 (38%) | 3/8 (38%) | **7/24 (29.2%)** |
| **raw_full** | gemini-3.5-flash-lite | 4/8 (50%) | 5/8 (62%) | 0/8 (0%) | 2/8 (25%) | 2/8 (25%) | **4/24 (16.7%)** |
| **rule_only** | baseline | 0/8 (0%) | 0/8 (0%) | 0/8 (0%) | 1/8 (12%) | 1/8 (12%) | **2/24 (8.3%)** |
| **size** | baseline | 0/8 (0%) | 0/8 (0%) | 0/8 (0%) | 0/8 (0%) | 0/8 (0%) | **0/24 (0.0%)** |
| **structured** | gemini-3.5-flash-lite | 0/8 (0%) | 0/8 (0%) | 0/8 (0%) | 0/8 (0%) | 0/8 (0%) | **0/24 (0.0%)** |
| **raw_full_corrected** | gemini-3.5-flash-lite | 4/7 (57%) | 5/7 (71%) | 0/8 (0%) | 2/7 (29%) | 2/6 (33%) | **4/21 (19.0%)** |

## 3. Paired Exact McNemar Tests (Holm-Bonferroni Corrected)

*McNemar tests pending completed evaluation entries in cache.*

## 4. Mechanistic Verification: Context Selection Quality

- **Malicious Payload in Selected Context Rate:** 50.0% (20/40)
- **Sanity Gate Status:** PASSED (threshold $\ge 50\%$)
- **Connected Path Discovery Rate:** 30.0%
- **Fallback Extraction Rate:** 70.0%
- **Mean Path Length:** 3.10 functions
- **Mean Functions Included:** 15.1
- **Mean Character Budget:** 2355 chars (~589 tokens) vs Hybrid 2745 chars

## 5. Preregistration Hypotheses Verdict
