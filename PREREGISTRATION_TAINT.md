# CrateShield Benchmark v3 — Preregistration: `hybrid_taint` Evaluation

**Date:** 2026-10-10  
**Status:** FROZEN  
**Benchmark Version:** v3.2  
**Independence Firewall Checkpoint:** Commit `2db0257`  

---

## 1. Executive Summary & Objective

In CrateShield Benchmark v3.1 confirmatory evaluation on the sealed evaluation set ($N=120$: 40 malicious, 40 clean, 40 lookalike-benign), full raw text conditions outperformed targeted regex windowing:
- `raw` (60,000 char budget): **42.5%** (17/40)
- `raw_full` (corrected testable $N=35$): **37.1%** (13/35) [overall $N=40$: **32.5%** (13/40)]
- `hybrid_fallback`: **20.0%** (8/40)
- `hybrid`: **12.5%** (5/40)
- `structured`: **0.0%** (0/40 strict, 4/40 suspicious under relaxed)

The objective of this preregistered study is to evaluate **`hybrid_taint`**, a new detection condition that selects source code context via static intra-crate data-flow (taint) analysis (using `tree-sitter-rust` AST parsing and bounded call-graph walk) instead of regex-pattern matching.

We investigate whether taint-guided context selection closes the recall gap to `raw` and `raw_full`, particularly on high evasion ladder levels ($L2$–$L4$: split-flow, hidden-API, and dependency-borne evasion), while operating under the identical character/token budget as `hybrid` ($\le 25,000$ characters).

---

## 2. Independence Firewall & Provenance

To eliminate data snooping and researcher degrees of freedom:
1. **Firewall Rule:** Taint source and sink definitions were authored strictly from `data/bench_v3/taxonomy.yaml` (Threat Families F1–F8) and standard Rust stdlib/network specifications before inspecting any individual payload file in `data/bench_v3/corpus_private`.
2. **Immutable Commit:** The firewall definitions were committed at commit **`2db0257`**.
3. **Sealed Dataset:** The evaluation uses the exact, immutable sealed eval set ($N=120$) from `data/bench_v3/manifest.json`. No changes to manifest, labels, or test samples are permitted.
4. **Offline Sanity Gate:** Offline AST validation (Task 3) was executed prior to spending any API budget.

---

## 3. Task 0 Resolution: `raw_full` Context Limits

In Task 0, all 120 raw_full eval samples were audited:
- Exactly **15 eval samples** (5 clusters $\times$ 3 twins: clean, malicious, lookalike-benign) exceeded model context limits (`total_chars > 600,000`) and were auto-labeled `BENIGN` (`calls: 0`, `cost: $0.00`):
  - `hyper` ($L4$, clean, mal, lookalike)
  - `hashbrown` ($L0$, clean, mal, lookalike)
  - `bindgen` ($L1$, clean, mal, lookalike)
  - `chrono` ($L3$, clean, mal, lookalike)
  - `tokio_wasi` ($L4$, clean, mal, lookalike)
- Among the 40 malicious samples, exactly 5 were untestable under raw_full:
  - **(a) Overall Computed (all 40 malicious):** Recall = **13/40 (32.5%)**  
    - $L0$: 4/8 (50.0%), $L1$: 5/8 (62.5%), $L2$: 0/8 (0.0%), $L3$: 2/8 (25.0%), $L4$: 2/8 (25.0%)  
    - $L2$–$L4$ pooled: 4/24 (16.7%)
  - **(b) Excluding Exceeds-Context (35 testable malicious):** Recall = **13/35 (37.1%)**  
    - $L0$: 4/7 (57.1%), $L1$: 5/7 (71.4%), $L2$: 0/8 (0.0%), $L3$: 2/7 (28.6%), $L4$: 2/6 (33.3%)  
    - $L2$–$L4$ pooled: 4/21 (19.0%)
- **Preregistered Decision:** Target (b) (13/35 = 37.1%) serves as the primary comparison baseline; target (a) (13/40 = 32.5%) is reported as a footnote.

---

## 4. Preregistered Hypotheses

- **$H_{taint.1}$ (Recall vs Hybrid):** `hybrid_taint` recall strictly exceeds `hybrid` recall (12.5%, 5/40) on the sealed eval set with Holm-corrected paired exact McNemar $p < 0.05$.
- **$H_{taint.2}$ (Recall vs Raw):** `hybrid_taint` closes the gap to `raw` (42.5%, 17/40) within non-inferiority margin, or paired McNemar does not reject equivalence.
- **$H_{taint.3}$ ($L2$–$L4$ Recovery):** `hybrid_taint` achieves higher recall on ladder levels $L2$–$L4$ than `hybrid` ($0\%$ on $L2$) and `raw_full` ($0\%$ on $L2$).
- **$H_{taint.4}$ (FPR Control):** `hybrid_taint` maintains false positive rate $\le 5\%$ across clean ($N=40$) and lookalike-benign ($N=40$) crates.
- **$H_{taint.5}$ (Cross-Model Transfer):** The relative performance ranking of `hybrid_taint` transfers to `qwen/qwen3.8-27b` on Groq without degradation to 0%.

---

## 5. Offline Validation Results (Task 3 Gate)

Prior to live execution, `scripts/v3/validate_taint_offline.py` evaluated all 120 eval samples and 30 tune samples:
- **Eval Malicious ($N=40$):**
  - Connected Path Found: 12/40 (30.0%)
  - Fallback Used: 28/40 (70.0%)
  - Mean Path Length: 3.10
  - Mean Functions Included: 15.1
  - Mean Chars: 2,355 chars (~589 tokens) vs Hybrid 2,745 chars (~686 tokens)
  - `payload_in_selected_context`: **20/40 (50.0%)**
  - **Sanity Gate Result: PASSED** on first attempt ($\ge 50.0\%$).
- **Ladder Breakdown for Payload in Context:**
  - $L0$: 6/8 (75.0%)
  - $L1$: 2/8 (25.0%)
  - $L2$: 6/8 (75.0%)
  - $L3$: 1/8 (12.5%)
  - $L4$: 5/8 (62.5%)

---

## 6. Experimental Execution Protocol

1. **Model & Hyperparameters:**
   - Primary: `gemini-3.5-flash-lite`, temperature 0.0, 1 run per sample.
   - Secondary: `qwen/qwen3.8-27b` on Groq, temperature 0.0, 1 run per sample, rate-limit paced ($\le 5,000$ tokens/call, exponential backoff tracking `Retry-After`).
2. **Context Budget:**
   - Maximum total chars: 25,000 characters (identical to `hybrid`).
3. **Statistical Tests:**
   - Paired two-sided exact McNemar test for discordant pairs between `hybrid_taint` and:
     1. `hybrid`
     2. `hybrid_fallback`
     3. `raw`
     4. `raw_full` (corrected testable $N=35$)
   - Family-wise error rate adjusted via Holm-Bonferroni step-down procedure ($\alpha = 0.05$).
4. **Honest Reporting Standard:**
   - If Holm-adjusted $p \ge 0.05$, a higher numerical recall is reported strictly as *"directionally favorable, not statistically confirmed"*.
   - Any null result or loss will be reported openly and unsoftened.
