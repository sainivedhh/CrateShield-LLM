# CrateShield Benchmark v3 — Preregistration: `contextual_purpose_consistency` Evaluation

**Date:** 2026-10-11  
**Status:** FROZEN  
**Benchmark Version:** v3.4  
**Condition Name:** `contextual_purpose_consistency`  
**Evaluation Set:** Sealed Benchmark v3 Eval Split ($N=120$: 40 malicious, 40 clean, 40 lookalike-benign)  

---

## 1. Executive Summary & Objective

In CrateShield Benchmark v3.2, static data-flow context selection (`hybrid_taint`) successfully extracted payload code for 75% of $L2$ split-flow samples, but achieved only **15.0%** (6/40) strict recall on the sealed evaluation split, trailing `raw` (**42.5%**, 17/40) and corrected `raw_full` (**37.1%**, 13/35). Qualitative inspection showed that isolated taint snippets lacked semantic intent context, preventing the model from recognizing multi-stage or dormant payloads as malicious.

This study evaluates **`contextual_purpose_consistency`**, a condition combining:
1. **Purpose-Consistency Verification Framing:** Stated crate purpose (Cargo.toml description and README overview) is compared directly against the code's actual actions.
2. **Module-Scoped Structural Context:** Enclosing module hierarchy, author doc comments, and in-place scope evaluation instructions are provided.
3. **Strict Omission of Absence Annotations:** All absence-of-connection notes (e.g. *"unreferenced internally"*, *"dead code"*) are silenced, ensuring the model does not excuse dormant or multi-stage payloads.

We investigate whether this combined condition closes the recall gap to `raw` and corrected `raw_full` on the sealed evaluation set while preserving false-positive control across all 40 clean and 40 lookalike-benign crates.

---

## 2. Iterative Pilot Disclosure & Overfitting Risk Limitation

> [!WARNING] Methodological Disclosure: Multi-Round Pilot Iteration on Development Split
> This candidate condition was developed and refined across **three successive pilot iterations** evaluated on the identical 10 development-split malicious samples (`s3_0001` through `s3_0030` in `data/bench_v3/manifest.json`):
> 1. **Candidate A (`hybrid_taint_contextual`):** Added module hierarchy and static call-site notes, but backfired by emitting *"unreferenced internally"* notes that excused real split-flow payloads as dead code (strict recall: 2/10 [20%]).
> 2. **Candidate B (`purpose_consistency`):** Introduced purpose-consistency framing, elevating relaxed recall from 50% to 70% (7/10), but carried a 10% lookalike FPR.
> 3. **Combined Candidate (`contextual_purpose_consistency`):** Unified purpose-consistency framing with module context, while explicitly removing all absence/dead-code notes, reaching 5/10 (50%) strict recall and 7/10 (70%) relaxed recall with 0/10 strict FPR on the development split.
> 
> **Explicit Limitation:** Because this candidate underwent 3 rounds of developer iteration against the same 10 tune-malicious samples, **tune-split metrics (50% strict / 70% relaxed recall) cannot be treated as an unbiased expectation for sealed performance.** Sealed evaluation on the untouched $N=120$ split is required to measure true generalizability free of development-sample tuning.

---

## 3. Frozen Specification of `contextual_purpose_consistency`

The prompt and context extraction logic are **strictly frozen** exactly as validated in the v3.3/v3.4 pilot (no further tuning or adjustments allowed):

1. **Declared Purpose Extraction:**
   - Pulled from `Cargo.toml` `[package].description` and the first $\le 500$ characters of `README.md` (or variant files).
   - Real crate name variants are scrubbed to neutral anonymized IDs (`crate_<8hex>`) via `_replace_name_variants`.
   - Fallback (if no description/README exists): Inferred from top doc comments (`//!` in `lib.rs`/`main.rs`).
2. **Contextual Taint Code Selection:**
   - Intra-crate call graph and AST parsing via `tree-sitter-rust`.
   - Bounded graph walk (max depth 4, max 25 nodes) connecting frozen source/sink definitions.
   - For each function on a path: module hierarchy path (`// Module: crate::...`), file-level purpose comments (`//!`), and function doc comments (`///`).
   - **Absence Note Omission:** `omit_absence_notes=True` strictly silences any note asserting that a function is unreferenced or dead code. Only presence notes (`// Static call-site: called by fn ...`) or scope entry-point notes are emitted.
3. **Prompt Framing & System Instructions:**
   - Reuses `COMBINED_SYSTEM_PROMPT` in `harness/pilot_v33/combined.py`.
   - Directs the model to evaluate whether code in each module and build script does only things consistent with declared purpose, or unexplained/unauthorized behaviors.
   - Strict adherence to the shared score bands and JSON response schema (`classification`, `confidence`, `malware_score`, `obfuscation_score`, `security_risk_score`, `primary_signals`, `reasoning`, `recommended_action`).

---

## 4. Preregistered Hypotheses

All hypotheses are evaluated against the immutable, sealed evaluation split ($N=120$: 40 malicious, 40 clean, 40 lookalike-benign):

- **$H_{v34.1}$ (Superiority vs `hybrid_taint`):**  
  `contextual_purpose_consistency` strict recall on the sealed eval split strictly exceeds `hybrid_taint` (15.0%, 6/40) with Holm-adjusted paired exact McNemar $p < 0.05$.
- **$H_{v34.2}$ (Recall vs `raw`):**  
  `contextual_purpose_consistency` closes the recall gap to `raw` (42.5%, 17/40) on the sealed eval split (tested via paired exact McNemar non-inferiority).
- **$H_{v34.3}$ (Recall vs Corrected `raw_full`):**  
  `contextual_purpose_consistency` closes the recall gap to corrected testable `raw_full` (37.1%, 13/35 testable; overall uncorrected 32.5%, 13/40).
- **$H_{v34.4}$ (Recall vs `grep` Baseline):**  
  `contextual_purpose_consistency` strict recall strictly exceeds the static `grep` baseline (32.5%, 13/40) with Holm-adjusted paired exact McNemar $p < 0.05$.
- **$H_{v34.5}$ (Lookalike FPR Control — Strict & Relaxed):**  
  `contextual_purpose_consistency` achieves strict False Positive Rate $\le 5.0\%$ (at most 2/40) on the 40 sealed lookalike-benign crates. In addition, **both strict and relaxed FPR** will be explicitly reported across all 40 lookalike-benign crates and all 40 clean crates.

---

## 5. Preregistered Comparison Set & Statistical Protocol

The primary statistical comparison evaluates `contextual_purpose_consistency` against exactly four prior benchmark conditions on identical samples from `data/bench_v3/eval_cache.json`:
1. **`hybrid_taint`** (15.0% strict recall, 0.0% clean FPR, 0.0% lookalike FPR)
2. **`raw`** (42.5% strict recall, 0.0% clean FPR, 10.0% lookalike FPR)
3. **`raw_full` (corrected testable $N=35$)** (37.1% strict recall, 0.0% clean FPR, 2.5% lookalike FPR)
4. **`grep`** (32.5% strict recall, 12.5% clean FPR, 12.5% lookalike FPR)

### Statistical Testing Protocol:
1. **Paired Two-Sided Exact McNemar Test:** Computed on the 2x2 contingency table of discordant pairs between `contextual_purpose_consistency` and each comparator.
2. **Multiplicity Correction:** Family-wise error rate across the 4 primary hypothesis tests is controlled using the **Holm-Bonferroni step-down procedure** ($\alpha = 0.05$).
3. **Reporting Threshold:** If Holm-adjusted $p \ge 0.05$, a higher numerical recall is reported strictly as *"directionally favorable, not statistically confirmed"*.
4. **Evaluation Budget:**
   - Single confirmatory run on `gemini-3.5-flash-lite`, temperature 0.0.
   - Exactly 120 calls on the sealed eval split.
   - Cache results stored to `data/bench_v3/eval_cache.json` under condition key `contextual_purpose_consistency`.
