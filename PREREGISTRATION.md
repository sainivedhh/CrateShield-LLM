# CrateShield-LLM v2: Preregistration Specification

**Registration Date:** October 9, 2026  
**Git Tag:** `prereg-v2`  
**Status:** Pre-registered before generation of v2 evaluation samples or execution of any v2 eval-split condition.

---

## 1. Study Overview & Purpose

This preregistration defines the experimental hypotheses, methodology, metrics, and statistical analysis plan for **CrateShield-LLM v2**. The study addresses all known confounders identified in the v1 snapshot:
1. **Tell-free matched pairs:** Elimination of fixed code comments, fixed routine names, and fixed call positions.
2. **Defanging isolation:** Disaggregating `.invalid` domains from plausible, non-resolvable fabricated domains.
3. **Independent authoring:** Re-authoring attack templates independently from incident descriptions in OSSF/RustSec without reusing grep pattern strings.
4. **Line-ending consistency:** Preserving original LF/CRLF line endings of each base crate.
5. **Scale test arm:** Testing detector resilience when payloads reside in files omitted or truncated by character packing budgets.
6. **Hybrid detector formulation:** Evaluating structured static signals augmented with targeted source code windows (+/- 15 lines) around flagged AST sites.

---

## 2. Hypotheses

### Primary Hypothesis
- **H1 (Hybrid Efficiency & Parity):** On tell-free v2 matched pairs, the `hybrid` condition (structured signals + targeted code windows) achieves:
  $$\text{Strict Recall}(\text{hybrid}) \ge \text{Strict Recall}(\text{raw}) - 0.10$$
  while consuming $\le 50\%$ of the mean tokens per sample required by `raw`, with $\text{FPR} \le 0.10$.

### Secondary Hypotheses
- **H2 (Defanging Confounder Test):** `structured` strict recall is higher on the fabricated-domain subset than on the `.invalid`-domain subset ($\text{Recall}(\text{fabricated}) > \text{Recall}(\text{.invalid})$), testing whether model awareness of reserved test domains caused false negatives in v1.
- **H3 (Scale & Truncation Resilience):** On samples where the payload sits in files that `raw` character-budget packing omits or truncates (`payload_in_omitted_region == True`):
  - `raw` strict recall drops significantly compared to its full-visibility baseline;
  - `hybrid` strict recall drops by no more than $0.10$ relative to its overall recall.
- **H4 (Marginal Impact of RAG Grounding):** There is no statistically significant difference in strict recall between `structured` and `structured_norag` ($p > 0.05$ via paired McNemar test).

---

## 3. Metrics

### Primary Metric
- **Strict Recall at $\text{FPR} \le 0.10$:** Classification of `MALICIOUS` is the sole positive class. `SUSPICIOUS` is treated as negative.

### Secondary Metrics
- **Relaxed Recall:** Both `MALICIOUS` and `SUSPICIOUS` treated as positive.
- **Precision:** $\frac{\text{TP}}{\text{TP} + \text{FP}}$ under strict and relaxed thresholds.
- **$\text{F}_1$-Score:** Harmonic mean of precision and recall.
- **Token Consumption:** Mean input, output, and total tokens per sample.
- **LLM Calls:** Mean API queries per sample.
- **Efficiency Index:** Strict Recall per 1,000 tokens.
- **Pair Consistency:** Percentage of base crates where both the clean twin and injected twin are classified correctly.

---

## 4. Experimental Conditions

All conditions evaluate on the **exact same sample slices**:

| Condition | Category | Description |
| :--- | :--- | :--- |
| **`size`** | Baseline | Flags malicious if total `.rs` bytes $< T$. Evaluated without fixed threshold via paired delta and ROC-AUC. |
| **`grep`** | Baseline | Frozen regex pattern matcher over source code and `build.rs` (patterns frozen from v1). |
| **`rule_only`** | Baseline | Static heuristic/AST signal rules without LLM (rules frozen from v1). |
| **`cargo_audit`** | Baseline | Advisory DB lookup (RustSec / OSSF). |
| **`structured`** | LLM | Structured static signals + leave-one-out RAG grounding + CoT prompt. |
| **`structured_norag`** | LLM (Ablation) | Structured static signals alone (no RAG) + CoT prompt. |
| **`hybrid`** | LLM (Proposed) | Structured static signals + targeted code windows (+/- 15 lines around matched sites) + full `build.rs` if $<15$ KB. |
| **`raw`** | LLM (Baseline) | Truncated source code packing (budget: 60,000 chars) + domain reasoning prompt. |
| **`naive`** | LLM (Baseline) | Truncated source code packing + generic system prompt (no domain guidance). |

---

## 5. Statistical Analysis Plan

1. **Paired Proportions (Tier 3 Twins):**
   - Exact two-tailed McNemar test on discordant pairs for all pairwise condition comparisons.
   - **Multiple Comparison Correction:** Holm-Bonferroni correction across the family of hypothesis tests (H1, H3, H4) at family-wise $\alpha = 0.05$.
2. **Confidence Intervals for Proportions:**
   - Wilson score intervals with continuity correction (or Clopper-Pearson exact intervals) for all binomial recall, precision, and FPR rates.
   - **Degenerate intervals rule:** Never report $[0.0, 0.0]$ when point estimate is $0/N$; report exact one-sided Clopper-Pearson upper bound $[0.0, 1 - (1 - \alpha)^{1/N}] \approx [0.0, 0.095]$ for $N=30$.
3. **Cluster Bootstrap:**
   - Resampling by base crate cluster ($B = 1000$, seeded) applied strictly to composite metrics ($\text{F}_1$-score, ROC-AUC) where analytical intervals are not available.
4. **Unpaired Proportions:**
   - Fisher's exact test for unpaired sub-cohort comparisons (e.g., H2: `.invalid` vs. fabricated domain recall).

---

## 6. Three-Tier Dataset Structure

- **Tier 1 (Real In-The-Wild):** `logs-update` (3 versions: 0.0.1, 0.0.2, 0.0.3). Reported strictly as $n=1$ crate, 3 versions. No aggregate percentages calculated.
- **Tier 2 (Behavior-Inspired Reconstructions):** Reconstructed historical incidents ($n=8$). Reported separately from Tiers 1 and 3.
- **Tier 3 (Injected Matched Pairs):** 10 Tune base crates (20 samples) and 30+ fresh Eval base crates (60+ samples: 50% clean, 50% injected twin).

---

## 7. Execution & Stopping Rules

1. **Sealed Eval Split:** The evaluation split is sealed. Prompts, window extraction logic, and hybrid formatting are developed and tested **exclusively on the 10 Tune base crates**.
2. **Single-Run Execution:** The eval split is executed exactly once per condition after preregistration is committed.
3. **No Silent Reruns:** Any anomaly, unexpected behavior, or bug discovered post-evaluation will be documented as a deviation in `DEVIATIONS.md` and discussed transparently in the final report.
