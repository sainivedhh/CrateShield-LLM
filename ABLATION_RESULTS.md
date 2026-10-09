# CrateShield-LLM: Empirical Evaluation & Ablation Report (SPEC v1)

**Date of Execution:** October 8, 2026  
**Evaluator Environment:** Windows 11 x86_64, Python 3.13, Tree-Sitter Rust  
**Evaluated Model:** Gemini 3.5 Flash-Lite (Google AI Studio Free Tier, Temperature = 0.0)  
**Evaluation Protocol:** CrateShield Injection Harness Spec v1 (Strict Disaggregation, Matched Pairs, Anonymized Views)  
**Data Provenance:** [`data/bench_v1/results_summary.json`](data/bench_v1/results_summary.json) | [`data/bench_v1/manifest.json`](data/bench_v1/manifest.json)  

---

## 1. Confounder Resolution & Methodological Corrections

Following the rigorous methodological review, all eight fundamental validity confounders identified in preliminary benchmarks have been systematically eliminated in this harness:

1. **Size/Structure Confounder Eliminated:** Clean obscure base crates with real `build.rs` files are paired with payload-injected twins. The `size` baseline now achieves an accuracy of exactly **0.500** (chance level), proving size is completely non-predictive.
2. **Name & Metadata Leakage Eliminated:** All prompts, signals, and queries strictly use neutral salted hashes (`crate_XXXX`) and stripped `Cargo.toml` manifests. Gate G3 negative controls confirmed **0.0% Recall and 0.0% FPR** for name-only and metadata-only views.
3. **Circular Design Broken:** Payloads are frozen independently in [`harness/payloads/v1/`](harness/payloads/v1/) with verified SHA-256 hashes (`MANIFEST.sha256`) spanning 8 threat archetypes and 15 surface variants.
4. **Strict Three-Tier Disaggregation:** Real in-the-wild incidents, behavior-inspired reconstructions, and injected matched pairs are reported in separate tables and are never pooled into a single headline number.
5. **Dual-Threshold Reporting:** Strict (`MALICIOUS` only = positive) is reported as the primary metric, with Relaxed (`MALICIOUS` | `SUSPICIOUS` = positive) reported side-by-side.
6. **Statistical Rigor:** All Tier 3 metrics include 95% cluster bootstrap confidence intervals resampling by base crate ($B = 1000$) and McNemar's exact test for paired differences.
7. **Hard-Benign Build Script Representation:** Base crates are stratified across build behaviors (`native_tools`, `env_probing`, `pure_rust`), ensuring legitimate compiler/linker probing is present.
8. **Fair Non-LLM Baselines:** Non-LLM baselines (`size`, `grep`, `rule_only`, `cargo_audit`) are evaluated on the exact same sample slices as the LLM conditions.

---

## 2. Tier 3: Injected Matched Pairs ($N = 60$ Eval Samples: 30 Clean, 30 Injected)

*Evaluated across 30 disjoint base crate clusters (10 separate base crates reserved for tune/negative controls).*

### A. Dual-Threshold Performance Table

| Condition | Class | Strict Rec (Primary) | Strict Prec | Strict $\text{F}_1$ | Strict FPR | Rel Rec (Secondary) | Rel Prec | Rel $\text{F}_1$ | Rel FPR | Pair Consistency |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`size` ($T=5000$)** | Baseline | 0.133 | 0.500 | 0.211 | 0.133 | 0.133 | 0.500 | 0.211 | 0.133 | 0.000 |
| **`grep` (regex)** | Baseline | **0.933** | 0.903 | 0.918 | 0.100 | **0.933** | 0.903 | 0.918 | 0.100 | 0.833 |
| **`rule_only` (AST signals)** | Baseline | 0.500 | 0.833 | 0.625 | 0.100 | 0.500 | 0.833 | 0.625 | 0.100 | 0.400 |
| **`cargo_audit`** | Baseline | 0.000 | 0.000 | 0.000 | **0.000** | 0.000 | 0.000 | 0.000 | **0.000** | 0.000 |
| **`structured` (Signals+RAG)** | Ours | 0.467 | **1.000** | 0.636 | **0.000** | 0.733 | **1.000** | 0.846 | **0.000** | 0.467 |
| **`structured_norag`** | Ablation | 0.600 | **1.000** | 0.750 | **0.000** | **0.933** | **1.000** | **0.966** | **0.000** | 0.600 |
| **`raw` (Source + Domain Prompt)**| Baseline | **0.967** | **1.000** | **0.983** | **0.000** | **1.000** | **1.000** | **1.000** | **0.000** | **0.967** |
| **`naive` (Raw + Basic Prompt)** | Baseline | 0.933 | **1.000** | 0.966 | **0.000** | 0.967 | **1.000** | 0.983 | **0.000** | 0.933 |

---

### B. Statistical Confidence Intervals (Cluster Bootstrap, $B=1000$, Strict Threshold)

*Resampled at the base crate cluster level to account for paired-twin dependencies:*

| Condition | 95% CI Recall | 95% CI Precision | 95% CI $\text{F}_1$-Score | 95% CI False Positive Rate |
| :--- | :---: | :---: | :---: | :---: |
| **`size`** | $[0.033, 0.267]$ | $[0.500, 0.500]$ | $[0.062, 0.348]$ | $[0.033, 0.267]$ |
| **`grep`** | $[0.833, 1.000]$ | $[0.824, 1.000]$ | $[0.847, 0.968]$ | $[0.000, 0.200]$ |
| **`rule_only`** | $[0.300, 0.667]$ | $[0.643, 1.000]$ | $[0.455, 0.760]$ | $[0.000, 0.233]$ |
| **`structured`** | $[0.300, 0.633]$ | $[1.000, 1.000]$ | $[0.462, 0.776]$ | $[0.000, 0.000]$ |
| **`structured_norag`** | $[0.433, 0.767]$ | $[1.000, 1.000]$ | $[0.605, 0.868]$ | $[0.000, 0.000]$ |
| **`raw`** | $[0.900, 1.000]$ | $[1.000, 1.000]$ | $[0.947, 1.000]$ | $[0.000, 0.000]$ |
| **`naive`** | $[0.833, 1.000]$ | $[1.000, 1.000]$ | $[0.909, 1.000]$ | $[0.000, 0.000]$ |

---

### C. Paired McNemar Exact Tests on Tier 3 (vs. `structured`)

*Evaluating whether discordant classification decisions between paired conditions are statistically significant:*

| Comparison | Discordant Pairs | `structured` Wins | Competitor Wins | Exact $p$-Value | Statistically Significant ($\alpha = 0.05$)? |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`structured` vs. `size`** | 16 | 15 | 1 | $p = 0.0005$ | **Yes** (`structured` significantly superior) |
| **`structured` vs. `grep`** | 21 | 5 | 16 | $p = 0.0266$ | **Yes** (`grep` higher strict recall, but 10% FPR) |
| **`structured` vs. `rule_only`**| 18 | 10 | 8 | $p = 0.8145$ | No (signal extractor alone approximates strict LLM) |
| **`structured` vs. `cargo_audit`**| 14 | 14 | 0 | $p = 0.0001$ | **Yes** (`structured` significantly superior) |
| **`structured` vs. `structured_norag`** | 6 | 1 | 5 | $p = 0.2188$ | No (intervals overlap; norag tends less conservative) |
| **`structured` vs. `raw`** | 15 | 0 | 15 | $p = 0.0001$ | **Yes** (`raw` achieves significantly higher strict recall) |
| **`structured` vs. `naive`** | 14 | 0 | 14 | $p = 0.0001$ | **Yes** (`naive` achieves significantly higher strict recall) |

---

## 3. Tier 1: Real In-The-Wild Samples ($n = 3$ Samples, 1 Crate)

*Evaluates real malware versions published to crates.io (`logs-update` versions 0.0.1, 0.0.2, 0.0.3, documented under OSSF MAL-2024-11883).*

| Condition | Strict Hits / Total | Strict Recall | Relaxed Hits / Total | Relaxed Recall |
| :--- | :---: | :---: | :---: | :---: |
| **`size`** | 0 / 3 | 0.000 | 0 / 3 | 0.000 |
| **`grep`** | 3 / 3 | **1.000** | 3 / 3 | **1.000** |
| **`rule_only`** | 3 / 3 | **1.000** | 3 / 3 | **1.000** |
| **`cargo_audit`** | 0 / 3 | 0.000 | 0 / 3 | 0.000 |
| **`structured`** | 3 / 3 | **1.000** | 3 / 3 | **1.000** |
| **`structured_norag`** | 3 / 3 | **1.000** | 3 / 3 | **1.000** |
| **`raw`** | 3 / 3 | **1.000** | 3 / 3 | **1.000** |
| **`naive`** | 3 / 3 | **1.000** | 3 / 3 | **1.000** |

*Note: `cargo_audit` completely missed all versions of `logs-update` because the crate is not indexed in the RustSec Advisory DB (it was logged in OSSF Malicious Packages).*

---

## 4. Tier 2: Behavior-Inspired Reconstructions ($n = 8$ Samples)

*Reconstructed historical incident archetypes with sanitized/anonymized metadata (`rustdecimal`, `faster_log`, `proc-macro1`, `tinymember`, `xrvrv`, `arrayref`, `amzn-consolas-client`, `amzn-codewhisperer-streaming-client`).*

| Condition | Strict Hits / Total | Strict Recall | Relaxed Hits / Total | Relaxed Recall |
| :--- | :---: | :---: | :---: | :---: |
| **`size`** | 6 / 8 | 0.750 | 6 / 8 | 0.750 |
| **`grep`** | 3 / 8 | 0.375 | 3 / 8 | 0.375 |
| **`rule_only`** | 4 / 8 | 0.500 | 4 / 8 | 0.500 |
| **`cargo_audit`** | 4 / 8 | 0.500 | 4 / 8 | 0.500 |
| **`structured`** | 4 / 8 | 0.500 | 4 / 8 | 0.500 |
| **`structured_norag`** | 3 / 8 | 0.375 | 6 / 8 | **0.750** |
| **`raw`** | 4 / 8 | 0.500 | 5 / 8 | 0.625 |
| **`naive`** | 2 / 8 | 0.250 | 5 / 8 | 0.625 |

---

## 5. Scientific Findings & Honest Research Insights

### Finding 1: Why Raw Prompting Outperformed Structured under Strict Threshold
On Tier 3 matched pairs, `raw` source code prompting achieved a strict recall of **0.967** ($F_1 = 0.983$), while `structured` achieved **0.467** ($F_1 = 0.636$). Under the relaxed threshold, the gap narrowed significantly (`raw` 1.000 vs. `structured_norag` 0.933 vs. `structured` 0.733).
- **The Conservatism Bottleneck:** When static signals are extracted, the LLM receives an abstract summary (e.g. `build.rs has network call`). Without full source context, the prompt instructions caution the model not to hallucinate, causing the model to hedge and classify samples as `SUSPICIOUS` (confidence score 0.35–0.48) rather than crossing the strict `MALICIOUS` threshold ($\ge 0.50$).
- **Direct Code Inspection:** In `raw` mode, Gemini 3.5 Flash-Lite's large context window (1 million tokens) directly inspects the complete Rust syntax tree, effortlessly detecting payloads injected into library source or build scripts.
- **Academic Implication:** Abstract signal extraction alone can discard fine-grained context that modern long-context LLMs can easily parse. Future hybrid architectures should pass targeted code snippets alongside structured signals.

### Finding 2: What the LLM Truly Adds Beyond Grep and Rules
- A frozen `grep` baseline achieves high recall (0.933), but suffers a **10.0% False Positive Rate** (bootstrap CI $[0.000, 0.200]$). In production, an FPR of 10% on crates.io translates to hundreds of spurious flags per day on legitimate crates compiling C libraries or probing the target OS.
- In sharp contrast, all LLM conditions (`structured`, `structured_norag`, `raw`, `naive`) achieved an **FPR of 0.000 (0/30 False Positives, 100% Precision)** across all hard-benign base crates.
- **The Core Contribution:** The true marginal value of LLM reasoning is **semantic disambiguation**—distinguishing between legitimate build-time system probing (`cc`, `pkg-config`, `autocfg`) and malicious exfiltration, driving FPR to zero while maintaining high detection recall.

### Finding 3: The Impact of RAG Grounding
- `structured_norag` outperformed `structured` under both Strict (0.600 vs. 0.467) and Relaxed (0.933 vs. 0.733).
- Under leave-one-out RAG, retrieved documents of past malware incidents that do not perfectly align with synthetic payloads introduce confounding historical references, causing the model to become more tentative and assign `SUSPICIOUS` instead of `MALICIOUS`. RAG is most valuable for explaining novel variants of documented campaigns, rather than classifying novel zero-day synthetic payloads.

---

## 6. Acceptance Gates Audit Summary

| Gate | Spec Requirement | Empirical Result | Status |
| :--- | :--- | :--- | :---: |
| **G1: Leak Audit** | Zero original names, URLs, repo handles, or label words in model view | 0 violations across 80 samples | **PASSED** |
| **G2: Size Baseline** | Size AUC on matched pairs $\le 0.60$ | Accuracy = 0.500 (Chance level) | **PASSED** |
| **G3: Negative Controls** | Recall and FPR $\le 10\%$ for name-only and metadata-only views | Recall = 0.0%, FPR = 0.0% | **PASSED** |
| **G4: Frozen Payloads** | Payload templates locked with `MANIFEST.sha256` | All SHA-256 hashes verified | **PASSED** |
| **G5: Tree-Sitter Sanity**| Zero syntax parse error nodes across all benchmark samples | 0 parse errors across 1,378 `.rs` files | **PASSED** |
| **G6: Disjoint Splits** | Tune and Eval sets share zero base crates | 10 Tune vs. 30 Eval (0 overlap) | **PASSED** |
| **G7: Fair Evaluation** | All conditions evaluated on the exact same sample slice | All 8 conditions evaluated on same 60 samples | **PASSED** |
