# CrateShield-LLM — LLM-Assisted Detection of Malicious Rust Crates

Structured static signal extraction + targeted code windows + an LLM reasoning layer as the **primary classifier**. No RandomForest, XGBoost, or trained black-box model is used in the decision path. The LLM evaluates structured static signals and contextual code windows inside an untrusted-data boundary to deliver the final verdict (`MALICIOUS`, `SUSPICIOUS`, or `BENIGN`).

---

## 1. System Architecture

```
                       Untrusted Crate (crates.io / source tree)
                                          |
                        +-----------------+-----------------+
                        |                                   |
                        v                                   v
             [Static Signal Extraction]          [Source Packing / Windows]
             - build.rs behavior analysis        - Targeted code windows (+/-15 lines)
             - unsafe/FFI concentration          - Merged & deduplicated intervals
             - Proc-macro execution scan         - Full build.rs (if <= 15 KB cap)
             - Typosquatting / name similarity   - Omitted region tracking
             - Dependency aliasing patterns      - Raw source packing (60k chars)
             - Library source scanner
             - Prompt injection detector
                        |                                   |
                        +-----------------+-----------------+
                                          |
                                          v
                               [Grounding & Framing]
                               - Local RAG Retrieval (TF-IDF / incident KB)
                               - Delimited framing: <untrusted_crate_data>
                               - Structured domain reasoning prompt
                                          |
                                          v
                               [LLM Decision Layer]
                               - Provider: Gemini 3.5 Flash-Lite / OpenAI / Anthropic
                               - Independent multi-attribute scoring:
                                 malware, security_risk, obfuscation, confidence
                                          |
                                          v
                         Verdict: MALICIOUS | SUSPICIOUS | BENIGN
```

---

## 2. Experimental Conditions

The benchmark supports full disaggregated ablation across 10 distinct evaluation conditions:

1. **`hybrid` (Proposed Method)**:
   - Structured static signals + targeted code windows ($\pm 15$ lines around signal matches) + RAG retrieval + LLM reasoning.
   - Strictly framed inside `<untrusted_crate_data>`.
   - Runs under a strict token budget ($\le 50\%$ of `raw` tokens).
2. **`hybrid_norag`**:
   - `hybrid` pipeline without RAG grounding (isolates the effect of retrieval).
3. **`structured`**:
   - Structured static signals + RAG retrieval + single-line flagged snippets (no surrounding context windows).
4. **`structured_norag`**:
   - Structured static signals alone without RAG context.
5. **`raw`**:
   - Packed raw source code (up to 60,000 characters) + domain security prompt + LLM.
6. **`naive`**:
   - Packed raw source code + bare unconstrained "is it malicious?" prompt without domain guidance or safety framing.
7. **`size` (Baseline)**:
   - Size anomaly detector (threshold-free ROC-AUC and byte delta).
8. **`grep` (Baseline)**:
   - Independent keyword regex scan over crate text.
9. **`rule_only` (Baseline)**:
   - Rule-based heuristic decision tree over static signals without LLM.
10. **`cargo_audit` (Advisory Baseline)**:
    - RustSec advisory database lookup (relevant for known historical incidents).

---

## 3. CrateShield v2 Benchmark: Confounders Fixed

The v2 evaluation benchmark addresses 8 critical confounders identified in earlier v1 baselines:

| Confounder | v1 Limitation | v2 Resolution |
| :--- | :--- | :--- |
| **A. Injection Tells** | Fixed comments (`// Platform integration hook`), `routine_` prefix, fixed main entry point. | Dynamic identifier generation from 20,000+ verb/noun combinations, synthetic comments eliminated, varied placements (P1, P3, P4; P2 and P5 not exercised in v2). |
| **B. Defanging Confound** | Injected connections to `.invalid` triggered false negatives ("inert placeholder"). | 50/50 balance between `.invalid` and plausible fabricated hostnames (`pkg-telemetry-sink.net`, etc.); H2 reclassified as not testable as executed due to category alignment. |
| **C. Author/Vocab Leak** | Payloads and baseline patterns shared identical vocabulary. | Independent re-authoring of C1..C8 templates from OSSF/RustSec incident descriptions; $\ge 70\%$ variants at obfuscation level $\ge 1$. |
| **D. Line Endings** | Injected twins used Windows CRLF while base files used LF. | Native binary detection and preservation; diffs contain zero whole-file line ending churn. |
| **E. Statistical Rigor** | Degenerate $[0, 0]$ CIs, no multiple testing correction, size gate cutoff. | Wilson score intervals, exact McNemar paired tests with Holm-Bonferroni correction, Fisher exact tests, and cluster bootstrap by base crate. |
| **F. Reproducibility** | Historical discrepancy in Tier 2 sample count (6 vs 8). | True cache count verified at n=6 (discrepancy resolved: `rustdecimal` and `faster_log` failed Gate G1 leak checks in v1). |
| **G. Split Hygiene** | 40 candidate crates used. | 30 fresh, completely disjoint evaluation base crates; 10 disjoint tune base crates (Gate G6). |
| **H. Scale-Test Arm** | Payloads always placed in root files. | Explicit placement of payloads in modules omitted by standard character packing limits (Hypothesis H3). |

---

## 4. Environment & Quickstart

### Prerequisites
- Python 3.10+
- Valid API key for Gemini (recommended, free tier) or OpenAI / Anthropic.

### Configuration
```bash
# Recommended: Gemini 3.5 Flash-Lite (Free Tier)
export CRATESHIELD_LLM_PROVIDER=gemini-3.5-flash-lite
export GEMINI_API_KEY="your-api-key-here"

# Alternative: OpenAI
export CRATESHIELD_LLM_PROVIDER=openai
export OPENAI_API_KEY="sk-..."

# Alternative: Anthropic
export CRATESHIELD_LLM_PROVIDER=anthropic
export ANTHROPIC_API_KEY="sk-ant-..."
```

### Installation
```bash
git clone https://github.com/user/crateshield-llm.git
cd crateshield-llm
pip install -e .
```

---

## 5. One-Command Reproduction (< 60 Seconds)

To verify all cryptographic hashes, validate benchmark manifest invariants, check tell audits, and regenerate the complete statistical report from cached evaluations without calling any external LLM APIs:

```bash
python scripts/verify_reproduction.py
```

---

## 5b. Benchmark v3 Reproduction (Hardened, Leak-Controlled, Multi-Model)

Benchmark v3 is a leak-controlled, non-saturated synthetic evaluation benchmark comprising 150 samples across 50 clusters (10 tune clusters, 40 sealed eval clusters) across 8 threat families (5 SEEN, 3 HELD-OUT) with difficulty ladder levels L0–L4, independent firewall generation, hard-negative lookalike twins, and multi-model evaluation (`gemini-3.5-flash-lite` and Groq `qwen/qwen3.8-27b`).

To verify Benchmark v3 reproduction completely offline in < 45 seconds:
```bash
python scripts/v3/verify_reproduction_v3.py
```

To run the offline test suite:
```bash
pytest tests/
```

---

## 6. CLI Usage

```bash
# Analyze a specific crate by name and version
python -m crateshield analyze serde 1.0.210 --condition hybrid

# Run with static pre-screening enabled
python -m crateshield analyze faster_log 0.1.2 --condition hybrid --prescreen

# Launch interactive web interface
python -m crateshield serve --port 8000
```

---

## 7. Repository Layout

```
crateshield-llm/
├── PREREGISTRATION.md           # Preregistered evaluation plan, hypotheses H1..H4, stopping rules
├── TUNING_LOG.md                # Log of tune-split calibrations and prompt revisions
├── DEVIATIONS.md                # Transparent audit log of documented benchmark deviations
├── REPORT_v2.md                 # Generated statistical evaluation report
├── pyproject.toml               # Package configuration and pytest definitions
├── src/crateshield/
│   ├── config.py                # Environment configuration and parameter thresholds
│   ├── pipeline.py              # End-to-end pipeline orchestrator
│   ├── llm/                     # Client dispatch, prompt constructors, response parser
│   ├── signals/                 # Static signal extractors (build_rs, source_scan, injection, etc.)
│   └── rag/                     # Embedding store and leave-one-out context retriever
├── harness/
│   ├── eval_v2.py               # Evaluation engine with deterministic caching and token metrics
│   ├── hybrid.py                # Targeted code window extractor (+/-15 lines) and prompt builder
│   ├── inject_v2.py             # Tell-free payload injector preserving native line endings
│   ├── audit_v2.py              # Tell frequency audit and logistic regression discriminator
│   ├── run_v2.py                # Benchmark manifest generator with scale-test arm
│   └── stats.py                 # Wilson CIs, exact McNemar tests, and cluster bootstrap
├── scripts/
│   ├── make_report.py           # Statistical report generator from immutable eval cache
│   ├── run_eval_v2.py           # Single-run sealed evaluation benchmark runner
│   ├── verify_reproduction.py   # One-command fast reproduction verification
│   └── fetch_data.py            # On-demand crate archive downloader
├── data/
│   ├── bench_v1/                # Frozen immutable historical v1 benchmark records
│   ├── bench_v2/
│   │   ├── manifest.json        # Benchmark manifest v2 (80 samples)
│   │   ├── eval_cache.json      # Keyed immutable evaluation result cache
│   │   └── results_summary.json # Machine-readable summary statistics
│   └── ossf/                    # OSSF malicious package advisories and availability records
└── tests/                       # Complete pytest unit and integration test suite
```

---

## 8. License & Ethical Research Note

All benchmarks, payloads, and analysis code are developed strictly for defensive static security research under academic and non-commercial guidelines. Crate payloads remain permanently inert static text syntax trees and are never compiled or executed during evaluation.
