# CrateShield-LLM v2: Tune Split Development & Tuning Log

This document records all prompt modifications, window size calibrations, and tune-split evaluations for the `hybrid` condition prior to sealing and freezing.

## Tune Split Baseline Configuration
- Split: 10 base crates (20 samples: 10 clean, 10 injected)
- Target: Validate window extraction, token budgeting, and baseline performance.

## Entries
## Entry 1: Hybrid Window Extraction & Baseline Benchmark Calibration (2026-10-09)

### Configuration
- Model: `gemini-3.5-flash-lite` (temperature 0.0)
- Sample set: 20 Tune samples (10 pairs: 10 clean, 10 malicious) from `data/bench_v2/manifest.json`
- Conditions evaluated: `hybrid`, `hybrid_norag`, `structured`, `raw`
- Hybrid parameters:
  - Code window radius: $\pm 15$ lines around signal matches (source_scan, injection, build_rs)
  - Interval merging: contiguous and overlapping intervals merged per file with 1-indexed line numbers
  - Full `build.rs` inclusion cap: $\le 15,000$ chars (300 lines)
  - Total hybrid code budget: $\le 25,000$ chars
  - Prompt: Security analyst system prompt with structured signals + code windows inside `<untrusted_crate_data>`

### Results Table (Tune Split, n=20)
| Condition | Strict Recall | Strict FPR | Relaxed Recall | Relaxed FPR | Mean In Tokens | Mean Out Tokens | Mean Total Tokens | % of Raw Tokens |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **hybrid** | **1.000 (10/10)** | **0.000 (0/10)** | **1.000 (10/10)** | **0.000 (0/10)** | 4,605.8 | 305.4 | **4,911.2** | **39.5%** |
| **hybrid_norag** | **1.000 (10/10)** | **0.000 (0/10)** | **1.000 (10/10)** | **0.000 (0/10)** | 3,965.1 | 287.9 | **4,252.9** | **34.2%** |
| **structured** | 0.700 (7/10) | 0.000 (0/10) | 1.000 (10/10) | 0.000 (0/10) | 3,509.8 | 303.6 | 3,813.4 | 30.7% |
| **raw** | 0.900 (9/10) | 0.000 (0/10) | 0.900 (9/10) | 0.000 (0/10) | 12,251.2 | 179.9 | 12,431.2 | 100.0% |

### Key Findings
1. **Hypothesis H1 Strongly Supported on Tune**: `hybrid` achieves strict recall 1.0 (exceeding `raw` at 0.9) while using **39.5% of raw's tokens** (4,911 vs 12,431), well within the preregistered $\le 50\%$ token bound and FPR $\le 0.10$ bound.
2. **Value of Targeted Windows**: On `structured` (without windows), the model classified 3 malicious samples as `SUSPICIOUS` (malware score ~0.35) rather than `MALICIOUS`, giving 0.7 strict recall. Adding the targeted code windows elevated all 3 to definitive `MALICIOUS` verdicts (strict recall 1.0) because the surrounding context revealed the malicious data flow.
3. **Budget Compliance**: No samples hit truncation or budget overflow on the tune set; windows averaged ~3.8 KB of code.
4. **Decision**: Prompt template and window logic are frozen with no further alterations needed. Ready for git tag `freeze-v2`.
