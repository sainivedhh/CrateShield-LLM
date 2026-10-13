# Coverage Extension Log (v3.5)

This log documents all design decisions, empirical measurements, and methodology notes for CrateShield Benchmark v3.5 (Evaluation Coverage Extension).

---

## 1. Scope & Execution Plan

1. **Part A (Qwen Cross-Model Evaluation)**:
   - Evaluates `qwen/qwen3.8-27b` via Groq on the sealed eval split ($N=120$) across conditions lacking complete coverage (`hybrid_taint`, `contextual_purpose_consistency`, `hybrid_fallback`, `raw_full`, `naive_full`, `raw`, `structured`, `hybrid`).
   - Groq rate limits handled with dynamic token-bucket pacing (8,000 ITPM buffer, exponential backoff on 429).
   - 413 / oversized requests cleanly mapped to `finish_reason: "exceeds_context"`.

2. **Part B (Repeatability Noise Floor)** — **COMPLETED**:
   - Fixed 24-sample reproducibility subset (8 clusters $\times$ 3 twins: 7 malicious, 9 clean, 8 lookalike).
   - Evaluated across 3 repeats at $T=0.0$ (deterministic jitter) and 3 repeats at $T=0.7$ (stochastic noise floor) across all 8 conditions using Gemini Key 2.

3. **Part C (Real-World FPR on Crates.io)**:
   - Evaluates 1,300 real-world crates (300 popular + 1,000 random) downloaded safely from static.crates.io CDN.
   - Stage 1 static pre-screen (0 LLM cost) executed across all 1,300 crates.
   - Protocol Gate: 494 crates flagged (38.0%), exceeding the $2\times$ threshold (>260 crates); paused before Stage 2 LLM execution.

---

## 2. Part B Results: Repeatability & Noise Floor

### Table 1: Deterministic Jitter at $T=0.0$ ($N=24$)
| Condition | Strict Mean Kappa | Strict Discordance | Relaxed Mean Kappa | Relaxed Discordance | Status |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `hybrid_taint` | **1.0000** | **0.0 / 24** | **1.0000** | **0.0 / 24** | 100% Deterministic |
| `contextual_purpose_consistency` | **1.0000** | **0.0 / 24** | **1.0000** | **0.0 / 24** | 100% Deterministic |
| `hybrid` | **1.0000** | **0.0 / 24** | **1.0000** | **0.0 / 24** | 100% Deterministic |
| `structured` | **1.0000** | **0.0 / 24** | **1.0000** | **0.0 / 24** | 100% Deterministic |
| `hybrid_fallback` | **1.0000** | **0.0 / 24** | **1.0000** | **0.0 / 24** | 100% Deterministic |
| `naive_full` | 0.9298 | 0.7 / 24 | 0.8760 | 1.3 / 24 | Minor MoE/floating-point jitter |
| `raw` | 0.8889 | 0.7 / 24 | 0.8523 | 1.3 / 24 | Minor MoE/floating-point jitter |
| `raw_full` | 0.8091 | 1.3 / 24 | 0.7739 | 2.0 / 24 | MoE/floating-point jitter |

### Table 2: Stochastic Noise Floor at $T=0.7$ ($N=24$)
| Condition | Strict Kappa | Strict Discordance | Strict Mal Recall (Min / Mean / Max) | Strict Spread | Relaxed Kappa | Relaxed Mal Recall (Min / Mean / Max) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `contextual_purpose_consistency` | **1.0000** | **0.0 / 24** | **28.6% / 28.6% / 28.6%** | **0.0%** | **1.0000** | **42.9% / 42.9% / 42.9%** |
| `hybrid_taint` | **1.0000** | **0.0 / 24** | **28.6% / 28.6% / 28.6%** | **0.0%** | **1.0000** | **28.6% / 28.6% / 28.6%** |
| `naive_full` | 0.9355 | 0.7 / 24 | 71.4% / 71.4% / 71.4% | 0.0% | 0.9355 | 71.4% / 71.4% / 71.4% |
| `raw_full` | 1.0000 | 0.0 / 24 | 42.9% / 42.9% / 42.9% | 0.0% | 1.0000 | 71.4% / 71.4% / 71.4% |
| `raw` | 0.9091 | 0.7 / 24 | 57.1% / 66.7% / 71.4% | **$\pm 7.1\%$ (14.3%)** | 0.8519 | 71.4% / 76.2% / 85.7% |
| `hybrid_fallback` | 0.7249 | 1.3 / 24 | 28.6% / 33.3% / 42.9% | **$\pm 7.1\%$ (14.3%)** | 1.0000 | 42.9% / 42.9% / 42.9% |

---

## 3. Part C Stage 1: Static Pre-Screen Audit & Rule Decomposition

### Protocol Qualification Mandate
> **Important Qualification**: Any characterization of the static pre-screen as achieving "zero-recall-loss" must be explicitly qualified as **"zero-recall-loss BY DESIGN against the 8 threat families in our taxonomy"**. This has **not** been empirically verified against real malicious traffic in this pass, since Part C's crates.io sample excludes all known-malicious crates by construction. It is an assumption inherited from the pre-screen's rule coverage across the synthetic benchmark families, not an empirically measured property of the real-world production run.

### Empirical Rule Breakdown (494 Flags / 1,300 Crates)
- **Traditional Structural Signals** (`build.rs`, `unsafe_ffi`, `proc_macro`, `typosquatting`, `version`):
  - Fired on only **107 of 1,300 crates (8.2%)**, matching the expected ~10% (130-crate) baseline.
- **Whole-Library Source Scan (`source_scan`)**:
  - Accounts for **387 of the 494 flagged crates (78.3%) as the SOLE trigger**.
  - Operates as a broad capability filter:
    - `source_scan.network`: 242 crates (49.0% of flagged; sole culprit for 85 crates). Matches any `TcpStream`, `UdpSocket`, `std::net::`, `tokio::net::`, `reqwest::`, `hyper::`.
    - `source_scan.process_spawn`: 179 crates (36.2% of flagged; sole culprit for 36 crates). Matches `Command::new`.
    - `source_scan.fs_walk`: 167 crates (33.8% of flagged; sole culprit for 32 crates). Matches `read_dir`, `WalkDir`.
    - `source_scan.sensitive_paths`: 122 crates (24.7% of flagged; sole culprit for 14 crates). Matches `.env`, `wallet`, `.aws`, `.ssh`.
    - `source_scan.decode_payload`: 80 crates (16.2% of flagged). Matches `base64::`.
    - `source_scan.ip_literal_url`: 75 crates (15.2% of flagged). Matches IP literals in tests/code.
    - `build_rs`: 72 crates (14.6% of flagged; sole culprit for 32 crates).

---

## 4. Next Step Checklist

- [x] Part B Gemini Repeats completed and verified (100% complete).
- [x] Part C Stage 1 Static Pre-Screen completed (494 flags / 1,300 crates).
- [x] Detailed rule-by-rule breakdown of pre-screen triggers compiled and analyzed.
- [ ] Part A Qwen evaluation across all conditions (currently running `hybrid_taint` at 112/120 on Groq).
- [ ] Receive go-ahead for Part C Stage 2 LLM evaluation (494 crates).
- [ ] Generate `review/flagged_for_review_v35.csv` with human verdict column blank.
- [ ] Generate comprehensive `REPORT_V35.md` with exact McNemar tests and all protocol qualifications.
