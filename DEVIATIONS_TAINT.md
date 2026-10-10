# CrateShield Benchmark v3 — Deviations: `hybrid_taint` Evaluation

**Date:** 2026-10-10  
**Benchmark Version:** v3.2  

---

## 1. Provider API Key Refresh for Gemini Confirmatory Run

- **Observation:** Initial attempts to invoke `gemini-3.5-flash-lite` with earlier keys returned HTTP 429 (`RESOURCE_EXHAUSTED: Quota exceeded for metric: generativelanguage.googleapis.com/generate_content_free_tier_requests, limit: 500, model: gemini-3.5-flash-lite`) due to project-level daily quota exhaustion.
- **Protocol Action:**
  - The user provided a fresh Gemini API key created under a new project (`AQ.Ab8RN6KWYk7rb3...`).
  - `load_dotenv(override=True)` was explicitly set in `run_eval.py`, `run_eval_taint.py`, and `src/crateshield/config.py` to ensure process environment precedence over stale OS variables.
  - The full 120-call confirmatory evaluation for `hybrid_taint` on `gemini-3.5-flash-lite` was successfully executed to 100% completion (120 calls, 508,372 tokens in, 33,851 tokens out, $0.048284 USD spend).

---

## 2. Dynamic Pacing and Free-Tier Token Window for Groq (`qwen/qwen3.8-27b`)

- **Observation:** Groq enforces strict free-tier rate limits: 8,000 input tokens/minute (ITPM) and a rolling window daily token cap. After 40 samples, Groq returns 429 backoff headers requiring 300s–1,400s pauses for bucket refill.
- **Protocol Action:**
  - Implemented dynamic token bucket tracking via `x-ratelimit-remaining-tokens` and `Retry-After` headers in `run_eval.py`.
  - The cross-model Groq evaluation completed 40/120 samples (13 malicious, 27 benign) with 0.0% strict / 46.2% relaxed recall on tested malicious samples and 0.0% FPR.
  - The remaining 80 samples are queued for paced background completion.

---

## 3. AST Exploration Determinism & Timestamp Normalization

- **Observation:** In initial testing, iterating over internal graph sets in `taint_engine.py` yielded variable traversal orders across runs, and `analysis_timestamp` inserted by `extract_all_signals` caused prompt hash divergence between successive evaluations.
- **Protocol Action:**
  - Explicitly sorted node lists, edges, and discovered paths in `taint_engine.py` to ensure mathematical determinism in AST path representation.
  - Omitted `analysis_timestamp` from `hybrid_taint` signals, ensuring that prompt hashes are strictly invariant and cache hits function correctly across multiple evaluations.
