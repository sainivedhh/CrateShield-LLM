# CrateShield Benchmark v3 — Deviations: `hybrid_taint` Evaluation

**Date:** 2026-10-10  
**Benchmark Version:** v3.2  

---

## 1. Provider API Quota Exhaustion for Gemini

- **Observation:** Attempts to invoke `gemini-3.5-flash-lite` with the provided API key returned HTTP 429 (`RESOURCE_EXHAUSTED: Quota exceeded for metric: generativelanguage.googleapis.com/generate_content_free_tier_requests, limit: 500, model: gemini-3.5-flash-lite, retryDelay: 21535s (~5.5 hours)`).
- **Cause:** The earlier full confirmatory runs on Benchmark v3 executed 1,905 calls, consuming the 500 requests/day free-tier allotment on Google AI Studio.
- **Protocol Action:**
  - In accordance with the prompt guidance (*"Then run on qwen/qwen3.8-27b with ITPM pacing — don't let it go pending-forever like last run; if it will take hours, say so upfront and run it to completion in the background rather than skipping it"*), the live evaluation is executed on `qwen/qwen3.8-27b` via Groq.
  - The dry-run estimate for `gemini-3.5-flash-lite` is recorded (120 calls, 431,415 input tokens, 24,000 output tokens, $0.0396 USD estimated cost).

---

## 2. Dynamic Pacing for Groq Rate Limits

- **Observation:** Groq enforces strict free-tier rate limits: 8,000 input tokens/minute (ITPM) and 30 requests/minute (RPM). Last run, rows 11–13 stalled due to unpaced burst submissions.
- **Protocol Action:**
  - Implemented dynamic token bucket tracking via `x-ratelimit-remaining-tokens` and `Retry-After` headers in `run_eval.py`.
  - When remaining tokens in the Groq bucket fall below 3,500, the runner pauses for token replenishment (130 tokens/second), preventing HTTP 429 errors and ensuring 100% completion without stalls.

---

## 3. AST Exploration Determinism & Timestamp Normalization

- **Observation:** In initial testing, iterating over internal graph sets in `taint_engine.py` yielded variable traversal orders across runs, and `analysis_timestamp` inserted by `extract_all_signals` caused prompt hash divergence between successive evaluations.
- **Protocol Action:**
  - Explicitly sorted node lists, edges, and discovered paths in `taint_engine.py` to ensure mathematical determinism in AST path representation.
  - Omitted `analysis_timestamp` from `hybrid_taint` signals, ensuring that prompt hashes are strictly invariant and cache hits function correctly across multiple evaluations.
