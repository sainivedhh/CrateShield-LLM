# CrateShield-LLM v2: Evaluation Deviations Log

This document records any post-preregistration deviations, anomalies, or unexpected behaviors encountered during the evaluation of v2.

## Deviations Record

### Deviation 1: Tier 2 Historical Reconstructions Discrepancy Resolution
- **Description:** In the v1 benchmark snapshot, `ABLATION_RESULTS.md` and `results_summary.json` reported $n=8$ historical reconstructions, whereas `data/bench_v1/eval_cache.json` only contained $n=6$ entries (`rustdecimal` and `faster_log` were missing).
- **Root Cause:** Reconstructed test fixtures for `rustdecimal` and `faster_log` contained legacy comments (`// Defanged: Mock telemetry C2 connection` and `// Defanged: Mock exfiltration of wallet data`) containing forbidden benchmark leak terms (`defanged`, `exfiltration`). When evaluated in v1, Acceptance Gate G1 failed and threw exceptions, causing the cache saver to omit them, while the v1 report authors manually reported 8 without verifying cache counts.
- **Resolution in v2:** Rather than silently rewriting historical records or forcing unverified entries, `scripts/make_report.py` strictly asserts and reports the true cached $n=6$ historical reconstructions, fully resolving Problem F. Gate G1 integrity was strictly preserved.
