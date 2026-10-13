# CrateShield v2 Technical Revisit & Consistency Report

## 1. Rule-Only Baseline Key Mismatch (`signals["injection"]` vs `signals["prompt_injection"]`)
- **Issue**: In `harness/baselines.py`, Rule 4 of `run_rule_only_baseline` evaluated `signals.get("injection", {}).get("detected")`, whereas the AST signal extractor (`src/crateshield/signals/extractor.py`) emitted `"prompt_injection"`.
- **Offline Recomputation**: Re-evaluating `rule_only` across all 80 benchmark v2 samples before and after fixing the key:
  - Total samples changed: **2 samples in the eval split**:
    - `s_0028_malicious` (split: eval, label: MALICIOUS, category: C8): was incorrectly classified as `BENIGN`, now correctly classified as `MALICIOUS`.
    - `s_0076_malicious` (split: eval, label: MALICIOUS, category: C8): was incorrectly classified as `BENIGN`, now correctly classified as `MALICIOUS`.
  - Impact: Recall for `rule_only` on eval split increases by +2/30 (+0.067, from 20/30 to 22/30). Clean samples and other categories are unaffected (FPR remains 0.00).
  - Frozen results: The published `data/bench_v2/eval_cache.json` and `data/bench_v2/results_summary.json` remain untouched per Hard Rule 2.

## 2. Score Bands Unification
- **Issue**: The prompt template in `src/crateshield/llm/prompt.py` instructed:
  `malware_score = 0-0.25 low, 0.25-0.5 possibly malicious, 0.5-0.75 likely malicious, 0.75-1 high probability. The label must agree with malware_score: BENIGN below 0.25, SUSPICIOUS from 0.25 to below 0.75, MALICIOUS at 0.5 or above.`
  This contained an overlapping boundary between 0.50 and 0.75 where both `SUSPICIOUS` and `MALICIOUS` were mentioned. Meanwhile, `parser.py` used `SUSPICIOUS_SCORE_FLOOR = 0.25` and `MALWARE_SCORE_THRESHOLD = 0.50`, with a confidence cut at 0.40.
- **Unification**: Introduced `src/crateshield/constants.py` as the single source of truth across both prompt text generation and parser logic:
  - `BENIGN`: `malware_score < 0.25` (Action: `Pass`)
  - `SUSPICIOUS`: `0.25 <= malware_score < 0.50` (Action: `Manual review`)
  - `MALICIOUS`: `malware_score >= 0.50` (Action: `Block`)
- **Offline Relabeling Impact**: Relabeling every cached v2 entry (425 LLM entries total):
  - Exactly **5 entries** would have their label change from `SUSPICIOUS` to `MALICIOUS` because their cached `malware_score` is in `[0.50, 0.75)`:
    1. `s_0036_malicious::structured_norag`: score 0.60
    2. `s_0052_malicious::structured_norag`: score 0.55
    3. `tier2_amzn-codewhisperer-streaming-client_99.0.1::structured_norag`: score 0.55
    4. `tier2_amzn-consolas-client_99.0.1::raw`: score 0.60
    5. `tier2_xrvrv_0.1.0::raw`: score 0.60
  - In strict evaluation mode (where only `MALICIOUS` is positive), these 5 entries were previously counted as false negatives due to the prompt ambiguity; under the unified bands, they align directly with their malware score.

## 3. Cluster Bootstrap Sensitivity: B=1000 vs B=2000
- **Issue**: The v2 preregistration mentioned B=1000 bootstrap iterations, while `scripts/make_report.py` used B=2000.
- **Recomputation**: Clustered bootstrap intervals by base crate on the sealed eval split (n=60, 30 pairs) at both B=1000 and B=2000:
  - `hybrid`:
    - B=1000: Recall CI [0.833, 1.000], FPR CI [0.000, 0.000], F1 CI [0.909, 1.000]
    - B=2000: Recall CI [0.833, 1.000], FPR CI [0.000, 0.000], F1 CI [0.909, 1.000] (Difference: 0.000)
  - `raw`:
    - B=1000: Recall CI [0.600, 0.900], FPR CI [0.000, 0.000], F1 CI [0.750, 0.947]
    - B=2000: Recall CI [0.600, 0.900], FPR CI [0.000, 0.000], F1 CI [0.750, 0.947] (Difference: 0.000)
  - `grep`:
    - B=1000: Recall CI [0.733, 0.967], FPR CI [0.000, 0.100], F1 CI [0.828, 0.983]
    - B=2000: Recall CI [0.733, 0.967], FPR CI [0.000, 0.100], F1 CI [0.830, 0.983] (Difference: 0.002)
  - `structured`:
    - B=1000: Recall CI [0.567, 0.900], FPR CI [0.000, 0.000], F1 CI [0.723, 0.947]
    - B=2000: Recall CI [0.567, 0.900], FPR CI [0.000, 0.000], F1 CI [0.723, 0.947] (Difference: 0.000)
  - Conclusion: The bootstrap intervals are completely insensitive to B=1000 vs B=2000.

## 4. Placement Routing Code vs Documentation (P1–P5)
- **Routing Reality in `harness/inject_v2.py`**:
  - `P1`: Injected into `build.rs` (main function or helper).
  - `P2`: Injected into primary library root (`src/lib.rs`).
  - `P3`: Injected into a secondary module across `src/**/*.rs` (other than `lib.rs`) when present; falls back to `src/lib.rs` if single-file.
  - `P4`: Injected into `src/lib.rs` (intended for proc-macro crate or library expansion).
  - `P5`: Injected into `build.rs` (fallback for helper modules imported by `build.rs`).
- Documentation updated to strictly reflect this actual routing mechanism. A unit test validates that documentation strings and routing logic agree.

## 5. Architectural Clarifications
- **Hybrid Source Windows**: Extracted via regex heuristics over source code files and `build.rs` (identifying entry points, process spawning, network calls, and sensitive paths) rather than a complete syntax tree.
- **Anonymizer Features**: The anonymizer (`harness/view.py`) derives view IDs and scrubs author/version tokens, and `harness/audit_v2.py` computes name/version features to verify invariance. However, these anonymized features are not consumed by the frozen static extractor, which inspects the un-anonymized crate text.
