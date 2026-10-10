# CrateShield Benchmark v3: Preregistration Protocol

**Date:** 2026-10-10  
**Version:** 3.0  
**Status:** PREREGISTERED  
**Git Tag:** `prereg-v3`  

---

## 1. Executive Summary & Purpose

Benchmark v3 is designed as a hardened, leak-controlled, non-saturated synthetic evaluation benchmark for Rust crate security triage. Because real malicious crates cannot be ethically or safely fetched without risk of execution or live C2 infrastructure, synthetic benchmarks must meet rigorous methodological standards:
1. **Independence Firewall:** Generators have zero access to detector rules, prompts, regexes, or historical templates.
2. **Non-Saturation:** Difficulty ladder (L0 to L4) ensuring realistic evasion and preventing ceiling effects.
3. **Hard-Negative Evaluation:** Clean lookalike twins testing false-positive susceptibility.
4. **Multi-Model Evaluation:** Cross-model evaluation across independent model families (Google Gemini & Groq Qwen).
5. **Inertness:** All hostnames use IANA-reserved domains (`example.com`, `example.org`, `example.net`) or RFC 2606 reserved TLDs (`.invalid`, `.test`). No live exploit payloads or credentials.

---

## 2. Benchmark Corpus Design

### 2.1 Splits & Cluster Allocation
The dataset is structured as **50 base crate clusters** $\times$ **3 twins per cluster** = **150 samples**:
- **Tune Split:** 10 clusters (30 samples: 10 clean, 10 malicious, 10 lookalike benign). Used strictly for prompt validation and detector tuning.
- **Eval Split:** 40 clusters (120 samples: 40 clean, 40 malicious, 40 lookalike benign). Sealed prior to confirmatory evaluation.

### 2.2 Attack Taxonomy & Families
The corpus spans 8 malicious families:
- **SEEN Families (5):**
  - `F1`: Network Exfiltration (subdomain DNS / HTTP POST)
  - `F2`: Credential / Token Harvesting (cargo config, SSH keys, env vars)
  - `F3`: Process Spawning & Shellcode Injection (sh, powershell, curl)
  - `F4`: Malicious Build Script (`build.rs` compile-time compromise)
  - `F7`: Cargo Dependency Confusion / Hijacking (`[dependencies]` substitution)
- **HELD-OUT Families (3):**
  - `F5`: Persistence & Crontab Modification
  - `F6`: Cryptomining / Resource Abuse (background threads)
  - `F8`: Unsafe Memory / FFI Exploit (arbitrary memory overwrite)

### 2.3 Obfuscation Difficulty Ladder
- `L0`: Plaintext (obvious API calls, standard rust strings).
- `L1`: Light obfuscation (environment variable indirection, hex strings).
- `L2`: Moderate obfuscation (byte slicing, `include_bytes!`, string concatenation).
- `L3`: Advanced evasion (conditional compilation, dynamic symbol resolution, multi-stage decoding).
- `L4`: Idiomatic stealth (camouflaged inside legitimate crate logic, lookalike naming, deferred execution).

### 2.4 Crossed Factorial Design
- **Carrier:** `build.rs` vs `src/lib.rs` / `src/main.rs`.
- **Position:** `start`, `middle`, `end` of file.
- **Host Style:** `example-subdomain` vs `reserved-invalid-or-test`.
- **Generators:** Generator A (`gemini-3.5-flash-lite`) vs Generator B (`qwen/qwen3.8-27b` on Groq).

---

## 3. Preregistered Hypotheses (H1 – H8)

### 3.1 Primary Confirmatory Hypotheses
Hypotheses H1 through H6 constitute the primary confirmatory set. Statistical significance is evaluated at $\alpha = 0.05$ (two-sided), controlled for family-wise error rate via the **Holm-Bonferroni step-down procedure** across the 6 tests.

* **H1: Non-Saturation on Eval Split (Primary)**
  * *Formula:* $\text{Recall}_{\text{strict}}(\text{hybrid}) < 0.90$.
  * *Decision Rule:* The top detector condition (`hybrid`) must NOT achieve ceiling recall ($\ge 0.90$) over the 40 malicious samples in the eval split, verifying benchmark difficulty.
  * *Test:* One-sided binomial test against $p_0 = 0.90$.

* **H2: Fair Baseline Superiority (Primary)**
  * *Formula:* $\text{Recall}_{\text{strict}}(\text{hybrid}) - \max(\text{Recall}_{\text{strict}}(\text{baselines})) \ge 0.10$.
  * *Decision Rule:* Hybrid detection must significantly outperform the strongest heuristic/static baseline (`rule_only`, `grep`, `size`) by at least 10 percentage points.
  * *Test:* Paired McNemar's test with continuity correction.

* **H3: Hard-Negative False-Positive Rate Control (Primary)**
  * *Formula:* $\text{FPR}_{\text{strict}}(\text{lookalike\_benign}, \text{hybrid}) \le 0.15$.
  * *Decision Rule:* The false-positive rate on lookalike benign twins under strict threshold must not exceed 15%.
  * *Test:* Binomial exact test against $p_0 = 0.15$.

* **H4: Token & Cost Efficiency (Primary)**
  * *Formula:* $\text{Tokens}_{\text{in}}(\text{hybrid}) \le 0.50 \times \text{Tokens}_{\text{in}}(\text{raw\_full})$.
  * *Decision Rule:* The hybrid prompt extraction mechanism must reduce prompt token consumption by at least 50% relative to unwindowed raw source representation.
  * *Test:* Paired two-sample t-test / Wilcoxon signed-rank test on token counts per sample.

* **H5: Generalization to Held-Out Families (Primary)**
  * *Formula:* $|\text{Recall}(\text{held-out}) - \text{Recall}(\text{seen})| \le 0.15$.
  * *Decision Rule:* Performance on held-out families (`F5`, `F6`, `F8`) must be statistically equivalent to seen families (`F1-F4`, `F7`) within an equivalence margin $\Delta = \pm 0.15$.
  * *Test:* Two One-Sided Tests (TOST) of proportions at $\alpha = 0.05$.

* **H6: Model Transfer Robustness (Primary)**
  * *Formula:* $\text{Rank}(\text{hybrid}) > \text{Rank}(\text{structured}) > \text{Rank}(\text{raw})$ holds across both Primary (`gemini-3.5-flash-lite`) and Secondary (`qwen/qwen3.8-27b`) models without rank inversion.
  * *Decision Rule:* Condition rankings remain monotonic across distinct model architectures.

### 3.2 Secondary Exploratory Hypotheses
* **H7: Run-to-Run Determinism (Exploratory)**
  * *Formula:* Standard deviation of F1 across 3 repeated evaluations at temperature $T=0.0$ on the 20% repeat split is $\sigma_{F1} \le 0.05$.
* **H8: Sampling Variance (Exploratory)**
  * *Formula:* Standard deviation of F1 across 3 repeated evaluations at temperature $T=0.7$ on the 20% repeat split is $\sigma_{F1} \le 0.10$.

---

## 4. Statistical Power Sizing & Sample Size Justification

From `scripts/v3/power.py`:
- At $N=40$ eval pairs with expected discordance rate $p_D = 0.20$, power to detect $|\delta| = 0.15$ is 56.8% at uncorrected $\alpha = 0.05$, and 77.2% to detect $|\delta| = 0.20$.
- TOST equivalence power for margin $\Delta = \pm 0.15$ at $N=40$ is 62.4%.
- To balance statistical power with strict API call caps (`CRATESHIELD_MAX_LLM_CALLS = 5000`, `CRATESHIELD_MAX_LLM_USD = 60.0`), $N=40$ eval clusters (120 eval samples) provides the maximum achievable statistical power within resource constraints.

---

## 5. Audit Gates & Quality Controls

Prior to unsealing and evaluating the corpus, all 150 samples must pass 5 mechanical audit gates (`scripts/v3/audit_gates.py`):
1. **Gate G1 (Tell Check):** No forbidden tell strings (`CRATESHIELD`, `PAYLOAD`, `EXFIL`, `MALICIOUS`, `HACK`, `BACKDOOR`, `C2`).
2. **Gate G2 (Line Endings):** 100% consistent LF (`\n`) line endings across all `.rs` and `.toml` files.
3. **Gate G3 (AST Validity):** Every modified carrier file must successfully parse into an abstract syntax tree without syntax corruption.
4. **Gate G4 (Inert Infrastructure):** All domain names must match `*.example.com`, `*.example.net`, `*.example.org`, `*.invalid`, or `*.test`.
5. **Gate G5 (Discriminator Check):** No binary difference flags, zero size anomalies exceeding base size thresholds.

---

## 6. Realism Review Kit Protocol

To ensure synthetic plausibility without researcher bias:
- 60 randomized hunks (20 malicious, 20 lookalike benign, 20 clean) are exported to `review/realism_kit_v3.csv` by `scripts/v3/make_realism_kit.py`.
- Evaluators score hunks blindly on a 1–5 realism scale.
- All scores are initialized as empty/pending; no scores are fabricated or simulated.

---

## 7. Version Control & Freeze Protocol

The experimental pipeline follows this immutable commit and tag sequence:
1. `v2.3-consistency`: Phase 0 consistency fixes.
2. `prereg-v3`: Preregistration protocol and taxonomy committed.
3. `freeze-v3`: Synthetic corpus generation completed, audit gates passed, prompts and baselines frozen.
4. `v3-benchmark`: Confirmatory evaluation completed, reports generated from cached results, final verification passed.