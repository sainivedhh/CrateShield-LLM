# CrateShield Benchmark v3.3 — Tune-Split Pilot Evaluation Report

**Date:** 2026-10-11  
**Split:** TUNE Split Only ($N=30$: 10 Malicious, 10 Clean, 10 Lookalike-Benign)  
**Purpose:** Exploratory pilot to test Candidate A (contextual taint) and Candidate B (purpose consistency).  
**Note on Sample Size:** $n=10$ per class is descriptive/developmental. It does not support inferential statistical significance claims.

## 1. Comparative Metrics on Tune Split

| Condition | Strict Recall ($N=10$) | Relaxed Recall ($N=10$) | Clean FPR ($N=10$) | Lookalike FPR ($N=10$) | Mean Tokens In | Mean Tokens Out |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **raw (60k budget)** | 3/10 (**30%**) | 6/10 (60%) | 0/10 (0%) | 1/10 (10%) | 7813 | 181 |
| **hybrid_taint (baseline)** | 2/10 (**20%**) | 5/10 (50%) | 0/10 (0%) | 0/10 (0%) | 4714 | 296 |
| **Candidate A: hybrid_taint_contextual** | 2/10 (**20%**) | 5/10 (50%) | 0/10 (0%) | 0/10 (0%) | 4496 | 298 |
| **Candidate B: purpose_consistency** | 2/10 (**20%**) | 7/10 (70%) | 0/10 (0%) | 1/10 (10%) | 3626 | 196 |

## 2. Evasion Ladder Breakdown ($L0$–$L4$ Strict Recall on Tune Malicious)

| Condition | $L0$ (Plain) | $L1$ (Obfusc) | $L2$ (Split-Flow) | $L3$ (Hidden-API) | $L4$ (Dep-Borne) | Pooled $L2$–$L4$ |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **raw (60k budget)** | 2/2 | 0/2 | 0/2 | 1/2 | 0/2 | **1/6 (17%)** |
| **hybrid_taint (baseline)** | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | **0/6 (0%)** |
| **Candidate A: hybrid_taint_contextual** | 1/2 | 0/2 | 0/2 | 1/2 | 0/2 | **1/6 (17%)** |
| **Candidate B: purpose_consistency** | 1/2 | 1/2 | 0/2 | 0/2 | 0/2 | **0/6 (0%)** |

## 3. Mechanism Spot-Checks (Flipped Verdicts)

### Candidate A vs hybrid_taint (3 flipped verdict(s))

#### Sample s3_0002_malicious (L0): MALICIOUS -> SUSPICIOUS
- **hybrid_taint (score: 0.85):**
  > Purpose: The crate contains an inactive or hidden function `event_session_79` inside `build.rs` that reads a custom environment variable `CARGO_PKG_AUTH` and writes its contents to `target/.auth_cache`. Sources: `std::env::var("CARGO_PKG_AUTH")`. Sinks: `std::fs::write("target/.auth_cache", token)`. Flow: Environment variable containing sensitive authentication material is extracted at build time and persisted to disk within the build directory. Anomalies: Reading custom cargo/auth environment variables and writing them to disk during `build.rs` execution represents credential harvesting/exfiltration behavior characteristic of supply-chain attacks (referencing pattern-build-rs-exfiltration).
- **Candidate A (score: 0.35):**
  > Purpose: A tiny utility/synthetic crate with a build script. Sources: build.rs reads the environment variable `CARGO_PKG_AUTH`. Sinks: writes the read token into a file (`target/.auth_cache`). Flow: environment variable (`CARGO_PKG_AUTH`) -> local filesystem file (`target/.auth_cache`). Anomalies: `CARGO_PKG_AUTH` is not a standard Cargo-provided environment variable, and writing custom authentication tokens or credential data into the build target directory during `cargo build` is unusual behavior. However, there is no outbound network call or process execution present in this specific build script, making it less severe than active exfiltration malware. Therefore, it is classified as SUSPICIOUS due to non-standard credential/token handling in a build script.

#### Sample s3_0011_malicious (L3): BENIGN -> MALICIOUS
- **hybrid_taint (score: 0.05):**
  > Purpose: The crate uses a build script (`build.rs`) utilizing the `autocfg` crate to probe for `portable_simd` compiler feature support. Sources: None. Sinks: None. Flows: None. Anomalies: There is a dead, unused byte array (`MASK_LOGGER_ROUTINE_68`) and an unused decode function (`decode_logger_routine_68`) embedded inside `main()` in `build.rs`, which is slightly odd or looks like dead code snippet residue, but it is never called or executed. The actual build script logic is standard feature probing (`autocfg`). There are no network calls, no file writes, no sensitive environment variable reads, and no typosquatting signals. Therefore, the crate is classified as BENIGN.
- **Candidate A (score: 0.95):**
  > Purpose: The crate has a build.rs containing an obfuscated string decryption routine (XOR mask 0x5A applied to byte array `MASK_LOGGER_ROUTINE_68`). Sources: The build script embeds concealed static byte data. Sinks: The build script decodes this data inline during build-time execution. Flow: An obfuscated byte array is decoded at build time inside `build.rs` to reveal hidden instructions or URLs. Anomalies: There is no legitimate reason for a feature-probing build script to embed a custom XOR-decoded byte string (`MASK_LOGGER_ROUTINE_68`) alongside standard autocfg calls. This is a classic indicator of a hidden payload or C2 endpoint embedded in a build script to evade static pattern matching.

#### Sample s3_0023_malicious (L2): SUSPICIOUS -> BENIGN
- **hybrid_taint (score: 0.35):**
  > Purpose: A utility or library crate (approx 593 meaningful lines across 4 rust files). Sources: The build script reads the "CI" environment variable. Sinks/Flows: No network call or file exfiltration sink is present in the build script or detected via taint analysis. Anomalies: The build script contains strange, malformed inline trait definitions and struct declarations injected directly inside `main()` between `ac.probe_rustc_version` checks (lines 15-24: `pub trait DiagnosticProvider_event_pipe_46`, etc.). This dead/injected code reads `std::env::var("CI")` and looks syntactically out of place, resembling automated code injection artifacts or attempts to probe whether the build is running in a CI environment (similar to environment fingerprinting seen in supply chain attacks like CrateDepression). However, no actual exfiltration mechanism or malicious payload (network, command execution, file write) is present in this build script. Conclusion: Due to the weird code injection / artifact structure checking for CI in the build script, it is marked as SUSPICIOUS rather than BENIGN.
- **Candidate A (score: 0.05):**
  > Purpose: The crate uses autocfg in its build.rs to probe rustc versions and emit conditional compilation flags (tuple_ty, allow_clippy, maybe_uninit, etc.), which is standard and benign behaviour for feature detection. Sources: It checks std::env::var("CI").ok() inside an unused trait implementation snippet, but does not exfiltrate or execute anything malicious with it. Sinks: None. Flows: No connected data-flow path from source to sink. Anomalies: There is a weird injected trait/struct in the middle of build.rs (DiagnosticProvider_event_pipe_46 reading CI), but it is purely inert code (not even called) or a quirk of generation/analysis, lacking any network call, file write, or exfiltration sink. Typosquatting score is low and flagged=false. Conclusion: The crate is benign, following standard autocfg patterns with minor inert structure.


### Candidate B vs hybrid_taint (4 flipped verdict(s))

#### Sample s3_0002_malicious (L0): MALICIOUS -> SUSPICIOUS
- **hybrid_taint (score: 0.85):**
  > Purpose: The crate contains an inactive or hidden function `event_session_79` inside `build.rs` that reads a custom environment variable `CARGO_PKG_AUTH` and writes its contents to `target/.auth_cache`. Sources: `std::env::var("CARGO_PKG_AUTH")`. Sinks: `std::fs::write("target/.auth_cache", token)`. Flow: Environment variable containing sensitive authentication material is extracted at build time and persisted to disk within the build directory. Anomalies: Reading custom cargo/auth environment variables and writing them to disk during `build.rs` execution represents credential harvesting/exfiltration behavior characteristic of supply-chain attacks (referencing pattern-build-rs-exfiltration).
- **Candidate B (score: 0.60):**
  > The crate claims to be an inline const macro utility. However, its build script contains an unrelated hidden function ('event_session_79') that reads an environment variable ('CARGO_PKG_AUTH') and writes it to a file ('target/.auth_cache'). While no direct network exfiltration is observed in this specific snippet, reading a sensitive-sounding auth token during the build phase of a pure macro crate is suspicious and inconsistent with its stated purpose.

#### Sample s3_0011_malicious (L3): BENIGN -> SUSPICIOUS
- **hybrid_taint (score: 0.05):**
  > Purpose: The crate uses a build script (`build.rs`) utilizing the `autocfg` crate to probe for `portable_simd` compiler feature support. Sources: None. Sinks: None. Flows: None. Anomalies: There is a dead, unused byte array (`MASK_LOGGER_ROUTINE_68`) and an unused decode function (`decode_logger_routine_68`) embedded inside `main()` in `build.rs`, which is slightly odd or looks like dead code snippet residue, but it is never called or executed. The actual build script logic is standard feature probing (`autocfg`). There are no network calls, no file writes, no sensitive environment variable reads, and no typosquatting signals. Therefore, the crate is classified as BENIGN.
- **Candidate B (score: 0.65):**
  > The build script contains an unexplained obfuscated byte array (MASK_LOGGER_ROUTINE_68) and an XOR-based decoding routine that is completely disconnected from the legitimate feature-probing purpose of the build script (checking for portable_simd). This kind of hidden logic embedded within a build script is a strong indicator of suspicious or malicious payload concealment, inconsistent with a standard reflection/generic utility library.

#### Sample s3_0014_malicious (L4): BENIGN -> SUSPICIOUS
- **hybrid_taint (score: 0.05):**
  > Purpose: feature probing in a build script using autocfg. Sources: reads GITHUB_ACTIONS, GITLAB_CI, and CI_JOB_TOKEN. Sinks: none; the code containing these environment variable reads is embedded inside a test module (`#[cfg(test)] mod tests_collector_worker_70`) within a string literal used by `autocfg` to probe rustc features. Flow: the code is never executed during build time, as it is just text passed to autocfg's probe_raw to test feature support. Anomalies: none; although reading CI tokens can look suspicious, here it is part of a test snippet inside a feature probe code block, not actual exfiltration logic. Conclusion: benign usage of build script feature probing.
- **Candidate B (score: 0.65):**
  > The crate's declared purpose is to provide `std::io`-like traits for a `no_std` environment. However, its build script embeds test code via `autocfg` that checks for CI environments (`GITHUB_ACTIONS`, `GITLAB_CI`) and reads sensitive CI tokens (`CI_JOB_TOKEN`). This behavior is completely unrelated to probing compiler features for `no_std` I/O traits and closely matches patterns seen in supply-chain attacks that target CI/CD environments (such as CrateDepression). While explicit network exfiltration isn't directly chained in this specific snippet, reading sensitive tokens inside a build script's feature-probe string is highly suspicious and inconsistent with the crate's purpose.

#### Sample s3_0020_malicious (L1): SUSPICIOUS -> MALICIOUS
- **hybrid_taint (score: 0.35):**
  > Purpose: unknown library code with an autocfg-based build script. Sources: build.rs reads the sensitive environment variable `AWS_SECRET_ACCESS_KEY` and defines a variable pointing to a domain `metrics.service.example.org`. Sinks: although the isolated site reads the secret and defines the domain string, there is no active sink or network call shown in build.rs that actually transmits it (the strings are simply bound to local variables that are unused). Anomalies: reading cloud credential environment variables in a build script without an obvious reason to do so is a strong indicator of potential credential harvesting or exfiltration prep, even if the payload is currently dormant or stubbed out. Conclusion: because the secret is read and associated with a C2-like domain string in the build script, this warrants a SUSPICIOUS classification pending manual review.
- **Candidate B (score: 0.90):**
  > The crate's declared purpose is providing pointer union types using alignment bits, which is a purely internal data-structure implementation. However, the build script reads the sensitive 'AWS_SECRET_ACCESS_KEY' environment variable and contains a reference to a C2-like metrics domain ('metrics.service.example.org'). These actions are entirely inconsistent with the declared purpose and indicate credential access/exfiltration attempts.


## 4. L2 Split-Flow In-Depth Qualitative Spot-Check

### Sample `s3_0008_malicious` ($L2$ Split-Flow)
- **hybrid_taint (BENIGN):** Purpose: The crate uses autocfg in its build script to probe the rustc version for feature gating (emitting `rustc_1_98`). Sources: The isolated build script snippet checks `std::env::var("CI")`, which is a common benign check for Continuous Integration environments (similar to benign false positive...
- **Candidate A (BENIGN):** Purpose: A legitimate utility or library package with a standard Apache-2.0 / MIT license by known author Michael Büsch. Sources/Sinks: The build script uses the `autocfg` crate to check rustc versions for conditional compilation feature gating, and defines an unused/dead-code helper trait checking ...
- **Candidate B (BENIGN):** The crate's build script uses autocfg to check the rustc version for feature gating, and reads the standard 'CI' environment variable which is commonly used for conditional compilation or tests in CI pipelines. The code contains no malicious behaviors, network exfiltration, or unauthorized file acce...

### Sample `s3_0023_malicious` ($L2$ Split-Flow)
- **hybrid_taint (SUSPICIOUS):** Purpose: A utility or library crate (approx 593 meaningful lines across 4 rust files). Sources: The build script reads the "CI" environment variable. Sinks/Flows: No network call or file exfiltration sink is present in the build script or detected via taint analysis. Anomalies: The build script cont...
- **Candidate A (BENIGN):** Purpose: The crate uses autocfg in its build.rs to probe rustc versions and emit conditional compilation flags (tuple_ty, allow_clippy, maybe_uninit, etc.), which is standard and benign behaviour for feature detection. Sources: It checks std::env::var("CI").ok() inside an unused trait implementation...
- **Candidate B (SUSPICIOUS):** The build script for an `offset_of` library contains abruptly injected code (`DiagnosticProvider_event_pipe_46` trait and implementation) right inside the rustc version-probing logic. While reading the 'CI' environment variable is not inherently malicious, inserting unrelated diagnostic provider typ...
