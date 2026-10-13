# Evidence Sheet: `loopflow` (v0.13.11)

**Sample ID**: `prod_rand_0948`  
**Cohort**: `random_1000`  
**Triage Recommendation**: Pending Human Review  

---

## 1. Package Metadata & Registry Links
* **Crate Name**: `loopflow`
* **Version**: `0.13.11`
* **crates.io**: [https://crates.io/crates/loopflow/0.13.11](https://crates.io/crates/loopflow/0.13.11)
* **docs.rs**: [https://docs.rs/loopflow/0.13.11](https://docs.rs/loopflow/0.13.11)
* **Repository**: [https://github.com/loopflowstudio/loopflow](https://github.com/loopflowstudio/loopflow)
* **Downloads**: 1,054 total registry downloads (9 for this version)
* **Created Date**: 2026-02-07T18:27:52.298378Z
* **Last Updated**: 2026-10-11T05:39:49.684807Z
* **Vulnerability DB Status (OSV / RustSec)**: None found in OSV/RustSec database

---

## 2. Severity & Priority Note (Task 2)
> [!WARNING]
> **Severity Warning**: This crate's flagged behavior, if malicious, would involve: file write / command execution / credential read.

---

## 3. Stage 1 Pre-Screen Capability Triggers
* **Fired Signal Categories**: `build_rs, prompt_injection, source_scan.network, source_scan.process_spawn, source_scan.sensitive_paths, source_scan.decode_payload, source_scan.fs_walk, source_scan.ip_literal_url`

### Exact Source Trigger Lines:
| File | Line | Trigger Rule / Pattern | Matched Source Snippet |
| :--- | :---: | :--- | :--- |
| `build.rs` | 14 | `build_rs (process_spawn)` | `use std::process::Command;` |
| `build.rs` | 46 | `build_rs (env_read)` | `PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));` |
| `build.rs` | 47 | `build_rs (env_read)` | `let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));` |
| `build.rs` | 81 | `build_rs (file_write)` | `fs::write(out_dir.join("canonical_schema.json"), json)` |
| `build.rs` | 94 | `build_rs (file_write)` | `fs::write(out_dir.join("draft_schema.json"), json).expect("write draft schema reference");` |
| `build.rs` | 112 | `build_rs (env_read)` | `env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION not set by Cargo");` |
| `build.rs` | 116 | `build_rs (env_read)` | `let provenance = env::var("LOOPFLOW_BUILD_PROVENANCE").unwrap_or_else(\|_\| {` |
| `build.rs` | 137 | `build_rs (env_read)` | `env::var("LOOPFLOW_MIGRATION_AUTHORITY").unwrap_or_else(\|_\| "validation_only".to_string());` |
| `build.rs` | 149 | `build_rs (process_spawn)` | `Command::new("git")` |
| `build.rs` | 161 | `build_rs (process_spawn)` | `Command::new("git")` |
| `build.rs` | 168 | `build_rs (env_read)` | `let release_candidate_tag = env::var("LOOPFLOW_RELEASE_TAG")` |
| `build.rs` | 185 | `build_rs (process_spawn)` | `Command::new("git")` |
| `build.rs` | 222 | `build_rs (process_spawn)` | `if let Ok(output) = Command::new("git")` |
| `build.rs` | 232 | `build_rs (process_spawn)` | `if let Ok(output) = Command::new("git")` |
| `build.rs` | 269 | `build_rs (file_write)` | `fs::write(out_dir.join("migration_draft_manifest.rs"), code)` |
| `build.rs` | 342 | `build_rs (file_write)` | `fs::write(&path, composed).unwrap_or_else(\|e\| panic!("write {}: {e}", path.display()));` |
| `build.rs` | 407 | `build_rs (file_write)` | `fs::write(out_path, code).unwrap_or_else(\|e\| panic!("write {}: {e}", out_path.display()));` |
| `build.rs` | 427 | `build_rs (file_write)` | `fs::write(out_path, code).unwrap_or_else(\|e\| panic!("write {}: {e}", out_path.display()));` |
| `src\provider_account.rs` | 2663 | `source_scan.network` | `let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();` |
| `src\subscription.rs` | 77 | `source_scan.network` | `let client = reqwest::Client::new();` |
| `src\subscription.rs` | 81 | `source_scan.network` | `if response.status() == reqwest::StatusCode::UNAUTHORIZED && !refreshed {` |
| `src\subscription.rs` | 112 | `source_scan.network` | `let client = reqwest::Client::new();` |
| `src\subscription.rs` | 121 | `source_scan.network` | `client: &reqwest::Client,` |
| `build.rs` | 14 | `source_scan.process_spawn` | `use std::process::Command;` |
| `build.rs` | 149 | `source_scan.process_spawn` | `Command::new("git")` |
| `build.rs` | 161 | `source_scan.process_spawn` | `Command::new("git")` |
| `build.rs` | 185 | `source_scan.process_spawn` | `Command::new("git")` |
| `build.rs` | 222 | `source_scan.process_spawn` | `if let Ok(output) = Command::new("git")` |
| `src\installation.rs` | 787 | `source_scan.sensitive_paths` | `.env("LF_HOME", &main_home)` |
| `src\installation.rs` | 788 | `source_scan.sensitive_paths` | `.env("LF_BIN", &destination);` |
| `src\os_process.rs` | 655 | `source_scan.sensitive_paths` | `.env("LF_RUN_ID", "run_dead")` |
| `src\os_process.rs` | 656 | `source_scan.sensitive_paths` | `.env("LF_RUN_DIR", "/dead/run")` |
| `src\os_process.rs` | 657 | `source_scan.sensitive_paths` | `.env("LF_FLOW_ID", "stale-flow")` |
| `src\provider_account.rs` | 1815 | `source_scan.decode_payload` | `use base64::prelude::*;` |
| `src\provider_account.rs` | 3023 | `source_scan.decode_payload` | `use base64::prelude::*;` |
| `tests\agent_tests.rs` | 3 | `source_scan.decode_payload` | `use base64::prelude::*;` |
| `tests\auth_tests.rs` | 5 | `source_scan.decode_payload` | `use base64::prelude::*;` |
| `tests\flow_tests.rs` | 2434 | `source_scan.decode_payload` | `use base64::prelude::*;` |
| `build.rs` | 58 | `source_scan.fs_walk` | `for entry in walkdir(&builtins_dir) {` |
| `build.rs` | 277 | `source_scan.fs_walk` | `if let Ok(cats) = fs::read_dir(builtins_dir) {` |
| `build.rs` | 440 | `source_scan.fs_walk` | `let Ok(read_dir) = fs::read_dir(dir) else {` |
| `build.rs` | 443 | `source_scan.fs_walk` | `for entry in read_dir {` |
| `build.rs` | 473 | `source_scan.fs_walk` | `fn walkdir(dir: &Path) -> Vec<PathBuf> {` |
| `src\subscription.rs` | 127 | `source_scan.ip_literal_url` | `.unwrap_or_else(\|_\| "http://127.0.0.1:1/profile".into());` |
| `src\subscription.rs` | 281 | `source_scan.ip_literal_url` | `{ std::env::var("LF_TEST_CLAUDE_TOKEN_URL").unwrap_or_else(\|_\| "http://127.0.0.1:1/token".into()) }` |
| `tests\task_flow_launch_tests.rs` | 23 | `source_scan.ip_literal_url` | `.env("HTTPS_PROXY", "http://127.0.0.1:1")` |
| `tests\task_flow_launch_tests.rs` | 24 | `source_scan.ip_literal_url` | `.env("HTTP_PROXY", "http://127.0.0.1:1");` |
| `src\harness\opencode.rs` | 110 | `source_scan.ip_literal_url` | `let base_url = format!("http://127.0.0.1:{port}");` |

---

## 4. Declared Stated Purpose (Prompt Context)
* **Cargo.toml Description**:  
  > "Run steps and flows with coding agents"

* **README Excerpt (as fed to LLM contextual analyzer)**:
```markdown
No README file present in extracted archive.
```

---

## 5. Stage 2 Verbatim LLM Evaluation (`gemini-3.5-flash-lite`)
* **Stage 2 Verdict**: `SUSPICIOUS`
* **Malware Score**: `0.0`
* **Primary Signals Cited by Model**: `oversized_codebase, exceeds_context`
* **Verbatim Reasoning**:
> Oversized crate (5,124,133 characters, ~1.28M tokens) exceeds model context / per-request token limit. Routed to manual review.

---

## 6. Human Reviewer Verdict Block
* **Reviewer Decision**:
  - [ ] **TRUE POSITIVE (Malicious)**
  - [ ] **FALSE POSITIVE (Benign)**
  - [ ] **UNSURE / AMBIGUOUS**
* **Reviewer Notes & Justification**:
  ```text

  ```
