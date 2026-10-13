# Evidence Sheet: `hawdb-search` (v0.7.0)

**Sample ID**: `prod_rand_0994`  
**Cohort**: `random_1000`  
**Triage Recommendation**: Pending Human Review  

---

## 1. Package Metadata & Registry Links
* **Crate Name**: `hawdb-search`
* **Version**: `0.7.0`
* **crates.io**: [https://crates.io/crates/hawdb-search/0.7.0](https://crates.io/crates/hawdb-search/0.7.0)
* **docs.rs**: [https://docs.rs/hawdb-search/0.7.0](https://docs.rs/hawdb-search/0.7.0)
* **Repository**: [https://github.com/nowledge-co/hawdb](https://github.com/nowledge-co/hawdb)
* **Downloads**: 128 total registry downloads (18 for this version)
* **Created Date**: 2026-09-22T07:18:54.936221Z
* **Last Updated**: 2026-10-11T05:31:53.740304Z
* **Vulnerability DB Status (OSV / RustSec)**: None found in OSV/RustSec database

---

## 2. Severity & Priority Note (Task 2)
> [!WARNING]
> **Severity Warning**: This crate's flagged behavior, if malicious, would involve: command execution / credential read.

---

## 3. Stage 1 Pre-Screen Capability Triggers
* **Fired Signal Categories**: `source_scan.process_spawn, source_scan.sensitive_paths, source_scan.fs_walk`

### Exact Source Trigger Lines:
| File | Line | Trigger Rule / Pattern | Matched Source Snippet |
| :--- | :---: | :--- | :--- |
| `src\out_of_core\generation_writer\spool\stage.rs` | 627 | `source_scan.process_spawn` | `let output = std::process::Command::new(std::env::current_exe().unwrap())` |
| `src\out_of_core\generation_writer\spool\stage_tests.rs` | 39 | `source_scan.process_spawn` | `let output = std::process::Command::new(std::env::current_exe().unwrap())` |
| `src\out_of_core\generation_writer\spool\stage_tests.rs` | 156 | `source_scan.process_spawn` | `let output = std::process::Command::new(std::env::current_exe().unwrap())` |
| `src\out_of_core\generation_writer\spool\stage_tests.rs` | 277 | `source_scan.process_spawn` | `let output = std::process::Command::new(std::env::current_exe().unwrap())` |
| `src\out_of_core\generation_writer\spool\stage_tests.rs` | 814 | `source_scan.process_spawn` | `let output = std::process::Command::new(std::env::current_exe().unwrap())` |
| `src\out_of_core\generation_writer\spool\stage.rs` | 638 | `source_scan.sensitive_paths` | `.env(CHILD, "1")` |
| `src\out_of_core\generation_writer\spool\stage_tests.rs` | 50 | `source_scan.sensitive_paths` | `.env(CHILD, "1")` |
| `src\out_of_core\generation_writer\spool\stage_tests.rs` | 167 | `source_scan.sensitive_paths` | `.env(CHILD, "1")` |
| `src\out_of_core\generation_writer\spool\stage_tests.rs` | 288 | `source_scan.sensitive_paths` | `.env(CHILD, "1")` |
| `src\out_of_core\generation_writer\spool\stage_tests.rs` | 825 | `source_scan.sensitive_paths` | `.env(CHILD, "1")` |
| `src\generation_cleanup.rs` | 208 | `source_scan.fs_walk` | `match fs::read_dir(root) {` |
| `src\lib.rs` | 4218 | `source_scan.fs_walk` | `let entries = match fs::read_dir(path) {` |
| `src\lib.rs` | 10775 | `source_scan.fs_walk` | `assert!(!std::fs::read_dir(&path).unwrap().flatten().any(\|entry\| {` |
| `src\lib.rs` | 10821 | `source_scan.fs_walk` | `assert!(!std::fs::read_dir(&path).unwrap().flatten().any(\|entry\| {` |
| `src\lib.rs` | 12530 | `source_scan.fs_walk` | `assert!(std::fs::read_dir(&path).unwrap().any(\|entry\| {` |

---

## 4. Declared Stated Purpose (Prompt Context)
* **Cargo.toml Description**:  
  > "An embedded Rust graph database for local data-plane workloads"

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
> Oversized crate (1,661,494 characters, ~415k tokens) exceeds model context / per-request token limit. Routed to manual review.

---

## 6. Human Reviewer Verdict Block
* **Reviewer Decision**:
  - [ ] **TRUE POSITIVE (Malicious)**
  - [ ] **FALSE POSITIVE (Benign)**
  - [ ] **UNSURE / AMBIGUOUS**
* **Reviewer Notes & Justification**:
  ```text

  ```
