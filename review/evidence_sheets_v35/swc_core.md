# Evidence Sheet: `swc_core` (v82.0.2)

**Sample ID**: `prod_rand_0879`  
**Cohort**: `random_1000`  
**Triage Recommendation**: Pending Human Review  

---

## 1. Package Metadata & Registry Links
* **Crate Name**: `swc_core`
* **Version**: `82.0.2`
* **crates.io**: [https://crates.io/crates/swc_core/82.0.2](https://crates.io/crates/swc_core/82.0.2)
* **docs.rs**: [https://docs.rs/swc_core/82.0.2](https://docs.rs/swc_core/82.0.2)
* **Repository**: [https://github.com/swc-project/swc.git](https://github.com/swc-project/swc.git)
* **Downloads**: 6,701,505 total registry downloads (18 for this version)
* **Created Date**: 2022-08-02T07:28:37.591869Z
* **Last Updated**: 2026-10-11T04:45:46.313490Z
* **Vulnerability DB Status (OSV / RustSec)**: None found in OSV/RustSec database

---

## 2. Severity & Priority Note (Task 2)
> [!WARNING]
> **Severity Warning**: This crate's flagged behavior, if malicious, would involve: file write / command execution.

---

## 3. Stage 1 Pre-Screen Capability Triggers
* **Fired Signal Categories**: `build_rs, source_scan.process_spawn`

### Exact Source Trigger Lines:
| File | Line | Trigger Rule / Pattern | Matched Source Snippet |
| :--- | :---: | :--- | :--- |
| `build.rs` | 19 | `build_rs (env_read)` | `let pkg_version = env::var("CARGO_PKG_VERSION").unwrap();` |
| `build.rs` | 20 | `build_rs (env_read)` | `let out_dir = env::var("OUT_DIR").expect("Outdir should exist");` |
| `build.rs` | 23 | `build_rs (file_write)` | `fs::write(out_dir.join("core_pkg_version.txt"), pkg_version)` |
| `build.rs` | 25 | `build_rs (file_write)` | `fs::write(out_dir.join("cargo_features.txt"), cargo_features())` |
| `tests\integration.rs` | 15 | `source_scan.process_spawn` | `let mut cmd = Command::new("cargo");` |

---

## 4. Declared Stated Purpose (Prompt Context)
* **Cargo.toml Description**:  
  > "TBD"

* **README Excerpt (as fed to LLM contextual analyzer)**:
```markdown
# swc_core

## Selecting version

If you are writing a Wasm plugin for SWC or next.js, please refer to [the documentation](https://swc.rs/docs/plugin/selecting-swc-core).
```

---

## 5. Stage 2 Verbatim LLM Evaluation (`gemini-3.5-flash-lite`)
* **Stage 2 Verdict**: `SUSPICIOUS`
* **Malware Score**: `0.0`
* **Primary Signals Cited by Model**: `None`
* **Verbatim Reasoning**:
> LLM response was not valid JSON and could not be parsed.

---

## 6. Human Reviewer Verdict Block
* **Reviewer Decision**:
  - [ ] **TRUE POSITIVE (Malicious)**
  - [ ] **FALSE POSITIVE (Benign)**
  - [ ] **UNSURE / AMBIGUOUS**
* **Reviewer Notes & Justification**:
  ```text

  ```
