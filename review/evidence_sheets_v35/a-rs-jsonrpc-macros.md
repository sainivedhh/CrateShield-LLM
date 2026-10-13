# Evidence Sheet: `a-rs-jsonrpc-macros` (v0.1.0)

**Sample ID**: `prod_rand_0401`  
**Cohort**: `random_1000`  
**Triage Recommendation**: Pending Human Review  

---

## 1. Package Metadata & Registry Links
* **Crate Name**: `a-rs-jsonrpc-macros`
* **Version**: `0.1.0`
* **crates.io**: [https://crates.io/crates/a-rs-jsonrpc-macros/0.1.0](https://crates.io/crates/a-rs-jsonrpc-macros/0.1.0)
* **docs.rs**: [https://docs.rs/a-rs-jsonrpc-macros/0.1.0](https://docs.rs/a-rs-jsonrpc-macros/0.1.0)
* **Repository**: [https://github.com/wangyingsm/a-rs-jsonrpc](https://github.com/wangyingsm/a-rs-jsonrpc)
* **Downloads**: 284 total registry downloads (284 for this version)
* **Created Date**: 2026-01-16T15:47:01.249781Z
* **Last Updated**: 2026-01-16T15:47:01.249781Z
* **Vulnerability DB Status (OSV / RustSec)**: None found in OSV/RustSec database

---

## 2. Severity & Priority Note (Task 2)
> *Standard Priority*: No high-severity execution/credential vectors detected.

---

## 3. Stage 1 Pre-Screen Capability Triggers
* **Fired Signal Categories**: `proc_macro, source_scan.network`

### Exact Source Trigger Lines:
| File | Line | Trigger Rule / Pattern | Matched Source Snippet |
| :--- | :---: | :--- | :--- |
| `src\lib.rs` | 149 | `proc_macro (suspicious_import: reqwest)` | `let resp = reqwest::Client::new()` |
| `src\lib.rs` | 175 | `proc_macro (suspicious_import: reqwest)` | `let resp = reqwest::Client::new()` |
| `src\lib.rs` | 198 | `proc_macro (suspicious_import: reqwest)` | `let resp = reqwest::Client::new().post(url).header("Content-Type", content_type).json(&body).send().await?;` |
| `src\lib.rs` | 216 | `proc_macro (suspicious_import: reqwest)` | `let resp = reqwest::Client::new().post(url).header("Content-Type", content_type).json(&body).send().await?;` |
| `src\lib.rs` | 396 | `proc_macro (suspicious_import: reqwest)` | `let resp = ::reqwest::Client::new().post(#url).header("Content-Type", #content_type).json(&body).send().await?;` |
| `src\lib.rs` | 149 | `source_scan.network` | `let resp = reqwest::Client::new()` |
| `src\lib.rs` | 175 | `source_scan.network` | `let resp = reqwest::Client::new()` |
| `src\lib.rs` | 198 | `source_scan.network` | `let resp = reqwest::Client::new().post(url).header("Content-Type", content_type).json(&body).send().await?;` |
| `src\lib.rs` | 216 | `source_scan.network` | `let resp = reqwest::Client::new().post(url).header("Content-Type", content_type).json(&body).send().await?;` |
| `src\lib.rs` | 396 | `source_scan.network` | `let resp = ::reqwest::Client::new().post(#url).header("Content-Type", #content_type).json(&body).send().await?;` |

---

## 4. Declared Stated Purpose (Prompt Context)
* **Cargo.toml Description**:  
  > "A battery-included JSON-RPC framework for Rust"

* **README Excerpt (as fed to LLM contextual analyzer)**:
```markdown
No README file present in extracted archive.
```

---

## 5. Stage 2 Verbatim LLM Evaluation (`gemini-3.5-flash-lite`)
* **Stage 2 Verdict**: `SUSPICIOUS`
* **Malware Score**: `0.4`
* **Primary Signals Cited by Model**: `proc_macro_network_calls, unexpected_dependency_in_macro`
* **Verbatim Reasoning**:
> The crate is declared as a JSON-RPC framework implemented as a proc-macro, but it imports 'reqwest' and performs network requests directly inside the macro logic (`src/lib.rs`). While a JSON-RPC framework might theoretically need network capabilities if it's a client library, performing HTTP requests directly within a procedural macro expansion context is unusual, highly risky, and deviates from standard macro design patterns (which typically generate code rather than executing network IO during compilation/expansion).

---

## 6. Human Reviewer Verdict Block
* **Reviewer Decision**:
  - [ ] **TRUE POSITIVE (Malicious)**
  - [ ] **FALSE POSITIVE (Benign)**
  - [ ] **UNSURE / AMBIGUOUS**
* **Reviewer Notes & Justification**:
  ```text

  ```
