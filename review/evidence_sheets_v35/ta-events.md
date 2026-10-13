# Evidence Sheet: `ta-events` (v0.17.11-alpha.7)

**Sample ID**: `prod_rand_0560`  
**Cohort**: `random_1000`  
**Triage Recommendation**: Pending Human Review  

---

## 1. Package Metadata & Registry Links
* **Crate Name**: `ta-events`
* **Version**: `0.17.11-alpha.7`
* **crates.io**: [https://crates.io/crates/ta-events/0.17.11-alpha.7](https://crates.io/crates/ta-events/0.17.11-alpha.7)
* **docs.rs**: [https://docs.rs/ta-events/0.17.11-alpha.7](https://docs.rs/ta-events/0.17.11-alpha.7)
* **Repository**: [https://github.com/trustedautonomy/ta](https://github.com/trustedautonomy/ta)
* **Downloads**: 426 total registry downloads (12 for this version)
* **Created Date**: 2026-04-16T07:22:34.501621Z
* **Last Updated**: 2026-09-10T15:37:55.618324Z
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
| `src\hooks.rs` | 17 | `source_scan.process_spawn` | `use std::process::Command;` |
| `src\hooks.rs` | 193 | `source_scan.process_spawn` | `match Command::new("sh").arg("-c").arg(cmd).envs(env).output() {` |
| `src\schema.rs` | 837 | `source_scan.sensitive_paths` | `resource_uri: "fs://workspace/secrets.env".into(),` |
| `src\store.rs` | 72 | `source_scan.fs_walk` | `let mut files: Vec<PathBuf> = fs::read_dir(&self.events_dir)?` |
| `src\tokens.rs` | 151 | `source_scan.fs_walk` | `for entry in fs::read_dir(&self.tokens_dir)? {` |
| `src\tokens.rs` | 175 | `source_scan.fs_walk` | `for entry in fs::read_dir(&self.tokens_dir)? {` |
| `src\tokens.rs` | 199 | `source_scan.fs_walk` | `for entry in fs::read_dir(&self.tokens_dir)? {` |

---

## 4. Declared Stated Purpose (Prompt Context)
* **Cargo.toml Description**:  
  > "Event system and subscription API for Trusted Autonomy"

* **README Excerpt (as fed to LLM contextual analyzer)**:
```markdown
No README file present in extracted archive.
```

---

## 5. Stage 2 Verbatim LLM Evaluation (`gemini-3.5-flash-lite`)
* **Stage 2 Verdict**: `SUSPICIOUS`
* **Malware Score**: `0.4`
* **Primary Signals Cited by Model**: `process_spawn, sensitive_paths`
* **Verbatim Reasoning**:
> The crate claims to be an event system and subscription API for Trusted Autonomy, but source code analysis reveals process spawning (`Command::new("sh").arg("-c").arg(cmd)`) and references to sensitive paths (`fs://workspace/secrets.env`). While these might be related to executing automation scripts or hooks in an autonomy platform, executing arbitrary shell commands combined with secret environment path references introduces a significant security risk that diverges slightly from standard event systems, warranting a suspicious classification.

---

## 6. Human Reviewer Verdict Block
* **Reviewer Decision**:
  - [ ] **TRUE POSITIVE (Malicious)**
  - [ ] **FALSE POSITIVE (Benign)**
  - [ ] **UNSURE / AMBIGUOUS**
* **Reviewer Notes & Justification**:
  ```text

  ```
