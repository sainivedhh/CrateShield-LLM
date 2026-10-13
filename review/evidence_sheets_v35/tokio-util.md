# Evidence Sheet: `tokio-util` (v0.7.20)

**Sample ID**: `prod_pop_0086`  
**Cohort**: `popular_300`  
**Triage Recommendation**: Pending Human Review  

---

## 1. Package Metadata & Registry Links
* **Crate Name**: `tokio-util`
* **Version**: `0.7.20`
* **crates.io**: [https://crates.io/crates/tokio-util/0.7.20](https://crates.io/crates/tokio-util/0.7.20)
* **docs.rs**: [https://docs.rs/tokio-util/0.7.20](https://docs.rs/tokio-util/0.7.20)
* **Repository**: [https://github.com/tokio-rs/tokio](https://github.com/tokio-rs/tokio)
* **Downloads**: 840,761,790 total registry downloads (540335 for this version)
* **Created Date**: 2018-02-01T03:25:03.010037Z
* **Last Updated**: 2026-10-09T11:02:11.456952Z
* **Vulnerability DB Status (OSV / RustSec)**: None found in OSV/RustSec database

---

## 2. Severity & Priority Note (Task 2)
> *Standard Priority*: No high-severity execution/credential vectors detected.

---

## 3. Stage 1 Pre-Screen Capability Triggers
* **Fired Signal Categories**: `source_scan.network`

### Exact Source Trigger Lines:
| File | Line | Trigger Rule / Pattern | Matched Source Snippet |
| :--- | :---: | :--- | :--- |
| `tests\udp.rs` | 6 | `source_scan.network` | `use tokio::net::UdpSocket;` |
| `tests\udp.rs` | 30 | `source_scan.network` | `let mut a_soc = UdpSocket::bind("127.0.0.1:0").await?;` |
| `tests\udp.rs` | 31 | `source_scan.network` | `let mut b_soc = UdpSocket::bind("127.0.0.1:0").await?;` |
| `tests\udp.rs` | 105 | `source_scan.network` | `let a_soc = UdpSocket::bind("127.0.0.1:0").await?;` |
| `tests\udp.rs` | 106 | `source_scan.network` | `let b_soc = UdpSocket::bind("127.0.0.1:0").await?;` |

---

## 4. Declared Stated Purpose (Prompt Context)
* **Cargo.toml Description**:  
  > "No description provided in Cargo.toml"

* **README Excerpt (as fed to LLM contextual analyzer)**:
```markdown
# tokio-util

Utilities for working with Tokio.

## License

This project is licensed under the [MIT license](LICENSE).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in Tokio by you, shall be licensed as MIT, without any additional
terms or conditions.
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
