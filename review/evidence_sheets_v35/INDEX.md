# Human Review Package: Stage 2 Flagged Crates (v3.5)

**Total Flagged Crates**: 10  
**Cohort Split**: 3 Popular (`popular_300`), 7 Random (`random_1000`)  
**Status**: Awaiting human `reviewer_verdict` in `review/flagged_for_review_v35.csv`.

---

## Index of Evidence Sheets

| Sample ID | Crate Name | Version | Cohort | Downloads | Stage 2 Score | Severity Note | Evidence Sheet |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- | :---: |
| `prod_pop_0138` | **zerocopy-derive** | 0.8.62 | `popular_300` | 662,582,829 | `0.3` | **High (Action)** | [zerocopy-derive.md](zerocopy-derive.md) |
| `prod_pop_0086` | **tokio-util** | 0.7.20 | `popular_300` | 840,761,790 | `0.0` | Normal | [tokio-util.md](tokio-util.md) |
| `prod_pop_0272` | **base64ct** | 1.8.3 | `popular_300` | 435,470,452 | `0.0` | Normal | [base64ct.md](base64ct.md) |
| `prod_rand_0224` | **FileSorterX** | 1.2.1 | `random_1000` | 5,819 | `0.45` | **High (Action)** | [FileSorterX.md](FileSorterX.md) |
| `prod_rand_0401` | **a-rs-jsonrpc-macros** | 0.1.0 | `random_1000` | 284 | `0.4` | Normal | [a-rs-jsonrpc-macros.md](a-rs-jsonrpc-macros.md) |
| `prod_rand_0560` | **ta-events** | 0.17.11-alpha.7 | `random_1000` | 426 | `0.4` | **High (Action)** | [ta-events.md](ta-events.md) |
| `prod_rand_0281` | **f1r3fly-rholang** | 0.1.1 | `random_1000` | 1,812 | `0.0` | **High (Action)** | [f1r3fly-rholang.md](f1r3fly-rholang.md) |
| `prod_rand_0879` | **swc_core** | 82.0.2 | `random_1000` | 6,701,505 | `0.0` | **High (Action)** | [swc_core.md](swc_core.md) |
| `prod_rand_0948` | **loopflow** | 0.13.11 | `random_1000` | 1,054 | `0.0` | **High (Action)** | [loopflow.md](loopflow.md) |
| `prod_rand_0994` | **hawdb-search** | 0.7.0 | `random_1000` | 128 | `0.0` | **High (Action)** | [hawdb-search.md](hawdb-search.md) |

---

## Priority Review Notes (Task 2 Factual Flags)

The following crates exhibit flagged behavior that, if malicious, would involve high-severity vectors (file writes, command execution, or credential access):

* **`zerocopy-derive` (v0.8.62)**: This crate's flagged behavior, if malicious, would involve: file write.
* **`FileSorterX` (v1.2.1)**: This crate's flagged behavior, if malicious, would involve: command execution / credential read.
* **`ta-events` (v0.17.11-alpha.7)**: This crate's flagged behavior, if malicious, would involve: command execution / credential read.
* **`f1r3fly-rholang` (v0.1.1)**: This crate's flagged behavior, if malicious, would involve: credential read.
* **`swc_core` (v82.0.2)**: This crate's flagged behavior, if malicious, would involve: file write / command execution.
* **`loopflow` (v0.13.11)**: This crate's flagged behavior, if malicious, would involve: file write / command execution / credential read.
* **`hawdb-search` (v0.7.0)**: This crate's flagged behavior, if malicious, would involve: command execution / credential read.

---

## Instructions for Human Reviewer
1. Review the individual evidence sheets in this directory (`review/evidence_sheets_v35/`).
2. Record your verdicts (`TP`, `FP`, or `UNSURE`) in `review/flagged_for_review_v35.csv` under the `reviewer_verdict` column.
3. Return the completed CSV to the agent to finalize the production false-positive rate and close `REPORT_V35.md`.
