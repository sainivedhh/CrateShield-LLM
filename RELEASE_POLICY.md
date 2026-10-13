# CrateShield v3 Release Policy

## Purpose & Scope
CrateShield Benchmark v3 is designed as a hardened, leak-controlled synthetic evaluation benchmark for Rust crate supply chain security. Because the benchmark includes synthesized offensive capabilities (such as credential harvesting, reverse shell stubs, and CI-gated evasion routines), this release policy governs the distribution, versioning, and access control of benchmark artifacts.

## Artifact Distribution Model

| Component | Repository Status | Storage Location | Distribution Method |
|---|---|---|---|
| **Threat Taxonomy & Specs** | Fully Public / Committed | `data/bench_v3/taxonomy.yaml`, `coverage_matrix.md` | Git version control |
| **Generators & Mutation Code** | Fully Public / Committed | `harness/gen_v3/` | Git version control |
| **Manifest & File Hashes** | Fully Public / Committed | `data/bench_v3/manifest.json` | Git version control |
| **Evaluation Code & Reports** | Fully Public / Committed | `scripts/v3/`, `REPORT_V3.md` | Git version control |
| **Generated Corpus Files** | Private / Gitignored | `data/bench_v3/corpus_private/` | On-demand reviewer pack |

## Reproducibility & Integrity Guarantee
- Every sample in Benchmark v3 has its directory structure and file contents hashed using SHA256. These cryptographic digests are committed to `data/bench_v3/manifest.json`.
- The dataset can be fully reproduced offline from the candidate base crates and seeded generators.
- To pack a review archive for researchers and peer reviewers, run:
  ```bash
  python scripts/v3/pack_corpus.py --output craneshield_v3_review_corpus.tar.gz
  ```
  The packing script automatically verifies all sample SHA256 hashes against `manifest.json` before building the archive.

## Ethical Handling & Defanging Constraints
1. **No Working Exploit Infrastructure**: All payloads are inert. They contain no real command-and-control server addresses.
2. **Strict Hostname Reservation**: All network endpoints are strictly confined to IANA-reserved domains (`*.example.com`, `*.example.net`, `*.example.org`) or RFC 2606 reserved domains (`*.invalid`, `*.test`).
3. **No Execution of Untrusted Code**: The harness never invokes `cargo`, `rustc`, `build.rs`, proc-macros, or crate binaries. All analysis is performed statically as text.