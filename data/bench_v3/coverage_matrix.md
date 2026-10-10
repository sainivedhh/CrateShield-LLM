# CrateShield v3 Threat Taxonomy and Incident Coverage Matrix

This document records the provenance and coverage of the 8 threat families in Benchmark v3, mapping documented real-world supply chain incidents from OSSF, RustSec, and the CrateShield Knowledge Base to their standardized threat abstractions.

## Threat Families Overview

| Family ID | Name | Split | Allowed Carriers | Provenance Summary |
|---|---|---|---|---|
| **F1** | credential_exfil | **SEEN** | `build.rs`, `lib.rs function`, `proc-macro`, `added path dependency`, `include!/OUT_DIR generated code` | Incidents rustdecimal (CrateDepression webhook exfil), amzn_codewhisperer_stream... |
| **F2** | reverse_shell_rce | **SEEN** | `build.rs`, `lib.rs function`, `proc-macro`, `added path dependency`, `include!/OUT_DIR generated code` | Incidents logs_update (GitLab runner reverse shell), proton_pfff (remote command... |
| **F3** | build_download_exec | **SEEN** | `build.rs`, `proc-macro`, `include!/OUT_DIR generated code` | Incidents littest (second-stage payload dropper in build.rs), supertag. Abstract... |
| **F4** | persistence | **SEEN** | `build.rs`, `proc-macro`, `added path dependency` | Incidents proc_macro1, proc_macro_en (proc-macro unauthorized filesystem writes)... |
| **F5** | supply_chain_dep | **HELD-OUT** | `added path dependency` | Incidents append_only_vec, arrayref (shadow dependency injection), dependency co... |
| **F6** | typosquat_payload | **HELD-OUT** | `lib.rs function`, `build.rs` | Incidents rustdecimal (mimicking rust_decimal), tinymember (mimicking tinyvec), ... |
| **F7** | conditional_gated | **SEEN** | `build.rs`, `lib.rs function`, `proc-macro`, `include!/OUT_DIR generated code` | Incidents rustdecimal (checking for GitLab CI and production build environments ... |
| **F8** | data_destructive_wallet | **HELD-OUT** | `lib.rs function`, `build.rs`, `added path dependency` | Incidents mysten_metrics (targeted telemetry and key harvesting), npm/crates cli... |

## Incident Coverage Matrix

| Package / Incident | Source | Mapped Families | Description |
|---|---|---|---|
| `rustdecimal` | OSSF / RUSTSEC-2022-0042 | **F1** (SEEN), **F6** (HELD-OUT), **F7** (SEEN) | Typosquat of rust_decimal. Checks GitLab CI env, exfiltrates environment variables via HTTP webhook. |
| `amzn_codewhisperer_streaming_client` | OSSF | **F1** (SEEN), **F5** (HELD-OUT) | Dependency confusion typosquat targeting AWS internal environments; harvests AWS credential files. |
| `amzn_consolas_client` | OSSF | **F1** (SEEN), **F5** (HELD-OUT) | Internal naming masquerade; exfiltrates developer environment keys and host identifiers. |
| `logs_update` | OSSF / Tier 1 | **F2** (SEEN) | GitLab runner malicious crate opening outbound TCP socket and spawning interactive /bin/sh reverse shell. |
| `proton_pfff` | OSSF | **F2** (SEEN) | Remote command execution backdoor listening on socket for arbitrary command dispatch. |
| `littest` | OSSF | **F3** (SEEN) | Build script (build.rs) initiates HTTP download of external second-stage binary and executes it. |
| `supertag` | OSSF | **F3** (SEEN) | Build-time dropper fetching executable payload and linking dynamically. |
| `proc_macro1` | OSSF / KnowledgeBase | **F4** (SEEN) | Procedural macro compilation hook that mutates host filesystem files to establish persistence. |
| `proc_macro_en` | OSSF / KnowledgeBase | **F4** (SEEN) | Proc-macro execution hook dropping persistence triggers in user dotfiles. |
| `append_only_vec` | OSSF | **F5** (HELD-OUT) | Shadow dependency mechanism introducing covert routines through external unvetted path dependency. |
| `arrayref` | OSSF | **F5** (HELD-OUT), **F6** (HELD-OUT) | Typosquatted/shadowed sub-dependency injection executing stealth payload. |
| `tinymember` | OSSF | **F6** (HELD-OUT) | Typosquat masquerading as popular crate tinyvec with payload triggered in standard methods. |
| `internment` | OSSF | **F6** (HELD-OUT) | Typosquat mimicking internment crate with embedded activation trigger. |
| `semantic_search_client` | OSSF | **F1** (SEEN), **F7** (SEEN) | Scrapes environment variables under CI conditions and transmits to external endpoint. |
| `mysten_metrics` | OSSF | **F8** (HELD-OUT) | Telemetry package collecting private cryptographic keys and wallet addresses from disk. |

## Family Coverage Summary

| Family ID | Name | Split | Incident Count | Primary Real Incident Anchors |
|---|---|---|---|---|
| **F1** | credential_exfil | **SEEN** | 4 | `rustdecimal`, `amzn_codewhisperer_streaming_client`, `amzn_consolas_client`, `semantic_search_client` |
| **F2** | reverse_shell_rce | **SEEN** | 2 | `logs_update`, `proton_pfff` |
| **F3** | build_download_exec | **SEEN** | 2 | `littest`, `supertag` |
| **F4** | persistence | **SEEN** | 2 | `proc_macro1`, `proc_macro_en` |
| **F5** | supply_chain_dep | **HELD-OUT** | 4 | `amzn_codewhisperer_streaming_client`, `amzn_consolas_client`, `append_only_vec`, `arrayref` |
| **F6** | typosquat_payload | **HELD-OUT** | 4 | `rustdecimal`, `arrayref`, `tinymember`, `internment` |
| **F7** | conditional_gated | **SEEN** | 2 | `rustdecimal`, `semantic_search_client` |
| **F8** | data_destructive_wallet | **HELD-OUT** | 1 | `mysten_metrics` |

## Generalization and Abstraction Rules

1. **Plaintext Behavior (WHAT, never HOW)**: Behaviour specs state what malicious outcome is produced (e.g. 'transmits environment variables to external host') without specifying code constructs, function names, or regex targets.
2. **Independence Firewall**: Generation prompts receive only the behavior spec and base crate context, never detector regexes, rule names, or v1/v2 templates.
3. **Held-Out Family Discipline**: Families **F5** (supply-chain via dependency), **F6** (typosquat masquerade), and **F8** (data-destructive / wallet theft) are strictly HELD-OUT. They are excluded from tune split and only evaluated in the sealed evaluation split to test zero-shot generalization (Hypothesis H5).
