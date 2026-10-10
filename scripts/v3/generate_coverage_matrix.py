"""Generates data/bench_v3/coverage_matrix.md from data/bench_v3/taxonomy.yaml and real advisory data."""
from __future__ import annotations

import json
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[2]
BENCH_V3 = ROOT / "data" / "bench_v3"
TAXONOMY_PATH = BENCH_V3 / "taxonomy.yaml"
OUTPUT_PATH = BENCH_V3 / "coverage_matrix.md"

INCIDENTS_MAP = [
    {
        "source": "OSSF / RUSTSEC-2022-0042",
        "package": "rustdecimal",
        "description": "Typosquat of rust_decimal. Checks GitLab CI env, exfiltrates environment variables via HTTP webhook.",
        "families": ["F1", "F6", "F7"],
    },
    {
        "source": "OSSF",
        "package": "amzn_codewhisperer_streaming_client",
        "description": "Dependency confusion typosquat targeting AWS internal environments; harvests AWS credential files.",
        "families": ["F1", "F5"],
    },
    {
        "source": "OSSF",
        "package": "amzn_consolas_client",
        "description": "Internal naming masquerade; exfiltrates developer environment keys and host identifiers.",
        "families": ["F1", "F5"],
    },
    {
        "source": "OSSF / Tier 1",
        "package": "logs_update",
        "description": "GitLab runner malicious crate opening outbound TCP socket and spawning interactive /bin/sh reverse shell.",
        "families": ["F2"],
    },
    {
        "source": "OSSF",
        "package": "proton_pfff",
        "description": "Remote command execution backdoor listening on socket for arbitrary command dispatch.",
        "families": ["F2"],
    },
    {
        "source": "OSSF",
        "package": "littest",
        "description": "Build script (build.rs) initiates HTTP download of external second-stage binary and executes it.",
        "families": ["F3"],
    },
    {
        "source": "OSSF",
        "package": "supertag",
        "description": "Build-time dropper fetching executable payload and linking dynamically.",
        "families": ["F3"],
    },
    {
        "source": "OSSF / KnowledgeBase",
        "package": "proc_macro1",
        "description": "Procedural macro compilation hook that mutates host filesystem files to establish persistence.",
        "families": ["F4"],
    },
    {
        "source": "OSSF / KnowledgeBase",
        "package": "proc_macro_en",
        "description": "Proc-macro execution hook dropping persistence triggers in user dotfiles.",
        "families": ["F4"],
    },
    {
        "source": "OSSF",
        "package": "append_only_vec",
        "description": "Shadow dependency mechanism introducing covert routines through external unvetted path dependency.",
        "families": ["F5"],
    },
    {
        "source": "OSSF",
        "package": "arrayref",
        "description": "Typosquatted/shadowed sub-dependency injection executing stealth payload.",
        "families": ["F5", "F6"],
    },
    {
        "source": "OSSF",
        "package": "tinymember",
        "description": "Typosquat masquerading as popular crate tinyvec with payload triggered in standard methods.",
        "families": ["F6"],
    },
    {
        "source": "OSSF",
        "package": "internment",
        "description": "Typosquat mimicking internment crate with embedded activation trigger.",
        "families": ["F6"],
    },
    {
        "source": "OSSF",
        "package": "semantic_search_client",
        "description": "Scrapes environment variables under CI conditions and transmits to external endpoint.",
        "families": ["F1", "F7"],
    },
    {
        "source": "OSSF",
        "package": "mysten_metrics",
        "description": "Telemetry package collecting private cryptographic keys and wallet addresses from disk.",
        "families": ["F8"],
    },
]


def generate_coverage_matrix() -> str:
    with open(TAXONOMY_PATH, "r", encoding="utf-8") as f:
        tax = yaml.safe_load(f)

    families = tax.get("families", [])
    fam_dict = {f["id"]: f for f in families}

    lines = [
        "# CrateShield v3 Threat Taxonomy and Incident Coverage Matrix",
        "",
        "This document records the provenance and coverage of the 8 threat families in Benchmark v3, mapping documented real-world supply chain incidents from OSSF, RustSec, and the CrateShield Knowledge Base to their standardized threat abstractions.",
        "",
        "## Threat Families Overview",
        "",
        "| Family ID | Name | Split | Allowed Carriers | Provenance Summary |",
        "|---|---|---|---|---|",
    ]

    for fam in families:
        fid = fam["id"]
        name = fam["name"]
        split = fam["split"]
        carriers = ", ".join(f"`{c}`" for c in fam["allowed_carriers"])
        lines.append(f"| **{fid}** | {name} | **{split}** | {carriers} | {fam['provenance'][:80]}... |")

    lines.extend([
        "",
        "## Incident Coverage Matrix",
        "",
        "| Package / Incident | Source | Mapped Families | Description |",
        "|---|---|---|---|",
    ])

    for inc in INCIDENTS_MAP:
        fam_badges = ", ".join(f"**{fid}** ({fam_dict[fid]['split']})" for fid in inc["families"])
        lines.append(f"| `{inc['package']}` | {inc['source']} | {fam_badges} | {inc['description']} |")

    lines.extend([
        "",
        "## Family Coverage Summary",
        "",
        "| Family ID | Name | Split | Incident Count | Primary Real Incident Anchors |",
        "|---|---|---|---|---|",
    ])

    for fam in families:
        fid = fam["id"]
        matched = [inc["package"] for inc in INCIDENTS_MAP if fid in inc["families"]]
        anchors = ", ".join(f"`{p}`" for p in matched)
        lines.append(f"| **{fid}** | {fam['name']} | **{fam['split']}** | {len(matched)} | {anchors} |")

    lines.extend([
        "",
        "## Generalization and Abstraction Rules",
        "",
        "1. **Plaintext Behavior (WHAT, never HOW)**: Behaviour specs state what malicious outcome is produced (e.g. 'transmits environment variables to external host') without specifying code constructs, function names, or regex targets.",
        "2. **Independence Firewall**: Generation prompts receive only the behavior spec and base crate context, never detector regexes, rule names, or v1/v2 templates.",
        "3. **Held-Out Family Discipline**: Families **F5** (supply-chain via dependency), **F6** (typosquat masquerade), and **F8** (data-destructive / wallet theft) are strictly HELD-OUT. They are excluded from tune split and only evaluated in the sealed evaluation split to test zero-shot generalization (Hypothesis H5).",
        "",
    ])

    content = "\n".join(lines)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Generated {OUTPUT_PATH} ({len(lines)} lines)")
    return content


if __name__ == "__main__":
    generate_coverage_matrix()