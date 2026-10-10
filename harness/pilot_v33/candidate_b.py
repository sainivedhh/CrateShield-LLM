"""Prompt construction for Candidate B: purpose_consistency.

Frames classification as a purpose-consistency check:
States declared crate purpose (description + README snippet) and evaluates whether
the taint-selected code does only things consistent with that purpose, or unexplained/unrelated
malicious behaviors.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Optional
import tomllib

from crateshield.llm.prompt import format_retrieved_context, wrap_untrusted
from harness.view import _replace_name_variants, compute_view_id


PURPOSE_SYSTEM_PROMPT = """You are an expert Rust code security auditor specialized in supply-chain security analysis.
Your task is to verify PURPOSE CONSISTENCY: evaluate whether the crate's code performs only actions consistent with its declared purpose, or whether it contains behaviors that are unrelated, unexplained, suspicious, or malicious.

Classification Categories:
- "MALICIOUS": The crate executes hidden, unauthorized, or deceptive actions inconsistent with its stated purpose (e.g. executing external shell commands, unauthorized network exfiltration, reading environment secrets or arbitrary files unrelated to its purpose).
- "SUSPICIOUS": The crate performs sensitive operations that deviate from or are poorly justified by its stated purpose, but malice is not conclusively proven.
- "BENIGN": The crate performs operations that are entirely consistent with and explained by its declared purpose.

Score Definitions (0.0 to 1.0):
- malware_score: Probability that the crate contains deliberate malicious payload (0.0=none, >=0.50=malicious).
- obfuscation_score: Extent of intentional concealment or deceptive structure (0.0=clear, >=0.50=high).
- security_risk_score: Potential security blast radius regardless of intent (0.0=minimal, >=0.50=high).

Output format: Return ONLY a valid JSON object with the exact keys:
{
  "classification": "MALICIOUS" | "SUSPICIOUS" | "BENIGN",
  "confidence": float,
  "malware_score": float,
  "obfuscation_score": float,
  "security_risk_score": float,
  "primary_signals": [string],
  "reasoning": string,
  "recommended_action": "BLOCK" | "WARN" | "ALLOW"
}
"""

PURPOSE_FEW_SHOT_EXAMPLES = [
    {
        "declared_purpose": "Fast string formatting utilities and string interpolation macro.",
        "code_summary": "build.rs reads std::env::var(\"AWS_SECRET_ACCESS_KEY\") and opens TcpStream::connect(\"198.51.100.1:443\").",
        "reply": {
            "classification": "MALICIOUS",
            "confidence": 0.98,
            "malware_score": 0.95,
            "obfuscation_score": 0.40,
            "security_risk_score": 0.95,
            "primary_signals": ["purpose_violation", "env_secret_read", "network_connect_in_build"],
            "reasoning": "The crate declares itself as a string formatting utility, but its build script connects to an external IP and accesses sensitive cloud credentials. This is entirely inconsistent with its declared purpose and constitutes clear credential exfiltration.",
            "recommended_action": "BLOCK"
        }
    },
    {
        "declared_purpose": "HTTP client library for making REST API requests.",
        "code_summary": "src/client.rs opens TcpStream and performs HTTP GET/POST requests.",
        "reply": {
            "classification": "BENIGN",
            "confidence": 0.95,
            "malware_score": 0.05,
            "obfuscation_score": 0.05,
            "security_risk_score": 0.20,
            "primary_signals": ["network_connect"],
            "reasoning": "The crate performs network communication via TcpStream, but this is directly consistent with its declared purpose as an HTTP client library.",
            "recommended_action": "ALLOW"
        }
    }
]


def extract_crate_declared_purpose(
    crate_dir: Path,
    view: dict[str, Any],
    sample_meta: dict[str, Any],
) -> dict[str, Any]:
    """Extracts declared purpose from Cargo.toml description and README, with fallback."""
    real_name = sample_meta.get("cluster_id") or sample_meta.get("sample_id", "")
    view_id = view.get("view_id") or compute_view_id(real_name, salt="crateshield-v3")

    description = ""
    ctoml_path = crate_dir / "Cargo.toml"
    if ctoml_path.exists():
        try:
            doc = tomllib.loads(ctoml_path.read_text("utf-8", errors="ignore"))
            raw_desc = doc.get("package", {}).get("description")
            if raw_desc and isinstance(raw_desc, str):
                description = _replace_name_variants(raw_desc.strip(), real_name, view_id)
        except Exception:
            pass

    readme_snippet = ""
    for rname in ("README.md", "README", "readme.md", "README.markdown", "README.txt"):
        rpath = crate_dir / rname
        if rpath.exists():
            try:
                raw_readme = rpath.read_text("utf-8", errors="ignore")[:500].strip()
                if raw_readme:
                    readme_snippet = _replace_name_variants(raw_readme, real_name, view_id)
                break
            except Exception:
                pass

    fallback_used = False
    if not description and not readme_snippet:
        fallback_used = True
        # Fallback: infer purpose from crate name and top doc comments
        doc_hints = []
        source_files = view.get("source_files") or {}
        for p in ("src/lib.rs", "src/main.rs"):
            if p in source_files:
                for line in source_files[p].splitlines()[:10]:
                    s = line.strip()
                    if s.startswith("//!") or s.startswith("///"):
                        doc_hints.append(s.lstrip("/! ").strip())
        doc_text = " ".join(doc_hints[:3]) if doc_hints else "No doc comments provided."
        description = f"Stated name: {view_id}. Author header notes: {doc_text}"

    return {
        "description": description or "(No description declared in manifest)",
        "readme_snippet": readme_snippet or "(No README provided)",
        "fallback_used": fallback_used,
    }


def build_candidate_b_prompt(
    signals: dict[str, Any],
    taint_context: dict[str, Any],
    purpose_info: dict[str, Any],
    retrieved_context: Optional[list[dict[str, Any]]] = None,
) -> list[dict[str, str]]:
    """Builds prompt for Candidate B: purpose consistency framing over taint-selected context."""
    messages = [{"role": "system", "content": PURPOSE_SYSTEM_PROMPT}]

    for ex in PURPOSE_FEW_SHOT_EXAMPLES:
        user_text = (
            f"Analyze purpose consistency for this crate:\n\n"
            f"Declared Crate Purpose:\n{ex['declared_purpose']}\n\n"
            f"Code Summary:\n{ex['code_summary']}"
        )
        messages.append({"role": "user", "content": user_text})
        messages.append({"role": "assistant", "content": json.dumps(ex["reply"])})

    omitted_note = ""
    if taint_context.get("omitted_regions"):
        omitted_note = f"\n\nOmitted regions (budget limit):\n" + "\n".join(
            f"- {r}" for r in taint_context["omitted_regions"]
        )

    mode_note = ""
    if taint_context.get("fallback_used"):
        mode_note = "\n\n[CONTEXT MODE: Fallback Mode - No connected source-sink path found; showing isolated sites and build script.]"
    else:
        mode_note = f"\n\n[CONTEXT MODE: Connected Taint Paths - {taint_context.get('paths_found', 0)} path(s) found.]"

    data_block = (
        f"--- DECLARED CRATE PURPOSE ---\n"
        f"Manifest Description:\n{purpose_info['description']}\n\n"
        f"README Overview:\n{purpose_info['readme_snippet']}\n\n"
        f"--- CRATE STATIC SIGNALS ---\n{json.dumps(signals, indent=2)}\n\n"
        f"--- EXTRACTED TAINT-FLOW CODE CONTEXT ---\n"
        f"{taint_context['formatted_text']}"
        f"{mode_note}"
        f"{omitted_note}"
    )

    rag_text = ""
    if retrieved_context:
        rag_text = (
            "\n\nRetrieved context (reference documents from knowledge base, ranked by relevance):\n"
            f"{format_retrieved_context(retrieved_context)}"
        )
    else:
        rag_text = "\n\nRetrieved context: (none provided -- evaluate consistency from declared purpose and code alone)"

    messages.append({
        "role": "user",
        "content": (
            "Evaluate whether this crate's code is consistent with its declared purpose:\n\n"
            f"{wrap_untrusted(data_block)}"
            f"{rag_text}\n\n"
            "Does the code do only things consistent with the declared purpose, or does it do something unrelated, "
            "unexplained, or suspicious? Classify and score the crate accordingly."
        ),
    })
    return messages
