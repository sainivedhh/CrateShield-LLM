"""Prompt construction for Combined Condition: contextual_purpose_consistency.

Combines:
1. Candidate B's purpose-consistency verification framing as the foundational evaluation logic.
2. Candidate A's module hierarchy, enclosing doc comments (author's stated purpose), and in-place scope evaluation.
3. Explicitly OMITS all "unreferenced internally" / dead-code / absence-of-connection call-site notes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from crateshield.llm.prompt import format_retrieved_context, wrap_untrusted
from harness.pilot_v33.candidate_b import (
    PURPOSE_SYSTEM_PROMPT, PURPOSE_FEW_SHOT_EXAMPLES, extract_crate_declared_purpose,
)


COMBINED_SYSTEM_PROMPT = """You are an expert Rust code security auditor specialized in supply-chain security analysis.
Your task is to verify CONTEXTUAL PURPOSE CONSISTENCY: evaluate whether the crate's code performs only actions consistent with its declared purpose, or whether it contains behaviors that are unrelated, unexplained, suspicious, or malicious.

Analysis Guidelines:
1. Compare Declared Purpose vs Code Functionality: Does the code in each module and build script align strictly with the stated library purpose?
2. In-Place Scope Evaluation: Evaluate sensitive operations strictly in place within their enclosing module or build script scope. If hidden XOR decoding routines, credential reads, or unexpected foreign traits appear inside build scripts or internal modules, evaluate them directly for what they do within that scope.
3. Classification Categories:
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


def build_combined_prompt(
    signals: dict[str, Any],
    taint_context: dict[str, Any],
    purpose_info: dict[str, Any],
    retrieved_context: Optional[list[dict[str, Any]]] = None,
) -> list[dict[str, str]]:
    """Builds prompt for contextual_purpose_consistency condition."""
    messages = [{"role": "system", "content": COMBINED_SYSTEM_PROMPT}]

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
        f"--- CONTEXTUAL TAINT-GUIDED CODE (Annotated with module hierarchy and author doc comments) ---\n"
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
        rag_text = "\n\nRetrieved context: (none provided -- evaluate consistency from declared purpose and code context alone)"

    messages.append({
        "role": "user",
        "content": (
            "Evaluate whether this crate's code is consistent with its declared purpose:\n\n"
            f"{wrap_untrusted(data_block)}"
            f"{rag_text}\n\n"
            "Does the code in each module and build script do only things consistent with the declared purpose, "
            "or does it perform unrelated, unexplained, or suspicious actions? Classify and score the crate accordingly."
        ),
    })
    return messages
