"""Hybrid Taint condition: structured signals + taint-flow guided code context.

Selects code context via static data-flow (taint) analysis (AST parsing + intra-crate
call-graph walk) instead of regex-line matching.

Operates under a fixed token budget matching hybrid/hybrid_fallback (25,000 chars).
Confines all crate-derived code and signals strictly within <untrusted_crate_data>.
"""
from __future__ import annotations

import json
from typing import Any, Optional

from crateshield.llm.prompt import (
    FEW_SHOT_EXAMPLES, SYSTEM_PROMPT, format_retrieved_context, wrap_untrusted,
)
from crateshield.taintflow.extractor import extract_taint_context, TAINT_TOTAL_CHAR_BUDGET


def build_hybrid_taint_prompt(
    signals: dict[str, Any],
    taint_context: dict[str, Any],
    retrieved_context: Optional[list[dict[str, Any]]] = None,
) -> list[dict[str, str]]:
    """Builds prompt for hybrid_taint condition: signals + taint-flow paths + RAG."""
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    for ex in FEW_SHOT_EXAMPLES:
        messages.append({
            "role": "user",
            "content": "Analyze this crate and classify it.\n\n"
                       + wrap_untrusted(f"Crate signals:\n{json.dumps(ex['signals'], indent=2)}"),
        })
        messages.append({"role": "assistant", "content": json.dumps(ex["reply"])})

    omitted_note = ""
    if taint_context.get("omitted_regions"):
        omitted_note = f"\n\nOmitted regions (budget limit):\n" + "\n".join(
            f"- {r}" for r in taint_context["omitted_regions"]
        )

    mode_note = ""
    if taint_context.get("fallback_used"):
        mode_note = "\n\n[CONTEXT MODE: Fallback Mode - No connected source-sink path found; showing isolated sites.]"
    else:
        mode_note = f"\n\n[CONTEXT MODE: Connected Taint Paths - {taint_context.get('paths_found', 0)} path(s) found.]"

    data_block = (
        f"Crate signals:\n{json.dumps(signals, indent=2)}\n\n"
        f"Taint-guided source code context (data-flow paths from taint sources to sinks):\n"
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
        rag_text = "\n\nRetrieved context: (none provided -- reason from signals and code context alone)"

    messages.append({
        "role": "user",
        "content": (
            "Analyze this crate and classify it. You are provided with structured signals "
            "AND taint-guided source code context containing line numbers along intra-crate data flows.\n\n"
            f"{wrap_untrusted(data_block)}"
            f"{rag_text}"
        ),
    })
    return messages
