"""Prompt construction for Candidate A: hybrid_taint_contextual."""

from __future__ import annotations

import json
from typing import Any, Optional

from crateshield.llm.prompt import (
    FEW_SHOT_EXAMPLES, SYSTEM_PROMPT, format_retrieved_context, wrap_untrusted,
)
from crateshield.taintflow.contextual_extractor import extract_taint_contextual


def build_candidate_a_prompt(
    signals: dict[str, Any],
    taint_context: dict[str, Any],
    retrieved_context: Optional[list[dict[str, Any]]] = None,
) -> list[dict[str, str]]:
    """Builds prompt for Candidate A: signals + contextual taint-flow paths + RAG."""
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
        mode_note = "\n\n[CONTEXT MODE: Fallback Mode - No connected source-sink path found; showing isolated sites with module/call-site context.]"
    else:
        mode_note = f"\n\n[CONTEXT MODE: Connected Taint Paths - {taint_context.get('paths_found', 0)} path(s) found with module/call-site annotations.]"

    data_block = (
        f"Crate signals:\n{json.dumps(signals, indent=2)}\n\n"
        f"Contextual taint-guided source code (data-flow paths annotated with module paths, static call-sites, and file purpose doc comments):\n"
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
            "AND contextual taint-guided source code containing module hierarchy, intra-crate call-site notes, "
            "and file-level author doc comments.\n\n"
            f"{wrap_untrusted(data_block)}"
            f"{rag_text}"
        ),
    })
    return messages
