"""Hybrid condition: structured signals + targeted code windows (+/- 15 lines).

Implements Phase 4 of CrateShield Spec v2:
1. Extracts targeted code windows around every line matched by signal extractors
   (source_scan, injection, build_rs).
2. Merges and de-duplicates overlapping windows per file with 1-indexed line numbers.
3. Includes full build.rs if under a size cap (15 KB).
4. Strictly confines all untrusted signals and source windows inside <untrusted_crate_data>.
5. Reports omitted regions explicitly when char/token budget is reached.
6. Operates under a fixed token budget (<= 50% of raw condition chars/tokens).
"""
from __future__ import annotations

import json
import re
from typing import Any

from crateshield.llm.prompt import (
    FEW_SHOT_EXAMPLES, SYSTEM_PROMPT, format_retrieved_context, wrap_untrusted,
)
from crateshield.signals.build_rs import _ALL_GROUPS, _find_matches
from crateshield.signals.injection import _PATTERNS as INJECTION_PATTERNS
from crateshield.signals.source_scan import CATEGORIES as SOURCE_SCAN_CATEGORIES

BUILD_RS_SIZE_CAP_CHARS = 15000
HYBRID_TOTAL_CHAR_BUDGET = 25000  # < 50% of RAW_SOURCE_CHAR_BUDGET (60,000)
WINDOW_RADIUS = 15


def extract_targeted_code_windows(
    preprocessed: dict[str, Any],
    window_radius: int = WINDOW_RADIUS,
    build_rs_max_chars: int = BUILD_RS_SIZE_CAP_CHARS,
    max_total_chars: int = HYBRID_TOTAL_CHAR_BUDGET,
) -> dict[str, Any]:
    """Extracts merged +/-15 line windows around all signal matches across files."""
    source_files = preprocessed.get("source_files") or {}
    build_rs_src = preprocessed.get("build_rs") or ""
    build_rs_path = preprocessed.get("build_script_path") or "build.rs"

    # Map of rel_path -> set of matched 1-indexed line numbers
    matched_lines: dict[str, set[int]] = {}

    # 1. Matches in source files (source_scan + injection)
    comment_pattern = re.compile(r"^\s*(//|\*|/\*)")
    for rel_path, content in source_files.items():
        if not content:
            continue
        lines = content.splitlines()
        for lineno, line in enumerate(lines, 1):
            if comment_pattern.match(line):
                # Prompt injection scan inspects comments as well
                if any(p.search(line) for p in INJECTION_PATTERNS):
                    matched_lines.setdefault(rel_path, set()).add(lineno)
                continue

            # Check source_scan categories
            if any(p.search(line) for p in SOURCE_SCAN_CATEGORIES.values()):
                matched_lines.setdefault(rel_path, set()).add(lineno)

            # Check injection patterns
            if any(p.search(line) for p in INJECTION_PATTERNS):
                matched_lines.setdefault(rel_path, set()).add(lineno)

    # 2. Build.rs handling
    build_rs_full = False
    if build_rs_src:
        if len(build_rs_src) <= build_rs_max_chars:
            build_rs_full = True
        else:
            # Extract matching lines from build.rs
            for group_patterns in _ALL_GROUPS.values():
                for pat in group_patterns:
                    for m in re.finditer(pat, build_rs_src):
                        # Determine line number
                        line_no = build_rs_src.count("\n", 0, m.start()) + 1
                        matched_lines.setdefault(build_rs_path, set()).add(line_no)

    # 3. Format and merge windows
    sections: list[str] = []
    omitted_regions: list[str] = []
    current_chars = 0
    files_covered = []

    # Include full build.rs if eligible
    if build_rs_full and build_rs_src:
        b_lines = build_rs_src.splitlines()
        numbered = "\n".join(f"{idx:4d}: {l}" for idx, l in enumerate(b_lines, 1))
        header = f"--- File: {build_rs_path} (Complete, Lines 1-{len(b_lines)}) ---"
        block = f"{header}\n{numbered}\n"
        if current_chars + len(block) <= max_total_chars:
            sections.append(block)
            current_chars += len(block)
            files_covered.append(build_rs_path)
        else:
            omitted_regions.append(f"{build_rs_path} (full build.rs omitted: exceeds budget)")

    # Process all windowed files
    for rel_path, hit_set in sorted(matched_lines.items()):
        if not hit_set:
            continue
        if rel_path == build_rs_path and build_rs_full:
            continue

        file_content = build_rs_src if rel_path == build_rs_path else source_files.get(rel_path, "")
        if not file_content:
            continue
        all_lines = file_content.splitlines()
        total_lines = len(all_lines)

        # Merge intervals
        raw_intervals = [
            (max(1, l - window_radius), min(total_lines, l + window_radius))
            for l in sorted(hit_set)
        ]
        merged_intervals: list[tuple[int, int]] = []
        for start, end in raw_intervals:
            if not merged_intervals:
                merged_intervals.append((start, end))
            else:
                last_start, last_end = merged_intervals[-1]
                if start <= last_end + 1:
                    merged_intervals[-1] = (last_start, max(last_end, end))
                else:
                    merged_intervals.append((start, end))

        # Render merged intervals
        file_rendered_blocks = []
        for start, end in merged_intervals:
            header = f"--- File: {rel_path} (Lines {start}-{end} of {total_lines}) ---"
            block_lines = [
                f"{line_idx:4d}: {all_lines[line_idx - 1]}"
                for line_idx in range(start, end + 1)
            ]
            rendered = f"{header}\n" + "\n".join(block_lines) + "\n"

            if current_chars + len(rendered) <= max_total_chars:
                file_rendered_blocks.append(rendered)
                current_chars += len(rendered)
            else:
                omitted_regions.append(f"{rel_path}: lines {start}-{end}")

        if file_rendered_blocks:
            sections.extend(file_rendered_blocks)
            files_covered.append(rel_path)

    formatted_text = "\n".join(sections) if sections else "(No suspicious code windows triggered)"
    return {
        "formatted_text": formatted_text,
        "files_covered": files_covered,
        "omitted_regions": omitted_regions,
        "total_chars": current_chars,
        "build_rs_included_full": build_rs_full,
    }


def build_hybrid_prompt(
    signals: dict[str, Any],
    code_windows: dict[str, Any],
    retrieved_context: list[dict[str, Any]] | None = None,
) -> list[dict[str, str]]:
    """Builds prompt for hybrid condition: signals + targeted source windows + RAG."""
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    for ex in FEW_SHOT_EXAMPLES:
        messages.append({
            "role": "user",
            "content": "Analyze this crate and classify it.\n\n"
                       + wrap_untrusted(f"Crate signals:\n{json.dumps(ex['signals'], indent=2)}"),
        })
        messages.append({"role": "assistant", "content": json.dumps(ex["reply"])})

    omitted_note = ""
    if code_windows.get("omitted_regions"):
        omitted_note = f"\n\nOmitted regions (budget limit):\n" + "\n".join(
            f"- {r}" for r in code_windows["omitted_regions"]
        )

    data_block = (
        f"Crate signals:\n{json.dumps(signals, indent=2)}\n\n"
        f"Targeted source code windows around flagged signals:\n"
        f"{code_windows['formatted_text']}"
        f"{omitted_note}"
    )

    rag_text = ""
    if retrieved_context:
        rag_text = (
            "\n\nRetrieved context (reference documents from knowledge base, ranked by relevance):\n"
            f"{format_retrieved_context(retrieved_context)}"
        )
    else:
        rag_text = "\n\nRetrieved context: (none provided -- reason from signals and code windows alone)"

    messages.append({
        "role": "user",
        "content": (
            "Analyze this crate and classify it. You are provided with structured signals "
            "AND targeted source code windows containing line numbers around the matched lines.\n\n"
            f"{wrap_untrusted(data_block)}"
            f"{rag_text}"
        ),
    })
    return messages
