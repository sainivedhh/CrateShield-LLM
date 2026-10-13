"""Hybrid Fallback condition: hybrid + static risk-ranked windows from unflagged files.

Implements Phase 5 requirement:
Samples windows from unflagged files ranked by static risk:
- std::process / Command
- std::net / TcpStream / UdpSocket
- std::fs / File
- std::env / env::var
- unsafe / FFI
- build.rs / proc-macro
Respects token budget.
"""
from __future__ import annotations

import json
import re
from typing import Any

from crateshield.llm.prompt import (
    FEW_SHOT_EXAMPLES, SYSTEM_PROMPT, format_retrieved_context, wrap_untrusted,
)
from harness.hybrid import (
    BUILD_RS_SIZE_CAP_CHARS, HYBRID_TOTAL_CHAR_BUDGET, WINDOW_RADIUS,
    extract_targeted_code_windows,
)


def _merge_intervals(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not intervals:
        return []
    intervals = sorted(intervals, key=lambda x: x[0])
    merged = [intervals[0]]
    for cur in intervals[1:]:
        last = merged[-1]
        if cur[0] <= last[1] + 1:
            merged[-1] = (last[0], max(last[1], cur[1]))
        else:
            merged.append(cur)
    return merged

RISK_PATTERNS = [
    (re.compile(r"\b(std::process|Command::new|spawn|exec)\b"), 4),
    (re.compile(r"\b(std::net|TcpStream|UdpSocket|connect)\b"), 4),
    (re.compile(r"\b(std::env|env::var|var_os)\b"), 3),
    (re.compile(r"\b(std::fs|File::create|write|remove_file)\b"), 2),
    (re.compile(r"\b(unsafe|extern\s+\"C\")\b"), 2),
    (re.compile(r"\b(proc_macro|TokenStream)\b"), 3),
]


def score_line_risk(line: str) -> tuple[int, bool]:
    score = 0
    matched = False
    for pat, weight in RISK_PATTERNS:
        if pat.search(line):
            score += weight
            matched = True
    return score, matched


def extract_fallback_code_windows(
    preprocessed: dict[str, Any],
    window_radius: int = WINDOW_RADIUS,
    max_total_chars: int = HYBRID_TOTAL_CHAR_BUDGET,
) -> dict[str, Any]:
    """Extracts targeted windows + risk-ranked fallback windows from unflagged files."""
    # 1. Base targeted windows
    base_res = extract_targeted_code_windows(
        preprocessed, window_radius=window_radius, max_total_chars=max_total_chars // 2
    )
    
    flagged_files = set(base_res.get("windows_by_file", {}).keys())
    source_files = preprocessed.get("source_files") or {}
    
    # 2. Score unflagged files
    file_scores: list[tuple[int, str, list[int]]] = []
    for rel_path, content in source_files.items():
        if rel_path in flagged_files or not content:
            continue
        lines = content.splitlines()
        tot_score = 0
        risk_lines = []
        for lineno, line in enumerate(lines, 1):
            s, matched = score_line_risk(line)
            if matched:
                tot_score += s
                risk_lines.append(lineno)
        if tot_score > 0:
            file_scores.append((tot_score, rel_path, risk_lines))

    # Sort descending by risk score
    file_scores.sort(key=lambda x: x[0], reverse=True)

    # 3. Add fallback windows
    curr_windows = dict(base_res.get("windows_by_file", {}))
    curr_chars = base_res.get("total_chars", 0)
    omitted = list(base_res.get("omitted_files", []))

    for score, rel_path, risk_lines in file_scores:
        if curr_chars >= max_total_chars:
            omitted.append(rel_path)
            continue

        content = source_files[rel_path]
        lines = content.splitlines()
        intervals = [(max(1, ln - window_radius), min(len(lines), ln + window_radius)) for ln in risk_lines]
        merged = _merge_intervals(intervals)

        file_hunks = []
        for start, end in merged:
            hunk_lines = [f"{i:4d} | {lines[i-1]}" for i in range(start, end + 1)]
            file_hunks.append(f"--- {rel_path} (lines {start}-{end}, fallback risk-score: {score}) ---\n" + "\n".join(hunk_lines))

        file_block = "\n\n".join(file_hunks)
        if curr_chars + len(file_block) > max_total_chars:
            omitted.append(rel_path)
            break
        curr_windows[rel_path] = file_hunks
        curr_chars += len(file_block)

    return {
        "windows_by_file": curr_windows,
        "total_chars": curr_chars,
        "build_rs_included_full": base_res.get("build_rs_included_full", False),
        "omitted_files": omitted,
    }


def build_hybrid_fallback_prompt(
    signals: dict[str, Any],
    code_windows: dict[str, Any],
    retrieved_context: list[dict[str, Any]] | None = None,
) -> list[dict[str, str]]:
    """Builds prompt combining structured signals, targeted windows, and risk-ranked fallback windows."""
    signals_json = json.dumps(signals, indent=2)

    windows_text_parts = []
    wb = code_windows.get("windows_by_file", {})
    if wb:
        windows_text_parts.append("### RELEVANT CODE WINDOWS & RISK-RANKED FALLBACK REGIONS:")
        for rel_path, hunks in wb.items():
            for h in hunks:
                windows_text_parts.append(h)
    else:
        windows_text_parts.append("No specific high-risk source windows flagged.")

    if code_windows.get("omitted_files"):
        windows_text_parts.append(
            f"\n[NOTE: The following files were omitted due to budget limits: {', '.join(code_windows['omitted_files'])}]"
        )

    code_section = "\n\n".join(windows_text_parts)

    user_content = f"""Analyze the following Rust crate using its extracted security signals AND prioritized code regions.

{format_retrieved_context(retrieved_context or [])}

{wrap_untrusted(signals_json + chr(10) + chr(10) + code_section)}

Evaluate the signals, targeted code windows, and fallback regions. Return your analysis as a strict JSON object with:
{{
  "verdict": "BENIGN" | "SUSPICIOUS" | "MALICIOUS",
  "confidence": 0.0 to 1.0,
  "malware_score": 0.0 to 1.0,
  "obfuscation_score": 0.0 to 1.0,
  "security_risk_score": 0.0 to 1.0,
  "primary_signals": ["..."],
  "reasoning": "...",
  "recommended_action": "ALLOW" | "FLAG_FOR_REVIEW" | "QUARANTINE" | "BLOCK"
}}
"""
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    for ex in FEW_SHOT_EXAMPLES:
        messages.append({
            "role": "user",
            "content": "Analyze this crate and classify it.\n\n"
                       + wrap_untrusted(f"Crate signals:\n{json.dumps(ex['signals'], indent=2)}"),
        })
        messages.append({"role": "assistant", "content": json.dumps(ex["reply"])})
    messages.append({"role": "user", "content": user_content})
    return messages