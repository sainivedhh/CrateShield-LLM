"""Contextual taint context extractor for hybrid_taint_contextual (Candidate A).

Extends hybrid_taint by attaching:
(a) Enclosing module path and doc comments on the enclosing impl/struct/fn
(b) Static call-site note (stating callers from intra-crate callgraph without LLM)
(c) File-level doc comments (//! or ///) stating the author's purpose for the file
"""

from __future__ import annotations

import re
from typing import Any, Optional

from .ast_parser import RustASTParser, FunctionDef, FileASTInfo
from .callgraph import CrateCallGraph
from .taint_engine import TaintEngine, TaintPath
from .extractor import BUILD_RS_SIZE_CAP_CHARS

CONTEXTUAL_CHAR_BUDGET = 32500  # Up to 30% overhead over baseline 25,000 chars


def rel_path_to_module(rel_path: str) -> str:
    """Converts a relative Rust source path to a module path."""
    p = rel_path.replace("\\", "/").strip("/")
    if p.endswith("build.rs"):
        return "crate::build_script"
    if p == "src/lib.rs":
        return "crate::root (lib)"
    if p == "src/main.rs":
        return "crate::root (bin)"
    if p.startswith("src/"):
        p = p[4:]
    if p.endswith(".rs"):
        p = p[:-3]
    if p.endswith("/mod"):
        p = p[:-4]
    parts = [part for part in p.split("/") if part]
    return "crate::" + "::".join(parts) if parts else "crate"


def extract_top_file_doc(file_content: str, max_lines: int = 5) -> str:
    """Extracts leading //! or /// module-level doc comments from file start."""
    lines = file_content.splitlines()
    doc_lines = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            if doc_lines:
                continue
            else:
                continue
        if stripped.startswith("//!") or stripped.startswith("///"):
            doc_lines.append(stripped)
            if len(doc_lines) >= max_lines:
                break
        elif stripped.startswith("//"):
            continue
        else:
            break
    if doc_lines:
        return "\n".join(f"// File Stated Purpose: {d.lstrip('/! ').strip()}" for d in doc_lines)
    return ""


def extract_fn_doc_comments(file_lines: list[str], start_line: int, max_lines: int = 4) -> str:
    """Extracts doc comments (///) immediately preceding a function definition."""
    idx = start_line - 2  # 0-indexed line before start_line
    doc_lines = []
    while idx >= 0 and len(doc_lines) < max_lines:
        line = file_lines[idx].strip()
        if line.startswith("///") or line.startswith("//!"):
            doc_lines.insert(0, f"// Doc: {line.lstrip('/! ').strip()}")
            idx -= 1
        elif not line:
            idx -= 1
        else:
            break
    return "\n".join(doc_lines) if doc_lines else ""


def extract_taint_contextual(
    view: dict[str, Any],
    manifest_sample: Optional[dict[str, Any]] = None,
    max_total_chars: int = CONTEXTUAL_CHAR_BUDGET,
    build_rs_max_chars: int = BUILD_RS_SIZE_CAP_CHARS,
    omit_absence_notes: bool = True,
) -> dict[str, Any]:
    """Extracts taint-guided code context enriched with static module and call-site context."""
    source_files = dict(view.get("source_files") or {})
    build_rs_src = view.get("build_rs") or ""
    build_rs_path = view.get("build_script_path") or "build.rs"

    if build_rs_src and build_rs_path not in source_files:
        source_files[build_rs_path] = build_rs_src

    # 1. Parse all .rs files with tree-sitter
    parser = RustASTParser()
    callgraph = CrateCallGraph()

    for rel_path, content in source_files.items():
        if not content:
            continue
        file_info = parser.parse_file(rel_path, content)
        callgraph.add_file(file_info)

    # 2. Build intra-crate call graph edges
    callgraph.build_edges()

    # 3. Find taint paths using frozen TaintEngine
    engine = TaintEngine(max_depth=4, max_nodes_visited=25)
    paths = engine.find_taint_paths(callgraph)

    sections: list[str] = []
    omitted_regions: list[str] = []
    current_chars = 0
    fallback_used = False
    functions_included: list[str] = []
    selected_line_ranges: dict[str, list[tuple[int, int]]] = {}

    def record_range(path_str: str, s: int, e: int):
        selected_line_ranges.setdefault(path_str, []).append((s, e))

    def format_contextual_function(fn: FunctionDef, shown_files: set[str]) -> str:
        file_content = source_files.get(fn.rel_path, "")
        file_lines = file_content.splitlines() if file_content else []

        # (a) Enclosing module path
        mod_path = rel_path_to_module(fn.rel_path)
        impl_note = f" (in impl {fn.impl_type})" if fn.impl_type else ""

        # (b) Static call-site note (from callgraph reverse edges)
        call_site_note = ""
        callers = sorted(list(callgraph.reverse_edges.get(fn.id, set())))
        if callers:
            caller_fn = callgraph.nodes.get(callers[0])
            if caller_fn:
                call_site_note = f"// Static call-site: called by fn {caller_fn.name}() in {caller_fn.rel_path}:{caller_fn.start_line}"
                if len(callers) > 1:
                    call_site_note += f" (+{len(callers)-1} other call-site(s))"
            else:
                call_site_note = f"// Static call-site: called from {callers[0]}"
        elif fn.rel_path.endswith("build.rs") and fn.name == "main":
            call_site_note = "// Scope: Cargo build script entry point (executed automatically during build)"
        elif fn.name == "main":
            call_site_note = "// Scope: Crate binary entry point (fn main)"
        elif fn.rel_path.endswith("lib.rs") or "pub " in fn.code[:30]:
            call_site_note = "// Scope: Library public entry point / exported function"
        else:
            if not omit_absence_notes:
                call_site_note = "// Static call-site: Unreferenced internally within crate (possible entry point or dead code)"

        # (c) Top-of-file doc comments (purpose)
        file_doc = ""
        if fn.rel_path not in shown_files:
            file_doc = extract_top_file_doc(file_content)
            if file_doc:
                file_doc += "\n"
            shown_files.add(fn.rel_path)

        # Preceding function doc comments
        fn_doc = extract_fn_doc_comments(file_lines, fn.start_line)
        if fn_doc:
            fn_doc += "\n"

        fn_header = f"--- File: {fn.rel_path} (Lines {fn.start_line}-{fn.end_line}) [fn {fn.name}{impl_note}] ---"

        # Line-numbered code
        numbered_lines = []
        for l_idx in range(fn.start_line, min(fn.end_line + 1, len(file_lines) + 1)):
            line_txt = file_lines[l_idx - 1] if l_idx - 1 < len(file_lines) else ""
            numbered_lines.append(f"{l_idx:4d}: {line_txt}")

        meta_lines = [f"// Module: {mod_path}"]
        if call_site_note:
            meta_lines.append(call_site_note)
        if file_doc:
            meta_lines.append(file_doc.rstrip("\n"))
        if fn_doc:
            meta_lines.append(fn_doc.rstrip("\n"))
        meta_block = "\n".join(meta_lines) + "\n"
        return f"{fn_header}\n{meta_block}" + "\n".join(numbered_lines)

    if paths:
        path_summaries: list[dict[str, Any]] = []
        shown_functions: set[str] = set()
        shown_files: set[str] = set()

        for idx, p in enumerate(paths, 1):
            path_header = f"=== Taint Flow Path {idx}: {p.source_desc} -> {p.sink_desc} (Length: {p.length}, Type: {p.path_type}) ==="
            path_blocks = [path_header]

            for fn in p.nodes:
                fn_key = fn.id
                functions_included.append(fn_key)
                record_range(fn.rel_path, fn.start_line, fn.end_line)

                if fn_key in shown_functions:
                    continue

                fn_block = format_contextual_function(fn, shown_files)
                path_blocks.append(fn_block)
                shown_functions.add(fn_key)

            rendered_path = "\n".join(path_blocks) + "\n"
            if current_chars + len(rendered_path) <= max_total_chars:
                sections.append(rendered_path)
                current_chars += len(rendered_path)
                path_summaries.append({
                    "source": p.source_desc,
                    "sink": p.sink_desc,
                    "length": p.length,
                    "type": p.path_type,
                })
            else:
                omitted_regions.append(f"Taint Path {idx} ({p.source_desc} -> {p.sink_desc})")

        formatted_text = "\n".join(sections) if sections else "(All discovered taint paths exceeded budget)"

    else:
        # Fallback mode
        fallback_used = True
        fallback_blocks: list[str] = [
            "NOTE: No connected source-sink path found; showing isolated sites and build script context with module/call-site annotations."
        ]

        # 1. Include build.rs
        if build_rs_src:
            if len(build_rs_src) <= build_rs_max_chars:
                b_lines = build_rs_src.splitlines()
                numbered = "\n".join(f"{idx:4d}: {l}" for idx, l in enumerate(b_lines, 1))
                b_header = f"--- File: {build_rs_path} (Complete Build Script, Lines 1-{len(b_lines)}) ---"
                block = f"{b_header}\n// Module: crate::build_script\n// Static call-site: Executed automatically by Cargo\n{numbered}\n"
                if current_chars + len(block) <= max_total_chars:
                    fallback_blocks.append(block)
                    current_chars += len(block)
                    record_range(build_rs_path, 1, len(b_lines))
                    functions_included.append(f"{build_rs_path}:build_rs:1")

        # 2. Add isolated source and sink functions with context
        isolated_nodes: list[FunctionDef] = []
        for fn in sorted(callgraph.nodes.values(), key=lambda f: (f.rel_path, f.start_line)):
            if fn.direct_sources or fn.direct_sinks:
                isolated_nodes.append(fn)

        shown_fb_files: set[str] = set()
        for fn in isolated_nodes:
            fn_key = fn.id
            if fn_key in functions_included:
                continue

            tag = "Taint Source" if fn.direct_sources else "Taint Sink"
            fn_block = format_contextual_function(fn, shown_fb_files)
            labeled_block = f"// [Isolated {tag}]\n{fn_block}\n"

            if current_chars + len(labeled_block) <= max_total_chars:
                fallback_blocks.append(labeled_block)
                current_chars += len(labeled_block)
                functions_included.append(fn_key)
                record_range(fn.rel_path, fn.start_line, fn.end_line)
            else:
                omitted_regions.append(f"Isolated site {fn_key}")

        formatted_text = "\n".join(fallback_blocks)

    # Check payload coverage against ground truth hunk
    payload_captured = False
    if manifest_sample:
        p_path = manifest_sample.get("payload_path")
        p_start = manifest_sample.get("payload_hunk_start")
        p_end = manifest_sample.get("payload_hunk_end")
        if p_path and p_start and p_end:
            for r_start, r_end in selected_line_ranges.get(p_path, []):
                if not (r_end < p_start or r_start > p_end):
                    payload_captured = True
                    break

    return {
        "formatted_text": formatted_text,
        "paths_found": len(paths),
        "fallback_used": fallback_used,
        "functions_included": functions_included,
        "selected_ranges": selected_line_ranges,
        "total_chars": len(formatted_text),
        "omitted_regions": omitted_regions,
        "payload_in_selected_context": payload_captured,
    }
