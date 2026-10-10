"""Context extraction and formatting for hybrid_taint condition."""

from __future__ import annotations

from typing import Any, Optional

from .ast_parser import RustASTParser, FunctionDef, FileASTInfo
from .callgraph import CrateCallGraph
from .taint_engine import TaintEngine, TaintPath

BUILD_RS_SIZE_CAP_CHARS = 15000
TAINT_TOTAL_CHAR_BUDGET = 25000  # Matches HYBRID_TOTAL_CHAR_BUDGET (25,000)


def extract_taint_context(
    view: dict[str, Any],
    manifest_sample: Optional[dict[str, Any]] = None,
    max_total_chars: int = TAINT_TOTAL_CHAR_BUDGET,
    build_rs_max_chars: int = BUILD_RS_SIZE_CAP_CHARS,
) -> dict[str, Any]:
    """Extracts taint-guided code context via AST parsing and call-graph path walking."""
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

    # 3. Find taint paths
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

    if paths:
        # Connected paths found! Format path-delimited code context
        path_summaries: list[dict[str, Any]] = []
        shown_functions: set[str] = set()

        for idx, p in enumerate(paths, 1):
            path_header = f"=== Taint Flow Path {idx}: {p.source_desc} -> {p.sink_desc} (Length: {p.length}, Type: {p.path_type}) ==="
            path_blocks = [path_header]

            for fn in p.nodes:
                fn_key = fn.id
                functions_included.append(fn_key)
                record_range(fn.rel_path, fn.start_line, fn.end_line)

                # Format function block
                file_info = callgraph.files.get(fn.rel_path)
                imports_note = ""
                if fn_key not in shown_functions and file_info and file_info.imports:
                    imports_note = "// Key imports:\n" + "\n".join(f"//   {imp}" for imp in file_info.imports[:4]) + "\n"

                impl_note = f" (in impl {fn.impl_type})" if fn.impl_type else ""
                fn_header = f"--- File: {fn.rel_path} (Lines {fn.start_line}-{fn.end_line}) [fn {fn.name}{impl_note}] ---"

                # Line-number the function code
                file_content = source_files.get(fn.rel_path, "")
                file_lines = file_content.splitlines() if file_content else []
                numbered_lines = []
                for l_idx in range(fn.start_line, min(fn.end_line + 1, len(file_lines) + 1)):
                    line_txt = file_lines[l_idx - 1] if l_idx - 1 < len(file_lines) else ""
                    numbered_lines.append(f"{l_idx:4d}: {line_txt}")

                fn_block = f"{imports_note}{fn_header}\n" + "\n".join(numbered_lines)
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
        # Fallback mode: no connected path found
        fallback_used = True
        fallback_blocks: list[str] = [
            "NOTE: No connected source-sink path found; showing isolated sites and build script context."
        ]

        # 1. Include full build.rs if eligible
        if build_rs_src:
            if len(build_rs_src) <= build_rs_max_chars:
                b_lines = build_rs_src.splitlines()
                numbered = "\n".join(f"{idx:4d}: {l}" for idx, l in enumerate(b_lines, 1))
                b_header = f"--- File: {build_rs_path} (Complete Build Script, Lines 1-{len(b_lines)}) ---"
                block = f"{b_header}\n{numbered}\n"
                if current_chars + len(block) <= max_total_chars:
                    fallback_blocks.append(block)
                    current_chars += len(block)
                    functions_included.append(f"{build_rs_path}:<full>")
                    record_range(build_rs_path, 1, len(b_lines))
                else:
                    omitted_regions.append(f"{build_rs_path} (exceeds budget)")
            else:
                omitted_regions.append(f"{build_rs_path} (size > 15KB)")

        # 2. Include isolated sources or sinks
        isolated_nodes = callgraph.get_source_nodes() + callgraph.get_sink_nodes()
        seen_iso: set[str] = set()

        for fn in isolated_nodes:
            if fn.id in seen_iso:
                continue
            seen_iso.add(fn.id)
            functions_included.append(fn.id)
            record_range(fn.rel_path, fn.start_line, fn.end_line)

            site_type = "source" if fn.direct_sources else "sink"
            pat = fn.direct_sources[0].pattern if fn.direct_sources else (fn.direct_sinks[0].pattern if fn.direct_sinks else "")
            header = f"--- Isolated {site_type} site: {pat} in File: {fn.rel_path} (Lines {fn.start_line}-{fn.end_line}) [fn {fn.name}] ---"

            file_content = source_files.get(fn.rel_path, "")
            file_lines = file_content.splitlines() if file_content else []
            numbered_lines = []
            for l_idx in range(fn.start_line, min(fn.end_line + 1, len(file_lines) + 1)):
                line_txt = file_lines[l_idx - 1] if l_idx - 1 < len(file_lines) else ""
                numbered_lines.append(f"{l_idx:4d}: {line_txt}")

            iso_block = f"{header}\n" + "\n".join(numbered_lines) + "\n"
            if current_chars + len(iso_block) <= max_total_chars:
                fallback_blocks.append(iso_block)
                current_chars += len(iso_block)
            else:
                omitted_regions.append(f"{fn.rel_path}: {fn.name}")

        formatted_text = "\n".join(fallback_blocks)

    # 4. Check payload_in_selected_context
    payload_in_selected_context = False
    if manifest_sample and manifest_sample.get("twin_type") == "malicious":
        carrier = manifest_sample.get("carrier")
        hunk_ranges = manifest_sample.get("hunk_line_ranges") or []

        if carrier and hunk_ranges:
            selected_for_carrier = selected_line_ranges.get(carrier, [])
            # Also check if carrier was included with relative path prefix or basename
            if not selected_for_carrier:
                for k, ranges in selected_line_ranges.items():
                    if k.endswith(carrier) or carrier.endswith(k):
                        selected_for_carrier = ranges
                        break

            # Check overlap between selected ranges and hunk ranges
            for h_start, h_end in hunk_ranges:
                for s_start, s_end in selected_for_carrier:
                    if max(h_start, s_start) <= min(h_end, s_end):
                        payload_in_selected_context = True
                        break
                if payload_in_selected_context:
                    break

    path_lengths = [p.length for p in paths]

    return {
        "formatted_text": formatted_text,
        "paths_found": len(paths),
        "path_lengths": path_lengths,
        "fallback_used": fallback_used,
        "functions_included": functions_included,
        "total_chars": current_chars,
        "omitted_regions": omitted_regions,
        "payload_in_selected_context": payload_in_selected_context,
    }
