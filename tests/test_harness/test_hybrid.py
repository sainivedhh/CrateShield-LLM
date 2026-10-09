"""Unit tests for harness.hybrid (Phase 4)."""
from __future__ import annotations

import json
from harness.hybrid import (
    BUILD_RS_SIZE_CAP_CHARS,
    HYBRID_TOTAL_CHAR_BUDGET,
    WINDOW_RADIUS,
    build_hybrid_prompt,
    extract_targeted_code_windows,
)


def test_extract_targeted_code_windows_basic():
    preprocessed = {
        "name": "test_crate",
        "version": "1.0.0",
        "build_rs": "fn main() {\n    let _ = 42;\n}\n",
        "build_script_path": "build.rs",
        "source_files": {
            "src/lib.rs": (
                "// Header\n"
                "use std::net::TcpStream;\n"
                + "\n".join(f"// padding line {i}" for i in range(1, 20))
                + "\npub fn connect() {\n    let _ = TcpStream::connect(\"127.0.0.1:8080\");\n}\n"
                + "\n".join(f"// tail line {i}" for i in range(1, 20))
            ),
        },
    }

    res = extract_targeted_code_windows(preprocessed, window_radius=5)
    assert res["build_rs_included_full"] is True
    assert "build.rs" in res["files_covered"]
    assert "src/lib.rs" in res["files_covered"]
    assert "TcpStream::connect" in res["formatted_text"]
    assert res["total_chars"] > 0
    assert len(res["omitted_regions"]) == 0


def test_window_merging_overlapping_ranges():
    # Two signals close to each other should produce one merged interval
    source = "\n".join(f"line_{i}" for i in range(1, 100))
    # inject signals at line 30 and line 35
    lines = source.splitlines()
    lines[29] = 'let _ = Command::new("ls");'
    lines[34] = 'let _ = TcpStream::connect("host:80");'
    modified_source = "\n".join(lines)

    preprocessed = {
        "name": "merge_test",
        "version": "0.1.0",
        "build_rs": None,
        "source_files": {"src/main.rs": modified_source},
    }

    res = extract_targeted_code_windows(preprocessed, window_radius=10)
    assert "src/main.rs" in res["files_covered"]
    # Should have merged into a single interval covering lines (30-10) to (35+10) = 20 to 45
    assert "Lines 20-45" in res["formatted_text"]


def test_budget_exceeded_omitted_regions():
    # Test strict enforcement of max_total_chars
    source = "\n".join(f"let _ = Command::new(\"cmd_{i}\");" for i in range(100))
    preprocessed = {
        "name": "budget_test",
        "version": "0.1.0",
        "build_rs": None,
        "source_files": {"src/heavy.rs": source},
    }

    res = extract_targeted_code_windows(preprocessed, max_total_chars=500)
    assert res["total_chars"] <= 500
    assert len(res["omitted_regions"]) > 0
    assert "budget" in res["omitted_regions"][0] or "lines" in res["omitted_regions"][0]


def test_build_hybrid_prompt_structure():
    signals = {"crate": "demo", "version": "0.1.0", "build_rs": {"has_build_rs": False}}
    code_windows = {
        "formatted_text": "--- File: src/lib.rs (Lines 1-10) ---\n   1: fn test() {}",
        "omitted_regions": ["src/extra.rs: lines 1-30"],
        "files_covered": ["src/lib.rs"],
    }
    retrieved = [
        {"id": "doc_1", "type": "incident", "similarity": 0.85, "title": "Test Incident", "text": "Details here"}
    ]

    # With RAG
    prompt_rag = build_hybrid_prompt(signals, code_windows, retrieved_context=retrieved)
    assert len(prompt_rag) > 1
    user_msg = prompt_rag[-1]["content"]
    assert "<untrusted_crate_data>" in user_msg
    assert "</untrusted_crate_data>" in user_msg
    assert "Targeted source code windows around flagged signals" in user_msg
    assert "Omitted regions (budget limit)" in user_msg
    assert "doc_1" in user_msg

    # Without RAG (hybrid_norag)
    prompt_norag = build_hybrid_prompt(signals, code_windows, retrieved_context=None)
    user_msg_norag = prompt_norag[-1]["content"]
    assert "<untrusted_crate_data>" in user_msg_norag
    assert "doc_1" not in user_msg_norag
    assert "(none provided" in user_msg_norag
