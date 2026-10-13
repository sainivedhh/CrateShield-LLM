"""Tests for the tree-sitter taint-flow extractor.

These tests are self-contained and do not require the private benchmark
corpus: the sample crate directories are generated on the fly in a temporary
directory and CORPUS_DIR is shadowed before calling evaluate_sample_v3.
"""
import json
import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "fixtures"))
from fixtures.v3_samples import create_minimal_sample

from crateshield.taintflow import (
    TaintEngine, CrateCallGraph, RustASTParser,
    extract_taint_context,
)
from harness.hybrid_taint import build_hybrid_taint_prompt

ROOT = Path(__file__).resolve().parents[1]


def test_taint_engine_simple_paths():
    """A tiny two-function crate with a source calling a sink."""
    src = (
        'use std::env;\n'
        "use std::fs::File;\n"
        "fn steal() {\n"
        '    let secret = env::var("AWS_SECRET").unwrap();\n'
        '    File::create("/tmp/dump").unwrap();\n'
        "}\n"
    )
    parser = RustASTParser()
    info = parser.parse_file("src/lib.rs", src)
    assert len(info.functions) == 1
    assert info.functions[0].direct_sources
    assert info.functions[0].direct_sinks


def test_parse_file_empty():
    """Empty content returns an empty FileASTInfo."""
    parser = RustASTParser()
    info = parser.parse_file("src/lib.rs", "")
    assert info.functions == []
    assert info.imports == []


def test_parse_file_invalid_rust_falls_back():
    """Malformed Rust still produces a FileASTInfo without crashing."""
    parser = RustASTParser()
    info = parser.parse_file("src/lib.rs", "this is not rust {{{")
    assert isinstance(info, type(parser.parse_file("src/lib.rs", "pub fn x() {}")))


def test_extract_taint_context_no_paths():
    """A crate with no taint paths yields an empty context."""
    pre = {
        "name": "sha2",
        "version": "1.0.0",
        "cargo_toml": '[package]\nname = "sha2"\nversion = "1.0.0"\n',
        "build_rs": None,
        "build_script_path": None,
        "source_files": {"src/lib.rs": "pub fn add(a: i32, b: i32) -> i32 { a + b }"},
    }
    from harness.view import build_anonymized_view
    view = build_anonymized_view(pre, salt="crateshield-v3")
    result = extract_taint_context(view, manifest_sample={
        "sample_id": "s3_0035_malicious",
        "pair_id": "pair_01",
        "cluster_id": "sha2",
        "split": "eval",
        "twin_type": "malicious",
        "label": "MALICIOUS",
        "family": "F1",
        "seen_or_heldout": "SEEN",
        "ladder_level": "L1",
    })
    assert "formatted_text" in result
    assert result["paths_found"] == 0


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


def test_hybrid_taint_dry_run_cache_bypass(tmp_path, monkeypatch):
    """Verify that a stale dry_run=True cache entry for hybrid_taint is bypassed on a live call."""
    from scripts.v3.run_eval import evaluate_sample_v3

    sys.path.insert(0, str(Path(__file__).resolve().parent / "fixtures"))
    from fixtures.v3_samples import create_minimal_sample

    from scripts.v3 import run_eval as run_eval_v3
    corpus_dir = tmp_path / "corpus"
    create_minimal_sample(corpus_dir, "s3_0035_malicious", "sha2")
    run_eval_v3.CORPUS_DIR = corpus_dir

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
