"""Regression tests for v3.1 fixes:
1. Report classification key matches parser key
2. Dry-run / live cache collision isolation
3. Oversized crate exceeds_context cache write
"""
import json
import sys
import pytest
from pathlib import Path
from crateshield.llm.parser import PARSER_CLASSIFICATION_KEY, parse_llm_response
from scripts.v3.make_report_v3 import REPORT_CLASSIFICATION_KEY, is_malicious

sys.path.insert(0, str(Path(__file__).resolve().parent / "fixtures"))
from fixtures.v3_samples import create_minimal_sample

ROOT = Path(__file__).resolve().parents[1]


def test_report_key_matches_parser_key():
    """Assert the key used in make_report_v3 matches what parser.py emits."""
    assert REPORT_CLASSIFICATION_KEY == PARSER_CLASSIFICATION_KEY == "classification"

    # Test with standard parser output
    mock_mal = '{"classification": "MALICIOUS", "confidence": "HIGH", "malware_score": 0.95, "reasoning": "malicious exfil"}'
    parsed_mal = parse_llm_response(mock_mal)
    assert PARSER_CLASSIFICATION_KEY in parsed_mal
    assert parsed_mal[PARSER_CLASSIFICATION_KEY] == "MALICIOUS"
    assert is_malicious({"classification": parsed_mal}) is True

    mock_ben = '{"classification": "BENIGN", "confidence": "HIGH", "malware_score": 0.05, "reasoning": "clean crate"}'
    parsed_ben = parse_llm_response(mock_ben)
    assert PARSER_CLASSIFICATION_KEY in parsed_ben
    assert parsed_ben[PARSER_CLASSIFICATION_KEY] == "BENIGN"
    assert is_malicious({"classification": parsed_ben}) is False

    # Test tolerance for models that emit "verdict"
    mock_verdict = '{"verdict": "MALICIOUS", "confidence": 0.9, "malware_score": 0.9, "reasoning": "verdict key"}'
    parsed_verdict = parse_llm_response(mock_verdict)
    assert parsed_verdict[PARSER_CLASSIFICATION_KEY] == "MALICIOUS"
    assert is_malicious({"classification": parsed_verdict}) is True


def _setup_v3_corpus(tmp_path: Path, corpus_name: str = "corpus") -> Path:
    """Creates a temporary benchmark-v3 corpus containing the two samples the
    tests exercise, then shadows the CORPUS_DIR used by scripts.v3.run_eval so
    no private corpus is required."""
    corpus_dir = tmp_path / corpus_name
    create_minimal_sample(corpus_dir, "s3_0035_malicious", "sha2")
    create_minimal_sample(corpus_dir, "s3_0149_malicious", "tokio_wasi")
    from scripts.v3 import run_eval
    run_eval.CORPUS_DIR = corpus_dir
    return corpus_dir


def test_dry_run_cache_isolation(tmp_path, monkeypatch):
    """Test that dry-run pass sets dry_run=True and live run refuses to hit dry-run cache."""
    from scripts.v3.run_eval import evaluate_sample_v3, make_cache_key

    _setup_v3_corpus(tmp_path)

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

    # 1. Run dry run
    dry_res = evaluate_sample_v3(sample_meta, "raw", "gemini-3.5-flash-lite", cache, repeat=0, dry_run=True)
    assert dry_res["dry_run"] is True
    assert dry_res["finish_reason"] == "dry_run"

    # If the dry_run entry is in cache (or quarantined):
    # Verify live evaluation refuses dry_run entries as cache hits:
    cache_key = next(iter(cache.keys())) if cache else "dummy"
    assert (cache[cache_key].get("dry_run") is True or cache[cache_key].get("finish_reason") == "dry_run")

    # Mock call_model_api to track whether a real call is made during live evaluation
    call_count = 0
    def mock_call_model_api(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return json.dumps({
            "classification": "MALICIOUS",
            "confidence": "HIGH",
            "malware_score": 0.95,
            "reasoning": "real live call"
        }), 100, 50, 0.001, "STOP"

    monkeypatch.setattr("scripts.v3.run_eval.call_model_api", mock_call_model_api)

    # 2. Run live pass (dry_run=False) with the dry-run polluted cache
    live_res = evaluate_sample_v3(sample_meta, "raw", "gemini-3.5-flash-lite", cache, repeat=0, dry_run=False)
    assert call_count == 1, "Live evaluation must NOT treat dry_run cache entry as a cache hit!"
    assert live_res["dry_run"] is False
    assert live_res["classification"]["classification"] == "MALICIOUS"
    assert live_res["finish_reason"] == "STOP"

    # 3. Run second live pass: must hit the live cache entry (call_count remains 1)
    second_live_res = evaluate_sample_v3(sample_meta, "raw", "gemini-3.5-flash-lite", cache, repeat=0, dry_run=False)
    assert call_count == 1, "Second live pass must hit live cache without calling API!"
    assert second_live_res["classification"]["classification"] == "MALICIOUS"


def test_exceeds_context_writes_cache(tmp_path, monkeypatch):
    """Test that exceeds_context branch (~332-363) writes to cache before returning."""
    from scripts.v3.run_eval import evaluate_sample_v3

    corpus_dir = _setup_v3_corpus(tmp_path)
    # Make the tokio_wasi sample exceed the 600k char raw_full budget.
    create_minimal_sample(corpus_dir, "s3_0149_malicious", "tokio_wasi", source_chars=700_000)

    cache = {}
    sample_meta = {
        "sample_id": "s3_0149_malicious",
        "pair_id": "pair_50",
        "cluster_id": "tokio_wasi",
        "split": "eval",
        "twin_type": "malicious",
        "label": "MALICIOUS",
        "family": "F2",
        "seen_or_heldout": "SEEN",
        "ladder_level": "L4",
    }

    # Evaluate on raw_full with dry_run=False
    res = evaluate_sample_v3(sample_meta, "raw_full", "gemini-3.5-flash-lite", cache, repeat=0, dry_run=False)
    assert res["classification"]["classification"] == "BENIGN"
    assert "exceeds_context" in res["classification"]["primary_signals"]

    # Verify that cache contains this entry
    matching_keys = [k for k in cache if "s3_0149_malicious" in k and "raw_full" in k]
    assert len(matching_keys) == 1, f"Expected cache write for oversized crate, found {len(matching_keys)}"
    cached_entry = cache[matching_keys[0]]
    assert cached_entry["sample_id"] == "s3_0149_malicious"
    assert cached_entry["classification"]["classification"] == "BENIGN"
