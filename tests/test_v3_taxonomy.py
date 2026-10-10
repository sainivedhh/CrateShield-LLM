"""Unit tests for Benchmark v3 taxonomy and coverage matrix (Phase 1)."""
from pathlib import Path
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
TAXONOMY_PATH = ROOT / "data" / "bench_v3" / "taxonomy.yaml"
MATRIX_PATH = ROOT / "data" / "bench_v3" / "coverage_matrix.md"

DETECTOR_KEYWORDS = [
    "signal_manifest", "build_rs_net", "unsafe_ffi", "crateshield.signals",
    "harness.baselines", "rule_only", "eval_cache", "results_summary"
]


def test_taxonomy_structure_and_counts():
    assert TAXONOMY_PATH.exists(), "taxonomy.yaml must exist"
    data = yaml.safe_load(TAXONOMY_PATH.read_text(encoding="utf-8"))
    
    assert data["version"] == "3.0"
    families = data.get("families", [])
    assert len(families) == 8, f"Expected 8 families, got {len(families)}"
    
    fids = [f["id"] for f in families]
    expected_ids = [f"F{i}" for i in range(1, 9)]
    assert fids == expected_ids, f"Expected {expected_ids}, got {fids}"
    
    seen = [f for f in families if f["split"] == "SEEN"]
    held_out = [f for f in families if f["split"] == "HELD-OUT"]
    
    assert len(seen) == 5, f"Expected 5 seen families, got {len(seen)}"
    assert len(held_out) >= 3, f"Expected >= 3 held-out families, got {len(held_out)}"
    assert set(f["id"] for f in held_out) == {"F5", "F6", "F8"}


def test_taxonomy_firewall_and_specs():
    data = yaml.safe_load(TAXONOMY_PATH.read_text(encoding="utf-8"))
    families = data.get("families", [])
    
    for f in families:
        fid = f["id"]
        assert f.get("behaviour_spec"), f"Missing behaviour_spec in {fid}"
        assert f.get("benign_lookalike_spec"), f"Missing benign_lookalike_spec in {fid}"
        assert f.get("allowed_carriers"), f"Missing allowed_carriers in {fid}"
        assert len(f["allowed_carriers"]) > 0
        
        # Check firewall: specs must not contain detector keywords
        spec_text = (f["behaviour_spec"] + " " + f["benign_lookalike_spec"]).lower()
        for kw in DETECTOR_KEYWORDS:
            assert kw not in spec_text, f"Detector keyword '{kw}' leaked into spec for {fid}"


def test_coverage_matrix_generated():
    assert MATRIX_PATH.exists(), "coverage_matrix.md must exist"
    content = MATRIX_PATH.read_text(encoding="utf-8")
    for i in range(1, 9):
        assert f"F{i}" in content, f"Family F{i} missing in coverage_matrix.md"
    assert "HELD-OUT" in content
    assert "SEEN" in content