import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import pytest
from harness.manifest import BenchmarkManifest, SampleRecord, save_manifest, load_manifest
from harness.split import split_base_crates


def test_manifest_validation_and_disjointness(tmp_path):
    m = BenchmarkManifest(version="v1", seed=42)
    # Add tune record
    r1 = SampleRecord(
        sample_id="s1", view_id="crate_1", pair_id="p1", cluster_id="base_a",
        tier=3, split="tune", label="BENIGN", label_evidence="clean",
        base_crate="base_a", base_version="1.0.0", dump_date="2026-10-08"
    )
    # Add eval record with different base
    r2 = SampleRecord(
        sample_id="s2", view_id="crate_2", pair_id="p2", cluster_id="base_b",
        tier=3, split="eval", label="BENIGN", label_evidence="clean",
        base_crate="base_b", base_version="1.0.0", dump_date="2026-10-08"
    )
    m.records = [r1, r2]
    assert m.validate_disjointness() is True

    # Test serialization
    out_file = tmp_path / "manifest.json"
    save_manifest(m, out_file)
    loaded = load_manifest(out_file)
    assert len(loaded.records) == 2
    assert loaded.get_tune_bases() == {"base_a"}
    assert loaded.get_eval_bases() == {"base_b"}


def test_gate_g6_overlap_raises():
    m = BenchmarkManifest(version="v1")
    # Intentional overlap violation: base_a in both tune and eval
    r1 = SampleRecord(
        sample_id="s1", view_id="crate_1", pair_id="p1", cluster_id="base_a",
        tier=3, split="tune", label="BENIGN", label_evidence="clean",
        base_crate="base_a", base_version="1.0.0", dump_date="2026-10-08"
    )
    r2 = SampleRecord(
        sample_id="s2", view_id="crate_1", pair_id="p1", cluster_id="base_a",
        tier=3, split="eval", label="MALICIOUS", label_evidence="injected",
        base_crate="base_a", base_version="1.0.0", dump_date="2026-10-08"
    )
    m.records = [r1, r2]
    with pytest.raises(AssertionError, match="Gate G6 violation"):
        m.validate_disjointness()


def test_split_base_crates():
    bases = [{"name": f"crate_{i}", "version": "1.0.0"} for i in range(40)]
    tune, ev = split_base_crates(bases, n_tune=10, n_eval=30, seed=42)
    assert len(tune) == 10
    assert len(ev) == 30
    tune_names = {b["name"] for b in tune}
    eval_names = {b["name"] for b in ev}
    assert tune_names.isdisjoint(eval_names)
