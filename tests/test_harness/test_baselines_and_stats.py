import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import pytest
from harness.baselines import run_size_baseline, run_grep_baseline, run_rule_only_baseline
from harness.stats import (
    wilson_score_interval,
    mcnemar_exact_test,
    paired_mcnemar,
    compute_metrics_for_sample_set,
    cluster_bootstrap_by_base,
    compute_pair_consistency,
)


def test_size_baseline():
    small_crate = {"build_rs": "fn main(){}", "source_files": {"src/lib.rs": "fn f(){}"}}
    res_small = run_size_baseline(small_crate, threshold_bytes=5000)
    assert res_small["classification"] == "MALICIOUS"

    large_crate = {"build_rs": "fn main(){}", "source_files": {"src/lib.rs": "a" * 10000}}
    res_large = run_size_baseline(large_crate, threshold_bytes=5000)
    assert res_large["classification"] == "BENIGN"


def test_grep_baseline():
    clean_crate = {"build_rs": "fn main(){}", "source_files": {"src/lib.rs": "pub fn add(a: i32) -> i32 { a + 1 }"}}
    res_clean = run_grep_baseline(clean_crate)
    assert res_clean["classification"] == "BENIGN"

    exfil_crate = {
        "build_rs": 'fn main() { let _ = std::net::TcpStream::connect("127.0.0.1:80"); }',
        "source_files": {},
    }
    res_exfil = run_grep_baseline(exfil_crate)
    assert res_exfil["classification"] == "MALICIOUS"


def test_rule_only_baseline():
    clean = {
        "name": "foo",
        "version": "1.0.0",
        "cargo_toml": '[package]\nname="foo"\n',
        "build_rs": "fn main(){}",
        "build_script_path": "build.rs",
        "source_files": {"src/lib.rs": "pub fn a() -> u32 { 1 }"},
    }
    res_clean = run_rule_only_baseline(clean)
    assert res_clean["classification"] == "BENIGN"

    exfil = {
        "name": "bad",
        "version": "1.0.0",
        "cargo_toml": '[package]\nname="bad"\n',
        "build_rs": 'fn main() { let s = std::net::TcpStream::connect("foo"); }',
        "build_script_path": "build.rs",
        "source_files": {},
    }
    res_exfil = run_rule_only_baseline(exfil)
    assert res_exfil["classification"] == "MALICIOUS"


def test_wilson_interval():
    low, high = wilson_score_interval(40, 50)
    assert 0.0 <= low <= 0.8 <= high <= 1.0


def test_mcnemar_exact_test():
    p1 = mcnemar_exact_test(0, 0)
    assert p1 == 1.0
    p2 = mcnemar_exact_test(15, 0)
    assert p2 < 0.01


def test_paired_mcnemar():
    r1 = [
        {"sample_id": "s1", "label": "MALICIOUS", "classification": {"classification": "MALICIOUS"}},
        {"sample_id": "s2", "label": "BENIGN", "classification": {"classification": "BENIGN"}},
        {"sample_id": "s3", "label": "MALICIOUS", "classification": {"classification": "MALICIOUS"}},
    ]
    r2 = [
        {"sample_id": "s1", "label": "MALICIOUS", "classification": {"classification": "BENIGN"}}, # discordant
        {"sample_id": "s2", "label": "BENIGN", "classification": {"classification": "BENIGN"}},
        {"sample_id": "s3", "label": "MALICIOUS", "classification": {"classification": "MALICIOUS"}},
    ]
    res = paired_mcnemar(r1, r2, strict=True)
    assert res["n_discordant"] == 1
    assert res["cond1_wins"] == 1
    assert res["cond2_wins"] == 0



def test_cluster_bootstrap():
    records = [
        {"cluster_id": "c1", "label": "MALICIOUS", "classification": {"classification": "MALICIOUS"}},
        {"cluster_id": "c1", "label": "BENIGN", "classification": {"classification": "BENIGN"}},
        {"cluster_id": "c2", "label": "MALICIOUS", "classification": {"classification": "MALICIOUS"}},
        {"cluster_id": "c2", "label": "BENIGN", "classification": {"classification": "BENIGN"}},
        {"cluster_id": "c3", "label": "MALICIOUS", "classification": {"classification": "BENIGN"}}, # FN
        {"cluster_id": "c3", "label": "BENIGN", "classification": {"classification": "BENIGN"}},
    ]
    ci = cluster_bootstrap_by_base(records, B=100, seed=42, strict=True)
    assert "recall_ci" in ci and "f1_ci" in ci
    rec_low, rec_high = ci["recall_ci"]
    assert 0.0 <= rec_low <= rec_high <= 1.0


def test_pair_consistency():
    records = [
        {"cluster_id": "c1", "label": "MALICIOUS", "classification": {"classification": "MALICIOUS"}},
        {"cluster_id": "c1", "label": "BENIGN", "classification": {"classification": "BENIGN"}},
        {"cluster_id": "c2", "label": "MALICIOUS", "classification": {"classification": "BENIGN"}},
        {"cluster_id": "c2", "label": "BENIGN", "classification": {"classification": "BENIGN"}},
    ]
    consistency = compute_pair_consistency(records, strict=True)
    assert consistency == 0.5
