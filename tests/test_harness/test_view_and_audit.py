import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import pytest
from harness.view import (
    compute_view_id,
    scrub_cargo_toml,
    scrub_source_code,
    build_anonymized_view,
    build_negative_control_views,
    derive_version_flags,
)
from harness.audit import audit_view, assert_gate_g1


def test_compute_view_id_format():
    vid1 = compute_view_id("serde")
    vid2 = compute_view_id("serde")
    vid3 = compute_view_id("tokio")
    assert vid1.startswith("crate_")
    assert len(vid1) == 14  # 'crate_' + 8 hex chars
    assert vid1 == vid2
    assert vid1 != vid3


def test_scrub_cargo_toml():
    manifest = """[package]
name = "my-awesome-crate"
version = "1.2.3"
authors = ["Alice <alice@example.com>"]
repository = "https://github.com/alice/my-awesome-crate"
description = "A great crate"

[dependencies]
serde = "1.0"
"""
    cleaned = scrub_cargo_toml(manifest, "crate_deadbeef", real_name="my-awesome-crate")
    assert 'name = "crate_deadbeef"' in cleaned
    assert "authors" not in cleaned
    assert "repository" not in cleaned
    assert "description" not in cleaned
    assert 'serde = "1.0"' in cleaned
    assert "my-awesome-crate" not in cleaned


def test_scrub_source_code():
    code = """// Welcome to my-crate!
use my_crate::helper;
pub fn info() -> &'static str {
    "Powered by my-crate version 1.0"
}
"""
    cleaned = scrub_source_code(code, "my-crate", "crate_12345678")
    assert "my-crate" not in cleaned
    assert "my_crate" not in cleaned
    assert "crate_12345678" in cleaned


def test_derive_version_flags():
    f1 = derive_version_flags("0.1.0")
    assert f1["pre_1_0"] is True
    assert f1["high_major"] is False

    f2 = derive_version_flags("99.0.0")
    assert f2["high_major"] is True
    assert f2["pre_1_0"] is False

    f3 = derive_version_flags("1.0.0-alpha")
    assert f3["is_prerelease"] is True


def test_gate_g1_passes_on_anonymized_view():
    preprocessed = {
        "name": "legit-tool",
        "version": "1.0.0",
        "cargo_toml": '[package]\nname = "legit-tool"\nversion = "1.0.0"\nauthors = ["Dev"]\n',
        "build_rs": "fn main() { println!(\"legit-tool build\"); }",
        "build_script_path": "build.rs",
        "source_files": {
            "src/lib.rs": "pub fn hello() { println!(\"legit-tool running\"); }",
        },
    }
    view = build_anonymized_view(preprocessed)
    violations = audit_view(view)
    assert violations == []
    assert_gate_g1(view)


def test_gate_g1_catches_leaks():
    leaky_view = {
        "view_id": "crate_00000000",
        "original_name": "secret-crate",
        "name": "crate_00000000",
        "cargo_toml": '[package]\nname = "crate_00000000"\n',
        "build_rs": None,
        "source_files": {
            "src/lib.rs": "pub fn run() { println!(\"I am secret-crate\"); }",
        },
    }
    violations = audit_view(leaky_view)
    assert any("secret-crate" in v for v in violations)

    forbidden_view = {
        "view_id": "crate_00000000",
        "original_name": "clean",
        "name": "crate_00000000",
        "cargo_toml": '[package]\nname = "crate_00000000"\n',
        "build_rs": None,
        "source_files": {
            "src/lib.rs": "// defanged mock_exfiltration test\npub fn run() {}",
        },
    }
    violations2 = audit_view(forbidden_view)
    assert any("Forbidden leak term" in v for v in violations2)


def test_negative_controls_structure():
    preprocessed = {
        "name": "my-tool",
        "version": "1.0.0",
        "cargo_toml": '[package]\nname = "my-tool"\nversion = "1.0.0"\n',
        "build_rs": "fn main() {}",
        "build_script_path": "build.rs",
        "source_files": {"src/lib.rs": "pub fn f() {}"},
    }
    view = build_anonymized_view(preprocessed)
    controls = build_negative_control_views(view)
    assert "name_only" in controls and "metadata_only" in controls
    assert controls["name_only"]["source_files"] == {}
    assert controls["name_only"]["build_rs"] is None
    assert controls["metadata_only"]["source_files"] == {}
