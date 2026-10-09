import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import pytest
from harness.inject import load_templates, randomize_identifiers, inject_payload, parse_and_verify


PAYLOADS_DIR = Path(__file__).resolve().parents[2] / "harness" / "payloads" / "v1"


def test_load_all_templates():
    templates = load_templates(PAYLOADS_DIR)
    assert len(templates) >= 8
    categories = {t["category"] for t in templates}
    assert {"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8"}.issubset(categories)


def test_randomize_identifiers():
    code = "fn do_something() { let a = 1; }\n"
    new_code, fn_name = randomize_identifiers(code, seed=123)
    assert "fn do_something" not in new_code
    assert fn_name in new_code
    assert fn_name.startswith("routine_")


def test_inject_payload_p1(tmp_path):
    base_dir = tmp_path / "base_crate"
    base_dir.mkdir()
    (base_dir / "Cargo.toml").write_text('[package]\nname = "test_pkg"\nversion = "0.1.0"\n')
    (base_dir / "build.rs").write_text("fn main() {\n    println!(\"build ok\");\n}\n")
    (base_dir / "src").mkdir()
    (base_dir / "src" / "lib.rs").write_text("pub fn run() -> i32 { 42 }\n")

    templates = load_templates(PAYLOADS_DIR)
    c1 = next(t for t in templates if t["category"] == "C1")

    twin_dir = tmp_path / "twin_crate"
    res = inject_payload(base_dir, twin_dir, c1, variant_idx=0, placement="P1", seed=42)

    assert res["category"] == "C1"
    assert "build.rs" in res["modified_files"]
    assert res["payload_bytes"] > 0

    # Verify syntax with tree-sitter
    assert parse_and_verify((twin_dir / "build.rs").read_bytes())
    assert parse_and_verify((twin_dir / "src" / "lib.rs").read_bytes())


def test_inject_payload_p2(tmp_path):
    base_dir = tmp_path / "base_crate2"
    base_dir.mkdir()
    (base_dir / "Cargo.toml").write_text('[package]\nname = "test_pkg2"\nversion = "0.1.0"\n')
    (base_dir / "build.rs").write_text("fn main() {}\n")
    (base_dir / "src").mkdir()
    (base_dir / "src" / "lib.rs").write_text("pub fn run() -> i32 { 42 }\n")

    templates = load_templates(PAYLOADS_DIR)
    c4 = next(t for t in templates if t["category"] == "C4")

    twin_dir = tmp_path / "twin_crate2"
    res = inject_payload(base_dir, twin_dir, c4, variant_idx=0, placement="P2", seed=99)

    assert res["category"] == "C4"
    assert "src/lib.rs" in res["modified_files"] or "src\\lib.rs" in res["modified_files"]

    # Verify syntax with tree-sitter
    assert parse_and_verify((twin_dir / "src" / "lib.rs").read_bytes())
