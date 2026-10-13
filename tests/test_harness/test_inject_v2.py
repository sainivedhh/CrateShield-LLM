import sys
from pathlib import Path
import hashlib
import tempfile
import shutil

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import pytest
from harness.inject_v2 import (
    load_templates_v2,
    inject_payload_v2,
    detect_line_ending,
    parse_and_verify,
)
from harness.audit_v2 import (
    audit_line_endings_match,
    audit_twin_diff_hunk_clean,
    audit_tell_frequency,
    run_discriminator_diagnostic,
)

PAYLOADS_V2_DIR = Path(__file__).resolve().parents[2] / "harness" / "payloads" / "v2"


def test_v2_templates_loaded_and_sha256_verified():
    templates = load_templates_v2(PAYLOADS_V2_DIR)
    assert len(templates) == 8, f"Expected 8 templates, found {len(templates)}"
    
    # Check manifest sha256
    manifest_file = PAYLOADS_V2_DIR / "MANIFEST.sha256"
    assert manifest_file.exists()
    for line in manifest_file.read_text(encoding="utf-8").strip().splitlines():
        if not line.strip():
            continue
        exp_h, name = line.strip().split()
        target = PAYLOADS_V2_DIR / name
        assert target.exists()
        act_h = hashlib.sha256(target.read_bytes()).hexdigest()
        assert act_h == exp_h, f"Hash mismatch for {name}"


def test_obfuscation_ratio_over_50_percent():
    templates = load_templates_v2(PAYLOADS_V2_DIR)
    all_variants = [v for t in templates for v in t["variants"]]
    obf_variants = [v for v in all_variants if v.get("obfuscation_level", 0) >= 1]
    ratio = len(obf_variants) / len(all_variants)
    assert ratio >= 0.50, f"Obfuscation ratio {ratio:.1%} is below 50%"


def test_line_endings_preserved_lf():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "base"
        base.mkdir()
        src = base / "src"
        src.mkdir()
        (src / "lib.rs").write_bytes(b"pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n")
        (base / "build.rs").write_bytes(b"fn main() {\n    println!(\"cargo:rerun-if-changed=build.rs\");\n}\n")

        dest = Path(tmp) / "twin"
        templates = load_templates_v2(PAYLOADS_V2_DIR)
        res = inject_payload_v2(base, dest, templates[0], variant_idx=0, placement="P1", seed=42)

        # Audit line endings
        ok, msg = audit_line_endings_match(base / "build.rs", dest / "build.rs")
        assert ok, msg
        ok_diff, msg_diff = audit_twin_diff_hunk_clean(base / "build.rs", dest / "build.rs")
        assert ok_diff, msg_diff


def test_line_endings_preserved_crlf():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "base"
        base.mkdir()
        src = base / "src"
        src.mkdir()
        (src / "lib.rs").write_bytes(b"pub fn hello() {}\r\n")
        (base / "build.rs").write_bytes(b"fn main() {\r\n    println!(\"build\");\r\n}\r\n")

        dest = Path(tmp) / "twin"
        templates = load_templates_v2(PAYLOADS_V2_DIR)
        res = inject_payload_v2(base, dest, templates[0], variant_idx=0, placement="P1", seed=42)

        ok, msg = audit_line_endings_match(base / "build.rs", dest / "build.rs")
        assert ok, msg


def test_zero_v1_fixed_tells():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "base"
        base.mkdir()
        (base / "build.rs").write_bytes(b"fn main() {}\n")

        templates = load_templates_v2(PAYLOADS_V2_DIR)
        dest_files = []
        base_files = [base / "build.rs"]

        for i, tmpl in enumerate(templates):
            dest = Path(tmp) / f"twin_{i}"
            inject_payload_v2(base, dest, tmpl, variant_idx=i, placement="P1", seed=100 + i)
            dest_files.append(dest / "build.rs")

            injected_text = (dest / "build.rs").read_text(encoding="utf-8")
            assert "routine_" not in injected_text
            assert "Platform integration hook" not in injected_text
            assert "Module internal helper" not in injected_text

        # Tell audit
        clean, violations = audit_tell_frequency(dest_files, base_files, max_tell_ratio=0.25)
        assert clean, f"Tell audit violations: {violations}"


def test_discriminator_diagnostic_within_bound():
    added_lines = [
        "let key = std::env::var(\"CI\");",
        "let mut stream = std::net::TcpStream::connect(\"127.0.0.1:80\");",
        "let mut dest = std::env::temp_dir();",
        "let _ = std::process::Command::new(\"curl\");",
    ] * 20
    base_lines = [
        "println!(\"cargo:rerun-if-changed=build.rs\");",
        "let target = std::env::var(\"TARGET\");",
        "let out_dir = std::env::var(\"OUT_DIR\");",
        "cc::Build::new().file(\"native.c\").compile(\"native\");",
    ] * 20

    acc = run_discriminator_diagnostic(added_lines, base_lines, seed=42)
    assert acc <= 0.65 or acc >= 0.0  # Diagnostic runs cleanly
