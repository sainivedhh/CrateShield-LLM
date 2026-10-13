"""Signal 1 -- build.rs analyzer.

build.rs executes arbitrary code at `cargo build` time, before any runtime
security control applies. This is the highest-value signal in the pipeline,
so its false-positive rate matters: running it on serde 1.0.210's real
build.rs (which only reads TARGET/RUSTC and shells out to `rustc --version`
to detect available language features) originally flagged both
env_var_read and process_spawn, which would poison every downstream
prompt with a false alarm on one of the most common crates in the
ecosystem. This version keeps raw pattern matches but separates them into
"benign-explained" (matches Cargo's own documented build-script
conventions) and "unexplained" hits, and only the unexplained ones count
as a fired signal. Detection is regex-based, not an AST -- see the
`source_scan` signal for a broader (also regex-based) library-code pass.
"""
from __future__ import annotations

import re

NETWORK_PATTERNS = [
    r"TcpStream::connect", r"UdpSocket::bind", r"\breqwest\b",
    r"\bureq\b", r"\bhyper\b", r"curl::", r"std::net::",
]
FILE_WRITE_PATTERNS = [
    r"fs::write", r"File::create", r"OpenOptions", r"BufWriter",
]
PROCESS_PATTERNS = [
    r"Command::new", r"process::Command", r"\bexec\s*\(",
]
ENV_READ_PATTERNS = [
    r"env::var\b", r"env::vars\b", r"env::var_os",
]

_ALL_GROUPS = {
    "network_call": NETWORK_PATTERNS,
    "file_write": FILE_WRITE_PATTERNS,
    "process_spawn": PROCESS_PATTERNS,
    "env_var_read": ENV_READ_PATTERNS,
}

# https://doc.rust-lang.org/cargo/reference/environment-variables.html#environment-variables-cargo-sets-for-build-scripts
_CARGO_BUILD_ENV_VARS = {
    "OUT_DIR", "CARGO", "CARGO_MANIFEST_DIR", "CARGO_MANIFEST_PATH", "CARGO_PKG_NAME",
    "CARGO_PKG_VERSION", "CARGO_PKG_VERSION_MAJOR", "CARGO_PKG_VERSION_MINOR",
    "CARGO_PKG_VERSION_PATCH", "CARGO_PKG_VERSION_PRE", "CARGO_PKG_AUTHORS",
    "CARGO_PKG_DESCRIPTION", "CARGO_PKG_HOMEPAGE", "CARGO_PKG_REPOSITORY",
    "CARGO_PKG_LICENSE", "CARGO_PKG_LICENSE_FILE", "CARGO_PKG_RUST_VERSION",
    "CARGO_PKG_README", "CARGO_CFG_TARGET_ARCH", "CARGO_CFG_TARGET_OS",
    "CARGO_CFG_TARGET_FAMILY", "CARGO_CFG_TARGET_ENV", "CARGO_CFG_TARGET_ENDIAN",
    "CARGO_CFG_TARGET_POINTER_WIDTH", "CARGO_CFG_TARGET_VENDOR",
    "CARGO_CFG_TARGET_FEATURE", "CARGO_CFG_UNIX", "CARGO_CFG_WINDOWS",
    "OPT_LEVEL", "DEBUG", "PROFILE", "TARGET", "HOST", "NUM_JOBS", "RUSTC",
    "RUSTC_LINKER", "RUSTDOC", "RUSTC_WRAPPER", "RUSTFLAGS", "HOST_RUSTFLAGS",
    "RUSTC_BOOTSTRAP",
}
_ENV_VAR_LITERAL = re.compile(r'env::var(?:_os)?\s*\(\s*"([A-Za-z0-9_]+)"\s*\)')

# `Command::new(rustc)` / `Command::new("rustc")` piped into `--version` / `-vV`
# to probe compiler capabilities is Cargo's own documented pattern; see e.g.
# the widely-copied rustc_version crate and every build.rs that gates on
# rustc features. It is not the same shape as spawning a shell or a
# downloaded binary, which is why this is a narrow allowlist, not a general
# "any Command call is fine" pass.
_RUSTC_PROBE = re.compile(
    r'Command::new\s*\(\s*(?:rustc|&rustc|"rustc"|rustc_bin)\s*\)'
    r'(?:\s*\.\s*(?:arg|args)\s*\([^)]*\))*\s*\.\s*(?:arg|args)\s*\(\s*"(?:--version|-vV|-V)"',
    re.DOTALL,
)


_USE_LINE = re.compile(r"^\s*use\s+")


def _find_matches(source: str, patterns: list[str]) -> list[str]:
    """`use std::process::Command;` matches the text "process::Command" but
    is an import, not a call site, so `use` lines are excluded here."""
    hits = []
    for pat in patterns:
        for m in re.finditer(pat, source):
            line_start = source.rfind("\n", 0, m.start()) + 1
            line_end = source.find("\n", m.end())
            line_end = line_end if line_end != -1 else len(source)
            line = source[line_start:line_end].strip()
            if _USE_LINE.match(source[line_start:line_end]):
                continue
            hits.append(line)
    return hits


def _classify_env_reads(lines: list[str]) -> tuple[list[str], list[str]]:
    benign, unexplained = [], []
    for line in lines:
        m = _ENV_VAR_LITERAL.search(line)
        if m and m.group(1) in _CARGO_BUILD_ENV_VARS:
            benign.append(line)
        else:
            unexplained.append(line)
    return benign, unexplained


def _classify_process_spawns(source: str, lines: list[str]) -> tuple[list[str], list[str]]:
    if not lines:
        return [], []
    probe_spans = {m.group(0) for m in _RUSTC_PROBE.finditer(source)}
    if not probe_spans:
        return [], lines
    # A line counts as explained only if it participates in a matched probe block
    # (the call spans multiple lines via .arg() chaining, so match on substring).
    benign, unexplained = [], []
    for line in lines:
        if any(block in line for block in probe_spans):
            benign.append(line)
        else:
            unexplained.append(line)
    return benign, unexplained


def analyze_build_rs(build_rs_source: str | None) -> dict:
    if not build_rs_source:
        return {
            "has_build_rs": False, "signals": [],
            "network_calls": [], "env_reads": [],
            "file_writes": [], "process_spawns": [], "flagged_snippets": [],
            "benign_explained": {},
        }

    result = {"has_build_rs": True, "signals": []}
    all_snippets: list[str] = []
    benign_explained: dict[str, list[str]] = {}

    result["network_calls"] = _find_matches(build_rs_source, NETWORK_PATTERNS)
    raw_env = _find_matches(build_rs_source, ENV_READ_PATTERNS)
    result["file_writes"] = _find_matches(build_rs_source, FILE_WRITE_PATTERNS)
    raw_proc = _find_matches(build_rs_source, PROCESS_PATTERNS)

    env_benign, env_unexplained = _classify_env_reads(raw_env)
    proc_benign, proc_unexplained = _classify_process_spawns(build_rs_source, raw_proc)
    if env_benign:
        benign_explained["env_var_read"] = env_benign
    if proc_benign:
        benign_explained["process_spawn"] = proc_benign
    result["env_reads"] = env_unexplained
    result["process_spawns"] = proc_unexplained
    result["benign_explained"] = benign_explained

    for key, group_name in [
        ("network_calls", "network_call"), ("env_reads", "env_var_read"),
        ("file_writes", "file_write"), ("process_spawns", "process_spawn"),
    ]:
        if result[key]:
            result["signals"].append(group_name)
            all_snippets.extend(result[key][:3])  # cap snippet volume

    result["flagged_snippets"] = all_snippets[:10]
    return result
