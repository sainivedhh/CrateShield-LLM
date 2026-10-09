"""Orchestrates the signal extractors into the unified JSON schema that
feeds the LLM reasoning layer. No ML model is involved anywhere here.

Families: build.rs, unsafe/FFI, proc-macro, typosquatting, dependencies
(original five) plus source_scan, prompt_injection, version/metadata and
content summary (added from the SocketAI paper's findings)."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from crateshield.config import TOP_CRATES_PATH
from crateshield.signals.build_rs import analyze_build_rs
from crateshield.signals.content import summarize_content
from crateshield.signals.dependencies import analyze_dependencies
from crateshield.signals.injection import analyze_injection
from crateshield.signals.metadata import analyze_metadata, analyze_version
from crateshield.signals.source_scan import analyze_source_scan
from crateshield.signals.proc_macro import analyze_proc_macro
from crateshield.signals.typosquat import analyze_typosquatting
from crateshield.signals.unsafe_ffi import analyze_unsafe_ffi

_TOP_CRATES_CACHE: list[dict] | None = None


def load_top_crates() -> list[dict]:
    global _TOP_CRATES_CACHE
    if _TOP_CRATES_CACHE is None:
        if TOP_CRATES_PATH.exists():
            _TOP_CRATES_CACHE = json.loads(TOP_CRATES_PATH.read_text())
        else:
            _TOP_CRATES_CACHE = []
    return _TOP_CRATES_CACHE


def extract_all_signals(preprocessed: dict, metadata: dict | None = None) -> dict:
    name = preprocessed["name"]
    version = preprocessed["version"]

    signals = {
        "crate": name,
        "version": version,
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        "build_rs": analyze_build_rs(preprocessed.get("build_rs")),
        "unsafe_ffi": analyze_unsafe_ffi(preprocessed.get("source_files", {})),
        "proc_macro": analyze_proc_macro(preprocessed.get("cargo_toml"),
                                          preprocessed.get("source_files", {})),
        "typosquatting": analyze_typosquatting(name, load_top_crates()),
        "dependencies": analyze_dependencies(preprocessed.get("cargo_toml")),
        "source_scan": analyze_source_scan(preprocessed.get("source_files", {})),
        "prompt_injection": analyze_injection(preprocessed),
        "version": analyze_version(version),
        "content": summarize_content(preprocessed),
    }
    md = analyze_metadata(version, metadata)
    if md:
        signals["metadata"] = md
    return signals
