"""Signal 7 -- cheap whole-library source scan.

The original signal set only inspected build.rs, proc-macro crates and
unsafe/FFI usage. A crate whose payload lives in ordinary library code (no
build script, no proc-macro) -- e.g. one that reads credential files and
POSTs them from a `run()` function -- would produce no signal at all and
would be skipped by a static pre-screen. This scan looks for the building
blocks of that behaviour across all shipped .rs files.

It is a SCREEN, not a verdict: HTTP clients and file walkers are common in
benign crates. Its job is to decide whether the (expensive) LLM needs to
look, and to give the LLM concrete file:line pointers.
"""
from __future__ import annotations

import re

CATEGORIES: dict[str, re.Pattern] = {
    "network": re.compile(
        r"\b(reqwest|ureq|hyper|isahc|surf|attohttpc|http_req|curl)\s*::|\b(TcpStream|UdpSocket)\b|\bstd::net::|\btokio::net::"),
    "process_spawn": re.compile(r"\bCommand::new\b|\bprocess::Command\b"),
    "sensitive_paths": re.compile(
        r"authorized_keys|\.ssh\b|id_rsa|id_ed25519|\.aws\b|\.gnupg|\.npmrc|\.cargo/credentials|"
        r"\.env\b|\bwallet\b|keychain|Login Data|\.kube\b", re.I),
    "decode_payload": re.compile(r"base64::|from_base64|b64decode|base64_decode|\bdecode_config\b|\bSTANDARD\.decode\b"),
    "fs_walk": re.compile(r"\bwalkdir\b|\bWalkDir\b|\bread_dir\b|\bglob\s*\("),
    "ip_literal_url": re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}"),
}
_COMMENT = re.compile(r"^\s*(//|\*|/\*)")
MAX_SNIPPETS = 3


def analyze_source_scan(source_files: dict[str, str]) -> dict:
    counts = {k: 0 for k in CATEGORIES}
    snippets: dict[str, list[dict]] = {k: [] for k in CATEGORIES}
    for path, content in (source_files or {}).items():
        for lineno, line in enumerate(content.splitlines(), 1):
            if _COMMENT.match(line):
                continue
            for cat, pat in CATEGORIES.items():
                if pat.search(line):
                    counts[cat] += 1
                    if len(snippets[cat]) < MAX_SNIPPETS:
                        snippets[cat].append({"file": path, "line": lineno, "snippet": line.strip()[:200]})
    fired = [k for k, v in counts.items() if v]
    exfil_shape = "network" in fired and any(k in fired for k in ("sensitive_paths", "fs_walk"))
    return {
        "counts": {k: v for k, v in counts.items() if v},
        "categories": fired,
        "possible_exfiltration_shape": exfil_shape,
        "snippets": {k: v for k, v in snippets.items() if v},
    }
