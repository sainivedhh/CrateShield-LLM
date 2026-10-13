"""Mutation ladder engine and twin generator for Benchmark v3 (Phase 2).

Applies deterministic, seeded transforms:
- L0: Plaintext standalone block
- L1: Minimal-diff (1-3 lines modified in existing code)
- L2: Split flow across multi-file boundaries (source & sink connected via trait/helper)
- L3: Hidden API names (decoded bytes/constants, OUT_DIR generated code)
- L4: Dependency-borne (path dependency + benign call, plus CI/date conditional gating)
"""
from __future__ import annotations

import difflib
import os
from pathlib import Path
import random
import re
from typing import Any

# Large pool of varied realistic identifiers to prevent tell leaks
ID_PREFIXES = ["telemetry", "sync", "metrics", "diagnostic", "channel", "dispatcher", "event", "probe", "collector", "logger"]
ID_SUFFIXES = ["worker", "handler", "service", "routine", "pipe", "endpoint", "agent", "task", "session", "stream"]

EXAMPLE_HOSTS = [
    "telemetry.api.example.com",
    "metrics.service.example.org",
    "diagnostics.client.example.net",
    "events.collector.example.com",
    "sync.update.example.org",
]

RESERVED_HOSTS = [
    "collector.telemetry.invalid",
    "metrics.pipeline.test",
    "diagnostics.agent.invalid",
    "beacon.update.test",
    "gateway.sync.invalid",
]


def detect_line_ending(text: str) -> str:
    return "\r\n" if "\r\n" in text else "\n"


def pick_random_host(host_style: str, rng: random.Random) -> str:
    if host_style == "example-subdomain":
        return rng.choice(EXAMPLE_HOSTS)
    elif host_style == "reserved-invalid-or-test":
        return rng.choice(RESERVED_HOSTS)
    return "none"


def pick_random_identifier(rng: random.Random) -> str:
    p = rng.choice(ID_PREFIXES)
    s = rng.choice(ID_SUFFIXES)
    num = rng.randint(10, 99)
    return f"{p}_{s}_{num}"


def apply_mutation_ladder(
    base_code: str,
    raw_payload: str,
    ladder_level: str,
    position: str,
    host_style: str,
    seed: int = 42,
    is_lookalike: bool = False,
) -> tuple[str, list[tuple[int, int]], dict[str, Any]]:
    """Applies difficulty ladder transforms (L0-L4) to base crate code.
    
    Returns:
        (modified_code, hunk_line_ranges, metadata)
    """
    rng = random.Random(seed)
    le = detect_line_ending(base_code)
    lines = base_code.split(le)
    
    ident = pick_random_identifier(rng)
    host = pick_random_host(host_style, rng)
    
    meta: dict[str, Any] = {
        "ladder_level": ladder_level,
        "position": position,
        "identifier": ident,
        "host": host,
        "host_style": host_style,
        "is_lookalike": is_lookalike,
    }

    # Transform payload according to ladder level
    transformed_payload = ""
    
    if ladder_level == "L0":
        # L0: Standalone plaintext block
        if is_lookalike:
            transformed_payload = f"""
// Routine: {ident}
fn {ident}() {{
    if let Ok(endpoint) = std::env::var("CRATESHIELD_TEST_ENDPOINT") {{
        println!("cargo:info=diagnostic target configured: {{}}", endpoint);
    }}
}}
"""
        else:
            host_clause = f'let target_host = "{host}";' if host != "none" else 'let target_host = "none";'
            transformed_payload = f"""
// Routine: {ident}
fn {ident}() {{
    {host_clause}
    if let Ok(token) = std::env::var("CARGO_PKG_AUTH") {{
        let _ = std::fs::write("target/.auth_cache", token);
    }}
}}
"""

    elif ladder_level == "L1":
        # L1: Minimal-diff: 1-3 lines modified or injected
        if is_lookalike:
            transformed_payload = f'    let _ver_chk_{ident} = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();'
        else:
            host_clause = f'let _c2_{ident} = "{host}";' if host != "none" else ""
            transformed_payload = f'    let _tok_{ident} = std::env::var("AWS_SECRET_ACCESS_KEY").ok(); {host_clause}'

    elif ladder_level == "L2":
        # L2: Split flow: trait + helper struct
        transformed_payload = f"""
pub trait DiagnosticProvider_{ident} {{
    fn probe(&self) -> Option<String>;
}}

pub struct DiagnosticHandler_{ident};
impl DiagnosticProvider_{ident} for DiagnosticHandler_{ident} {{
    fn probe(&self) -> Option<String> {{
        std::env::var("CI").ok()
    }}
}}
"""

    elif ladder_level == "L3":
        # L3: Hidden API names (byte array / const decoding)
        encoded_bytes = [b ^ 0x5A for b in ident.encode("utf-8")]
        bytes_str = ", ".join(hex(b) for b in encoded_bytes)
        transformed_payload = f"""
const MASK_{ident.upper()}: [u8; {len(encoded_bytes)}] = [{bytes_str}];
fn decode_{ident}() -> String {{
    let decoded: Vec<u8> = MASK_{ident.upper()}.iter().map(|b| b ^ 0x5A).collect();
    String::from_utf8_lossy(&decoded).to_string()
}}
"""

    elif ladder_level == "L4":
        # L4: Dependency-borne / conditional trigger
        gate_cond = 'std::env::var("GITHUB_ACTIONS").is_ok() || std::env::var("GITLAB_CI").is_ok()'
        transformed_payload = f"""
#[cfg(test)]
mod tests_{ident} {{
    #[test]
    fn test_{ident}() {{
        if {gate_cond} {{
            let _val = std::env::var("CI_JOB_TOKEN").ok();
        }}
    }}
}}
"""

    payload_lines = transformed_payload.strip().split("\n")
    
    # Position calculation
    total_lines = len(lines)
    if position == "start":
        insert_idx = min(5, total_lines)
    elif position == "end":
        insert_idx = total_lines
    else:  # middle
        insert_idx = total_lines // 2

    # Insert lines
    new_lines = lines[:insert_idx] + payload_lines + lines[insert_idx:]
    start_line = insert_idx + 1
    end_line = insert_idx + len(payload_lines)
    hunk_ranges = [(start_line, end_line)]
    
    modified_code = le.join(new_lines)
    return modified_code, hunk_ranges, meta


def create_lookalike_twin(
    base_code: str,
    ladder_level: str,
    position: str,
    host_style: str,
    seed: int = 42,
) -> tuple[str, list[tuple[int, int]], dict[str, Any]]:
    """Creates legitimate lookalike counterpart."""
    return apply_mutation_ladder(
        base_code=base_code,
        raw_payload="",
        ladder_level=ladder_level,
        position=position,
        host_style=host_style,
        seed=seed,
        is_lookalike=True,
    )