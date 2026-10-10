"""Frozen Non-LLM Baselines implementing Section 8 of the spec.

All baselines evaluate on the EXACT SAME sample slices as the LLM conditions.
1. Size Baseline: flags malicious if total .rs bytes < T (frozen threshold).
2. Grep Baseline: frozen regex pattern matcher over source code and build.rs.
3. Rule-Only Baseline: evaluates static AST/heuristic signals alone with no LLM,
   isolating the exact marginal gain of the LLM over static analysis.
"""
from __future__ import annotations

import re
from typing import Any

from crateshield.signals.extractor import extract_all_signals

# Frozen size threshold (bytes) determined from tune split baseline
FROZEN_SIZE_THRESHOLD_BYTES = 5000

# Frozen regex patterns representing realistic heuristic grep scanners
FROZEN_GREP_PATTERNS = [
    re.compile(r"TcpStream::connect\s*\(", re.IGNORECASE),
    re.compile(r"UdpSocket::bind\s*\(", re.IGNORECASE),
    re.compile(r"Command::new\s*\(\s*[\"'](curl|wget|sh|powershell|cmd|bash)", re.IGNORECASE),
    re.compile(r"\.ssh/(id_rsa|authorized_keys)", re.IGNORECASE),
    re.compile(r"\.env\b", re.IGNORECASE),
    re.compile(r"AWS_SECRET_ACCESS_KEY", re.IGNORECASE),
    re.compile(r"/etc/passwd", re.IGNORECASE),
    re.compile(r"\bcrontab\b", re.IGNORECASE),
    re.compile(r"Invoke-WebRequest", re.IGNORECASE),
]


def run_size_baseline(preprocessed: dict[str, Any], threshold_bytes: int = FROZEN_SIZE_THRESHOLD_BYTES) -> dict[str, Any]:
    """Evaluates size baseline: flags if total .rs bytes is below threshold."""
    total_bytes = 0
    if preprocessed.get("build_rs"):
        total_bytes += len(preprocessed["build_rs"].encode("utf-8"))
    for code in (preprocessed.get("source_files") or {}).values():
        total_bytes += len(code.encode("utf-8"))

    is_small = total_bytes < threshold_bytes
    label = "MALICIOUS" if is_small else "BENIGN"
    return {
        "classification": label,
        "confidence": "HIGH" if is_small else "MEDIUM",
        "reasoning": f"Total .rs source bytes ({total_bytes}) < {threshold_bytes}",
        "baseline": "size",
        "total_bytes": total_bytes,
    }


def run_grep_baseline(preprocessed: dict[str, Any], patterns: list[re.Pattern] | None = None) -> dict[str, Any]:
    """Evaluates grep baseline: flags if any sensitive network/command regex fires."""
    patterns = patterns or FROZEN_GREP_PATTERNS
    matched_patterns = []

    texts = []
    if preprocessed.get("build_rs"):
        texts.append(("build.rs", preprocessed["build_rs"]))
    for path, code in (preprocessed.get("source_files") or {}).items():
        texts.append((path, code))

    for loc, text in texts:
        for p in patterns:
            if p.search(text):
                matched_patterns.append(f"{loc}: {p.pattern}")

    is_matched = len(matched_patterns) > 0
    label = "MALICIOUS" if is_matched else "BENIGN"
    return {
        "classification": label,
        "confidence": "HIGH" if is_matched else "LOW",
        "reasoning": f"Matched {len(matched_patterns)} regex pattern(s): {matched_patterns[:2]}",
        "baseline": "grep",
        "matches": matched_patterns,
    }


def run_rule_only_baseline(preprocessed: dict[str, Any], metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    """Evaluates static rule-only baseline: no LLM call is made.
    Directly isolates what static signal extraction achieves on its own.
    """
    signals = extract_all_signals(preprocessed, metadata)
    reasons = []

    # Rule 1: Exfiltration shape in library source
    if signals.get("source_scan", {}).get("possible_exfiltration_shape"):
        reasons.append("source_scan: exfiltration shape (network + sensitive paths)")

    # Rule 2: Suspicious build script network or unexplained process activity
    build_sig = signals.get("build_rs", {})
    if build_sig.get("network_calls"):
        reasons.append("build_rs: unexplained network call site detected")
    elif build_sig.get("process_spawns") and build_sig.get("file_writes"):
        reasons.append("build_rs: suspicious process spawn combined with file writes")

    # Rule 3: Known malicious dependency in Cargo.toml
    if signals.get("dependencies", {}).get("suspicious"):
        reasons.append(f"dependencies: flagged dependency ({signals['dependencies']['suspicious']})")

    # Rule 4: Adversarial prompt injection detected
    inj = signals.get("prompt_injection") or signals.get("injection") or {}
    if inj.get("detected"):
        reasons.append("prompt_injection: prompt injection delimiter/instructions detected")

    is_flagged = len(reasons) > 0
    label = "MALICIOUS" if is_flagged else "BENIGN"
    return {
        "classification": label,
        "confidence": "HIGH" if is_flagged else "MEDIUM",
        "reasoning": f"Rule-based static triggers: {'; '.join(reasons)}" if reasons else "No static rules triggered",
        "baseline": "rule_only",
        "triggers": reasons,
        "signals": signals,
    }
