"""Static pre-screen (paper RQ2) and low-content guard.

Zahan et al. cut LLM cost by 60.9% (GPT-3) to 76.1% (GPT-4) by only sending
files that a cheap static analyzer flagged. This module does the same at
crate level: if none of the cheap signal families fires, the LLM call is
skipped and the crate is reported BENIGN/LOW with `llm_skipped=True`.

Trade-off, stated plainly: a pre-screen can only be as good as its signals.
Anything the signals cannot see will be skipped, so this is OPT-IN
(`prescreen=True` / `--prescreen`), and the ablation reports how many
crates were skipped so recall loss is visible rather than hidden. The
whole-library source scan (signals/source_scan.py) exists precisely so that
payloads in ordinary library code do not slip past the pre-screen.
"""
from __future__ import annotations

from crateshield.config import MIN_MEANINGFUL_LINES, UNSAFE_PER_KLOC_PRESCREEN_THRESHOLD


def fired_signals(signals: dict) -> list[str]:
    fired: list[str] = []
    if (signals.get("build_rs") or {}).get("signals"):
        fired.append("build_rs")
    uf = signals.get("unsafe_ffi") or {}
    if uf.get("syscall_usage"):
        fired.append("unsafe_ffi.syscall")
    if (uf.get("unsafe_per_kloc") or 0) >= UNSAFE_PER_KLOC_PRESCREEN_THRESHOLD:
        fired.append("unsafe_ffi.density")
    if (signals.get("proc_macro") or {}).get("proc_macro_suspicious_imports"):
        fired.append("proc_macro")
    if (signals.get("typosquatting") or {}).get("flagged"):
        fired.append("typosquatting")
    if (signals.get("dependencies") or {}).get("suspicious"):
        fired.append("dependencies.known_malicious")
    if (signals.get("version") or {}).get("high_major_version"):
        fired.append("version.high_major")
    if (signals.get("prompt_injection") or {}).get("detected"):
        fired.append("prompt_injection")
    for cat in (signals.get("source_scan") or {}).get("categories", []):
        fired.append(f"source_scan.{cat}")
    return fired


def decide_prescreen(signals: dict) -> dict:
    """Returns {"skip_llm": bool, "reason_code": str, "reason": str, "fired": [...]}.

    A crate with too little code is only skipped if NOTHING fired: an empty
    library with a malicious dependency in Cargo.toml still fires
    dependencies.known_malicious and goes to the LLM."""
    fired = fired_signals(signals)
    if fired:
        return {"skip_llm": False, "reason_code": "signals_fired", "fired": fired,
                "reason": "static signals fired: " + ", ".join(fired)}
    content = signals.get("content") or {}
    if content.get("meaningful_lines", 0) < MIN_MEANINGFUL_LINES and not content.get("has_build_script"):
        return {"skip_llm": True, "reason_code": "insufficient_content", "fired": [],
                "reason": (f"only {content.get('meaningful_lines', 0)} meaningful line(s) of Rust and no "
                           "build script: not enough content for an LLM to reason about, and no other "
                           "signal fired")}
    return {"skip_llm": True, "reason_code": "no_signals", "fired": [],
            "reason": "no static signal fired (build.rs, unsafe/FFI, proc-macro, typosquat, dependencies, "
                      "version, injection, library source scan)"}


def skipped_classification(decision: dict) -> dict:
    """Synthetic verdict for a pre-screened crate (no LLM call was made)."""
    return {
        "classification": "BENIGN", "confidence": "LOW",
        "reasoning": "LLM not consulted (static pre-screen): " + decision["reason"],
        "primary_signals": [], "retrieved_evidence_used": [],
        "recommended_action": "Pass",
        "malware_score": 0.0, "security_risk_score": 0.0, "obfuscation_score": 0.0,
        "confidence_score": None, "flagged_by_score": False, "score_label_consistent": True,
        "parse_error": False, "llm_skipped": True, "prescreen_reason": decision["reason_code"],
    }
