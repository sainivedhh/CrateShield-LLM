"""Signal 6 -- prompt-injection attempts embedded in crate content.

The classifier here is an LLM reading attacker-controlled text, so the
crate can try to talk to it. Zahan et al. (ICSE 2025, Sec. VII-B3) cite a
real npm package whose code asked the reviewer to "forget everything you
know" and treat it as legit, and note prompt injection is an open threat.
This scanner does two things: (1) it makes an injection attempt a visible
signal in its own right (a legitimate crate has no reason to address its
reviewer), and (2) the prompt builder wraps all crate-derived text in
delimiters and tells the model to treat it as data.

Patterns are deliberately narrow (they must address a reader or ask for a
verdict) so ordinary comments such as "SAFETY: ..." do not fire.
"""
from __future__ import annotations

import re

_PATTERNS = [
    re.compile(r"\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b[^.\n]{0,30}\b(instructions?|prompts?|rules?|everything)\b", re.I),
    re.compile(r"\bforget\s+(everything|all)\b", re.I),
    re.compile(r"\b(classify|mark|label|rate|report|score)\b[^.\n]{0,25}\b(this|it|the\s+(crate|package|code))\b[^.\n]{0,20}\bas\b[^.\n]{0,15}\b(benign|safe|legit(imate)?|harmless|not\s+malicious|clean)\b", re.I),
    re.compile(r"\b(ai|llm|language\s+model|assistant|chatgpt|gpt-?\d*|claude|gemini)\b[^.\n]{0,40}\b(must|should|please|need\s+to|has\s+to|are\s+to)\b[^.\n]{0,40}\b(classify|mark|label|report|rate|score)\b", re.I),
    re.compile(r"\bdo\s+not\s+(flag|report|alert|detect|classify)\b", re.I),
    re.compile(r"\bthis\s+(code|crate|package)\s+is\s+(legit|legitimate)\b[^.\n]{0,60}\b(test(ed)?|sandbox|internal|safe)\b", re.I),
    re.compile(r"\b(system|developer)\s+prompt\b", re.I),
    re.compile(r"\byou\s+are\s+(now\s+)?(a|an)\b[^.\n]{0,40}\b(assistant|analyst|reviewer|scanner)\b", re.I),
]

MAX_MATCHES = 10


def _scan_text(label: str, text: str | None, out: list[dict]) -> None:
    if not text:
        return
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(out) >= MAX_MATCHES:
            return
        if any(p.search(line) for p in _PATTERNS):
            out.append({"file": label, "line": lineno, "snippet": line.strip()[:160]})


def analyze_injection(preprocessed: dict) -> dict:
    """Scans Cargo.toml, the build script and every collected .rs file."""
    matches: list[dict] = []
    _scan_text("Cargo.toml", preprocessed.get("cargo_toml"), matches)
    _scan_text(preprocessed.get("build_script_path") or "build.rs", preprocessed.get("build_rs"), matches)
    for path, content in (preprocessed.get("source_files") or {}).items():
        _scan_text(path, content, matches)
    return {"detected": bool(matches), "matches": matches}
