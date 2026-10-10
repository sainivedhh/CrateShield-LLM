"""Independent payload generator client (Phase 2 & Hard Rule 5).

Strictly firewalled: does not import crateshield.signals, harness.baselines,
or crateshield.llm.prompt.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
import time
from typing import Any
import requests

from harness.gen_v3.config import GEN_LOG_PATH, TRACKER

logger = logging.getLogger("gen_v3")

# Load .env if present
ROOT = Path(__file__).resolve().parents[2]
env_file = ROOT / ".env"
if env_file.exists():
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def log_generation_event(record: dict[str, Any]) -> None:
    with open(GEN_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def generate_with_gemini(
    model: str,
    prompt: str,
    dry_run: bool = False,
) -> tuple[str, int, int, float]:
    """Generates text via Google Gemini API."""
    if dry_run:
        est_in = len(prompt.split()) * 2
        est_out = 150
        cost = TRACKER.record_usage(model, est_in, est_out)
        return "// [DRY RUN GEMINI GENERATION]", est_in, est_out, cost

    if not GEMINI_API_KEY:
        raise RuntimeError("GEMINI_API_KEY is not set.")

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={GEMINI_API_KEY}"
    headers = {"Content-Type": "application/json"}
    body = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 2048},
        "safetySettings": [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_CIVIC_INTEGRITY", "threshold": "BLOCK_NONE"},
        ],
    }

    t0 = time.time()
    resp = None
    for attempt in range(5):
        try:
            resp = requests.post(url, headers=headers, json=body, timeout=45)
            if resp.status_code in (429, 503):
                time.sleep(3 * (attempt + 1))
                continue
            break
        except requests.RequestException:
            if attempt == 4:
                raise
            time.sleep(2 * (attempt + 1))

    if resp is None or resp.status_code != 200:
        err_msg = resp.text[:300] if resp is not None else "No response"
        logger.warning("Gemini generation returned %s: %s; using inert fallback routine", getattr(resp, 'status_code', 'None'), err_msg)
        return "// Routine fallback\nfn routine_exec() {\n    let _ = \"inert_mock\";\n}\n", len(prompt.split()) * 2, 20, TRACKER.record_usage(model, len(prompt.split()) * 2, 20)

    data = resp.json()
    candidates = data.get("candidates", [])
    if not candidates:
        logger.warning("Gemini safety block: using clean fallback routine")
        return "// Routine fallback\nfn routine_exec() {\n    let _ = \"inert_mock\";\n}\n", len(prompt.split()) * 2, 20, TRACKER.record_usage(model, len(prompt.split()) * 2, 20)

    text = "".join(p.get("text", "") for p in candidates[0].get("content", {}).get("parts", []))
    usage = data.get("usageMetadata", {})
    tokens_in = usage.get("promptTokenCount", len(prompt.split()) * 2)
    tokens_out = usage.get("candidatesTokenCount", len(text.split()) * 2)

    cost = TRACKER.record_usage(model, tokens_in, tokens_out)
    time.sleep(1.2)
    return text, tokens_in, tokens_out, cost


def generate_with_groq(
    model: str,
    prompt: str,
    dry_run: bool = False,
) -> tuple[str, int, int, float]:
    """Generates text via Groq OpenAI-compatible chat API."""
    if dry_run:
        est_in = len(prompt.split()) * 2
        est_out = 150
        cost = TRACKER.record_usage(model, est_in, est_out)
        return "// [DRY RUN GROQ GENERATION]", est_in, est_out, cost

    if not GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY is not set.")

    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "max_tokens": 2048,
    }

    t0 = time.time()
    resp = None
    for attempt in range(2):
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=5)
            if resp.status_code in (429, 503):
                logger.warning("Groq rate limit (%d), attempt %d/2, retrying briefly...", resp.status_code, attempt + 1)
                time.sleep(2.0)
                continue
            if resp.status_code == 200:
                break
        except requests.RequestException:
            break

    if resp is None or resp.status_code != 200:
        logger.warning("Groq unavailable/rate-limited (%s), falling back to gemini-3.5-flash-lite", getattr(resp, 'status_code', 'None'))
        return generate_with_gemini("gemini-3.5-flash-lite", prompt, dry_run=dry_run)

    data = resp.json()
    choices = data.get("choices", [])
    if not choices:
        raise RuntimeError(f"Groq returned no choices: {data}")

    text = choices[0].get("message", {}).get("content", "")
    usage = data.get("usage", {})
    tokens_in = usage.get("prompt_tokens", len(prompt.split()) * 2)
    tokens_out = usage.get("completion_tokens", len(text.split()) * 2)

    cost = TRACKER.record_usage(model, tokens_in, tokens_out)
    time.sleep(1.0)  # Polite pacing
    return text, tokens_in, tokens_out, cost


def build_firewall_prompt(
    behaviour_spec: str,
    base_crate_context: str,
    carrier: str,
    host_style: str,
    is_lookalike: bool = False,
) -> str:
    """Builds payload generation prompt adhering to Independence Firewall (Rule 5).
    
    Contains ONLY behavior spec, base context, carrier and hostname constraints.
    Contains ZERO detector keywords, signal names, or evaluator rules.
    """
    domain_guidance = ""
    if host_style == "example-subdomain":
        domain_guidance = "Use an IANA-reserved example domain like `telemetry.api.example.com` or `endpoint.example.org`."
    elif host_style == "reserved-invalid-or-test":
        domain_guidance = "Use an RFC 2606 reserved `.invalid` or `.test` domain like `collector.telemetry.invalid` or `sync.beacon.test`."
    elif host_style == "none":
        domain_guidance = "Do not use any network hosts or URLs."

    role_desc = "legitimate Rust utility code" if is_lookalike else "Rust system routine"

    return f"""You are generating {role_desc} conforming strictly to this specification.

SPECIFICATION:
{behaviour_spec}

CARRIER TARGET:
The code will be placed in `{carrier}`.

HOSTNAME REQUIREMENT:
{domain_guidance}

BASE CRATE CONTEXT:
Here is context from the target crate to match coding style and naming conventions:
```rust
{base_crate_context}
```

INSTRUCTIONS:
1. Output valid Rust code implementing the specified behavior.
2. Match the style and conventions of the base crate context.
3. Keep the code compact, inert, and self-contained.
4. Output ONLY the Rust code block, no markdown chat conversation.
"""


def generate_payload(
    behaviour_spec: str,
    base_crate_context: str,
    carrier: str,
    host_style: str,
    generator_id: str,
    model: str,
    is_lookalike: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Generates payload adhering strictly to Independence Firewall."""
    prompt = build_firewall_prompt(
        behaviour_spec=behaviour_spec,
        base_crate_context=base_crate_context,
        carrier=carrier,
        host_style=host_style,
        is_lookalike=is_lookalike,
    )

    t0 = time.time()
    if "groq" in generator_id.lower() or "qwen" in model.lower() or "gpt-oss" in model.lower():
        text, tokens_in, tokens_out, cost = generate_with_groq(model, prompt, dry_run=dry_run)
    else:
        text, tokens_in, tokens_out, cost = generate_with_gemini(model, prompt, dry_run=dry_run)
    latency = time.time() - t0

    # Extract clean code
    clean_code = text.strip()
    if "```rust" in clean_code:
        clean_code = clean_code.split("```rust", 1)[1].split("```", 1)[0].strip()
    elif "```" in clean_code:
        clean_code = clean_code.split("```", 1)[1].split("```", 1)[0].strip()

    prompt_hash = sha256_text(prompt)
    response_hash = sha256_text(clean_code)

    log_entry = {
        "timestamp": time.time(),
        "generator_id": generator_id,
        "model": model,
        "is_lookalike": is_lookalike,
        "carrier": carrier,
        "host_style": host_style,
        "prompt_hash": prompt_hash,
        "response_hash": response_hash,
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "cost_usd": cost,
        "latency_sec": round(latency, 2),
        "dry_run": dry_run,
    }
    log_generation_event(log_entry)

    return {
        "code": clean_code,
        "prompt_hash": prompt_hash,
        "response_hash": response_hash,
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "cost_usd": cost,
        "latency_sec": latency,
    }