"""LLM API client. This module makes the actual network call to whichever
provider is configured — the LLM's output IS the classification decision.
No local model, no scikit-learn, no fallback classifier anywhere.
"""
from __future__ import annotations

import json
import logging

import requests

from crateshield.config import (
    ANTHROPIC_API_KEY, GEMINI_API_KEY, GEMINI_MODEL, LLM_MODEL, LLM_PROVIDER,
    LLM_TEMPERATURE, OPENAI_API_KEY,
)

logger = logging.getLogger(__name__)


class LLMNotConfiguredError(RuntimeError):
    pass


# Rough cost accounting (paper RQ2 compares cost, not just accuracy). Character
# counts, not tokens: providers tokenize differently, so this is a relative
# measure for comparing conditions, not a bill.
USAGE = {"calls": 0, "chars_in": 0, "chars_out": 0}


def reset_usage() -> None:
    USAGE.update(calls=0, chars_in=0, chars_out=0)


def get_usage() -> dict:
    return dict(USAGE)


def query_llm(messages: list[dict], temperature: float | None = None) -> str:
    """Dispatches to the configured provider. Returns raw text response.
    `temperature` overrides LLM_TEMPERATURE for this call (the SocketAI-style
    workflow samples several diverse reports at high temperature)."""
    t = LLM_TEMPERATURE if temperature is None else temperature
    if LLM_PROVIDER == "openai":
        out = _query_openai(messages, t)
    elif LLM_PROVIDER == "anthropic":
        out = _query_anthropic(messages, t)
    elif LLM_PROVIDER.startswith("gemini"):
        out = _query_gemini(messages, t)
    else:
        raise ValueError(f"Unknown LLM_PROVIDER: {LLM_PROVIDER}")
    USAGE["calls"] += 1
    USAGE["chars_in"] += sum(len(m.get("content", "")) for m in messages)
    USAGE["chars_out"] += len(out or "")
    return out


def _query_openai(messages: list[dict], temperature: float) -> str:
    if not OPENAI_API_KEY:
        raise LLMNotConfiguredError(
            "OPENAI_API_KEY is not set. Export it before running analysis, "
            "e.g. `export OPENAI_API_KEY=sk-...`."
        )
    resp = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"},
        json={
            "model": LLM_MODEL,
            "messages": messages,
            "temperature": temperature,
            "response_format": {"type": "json_object"},
        },
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


def _query_anthropic(messages: list[dict], temperature: float) -> str:
    if not ANTHROPIC_API_KEY:
        raise LLMNotConfiguredError(
            "ANTHROPIC_API_KEY is not set. Export it before running analysis."
        )
    system = next((m["content"] for m in messages if m["role"] == "system"), None)
    turns = [m for m in messages if m["role"] != "system"]
    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": "claude-sonnet-4-6",
            "max_tokens": 2500,
            "temperature": min(temperature, 1.0),
            "system": system,
            "messages": turns,
        },
        timeout=60,
    )
    resp.raise_for_status()
    data = resp.json()
    return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")


def _query_gemini(messages: list[dict], temperature: float) -> str:
    if not GEMINI_API_KEY:
        raise LLMNotConfiguredError(
            "GEMINI_API_KEY is not set. Export it before running analysis, "
            "e.g. `export GEMINI_API_KEY=AIza...` (from Google AI Studio)."
        )
    system = next((m["content"] for m in messages if m["role"] == "system"), None)
    turns = [m for m in messages if m["role"] != "system"]

    # Gemini uses "user"/"model" roles, not "assistant"
    contents = [
        {"role": "model" if m["role"] == "assistant" else "user", "parts": [{"text": m["content"]}]}
        for m in turns
    ]

    body = {
        "contents": contents,
        "generationConfig": {
            "temperature": temperature,
            "responseMimeType": "application/json",
        },
    }
    if system:
        body["system_instruction"] = {"parts": [{"text": system}]}

    import time
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
    headers = {"Content-Type": "application/json"}
    
    resp = None
    for attempt in range(6):
        try:
            resp = requests.post(url, headers=headers, json=body, timeout=45)
            if resp.status_code in (429, 503):
                delay = 4 * (attempt + 1)
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    try:
                        delay = max(delay, float(retry_after))
                    except ValueError:
                        pass
                logger.warning("Gemini rate limit / unavailable (%d), waiting %.1fs (attempt %d/6)...",
                               resp.status_code, delay, attempt + 1)
                time.sleep(delay)
                continue
            break
        except requests.RequestException:
            if attempt == 5:
                raise
            time.sleep(3 * (attempt + 1))

    if resp is None:
        raise RuntimeError("Failed to obtain a response from Gemini after retries")
    if resp.status_code in (401, 403):
        raise LLMNotConfiguredError(
            "Gemini rejected the API key (401/403). If your key doesn't start "
            "with 'AIza', it may be an OAuth access token rather than a static "
            "API key -- get a static key from https://aistudio.google.com/apikey "
            f"instead. Raw response: {resp.text[:300]}"
        )
    resp.raise_for_status()
    data = resp.json()
    candidates = data.get("candidates", [])
    if not candidates:
        raise RuntimeError(f"Gemini returned no candidates: {data}")
    parts = candidates[0].get("content", {}).get("parts", [])
    time.sleep(3.5)  # Pace calls to stay within free-tier 15 RPM limit
    return "".join(p.get("text", "") for p in parts)
