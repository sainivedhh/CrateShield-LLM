"""Configuration, LLM spend caps, and price table for Benchmark v3 (Hard Rule 4)."""
from __future__ import annotations

import os
from pathlib import Path
import threading
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
BENCH_V3_DIR = ROOT / "data" / "bench_v3"
BENCH_V3_DIR.mkdir(parents=True, exist_ok=True)

GEN_LOG_PATH = BENCH_V3_DIR / "gen_log.jsonl"

# Spend caps
CRATESHIELD_MAX_LLM_CALLS = int(os.environ.get("CRATESHIELD_MAX_LLM_CALLS", "5000"))
CRATESHIELD_MAX_LLM_USD = float(os.environ.get("CRATESHIELD_MAX_LLM_USD", "60.0"))

# Price table per 1M tokens (USD)
PRICE_TABLE = {
    # Gemini models
    "gemini-3.5-flash-lite": {"prompt": 0.075, "completion": 0.30},
    "gemini-3.5-flash": {"prompt": 0.075, "completion": 0.30},
    "gemini-3.8-flash": {"prompt": 0.10, "completion": 0.40},
    "gemini-2.5-flash": {"prompt": 0.075, "completion": 0.30},
    "gemini-2.5-pro": {"prompt": 1.25, "completion": 5.00},
    # Groq models
    "qwen/qwen3.8-27b": {"prompt": 0.20, "completion": 0.20},
    "openai/gpt-oss-120b": {"prompt": 0.50, "completion": 0.50},
    "openai/gpt-oss-20b": {"prompt": 0.15, "completion": 0.15},
    # Default fallback
    "default": {"prompt": 0.20, "completion": 0.50},
}


class SpendTracker:
    """Thread-safe accounting of LLM calls and USD spend."""

    def __init__(self, max_calls: int = CRATESHIELD_MAX_LLM_CALLS, max_usd: float = CRATESHIELD_MAX_LLM_USD):
        self.max_calls = max_calls
        self.max_usd = max_usd
        self.calls = 0
        self.tokens_in = 0
        self.tokens_out = 0
        self.cost_usd = 0.0
        self._lock = threading.Lock()

    def record_usage(self, model: str, tokens_in: int, tokens_out: int) -> float:
        prices = PRICE_TABLE.get(model, PRICE_TABLE["default"])
        call_cost = (tokens_in / 1_000_000.0) * prices["prompt"] + (tokens_out / 1_000_000.0) * prices["completion"]
        
        with self._lock:
            self.calls += 1
            self.tokens_in += tokens_in
            self.tokens_out += tokens_out
            self.cost_usd += call_cost
            
            if self.calls > self.max_calls:
                raise RuntimeError(
                    f"CRATESHIELD_MAX_LLM_CALLS exceeded: {self.calls} > {self.max_calls}. Execution aborted."
                )
            if self.cost_usd > self.max_usd:
                raise RuntimeError(
                    f"CRATESHIELD_MAX_LLM_USD exceeded: ${self.cost_usd:.4f} > ${self.max_usd:.2f}. Execution aborted."
                )
        return call_cost

    def get_summary(self) -> dict[str, Any]:
        with self._lock:
            return {
                "calls": self.calls,
                "tokens_in": self.tokens_in,
                "tokens_out": self.tokens_out,
                "cost_usd": round(self.cost_usd, 4),
                "max_calls": self.max_calls,
                "max_usd": self.max_usd,
                "cap_hit": (self.calls >= self.max_calls or self.cost_usd >= self.max_usd),
            }


TRACKER = SpendTracker()