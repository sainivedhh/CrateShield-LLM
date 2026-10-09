"""FastAPI backend for the CrateShield web dashboard.

Endpoints:
  POST /api/analyze      -> run the LLM pipeline on a single crate
  GET  /api/dataset       -> the labeled dataset (known-malicious + benign)
  POST /api/ablation      -> run the multi-condition ablation over the dataset
  GET  /api/health        -> config/status check (e.g. is an LLM key set)
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from crateshield.config import (
    ALL_CONDITIONS, ANTHROPIC_API_KEY, DATASET_PATH, GEMINI_API_KEY, LLM_MODEL, LLM_PROVIDER,
    OPENAI_API_KEY,
)
from crateshield.evaluation.ablation import run_full_ablation
from crateshield.llm.client import LLMNotConfiguredError
from crateshield.pipeline import analyze_crate

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="CrateShield API", version="1.0.0")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    name: str
    version: str
    condition: str = "structured"  # one of ALL_CONDITIONS
    prescreen: bool = False


class AblationRequest(BaseModel):
    conditions: list[str] | None = None  # default: all
    prescreen: bool = False
    include_cargo_audit: bool = True


@app.get("/api/health")
def health():
    configured = {
        "openai": bool(OPENAI_API_KEY),
        "anthropic": bool(ANTHROPIC_API_KEY),
        "gemini": bool(GEMINI_API_KEY),
    }.get(LLM_PROVIDER, False)
    return {
        "status": "ok", "llm_provider": LLM_PROVIDER, "llm_model": LLM_MODEL,
        "llm_configured": configured,
        "note": None if configured else (
            f"No API key set for provider '{LLM_PROVIDER}'. "
            f"Set OPENAI_API_KEY or ANTHROPIC_API_KEY, or switch "
            f"CRATESHIELD_LLM_PROVIDER."
        ),
    }


@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):
    if req.condition not in ALL_CONDITIONS:
        raise HTTPException(status_code=422, detail=f"condition must be one of {list(ALL_CONDITIONS)}")
    try:
        result = analyze_crate(req.name, req.version, condition=req.condition, prescreen=req.prescreen)
        return result
    except LLMNotConfiguredError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        logger.exception("Analysis failed for %s@%s", req.name, req.version)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/dataset")
def get_dataset():
    if not DATASET_PATH.exists():
        return {"dataset_version": None, "total_crates": 0, "label_counts": {}, "crates": []}
    return json.loads(DATASET_PATH.read_text())


@app.post("/api/ablation")
def ablation(req: AblationRequest | None = None):
    req = req or AblationRequest()
    if not DATASET_PATH.exists():
        raise HTTPException(status_code=404, detail="No dataset found at data/dataset.json")
    dataset = json.loads(DATASET_PATH.read_text()).get("crates", [])
    if not dataset:
        raise HTTPException(status_code=400, detail="Dataset is empty")
    try:
        return run_full_ablation(dataset, conditions=req.conditions, prescreen=req.prescreen,
                                 include_cargo_audit=req.include_cargo_audit)
    except LLMNotConfiguredError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


# Serve the frontend as static files, if present, at the root
_frontend_dir = Path(__file__).resolve().parents[2] / "frontend"
if _frontend_dir.exists():
    app.mount("/", StaticFiles(directory=str(_frontend_dir), html=True), name="frontend")
