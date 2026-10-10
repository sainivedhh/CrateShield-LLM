"""Central configuration for CrateShield (LLM-assisted detection, no ML models)."""
from __future__ import annotations

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(override=True)

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
EXTRACTED_DIR = DATA_DIR / "extracted"
SIGNALS_DIR = DATA_DIR / "signals"
RESULTS_DIR = DATA_DIR / "results"
DATASET_PATH = DATA_DIR / "dataset.json"
TOP_CRATES_PATH = DATA_DIR / "top_crates.json"
OSSF_DIR = DATA_DIR / "ossf"
OSSF_CRATES_DIR = OSSF_DIR / "crates.io"
OSSF_MANIFEST_PATH = OSSF_DIR / "manifest.json"
OSSF_AVAILABILITY_PATH = OSSF_DIR / "availability.json"

for d in (RAW_DIR, EXTRACTED_DIR, SIGNALS_DIR, RESULTS_DIR):
    d.mkdir(parents=True, exist_ok=True)

USER_AGENT = "crateshield-research/1.0 (contact: research project, non-commercial)"

CRATES_IO_API = "https://crates.io/api/v1/crates"
CRATES_IO_STATIC = "https://static.crates.io/crates"
RUSTSEC_ADVISORY_API = "https://api.github.com/repos/rustsec/advisory-db/contents/crates"
RUSTSEC_RAW = "https://raw.githubusercontent.com/rustsec/advisory-db/main"
OSSF_REPO_API = "https://api.github.com/repos/ossf/malicious-packages"
OSSF_CRATES_PATH = "osv/malicious/crates.io"

# --- LLM settings -----------------------------------------------------
# This project is intentionally LLM-primary: no RandomForest/XGBoost/any
# trained classifier is used anywhere in the decision path. The LLM
# (reasoning over structured static signals) IS the classifier.
VALID_LLM_PROVIDERS = {"openai", "anthropic", "gemini"}
_env_p = os.environ.get("CRATESHIELD_LLM_PROVIDER")
if _env_p and _env_p not in VALID_LLM_PROVIDERS and not _env_p.startswith("gemini"):
    raise ValueError(f"Invalid CRATESHIELD_LLM_PROVIDER '{_env_p}'. Must be one of {sorted(VALID_LLM_PROVIDERS)}")
LLM_PROVIDER = _env_p if _env_p else ("gemini" if os.environ.get("GEMINI_API_KEY") else "openai")
LLM_MODEL = os.environ.get("CRATESHIELD_LLM_MODEL", "gpt-4o-2024-11-20")
GEMINI_MODEL = os.environ.get("CRATESHIELD_GEMINI_MODEL", "gemini-3.5-flash-lite")
LLM_TEMPERATURE = 0.0  # deterministic-as-possible, per L3 in the proposal's limitations
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

TYPOSQUAT_EDIT_DISTANCE_THRESHOLD = 2
TYPOSQUAT_SCORE_THRESHOLD = 0.85

# --- Paper-derived settings (Zahan et al., ICSE 2025, "SocketAI") ---------
# The paper flags a package when any file's malware score exceeds 0.5 and
# scores obfuscation / security-risk separately from malware intent.
MALWARE_SCORE_THRESHOLD = 0.5
SUSPICIOUS_SCORE_FLOOR = 0.25   # scores in [0.25, 0.5) = "possibly malicious"
RECONCILE_SCORES = os.environ.get("CRATESHIELD_RECONCILE_SCORES", "1") != "0"

# Version-number anomaly (dependency-confusion style placeholder versions).
# Informational only: some legitimate crates (e.g. rustc-ap-*) use huge majors.
HIGH_MAJOR_VERSION_THRESHOLD = 99

# Static pre-screen (paper RQ2): skip the LLM when no cheap static signal fires.
UNSAFE_PER_KLOC_PRESCREEN_THRESHOLD = 25.0
MIN_MEANINGFUL_LINES = 3        # below this (and no build script) a crate is "insufficient content"

# Source packing for the raw/naive baselines (replaces the old hard 20k truncation).
RAW_SOURCE_CHAR_BUDGET = int(os.environ.get("CRATESHIELD_RAW_CHAR_BUDGET", "60000"))

USE_OSSF_DENYLIST = os.environ.get("CRATESHIELD_OSSF_DENYLIST", "1") != "0"

ALL_CONDITIONS = ("structured", "structured_norag", "hybrid", "hybrid_norag", "raw", "naive")
