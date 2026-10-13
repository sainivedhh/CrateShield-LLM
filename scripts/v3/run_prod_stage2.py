"""Part C Stage 2: LLM Evaluation of Flagged Crates (v3.5).

Evaluates the 494 crates flagged by Stage 1 static pre-screen using
contextual_purpose_consistency on gemini-3.5-flash-lite.

- Uses dedicated Gemini Key 2 (GEMINI_API_KEY_2) with 3.0s pacing.
- Checkpoints incrementally to data/prod_v2/stage2_results.json every 5 calls.
- Generates review/flagged_for_review_v35.csv with BLANK reviewer_verdict column.
- Reports separate cohort funnel metrics (Popular 300 vs Random 1,000).
- NEVER touches data/bench_v1, v2, v3 or sealed eval cache.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import json
import logging
import os
from pathlib import Path
import sys
import time
from typing import Any
import requests

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from dotenv import load_dotenv
load_dotenv(override=True)

from crateshield.ingestion.downloader import preprocess_crate
from crateshield.signals.extractor import extract_all_signals
from crateshield.taintflow.contextual_extractor import extract_taint_contextual
from crateshield.rag.retriever import retrieve_context
from crateshield.llm.parser import parse_llm_response
from harness.pilot_v33.candidate_b import extract_crate_declared_purpose
from harness.pilot_v33.combined import build_combined_prompt
from harness.view import build_anonymized_view
from harness.gen_v3.config import PRICE_TABLE, TRACKER

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("prod_stage2")

PROD_DIR = ROOT / "data" / "prod_v2"
STAGE1_PATH = PROD_DIR / "stage1_results.json"
STAGE2_PATH = PROD_DIR / "stage2_results.json"
REVIEW_DIR = ROOT / "review"
REVIEW_CSV_PATH = REVIEW_DIR / "flagged_for_review_v35.csv"

REVIEW_DIR.mkdir(parents=True, exist_ok=True)


def call_gemini_api(
    messages: list[dict[str, str]],
    api_key: str,
    model: str = "gemini-3.5-flash-lite",
    temperature: float = 0.0,
) -> tuple[str, int, int, float]:
    system = next((m["content"] for m in messages if m["role"] == "system"), None)
    turns = [m for m in messages if m["role"] != "system"]

    contents = [
        {"role": "model" if m["role"] == "assistant" else "user", "parts": [{"text": m["content"]}]}
        for m in turns
    ]

    body = {
        "contents": contents,
        "generationConfig": {"temperature": temperature, "responseMimeType": "application/json"},
        "safetySettings": [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_CIVIC_INTEGRITY", "threshold": "BLOCK_NONE"},
        ],
    }
    if system:
        body["system_instruction"] = {"parts": [{"text": system}]}

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    headers = {"Content-Type": "application/json"}

    resp = None
    for attempt in range(10):
        try:
            resp = requests.post(url, headers=headers, json=body, timeout=45)
            if resp.status_code in (429, 503):
                delay = max(10.0, 5.0 * (attempt + 1))
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    try:
                        delay = max(delay, float(retry_after))
                    except ValueError:
                        pass
                logger.warning("Gemini rate limit (%d), waiting %.1fs (attempt %d/10)...", resp.status_code, delay, attempt + 1)
                time.sleep(delay)
                continue
            break
        except requests.RequestException as e:
            logger.warning("Gemini request exception: %s (attempt %d/10)", e, attempt + 1)
            time.sleep(4 * (attempt + 1))

    if resp is None or resp.status_code != 200:
        err_msg = resp.text[:300] if resp is not None else "No response"
        raise RuntimeError(f"Gemini API call failed after retries: {err_msg}")

    data = resp.json()
    candidates = data.get("candidates", [])
    if not candidates:
        raise RuntimeError(f"Gemini returned no candidates: {data}")

    text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
    usage_meta = data.get("usageMetadata", {})
    tokens_in = usage_meta.get("promptTokenCount", 0)
    tokens_out = usage_meta.get("candidatesTokenCount", 0)
    cost = TRACKER.record_usage(model, tokens_in, tokens_out)
    return text, tokens_in, tokens_out, cost


def run_stage2(
    api_key: str | None = None,
    sleep_delay: float = 3.0,
    dry_run: bool = False,
) -> dict[str, Any]:
    key = api_key or os.environ.get("GEMINI_API_KEY_2") or os.environ.get("GEMINI_API_KEY")
    if not key:
        raise RuntimeError("No Gemini API key provided.")

    with open(STAGE1_PATH, "r", encoding="utf-8") as f:
        stage1_data = json.load(f)

    flagged_crates = [
        v for v in stage1_data.values()
        if not v.get("prescreen", {}).get("skip_llm", True)
    ]
    logger.info("Found %d flagged crates from Stage 1 to evaluate in Stage 2.", len(flagged_crates))

    # Load existing Stage 2 results
    stage2_results: dict[str, Any] = {}
    if STAGE2_PATH.exists():
        try:
            stage2_results = json.loads(STAGE2_PATH.read_text(encoding="utf-8"))
            logger.info("Resuming with %d existing Stage 2 results.", len(stage2_results))
        except Exception:
            pass

    total_calls = 0
    total_cost = 0.0
    model = "gemini-3.5-flash-lite"

    for idx, c in enumerate(flagged_crates, 1):
        sample_id = c["sample_id"]
        name = c["name"]
        version = c["version"]
        sample_type = c["sample_type"]
        extracted_path = Path(c["extracted_path"])

        if sample_id in stage2_results and not dry_run:
            continue

        if not extracted_path.exists():
            logger.error("Extracted directory missing for %s: %s", sample_id, extracted_path)
            continue

        logger.info("[%d/%d] Evaluating %s (%s v%s, cohort=%s)...", idx, len(flagged_crates), sample_id, name, version, sample_type)

        try:
            t0 = time.time()
            pre = preprocess_crate(name, version, extracted_path)
            view = build_anonymized_view(pre, salt="crateshield-v3")
            signals = extract_all_signals(view)
            manifest_sample = {"sample_id": sample_id, "cluster_id": name}
            purpose_info = extract_crate_declared_purpose(extracted_path, view, manifest_sample)
            taint_context = extract_taint_contextual(view, manifest_sample=manifest_sample, omit_absence_notes=True)
            retrieved = retrieve_context(signals, top_k=3, exclude_crates={name})
            messages = build_combined_prompt(signals, taint_context, purpose_info, retrieved_context=retrieved)

            if dry_run:
                raw_text = '{"verdict": "BENIGN", "confidence": 0.9, "malware_score": 0.0, "reasoning": "[DRY RUN]"}'
                t_in, t_out, cost = 1500, 100, 0.0003
            else:
                raw_text, t_in, t_out, cost = call_gemini_api(messages, api_key=key, model=model, temperature=0.0)
                total_calls += 1
                total_cost += cost

            parsed = parse_llm_response(raw_text)
            elapsed = time.time() - t0

            # Determine Stage 2 classification
            v_str = str(parsed.get("verdict") or parsed.get("classification") or "BENIGN").upper()
            m_score = float(parsed.get("malware_score") or 0.0)
            is_mal_strict = (v_str == "MALICIOUS")
            is_mal_relaxed = (v_str in ("MALICIOUS", "SUSPICIOUS") or m_score >= 0.25)

            record = {
                "sample_id": sample_id,
                "name": name,
                "version": version,
                "sample_type": sample_type,
                "downloads": c.get("downloads", 0),
                "fired_signals": c.get("fired_signals", []),
                "condition": "contextual_purpose_consistency",
                "model": model,
                "temperature": 0.0,
                "classification": {
                    "verdict": v_str,
                    "malware_score": m_score,
                    "security_risk_score": float(parsed.get("security_risk_score") or 0.0),
                    "confidence": parsed.get("confidence", 0.0),
                    "reasoning": parsed.get("reasoning", ""),
                    "primary_signals": parsed.get("primary_signals", []),
                    "recommended_action": parsed.get("recommended_action", "ALLOW"),
                    "is_malicious_strict": is_mal_strict,
                    "is_malicious_relaxed": is_mal_relaxed,
                },
                "usage": {"tokens_in": t_in, "tokens_out": t_out, "cost_usd": cost},
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
            stage2_results[sample_id] = record

            logger.info("  --> Verdict: %s (score=%.2f) in %.2fs (tokens: in=%d, out=%d)", v_str, m_score, elapsed, t_in, t_out)

            # Checkpoint save
            if not dry_run and total_calls % 5 == 0:
                STAGE2_PATH.write_text(json.dumps(stage2_results, indent=2), encoding="utf-8")
                logger.info("  [Checkpoint] Saved Stage 2 results (%d entries, calls made=%d, cost=$%.4f)", len(stage2_results), total_calls, total_cost)

            if not dry_run:
                time.sleep(sleep_delay)

        except Exception as e:
            logger.error("Error evaluating %s: %s", sample_id, e, exc_info=True)

    # Final save
    if not dry_run:
        STAGE2_PATH.write_text(json.dumps(stage2_results, indent=2), encoding="utf-8")
        logger.info("Final Stage 2 results saved to %s (%d entries, total cost=$%.4f).", STAGE2_PATH, len(stage2_results), total_cost)

    # Generate review CSV
    export_review_csv(stage2_results)
    return stage2_results


def export_review_csv(results: dict[str, Any]) -> None:
    """Exports review CSV for human triage with BLANK reviewer_verdict."""
    rows = []
    for sid, r in results.items():
        cls_info = r.get("classification", {})
        v_str = cls_info.get("verdict", "BENIGN")
        is_rel = cls_info.get("is_malicious_relaxed", False)
        # Include all crates flagged as MALICIOUS or SUSPICIOUS or relaxed-flagged
        if v_str in ("MALICIOUS", "SUSPICIOUS") or is_rel:
            rows.append({
                "sample_id": sid,
                "crate_name": r.get("name", ""),
                "version": r.get("version", ""),
                "cohort": r.get("sample_type", ""),
                "downloads": r.get("downloads", 0),
                "stage1_signals": ";".join(r.get("fired_signals", [])),
                "stage2_verdict": v_str,
                "malware_score": cls_info.get("malware_score", 0.0),
                "reasoning": cls_info.get("reasoning", "").replace("\n", " "),
                "reviewer_verdict": "",  # EXPLICITLY BLANK per protocol
                "reviewer_notes": "",
            })

    # Sort by malware score descending
    rows.sort(key=lambda x: x["malware_score"], reverse=True)

    with open(REVIEW_CSV_PATH, "w", encoding="utf-8", newline="") as f:
        fieldnames = [
            "sample_id", "crate_name", "version", "cohort", "downloads",
            "stage1_signals", "stage2_verdict", "malware_score", "reasoning",
            "reviewer_verdict", "reviewer_notes"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    logger.info("Wrote %d candidates flagged for human review to %s (reviewer_verdict column blank).", len(rows), REVIEW_CSV_PATH)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-key", type=str, default=None)
    parser.add_argument("--sleep", type=float, default=3.0)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    run_stage2(api_key=args.api_key, sleep_delay=args.sleep, dry_run=args.dry_run)
