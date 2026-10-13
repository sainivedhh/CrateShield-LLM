"""Builds a retrieval query from a crate's structured signals, then
returns the top-k most relevant knowledge base entries (real incidents +
general attack patterns) to ground the LLM's reasoning."""
from __future__ import annotations

import logging
from pathlib import Path

from crateshield.rag.store import VectorStore, load_corpus

logger = logging.getLogger(__name__)

_store: VectorStore | None = None


def get_store() -> VectorStore:
    global _store
    if _store is None:
        from crateshield.config import DATA_DIR
        corpus_path = DATA_DIR / "knowledge_base" / "corpus.json"
        cache_path = DATA_DIR / "knowledge_base" / ".embeddings_cache.npy"
        documents = load_corpus(corpus_path)
        _store = VectorStore(documents, cache_path=cache_path)
    return _store


def build_retrieval_query(signals: dict) -> str:
    """Turns structured signals into a natural-language query -- retrieval
    works on semantic similarity, so we describe what was FOUND, not just
    dump the raw JSON (which embeds poorly as a search query)."""
    parts = [f"Analyzing Rust crate '{signals.get('crate', 'unknown')}'."]

    br = signals.get("build_rs", {})
    if br.get("has_build_rs"):
        if br.get("signals"):
            parts.append(f"build.rs triggers signals: {', '.join(br['signals'])}.")
        else:
            parts.append("Has a build.rs with no flagged signals.")

    uf = signals.get("unsafe_ffi", {})
    if uf.get("syscall_usage"):
        parts.append("Contains raw syscall usage inside unsafe blocks.")
    elif uf.get("unsafe_block_count", 0) > 0:
        parts.append(f"Contains {uf['unsafe_block_count']} unsafe block(s).")

    pm = signals.get("proc_macro", {})
    if pm.get("is_proc_macro") and pm.get("proc_macro_suspicious_imports"):
        parts.append(f"Proc-macro with suspicious imports: {', '.join(pm['proc_macro_suspicious_imports'])}.")

    ts = signals.get("typosquatting", {})
    if ts.get("flagged"):
        parts.append(f"High typosquatting similarity to '{ts.get('target')}' (score {ts.get('score')}).")

    ss = signals.get("source_scan", {})
    if ss.get("possible_exfiltration_shape"):
        parts.append("Library source combines network access with filesystem walking or sensitive file paths.")
    elif ss.get("categories"):
        parts.append(f"Library source uses: {', '.join(ss['categories'])}.")
    if not br.get("has_build_rs") and ss.get("categories"):
        parts.append("No build script; behaviour is in ordinary library code.")

    dep = signals.get("dependencies", {})
    if dep.get("suspicious"):
        parts.append(f"Depends on crate(s) reported malicious: {', '.join(dep['suspicious'])}.")

    if signals.get("version", {}).get("high_major_version"):
        parts.append("Unusually high major version number (placeholder-style version).")
    if signals.get("prompt_injection", {}).get("detected"):
        parts.append("Crate text tries to instruct the reviewer / AI about its verdict (prompt injection).")

    return " ".join(parts)


def _norm(name: str) -> str:
    return name.lower().replace("-", "_")


def excluded_doc_ids(documents: list[dict], exclude_crates: set[str] | None) -> set[str]:
    """Ids of knowledge-base documents that describe any of `exclude_crates`
    (via each document's optional `crates` list)."""
    if not exclude_crates:
        return set()
    wanted = {_norm(c) for c in exclude_crates}
    return {d["id"] for d in documents if wanted & {_norm(c) for c in d.get("crates", [])}}


def retrieve_context(signals: dict, top_k: int = 3, exclude_crates: set[str] | None = None) -> list[dict]:
    """exclude_crates: leave-one-out for evaluation. Any document whose
    `crates` list names one of these crates is not eligible for retrieval."""
    try:
        query = build_retrieval_query(signals)
        store = get_store()
        results = store.search(query, top_k=top_k,
                               exclude_ids=excluded_doc_ids(store.documents, exclude_crates))
        logger.info("Retrieved %d grounding docs (query: %.80s...)", len(results), query)
        return results
    except Exception as e:
        # Retrieval failure should degrade gracefully, not break analysis --
        # the LLM can still reason from signals alone, just less grounded.
        logger.warning("RAG retrieval failed, continuing without grounding: %s", e)
        return []
