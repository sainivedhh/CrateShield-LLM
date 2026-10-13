import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import numpy as np


def _mock_embed_texts(texts):
    """Deterministic fake embeddings for testing store/retriever logic
    without downloading real sentence-transformers weights."""
    rng = np.random.default_rng(0)
    vecs = rng.normal(size=(len(texts), 384)).astype("float32")
    norms = np.linalg.norm(vecs, axis=1, keepdims=True)
    return vecs / norms


def test_vector_store_search_returns_top_k(monkeypatch):
    import crateshield.rag.embedder as embedder_mod
    monkeypatch.setattr(embedder_mod, "embed_texts", _mock_embed_texts)

    from crateshield.rag.store import VectorStore

    docs = [
        {"id": f"doc{i}", "type": "pattern", "title": f"Title {i}", "text": f"Text {i}", "source": "test"}
        for i in range(5)
    ]
    store = VectorStore(docs, cache_path=None)
    results = store.search("some query", top_k=3)
    assert len(results) == 3
    assert all("similarity" in r for r in results)
    # results should be sorted descending by similarity
    sims = [r["similarity"] for r in results]
    assert sims == sorted(sims, reverse=True)


def test_build_retrieval_query_includes_flagged_signals():
    from crateshield.rag.retriever import build_retrieval_query

    signals = {
        "crate": "evilcrate",
        "build_rs": {"has_build_rs": True, "signals": ["network_call", "env_var_read"]},
        "typosquatting": {"flagged": True, "target": "goodcrate", "score": 0.9},
    }
    query = build_retrieval_query(signals)
    assert "evilcrate" in query
    assert "network_call" in query
    assert "goodcrate" in query


def test_retrieve_context_degrades_gracefully_on_failure(monkeypatch):
    """If embedding/retrieval fails for any reason, analysis should
    continue with an empty context list rather than crash the pipeline."""
    from crateshield.rag import retriever

    def broken_get_store():
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(retriever, "get_store", broken_get_store)
    result = retriever.retrieve_context({"crate": "x"})
    assert result == []


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
