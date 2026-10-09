"""Embeds text for the RAG retriever using a local sentence-transformers
model. Deliberately NOT calling an LLM API for embeddings: this keeps
retrieval fast, free, deterministic, and independent of the LLM provider
you pick for reasoning (Gemini/OpenAI/Anthropic) -- retrieval always works
the same way regardless of which model does the final classification.
"""
from __future__ import annotations

import logging

import numpy as np

logger = logging.getLogger(__name__)

_MODEL_NAME = "all-MiniLM-L6-v2"  # small, fast, well-established (384-dim)
_model = None


def _get_model():
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer
        logger.info("Loading embedding model %s (first call only, cached after)", _MODEL_NAME)
        _model = SentenceTransformer(_MODEL_NAME)
    return _model


def embed_texts(texts: list[str]) -> np.ndarray:
    """Returns an (N, 384) array of L2-normalized embeddings."""
    model = _get_model()
    vectors = model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
    return np.asarray(vectors, dtype=np.float32)


def embed_query(text: str) -> np.ndarray:
    return embed_texts([text])[0]
