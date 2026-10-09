"""A minimal vector store. At corpus sizes in the dozens-to-low-hundreds
(this project's realistic knowledge-base scale), a full vector database is
unjustified engineering overhead -- brute-force cosine similarity over a
NumPy array is both simpler to explain in a review and fast enough
(sub-millisecond for this corpus size). Embeddings are cached to disk so
you don't re-embed the whole corpus on every server restart.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

import numpy as np

from crateshield.rag import embedder

logger = logging.getLogger(__name__)


class VectorStore:
    def __init__(self, documents: list[dict], cache_path: Path | None = None):
        self.documents = documents
        self.cache_path = cache_path
        self.embeddings: np.ndarray | None = None
        self._tfidf = None
        self._load_or_build()

    def _load_or_build(self):
        try:
            from sentence_transformers import SentenceTransformer
            has_st = True
        except ImportError:
            has_st = False

        if has_st:
            if self.cache_path and self.cache_path.exists():
                cached = np.load(self.cache_path, allow_pickle=True).item()
                if cached.get("n_docs") == len(self.documents):
                    self.embeddings = cached["embeddings"]
                    logger.info("Loaded cached embeddings (%d docs)", len(self.documents))
                    return
                logger.info("Corpus size changed, re-embedding")

            texts = [f"{d['title']}. {d['text']}" for d in self.documents]
            self.embeddings = embedder.embed_texts(texts)
            if self.cache_path:
                self.cache_path.parent.mkdir(parents=True, exist_ok=True)
                np.save(self.cache_path, {"embeddings": self.embeddings, "n_docs": len(self.documents)})
        else:
            texts = [f"{d['title']}. {d['text']}" for d in self.documents]
            try:
                from sklearn.feature_extraction.text import TfidfVectorizer
                vec = TfidfVectorizer(norm="l2", token_pattern=r"(?u)\b\w+\b")
                self.embeddings = vec.fit_transform(texts).toarray()
                self._tfidf = vec
                logger.info("Loaded TF-IDF embeddings (%d docs)", len(self.documents))
            except Exception as e:
                logger.warning("Could not initialize TF-IDF fallback: %s", e)
                self._tfidf = None
                self.embeddings = embedder.embed_texts(texts)

    def search(self, query: str, top_k: int = 3, exclude_ids: set[str] | None = None) -> list[dict]:
        """exclude_ids: documents to leave out BEFORE ranking (used for
        leave-one-out evaluation, so a crate's own incident write-up cannot
        be retrieved as 'grounding' for that same crate)."""
        if self._tfidf is not None:
            query_vec = self._tfidf.transform([query]).toarray()[0]
        else:
            query_vec = embedder.embed_texts([query])[0]
        # cosine similarity == dot product, since embeddings are L2-normalized
        scores = self.embeddings @ query_vec
        order = np.argsort(-scores)
        if exclude_ids:
            order = [i for i in order if self.documents[i]["id"] not in exclude_ids]
        return [
            {**self.documents[i], "similarity": float(scores[i])}
            for i in list(order)[:top_k]
        ]


def load_corpus(path: Path) -> list[dict]:
    return json.loads(path.read_text())
