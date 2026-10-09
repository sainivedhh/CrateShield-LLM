"""Tune vs. Eval Dataset Splitting by Base Crate.

Enforces Section 4 of the spec:
- Split by BASE CRATE, never by sample. Both twins of a base go to the same split.
- Base-crate sets of tune and eval must be strictly disjoint (Gate G6).
- Tune split is used for prompting and rule development; eval split is kept untouched.
"""
from __future__ import annotations

import random


def split_base_crates(
    base_crates: list[dict],
    n_tune: int = 10,
    n_eval: int = 30,
    seed: int = 42,
) -> tuple[list[dict], list[dict]]:
    """Splits base crates into disjoint tune and eval sets.

    Args:
        base_crates: List of base crate dictionaries (each having 'name', 'version', etc.).
        n_tune: Target count for tuning split.
        n_eval: Target count for evaluation split.
        seed: Deterministic random seed.

    Returns:
        (tune_bases, eval_bases)
    """
    total = len(base_crates)
    if total < n_tune + n_eval:
        raise ValueError(
            f"Not enough base crates ({total}) for requested {n_tune} tune + {n_eval} eval."
        )

    # Copy and deterministically shuffle
    pool = list(base_crates)
    rng = random.Random(seed)
    rng.shuffle(pool)

    tune_crates = pool[:n_tune]
    eval_crates = pool[n_tune : n_tune + n_eval]

    # Verify disjointness (Gate G6)
    tune_names = {c["name"] for c in tune_crates}
    eval_names = {c["name"] for c in eval_crates}
    overlap = tune_names & eval_names
    if overlap:
        raise AssertionError(f"Gate G6 violation: tune and eval share base crates: {overlap}")

    return tune_crates, eval_crates
