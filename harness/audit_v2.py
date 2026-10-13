"""Tell audit and discriminator diagnostic for CrateShield v2.

Enforces Phase 2 requirements:
1. Line-ending consistency: Fails if payload-containing files differ from base in line endings.
2. Tell detection: Fails if any fixed string, identifier prefix, or comment appears in >= 20%
   of malicious twins and 0% of benign twins.
3. Discriminator check: Bag-of-tokens logistic regression on added lines vs base lines must not
   reach > 0.65 accuracy on a held-out slice.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
from typing import Any


def audit_line_endings_match(base_file: Path, twin_file: Path) -> tuple[bool, str]:
    """Verifies that the injected twin file preserves the base file's native line endings."""
    base_bytes = base_file.read_bytes()
    twin_bytes = twin_file.read_bytes()

    base_crlf = b"\r\n" in base_bytes
    twin_crlf = b"\r\n" in twin_bytes

    if base_crlf != twin_crlf:
        return False, f"Line ending mismatch: base is {'CRLF' if base_crlf else 'LF'}, twin is {'CRLF' if twin_crlf else 'LF'}"
    return True, "OK"


def audit_twin_diff_hunk_clean(base_file: Path, twin_file: Path) -> tuple[bool, str]:
    """Verifies that the diff between twin and base contains only intended additions."""
    base_text = base_file.read_text(encoding="utf-8", errors="replace")
    twin_text = twin_file.read_text(encoding="utf-8", errors="replace")

    base_lines = set(line.strip() for line in base_text.splitlines() if line.strip())
    twin_lines = set(line.strip() for line in twin_text.splitlines() if line.strip())

    # All base lines should still exist in twin (only additions made)
    missing_base_lines = base_lines - twin_lines
    if missing_base_lines:
        return False, f"Base lines were deleted or modified: {list(missing_base_lines)[:2]}"
    return True, "OK"


def audit_tell_frequency(
    malicious_files: list[Path],
    benign_files: list[Path],
    max_tell_ratio: float = 0.20,
) -> tuple[bool, list[str]]:
    """Flags any fixed comment, identifier prefix, or fixed string literal appearing in >= 20% of malicious and 0% of benign."""
    mal_texts = [f.read_text(encoding="utf-8", errors="ignore") for f in malicious_files]
    ben_texts = [f.read_text(encoding="utf-8", errors="ignore") for f in benign_files]

    n_mal = len(mal_texts)
    if n_mal == 0:
        return True, []

    violations = []

    # 1. Check for known v1 tells explicitly
    forbidden_v1_tells = [
        "Platform integration hook",
        "Module internal helper",
        "routine_",
    ]
    for tell in forbidden_v1_tells:
        mal_count = sum(1 for t in mal_texts if tell in t)
        if mal_count > 0:
            violations.append(f"Forbidden v1 tell '{tell}' found in {mal_count}/{n_mal} malicious files")

    # 2. Check for fixed comment lines appearing in >= 20% of malicious and 0% of benign
    mal_comments = Counter()
    for t in mal_texts:
        for line in t.splitlines():
            s = line.strip()
            if s.startswith("//") and len(s) > 5:
                mal_comments[s] += 1

    for comment, count in mal_comments.items():
        if count >= 3 and count / n_mal >= max_tell_ratio:
            ben_has = any(comment in bt for bt in ben_texts)
            if not ben_has:
                violations.append(f"Fixed comment '{comment}' in {count}/{n_mal} ({count/n_mal:.1%}) malicious files and 0% benign")

    # 3. Check for function name identifier prefixes
    fn_name_pattern = re.compile(r"\bfn\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(")
    mal_fn_prefixes = Counter()
    for t in mal_texts:
        fns = fn_name_pattern.findall(t)
        for fn in fns:
            if "_" in fn:
                prefix = fn.split("_", 1)[0] + "_"
                if len(prefix) >= 4:
                    mal_fn_prefixes[prefix] += 1

    for prefix, count in mal_fn_prefixes.items():
        if count >= 3 and count / n_mal >= max_tell_ratio:
            ben_has = any(re.search(rf"\bfn\s+{re.escape(prefix)}", bt) for bt in ben_texts)
            if not ben_has:
                violations.append(f"Fixed fn prefix '{prefix}' in {count}/{n_mal} ({count/n_mal:.1%}) malicious files and 0% benign")

    # 4. Check for fixed string literals >= 15 chars appearing across >= 20% malicious and 0% benign
    str_pattern = re.compile(r'"([^"\\]{15,})"')
    mal_strings = Counter()
    for t in mal_texts:
        strs = set(str_pattern.findall(t))
        for s in strs:
            mal_strings[s] += 1

    for s, count in mal_strings.items():
        if count >= 3 and count / n_mal >= max_tell_ratio:
            ben_has = any(s in bt for bt in ben_texts)
            if not ben_has:
                violations.append(f"Fixed string literal '{s[:30]}...' in {count}/{n_mal} ({count/n_mal:.1%}) malicious files and 0% benign")

    return len(violations) == 0, violations


def run_discriminator_diagnostic(
    added_lines: list[str],
    base_lines: list[str],
    seed: int = 42,
) -> float:
    """Trivial bag-of-words logistic regression diagnostic to ensure added lines don't form an obvious cluster.
    Must not reach > 0.65 accuracy on a held-out slice.
    """
    import random
    import math

    if not added_lines or not base_lines:
        return 0.50

    rng = random.Random(seed)
    
    # Simple token extraction
    def tokenize(s: str) -> set[str]:
        return set(re.findall(r"\b[a-z]{3,}\b", s.lower()))

    data = [(l, 1) for l in added_lines] + [(l, 0) for l in base_lines]
    rng.shuffle(data)

    split_idx = int(0.7 * len(data))
    train, test = data[:split_idx], data[split_idx:]
    if not test:
        return 0.50

    # Build vocab on train
    word_doc_counts = Counter()
    for text, _ in train:
        for w in tokenize(text):
            word_doc_counts[w] += 1
    
    vocab = [w for w, c in word_doc_counts.items() if c >= 2]
    w_to_idx = {w: i for i, w in enumerate(vocab)}
    dim = len(vocab)
    if dim == 0:
        return 0.50

    # Train weights using simple SGD logistic regression
    weights = [0.0] * dim
    bias = 0.0
    lr = 0.05

    for _ in range(10):  # 10 epochs
        for text, label in train:
            feats = [w_to_idx[w] for w in tokenize(text) if w in w_to_idx]
            z = bias + sum(weights[i] for i in feats)
            p = 1.0 / (1.0 + math.exp(-max(min(z, 20.0), -20.0)))
            err = label - p
            bias += lr * err
            for i in feats:
                weights[i] += lr * err

    # Evaluate on held-out test
    correct = 0
    for text, label in test:
        feats = [w_to_idx[w] for w in tokenize(text) if w in w_to_idx]
        z = bias + sum(weights[i] for i in feats)
        pred = 1 if z >= 0.0 else 0
        if pred == label:
            correct += 1

    acc = correct / len(test)
    return round(acc, 3)
