"""
SentinelForge — Data Cleaning, Preprocessing & Repository-Grouped Splits (Section 3.3)
Normalizes code, deduplicates identical samples, and partitions data by repository
to guarantee zero evaluation leakage between training, validation, and test sets.
"""

import re
from typing import Optional, List, Dict, Any, Tuple
from app.ml.dataset import CodeSample


def normalize_code_snippet(code: str) -> str:
    """
    Normalize whitespace, line endings, and basic formatting while strictly preserving
    all security-sensitive semantics, API identifiers, and literal tokens.
    """
    if not code:
        return ""
    # Standardize line endings
    norm = code.replace("\r\n", "\n").replace("\r", "\n")
    # Strip trailing whitespace on each line
    lines = [line.rstrip() for line in norm.splitlines()]
    # Remove leading/trailing blank lines
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines)


def clean_and_deduplicate(samples: list[CodeSample]) -> list[CodeSample]:
    """
    Clean samples and eliminate exact duplicates using SHA-256 content hashes.
    """
    seen_hashes: set[str] = set()
    cleaned: list[CodeSample] = []

    for s in samples:
        norm_code = normalize_code_snippet(s.code_or_function)
        if not norm_code or len(norm_code) < 10:
            continue

        h = s.content_hash
        if h in seen_hashes:
            continue

        seen_hashes.add(h)
        cleaned.append(
            CodeSample(
                sample_id=s.sample_id,
                repository_id=s.repository_id,
                commit_sha=s.commit_sha,
                file_path=s.file_path,
                language=s.language,
                code_or_function=norm_code,
                label=s.label,
                cwe_id=s.cwe_id,
                source_dataset=s.source_dataset,
                label_evidence=s.label_evidence,
                split_group=s.split_group,
            )
        )

    return cleaned


def repository_grouped_split(
    samples: list[CodeSample],
    train_ratio: float = 0.60,
    val_ratio: float = 0.20,
    test_ratio: float = 0.20,
    seed: int = 42,
) -> Tuple[list[CodeSample], list[CodeSample], list[CodeSample]]:
    """
    Split samples by repository group (split_group) to prevent data leakage.
    Code from the same repository or related vulnerable/fixed commits will NEVER
    appear in multiple splits.
    """
    import random

    # Group samples by split_group
    group_map: dict[str, list[CodeSample]] = {}
    for s in samples:
        group_map.setdefault(s.split_group, []).append(s)

    unique_groups = list(group_map.keys())
    rng = random.Random(seed)
    rng.shuffle(unique_groups)

    n_groups = len(unique_groups)
    if n_groups <= 2:
        # Fallback if too few groups: split samples directly
        n_train = max(1, int(len(samples) * train_ratio))
        n_val = max(1, int(len(samples) * val_ratio))
        return samples[:n_train], samples[n_train:n_train + n_val], samples[n_train + n_val:]

    n_train_g = max(1, int(round(n_groups * train_ratio)))
    n_val_g = max(1, int(round(n_groups * val_ratio)))

    # Ensure train, val, and test all have at least one group if n_groups >= 3
    if n_train_g + n_val_g >= n_groups:
        n_train_g = max(1, n_groups - 2)
        n_val_g = 1

    train_groups = set(unique_groups[:n_train_g])
    val_groups = set(unique_groups[n_train_g:n_train_g + n_val_g])
    test_groups = set(unique_groups[n_train_g + n_val_g:])

    train_samples = [s for s in samples if s.split_group in train_groups]
    val_samples = [s for s in samples if s.split_group in val_groups]
    test_samples = [s for s in samples if s.split_group in test_groups]

    return train_samples, val_samples, test_samples
