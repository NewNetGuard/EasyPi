"""Small shared text helpers. Leaf module — imports only the standard library, so it
is safe to import from anywhere in the package (no circular-import risk).
"""

from __future__ import annotations

import math
from collections import Counter
from functools import lru_cache


@lru_cache(maxsize=20000)
def shannon_entropy(text: str) -> float:
    """Shannon entropy (base-2) over the characters of `text`, case-insensitive.

    Single source of truth: the DGA / ad-tracker / domain-analysis / threat-intel
    detectors all call this instead of each carrying their own copy of the formula.
    """
    if not text:
        return 0.0
    counts = Counter(text.lower())
    n = len(text)
    entropy = 0.0
    for c in counts.values():
        p = c / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy
