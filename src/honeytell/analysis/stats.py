"""Statistics the paper needs, in plain Python.

Kept dependency-free so the numbers can be reproduced on a bare interpreter.
Choices worth stating: Wilson rather than the normal approximation, because
detection rates sit near zero and one where the normal interval runs outside
the unit range; Cliff's delta rather than a mean difference, because latency
distributions are skewed and bounded below; Benjamini-Hochberg rather than
Bonferroni, because the probe by target grid has many related tests and
controlling the false discovery rate is the right target.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Interval:
    point: float
    low: float
    high: float
    n: int

    def __str__(self) -> str:
        return f"{self.point:.3f} [{self.low:.3f}, {self.high:.3f}] (n={self.n})"


def wilson_interval(successes: int, n: int, z: float = 1.959963984540054) -> Interval:
    """Wilson score interval for a proportion. Default z is the 95% level."""
    if n <= 0:
        return Interval(float("nan"), float("nan"), float("nan"), 0)
    p = successes / n
    d = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return Interval(p, max(0.0, centre - half), min(1.0, centre + half), n)


def cliffs_delta(a: list[float], b: list[float]) -> tuple[float | None, str]:
    """Cliff's delta between two samples, with the usual magnitude label.

    Returns a value in [-1, 1]: the chance a draw from ``a`` exceeds one from
    ``b`` minus the chance it falls below. No distributional assumption.
    """
    xs = [x for x in a if x is not None and math.isfinite(x)]
    ys = [y for y in b if y is not None and math.isfinite(y)]
    if not xs or not ys:
        return None, "undefined"
    gt = lt = 0
    for x in xs:
        for y in ys:
            if x > y:
                gt += 1
            elif x < y:
                lt += 1
    d = (gt - lt) / (len(xs) * len(ys))
    m = abs(d)
    label = (
        "negligible" if m < 0.147 else
        "small" if m < 0.33 else
        "medium" if m < 0.474 else
        "large"
    )
    return d, label


def mann_whitney_p(a: list[float], b: list[float]) -> float | None:
    """Two-sided Mann-Whitney U p-value by normal approximation with tie correction.

    Adequate for the sample sizes here. For very small samples the p-value is
    conservative, which is the safe direction.
    """
    xs = [x for x in a if x is not None and math.isfinite(x)]
    ys = [y for y in b if y is not None and math.isfinite(y)]
    n1, n2 = len(xs), len(ys)
    if n1 < 3 or n2 < 3:
        return None

    merged = sorted([(v, 0) for v in xs] + [(v, 1) for v in ys])
    ranks = [0.0] * len(merged)
    tie_term = 0.0
    i = 0
    while i < len(merged):
        j = i
        while j + 1 < len(merged) and merged[j + 1][0] == merged[i][0]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[k] = avg
        t = j - i + 1
        if t > 1:
            tie_term += t ** 3 - t
        i = j + 1

    r1 = sum(r for r, (_, g) in zip(ranks, merged, strict=False) if g == 0)
    u1 = r1 - n1 * (n1 + 1) / 2.0
    u = min(u1, n1 * n2 - u1)
    mu = n1 * n2 / 2.0
    n = n1 + n2
    var = (n1 * n2 / 12.0) * ((n + 1) - tie_term / (n * (n - 1)))
    if var <= 0:
        return 1.0
    z = (u - mu + 0.5) / math.sqrt(var)
    return max(0.0, min(1.0, 2.0 * 0.5 * math.erfc(-z / math.sqrt(2)) if z < 0
                        else 2.0 * (1.0 - 0.5 * math.erfc(-z / math.sqrt(2)))))


def benjamini_hochberg(pvalues: dict[str, float], q: float = 0.05) -> dict[str, dict]:
    """Benjamini-Hochberg step-up. Returns per-test adjusted values and decisions."""
    items = [(k, v) for k, v in pvalues.items() if v is not None and math.isfinite(v)]
    m = len(items)
    if m == 0:
        return {}
    items.sort(key=lambda kv: kv[1])

    adjusted: list[float] = [0.0] * m
    prev = 1.0
    for i in range(m - 1, -1, -1):
        val = min(prev, items[i][1] * m / (i + 1))
        adjusted[i] = min(1.0, val)
        prev = adjusted[i]

    out: dict[str, dict] = {}
    for i, (name, raw) in enumerate(items):
        out[name] = {
            "p": raw,
            "p_adjusted": adjusted[i],
            "rank": i + 1,
            "tests": m,
            "q": q,
            "significant": adjusted[i] <= q,
        }
    return out
