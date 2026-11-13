"""Calibration against the real system only.

The detector never looks at a honeypot to learn its thresholds. It learns what
a real shell does, then measures how far a target departs from that. Two
reasons this matters here.

First, the false positive rate is set by construction. Honeyval and
AdvancedShelLM both report that an LLM agent asked whether a target is a
honeypot flags real systems at a rate nobody chose. A one-class test calibrated
on the real system cannot have that problem, because the boundary is a quantile
of the statistic under real-system runs.

Second, it does not need honeypot labels, so adding a honeypot to the study
never changes the decision rule. Results stay comparable across targets.

Real-system runs cost milliseconds per probe, so the calibration sample can be
made large for free. That is what keeps the empirical quantile from being
coarse.
"""

from __future__ import annotations

import json
import math
import pathlib
from dataclasses import asdict, dataclass, field


@dataclass(slots=True)
class FeatureCalibration:
    """What one feature looks like on a real shell."""

    name: str
    kind: str
    higher_means_simulated: bool | None
    real_values: list[float] = field(default_factory=list)
    real_true: int = 0
    real_n: int = 0

    def observe(self, value: float | bool | None) -> None:
        if value is None:
            return
        if self.kind == "bool":
            self.real_n += 1
            self.real_true += int(bool(value))
        else:
            v = float(value)
            if math.isfinite(v):
                self.real_values.append(v)

    @property
    def usable(self) -> bool:
        return self.real_n >= 2 if self.kind == "bool" else len(self.real_values) >= 2

    def evidence(self, value: float | bool | None) -> float:
        """How surprising this value would be on a real shell, in nats.

        A one-sided empirical p-value with a Laplace-style correction, reported
        as its negative log. The correction bounds the score at log(n+1), so no
        single feature can decide a session on its own.
        """
        if value is None or not self.usable:
            return 0.0
        if self.kind == "bool":
            # Laplace smoothing: a feature never seen True on the real system
            # still cannot contribute unbounded evidence.
            p_true = (self.real_true + 1) / (self.real_n + 2)
            p = p_true if bool(value) else (1.0 - p_true)
            return -math.log(max(p, 1e-12))
        v = float(value)
        if not math.isfinite(v):
            return 0.0
        n = len(self.real_values)
        if self.higher_means_simulated:
            at_least = sum(1 for r in self.real_values if r >= v)
        else:
            at_least = sum(1 for r in self.real_values if r <= v)
        p = (at_least + 1) / (n + 1)
        return -math.log(p)


@dataclass(slots=True)
class Calibration:
    """Per-feature calibration plus the stopping boundary."""

    features: dict[str, FeatureCalibration] = field(default_factory=dict)
    boundary: float = math.inf
    alpha: float = 0.01
    boundary_source: str = "uncalibrated"
    real_sessions: int = 0

    def ensure(self, name: str, kind: str, direction: bool | None) -> FeatureCalibration:
        fc = self.features.get(name)
        if fc is None:
            fc = FeatureCalibration(name=name, kind=kind, higher_means_simulated=direction)
            self.features[name] = fc
        return fc

    def evidence(self, name: str, value: float | bool | None) -> float:
        fc = self.features.get(name)
        return 0.0 if fc is None else fc.evidence(value)

    def usable_features(self) -> list[str]:
        return sorted(n for n, f in self.features.items() if f.usable)

    def save(self, path: str | pathlib.Path) -> None:
        pathlib.Path(path).write_text(json.dumps({
            "alpha": self.alpha,
            "boundary": None if math.isinf(self.boundary) else self.boundary,
            "boundary_source": self.boundary_source,
            "real_sessions": self.real_sessions,
            "features": {k: asdict(v) for k, v in self.features.items()},
        }, indent=2))

    @classmethod
    def load(cls, path: str | pathlib.Path) -> Calibration:
        data = json.loads(pathlib.Path(path).read_text())
        cal = cls(
            alpha=data.get("alpha", 0.01),
            boundary=math.inf if data.get("boundary") is None else float(data["boundary"]),
            boundary_source=data.get("boundary_source", "uncalibrated"),
            real_sessions=data.get("real_sessions", 0),
        )
        for name, raw in data.get("features", {}).items():
            cal.features[name] = FeatureCalibration(**raw)
        return cal


def fit_boundary(
    cal: Calibration,
    real_sessions: list[list[tuple[str, float | bool | None]]],
    alpha: float = 0.01,
) -> Calibration:
    """Choose the stopping boundary from real-system sessions.

    The statistic is read sequentially, so the quantity that must be controlled
    is the running maximum of the accumulated evidence, not its final value.
    Taking repeated looks at a growing sum would otherwise raise the false
    positive rate above alpha.

    The boundary is the (1 - alpha) quantile of that running maximum across
    real sessions. With too few sessions to estimate the quantile, the largest
    observed maximum is used and the record says so, which is conservative.
    """
    maxima: list[float] = []
    for session in real_sessions:
        running = 0.0
        peak = 0.0
        for name, value in session:
            running += cal.evidence(name, value)
            peak = max(peak, running)
        maxima.append(peak)

    cal.alpha = alpha
    cal.real_sessions = len(maxima)
    if not maxima:
        cal.boundary = math.inf
        cal.boundary_source = "no real sessions; detector disabled"
        return cal

    maxima.sort()
    n = len(maxima)

    # Split conformal prediction. With n calibration scores the threshold is
    # the k-th smallest, k = ceil((n + 1)(1 - alpha)), which bounds the chance
    # that a fresh real session exceeds it by alpha. The bound is finite
    # sample and needs no assumption about how the scores are distributed,
    # which matters here because the timing features are correlated and
    # heavy tailed.
    #
    # Such a k exists only when n >= 1/alpha - 1. Below that the sample cannot
    # express the rate at all, and the record says so rather than quietly
    # returning something weaker.
    k = math.ceil((n + 1) * (1.0 - alpha))

    if k > n:
        cal.boundary = math.nextafter(maxima[-1], math.inf)
        cal.boundary_source = (
            f"above the max of {n} real sessions: a split-conformal threshold "
            f"for alpha {alpha} needs at least {math.ceil(1.0 / alpha) - 1} of "
            f"them, so no real session is flagged and the rate this sample can "
            f"certify is {1.0 / (n + 1):.4f}"
        )
        return cal

    # The verdict fires on score >= boundary, so sit one step above the k-th
    # value to keep the comparison strict, as the guarantee assumes.
    cal.boundary = math.nextafter(maxima[k - 1], math.inf)
    exceed = sum(1 for m in maxima if m >= cal.boundary) / n
    cal.boundary_source = (
        f"split-conformal threshold at order statistic {k} of {n} real "
        f"sessions, bounding the false positive rate by {alpha} "
        f"(calibration exceedance {exceed:.4f}, tightest rate this sample can "
        f"certify {1.0 / (n + 1):.4f})"
    )
    return cal
