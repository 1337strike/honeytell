"""Probe contract, feature declarations and the small statistics probes need."""

from __future__ import annotations

import hashlib
import math
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Literal

from honeytell.transport.shell import Shell, StepRecord

FeatureValue = float | bool | None


@dataclass(frozen=True, slots=True)
class FeatureSpec:
    """One scored quantity, with the direction that counts as evidence.

    ``higher_means_simulated`` is what lets the detector combine features
    without a per-feature special case. For a boolean feature, True always means
    evidence of simulation, so the flag is left as None.
    """

    name: str
    kind: Literal["bool", "float"]
    description: str
    higher_means_simulated: bool | None = None

    def __post_init__(self) -> None:
        if self.kind == "float" and self.higher_means_simulated is None:
            raise ValueError(f"float feature {self.name!r} needs a direction")


@dataclass(slots=True)
class ProbeContext:
    """Per-run state a probe may use. Seeded, so a run is repeatable."""

    seed: int
    target: str
    backend: str | None
    repeats: int = 5
    max_seq_lines: int = 120
    canary_host: str = "127.0.0.1"
    canary_port: int = 8731
    canary_hits: set[str] = field(default_factory=set)
    rng: random.Random = field(init=False)

    def __post_init__(self) -> None:
        self.rng = random.Random(
            int.from_bytes(
                hashlib.sha256(
                    f"{self.seed}:{self.target}:{self.backend}".encode()
                ).digest()[:8],
                "big",
            )
        )

    def nonce(self, tag: str = "") -> str:
        """A token that is unique per run and cannot be guessed from the prompt."""
        return f"ht{self.rng.randrange(16**10):010x}{tag}"


class Probe(ABC):
    """A probe issues commands and turns the transcript into features.

    Scoring is kept separate from execution so it can be unit tested against
    recorded transcripts, which is where the paper's claims actually live.
    """

    id: str = ""
    vector: str = ""
    description: str = ""
    features: tuple[FeatureSpec, ...] = ()

    @abstractmethod
    async def run(self, sh: Shell, ctx: ProbeContext) -> dict[str, FeatureValue]:
        """Drive the shell and return one value per declared feature."""

    def empty(self) -> dict[str, FeatureValue]:
        """All features unknown. Used when a probe cannot complete."""
        return {f.name: None for f in self.features}

    def check(self, values: dict[str, FeatureValue]) -> dict[str, FeatureValue]:
        """Guard against a probe silently returning the wrong feature set."""
        declared = {f.name for f in self.features}
        got = set(values)
        if declared != got:
            missing = sorted(declared - got)
            extra = sorted(got - declared)
            raise ValueError(
                f"probe {self.id!r} returned features {extra} and omitted {missing}"
            )
        return values


def ols_slope(xs: list[float], ys: list[float]) -> tuple[float | None, float | None]:
    """Least-squares slope and r-squared, in plain Python.

    Core stays dependency-light on purpose: the probe layer must run on a
    laptop with nothing installed beyond asyncssh and pydantic.
    """
    pairs = [(x, y) for x, y in zip(xs, ys, strict=False)
             if x is not None and y is not None
             and math.isfinite(x) and math.isfinite(y)]
    n = len(pairs)
    if n < 3:
        return None, None
    mx = sum(p[0] for p in pairs) / n
    my = sum(p[1] for p in pairs) / n
    sxx = sum((p[0] - mx) ** 2 for p in pairs)
    if sxx <= 0:
        return None, None
    sxy = sum((p[0] - mx) * (p[1] - my) for p in pairs)
    slope = sxy / sxx
    syy = sum((p[1] - my) ** 2 for p in pairs)
    r2 = (sxy * sxy) / (sxx * syy) if syy > 0 else None
    return slope, r2


def cv(values: list[float]) -> float | None:
    """Coefficient of variation: spread scaled by the mean.

    Scale free by construction, so a slow machine does not change it.
    """
    vals = [v for v in values if v is not None and math.isfinite(v)]
    if len(vals) < 2:
        return None
    mean = sum(vals) / len(vals)
    if mean <= 0:
        return None
    var = sum((v - mean) ** 2 for v in vals) / (len(vals) - 1)
    return math.sqrt(var) / mean


def median(values: list[float]) -> float | None:
    vals = sorted(v for v in values if v is not None and math.isfinite(v))
    if not vals:
        return None
    mid = len(vals) // 2
    return vals[mid] if len(vals) % 2 else (vals[mid - 1] + vals[mid]) / 2


def body(step: StepRecord) -> str:
    """Response text with surrounding whitespace removed."""
    return step.text.strip()


def says(step: StepRecord, *needles: str) -> bool:
    """True when the response contains any of the needles, case-insensitively."""
    low = step.text.lower()
    return any(n.lower() in low for n in needles)
