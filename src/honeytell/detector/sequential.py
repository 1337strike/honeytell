"""Sequential decision, which also answers how much a verdict costs.

Evidence is accumulated in the order the probes ran. The first point where it
crosses the boundary is the verdict, and the number of commands issued up to
that point is the attacker's cost. Nothing extra is needed to measure it.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from honeytell.detector.calibrate import Calibration


@dataclass(slots=True)
class SequentialVerdict:
    """Outcome of reading one session."""

    simulated: bool
    score: float
    boundary: float
    features_used: int
    commands_to_verdict: int | None
    probes_to_verdict: int | None
    deciding_feature: str | None
    trace: list[tuple[str, float, float]] = field(default_factory=list)

    def to_json(self) -> dict:
        return {
            "simulated": self.simulated,
            "score": round(self.score, 4),
            "boundary": None if math.isinf(self.boundary) else round(self.boundary, 4),
            "features_used": self.features_used,
            "commands_to_verdict": self.commands_to_verdict,
            "probes_to_verdict": self.probes_to_verdict,
            "deciding_feature": self.deciding_feature,
        }


def decide(
    cal: Calibration,
    ordered: list[tuple[str, float | bool | None]],
    commands_after_feature: dict[str, int] | None = None,
) -> SequentialVerdict:
    """Read features in order and stop at the first crossing.

    ``commands_after_feature`` maps a feature name to how many commands had been
    issued by the time it was scored, so the cost is reported in commands rather
    than in features.
    """
    running = 0.0
    used = 0
    hit_at: str | None = None
    probes_at: int | None = None
    trace: list[tuple[str, float, float]] = []

    for position, (name, value) in enumerate(ordered, start=1):
        e = cal.evidence(name, value)
        if e:
            used += 1
        running += e
        trace.append((name, e, running))
        if hit_at is None and running >= cal.boundary:
            hit_at = name
            probes_at = position

    commands = None
    if hit_at is not None and commands_after_feature:
        commands = commands_after_feature.get(hit_at)

    return SequentialVerdict(
        simulated=hit_at is not None,
        score=running,
        boundary=cal.boundary,
        features_used=used,
        commands_to_verdict=commands,
        probes_to_verdict=probes_at,
        deciding_feature=hit_at,
        trace=trace,
    )
