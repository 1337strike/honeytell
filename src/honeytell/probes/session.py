"""Features read from the whole session rather than from one exchange.

Some properties only exist across a conversation. The strongest one measured
so far is how the cost of a command changes as the session goes on: an LLM
honeypot resends the whole conversation on every command, so its prompt grows
and the time to answer grows with it. Ollama's own log, during one Beelzebub
session, went from 892 ms on the first commands to a full minute by the
thirtieth.

A real shell does not care how long you have been logged in.

The measure is a slope within one session, so a slower machine moves every
point together and the slope stays comparable.
"""

from __future__ import annotations

from honeytell.probes.base import (
    FeatureSpec,
    FeatureValue,
    Probe,
    ProbeContext,
    median,
    ols_slope,
)
from honeytell.transport.shell import Shell


class LatencyGrowth(Probe):
    """Does answering get more expensive as the session goes on?

    Issues no commands of its own: it reads the session that the other probes
    have already produced, so it must run last.
    """

    id = "session.latency_growth"
    vector = "session"
    description = "Slope of response time against position in the session"
    features = (
        FeatureSpec(
            "ms_per_command",
            "float",
            "Milliseconds of response time added per command issued, by least "
            "squares over the session",
            higher_means_simulated=True,
        ),
        FeatureSpec(
            "growth_r2",
            "float",
            "Fit quality of the time against position regression. Diagnostic only",
            higher_means_simulated=True,
            decisive=False,
        ),
        FeatureSpec(
            "last_over_first",
            "float",
            "Median response time of the final fifth of the session divided by "
            "that of the first fifth",
            higher_means_simulated=True,
        ),
    )

    async def run(self, sh: Shell, ctx: ProbeContext) -> dict[str, FeatureValue]:
        usable = [s for s in sh.steps if not s.timed_out and s.total_ms is not None]
        if len(usable) < 10:
            return self.check(self.empty())

        xs = [float(i) for i, _ in enumerate(usable)]
        ys = [s.total_ms for s in usable]
        slope, r2 = ols_slope(xs, ys)

        fifth = max(2, len(usable) // 5)
        early = median([s.total_ms for s in usable[:fifth]])
        late = median([s.total_ms for s in usable[-fifth:]])
        ratio = None if not early or late is None or early <= 0 else late / early

        return self.check({
            "ms_per_command": slope,
            "growth_r2": r2,
            "last_over_first": ratio,
        })


PROBES: tuple[Probe, ...] = (LatencyGrowth(),)
