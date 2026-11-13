"""Timing probes built from ratios and slopes, never absolute latency.

Absolute latency measures the machine the backend runs on. On a laptop CPU an
open-weight model is slow, which would make detection look easy for a reason
that has nothing to do with the honeypot. Every feature here is a ratio or a
slope, so a slower machine moves numerator and denominator together and the
feature stays comparable.

Absolute times are still written to the transcripts and reported as context,
but they are not detection features.
"""

from __future__ import annotations

from honeytell.probes.base import (
    FeatureSpec,
    FeatureValue,
    Probe,
    ProbeContext,
    cv,
    median,
    ols_slope,
)
from honeytell.transport.shell import Shell


class LengthSlope(Probe):
    """Does response time grow with the amount of output?

    A real shell copies bytes it already has, so time is nearly flat in output
    size. A language model emits tokens one at a time, so time rises with the
    length of what it produces. The slope is the signal and it is positive for
    any generator on any hardware.
    """

    id = "timing.length_slope"
    vector = "timing"
    description = "Regress streaming time on output size using seq of growing length"
    features = (
        FeatureSpec(
            "ms_per_kib",
            "float",
            "Streaming milliseconds per KiB of output, by least squares",
            higher_means_simulated=True,
        ),
        FeatureSpec(
            "slope_r2",
            "float",
            "Fit quality of the time against size regression",
            higher_means_simulated=True,
        ),
    )

    # Fractions of the configured ceiling rather than fixed counts. The slope
    # needs a spread along x, not a large x, and a generator is charged per
    # token for every line it has to produce.
    #
    # Note the regression uses the output actually received, not the output
    # requested. A target that truncates is measured on what it really emitted.
    _fractions = (0.008, 0.04, 0.17, 0.42, 1.0)

    def _counts(self, ceiling: int) -> tuple[int, ...]:
        return tuple(sorted({max(1, round(ceiling * f)) for f in self._fractions}))

    async def run(self, sh: Shell, ctx: ProbeContext) -> dict[str, FeatureValue]:
        sizes: list[float] = []
        times: list[float] = []
        for n in self._counts(ctx.max_seq_lines):
            step = await sh.run(f"seq 1 {n}")
            if step.timed_out or step.stream_ms is None:
                continue
            sizes.append(step.output_bytes / 1024.0)
            times.append(step.stream_ms)
        slope, r2 = ols_slope(sizes, times)
        return self.check({"ms_per_kib": slope, "slope_r2": r2})


class RepeatVariance(Probe):
    """How much does the same command vary in time?

    A real shell is close to deterministic. Sampling from a model is not, so
    repeated identical commands spread out.
    """

    id = "timing.repeat_cv"
    vector = "timing"
    description = "Coefficient of variation of response time over identical commands"
    features = (
        FeatureSpec(
            "total_cv",
            "float",
            "Coefficient of variation of total response time",
            higher_means_simulated=True,
        ),
        FeatureSpec(
            "bytes_cv",
            "float",
            "Coefficient of variation of output size for an identical command",
            higher_means_simulated=True,
        ),
    )

    async def run(self, sh: Shell, ctx: ProbeContext) -> dict[str, FeatureValue]:
        times: list[float] = []
        sizes: list[float] = []
        for _ in range(max(3, ctx.repeats)):
            step = await sh.run("uname -sr")
            if step.timed_out:
                continue
            if step.total_ms is not None:
                times.append(step.total_ms)
            sizes.append(float(step.output_bytes))
        return self.check({"total_cv": cv(times), "bytes_cv": cv(sizes)})


class EmptyVersusLong(Probe):
    """Compare a command that prints nothing with one that prints a lot.

    On a real shell both return almost immediately, so the ratio sits near one.
    A generator pays per token, so the long one costs far more.
    """

    id = "timing.empty_vs_long"
    vector = "timing"
    description = "Ratio of response time for a long output against a silent command"
    features = (
        FeatureSpec(
            "long_over_silent",
            "float",
            "Median time for the longest seq divided by median time for a silent "
            "command",
            higher_means_simulated=True,
        ),
    )

    async def run(self, sh: Shell, ctx: ProbeContext) -> dict[str, FeatureValue]:
        silent: list[float] = []
        loud: list[float] = []
        for _ in range(max(3, ctx.repeats)):
            a = await sh.run("true")
            if not a.timed_out and a.total_ms is not None:
                silent.append(a.total_ms)
            b = await sh.run(f"seq 1 {ctx.max_seq_lines}")
            if not b.timed_out and b.total_ms is not None:
                loud.append(b.total_ms)
        ms, ml = median(silent), median(loud)
        ratio = None if not ms or ml is None or ms <= 0 else ml / ms
        return self.check({"long_over_silent": ratio})


class StreamFraction(Probe):
    """How much of the reply arrives after the first byte?

    A real shell writes its output in one burst, so the first byte and the last
    byte are nearly simultaneous. A streaming generator spends most of the wall
    clock between them.
    """

    id = "timing.stream_fraction"
    vector = "timing"
    description = "Share of total response time spent streaming after the first byte"
    features = (
        FeatureSpec(
            "stream_share",
            "float",
            "Streaming time divided by total time for a long reply",
            higher_means_simulated=True,
        ),
    )

    async def run(self, sh: Shell, ctx: ProbeContext) -> dict[str, FeatureValue]:
        shares: list[float] = []
        for _ in range(max(3, ctx.repeats)):
            step = await sh.run(f"seq 1 {ctx.max_seq_lines}")
            if step.timed_out or step.total_ms is None or step.stream_ms is None:
                continue
            if step.total_ms > 0:
                shares.append(step.stream_ms / step.total_ms)
        return self.check({"stream_share": median(shares)})


PROBES: tuple[Probe, ...] = (
    LengthSlope(),
    RepeatVariance(),
    EmptyVersusLong(),
    StreamFraction(),
)
