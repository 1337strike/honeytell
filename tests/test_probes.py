"""Probe scoring. These tests are where the paper's claims are checked."""

from __future__ import annotations

import pytest

from honeytell.probes import compound, state, timing
from honeytell.probes.base import ols_slope


class TestCryptoDigest:
    """A model cannot evaluate SHA-256, and the input is new every run."""

    async def test_real_shell_passes(self, honest, ctx):
        v = await compound.CryptoDigest().run(honest, ctx)
        assert v["sha256_wrong"] is False
        assert v["md5_wrong"] is False
        assert v["sha256_shaped_but_wrong"] is False

    async def test_hallucinated_digest_caught(self, hallucinating, ctx):
        v = await compound.CryptoDigest().run(hallucinating, ctx)
        assert v["sha256_wrong"] is True
        assert v["md5_wrong"] is True
        # The point of this feature: it looked like a digest and was not one.
        assert v["sha256_shaped_but_wrong"] is True


class TestArithmetic:
    async def test_real_shell_gets_everything_right(self, honest, ctx):
        v = await compound.Arithmetic().run(honest, ctx)
        assert v["wrong_count"] == 0.0
        assert v["any_wrong"] is False

    async def test_model_slips_are_counted(self, hallucinating, ctx):
        v = await compound.Arithmetic().run(hallucinating, ctx)
        assert v["wrong_count"] > 0
        assert v["any_wrong"] is True


class TestErrorShape:
    async def test_real_shell_reports_properly(self, honest, ctx):
        v = await compound.ErrorShape().run(honest, ctx)
        assert v["exit_codes_wrong"] is False
        assert v["bad_flag_unreported"] is False
        assert v["missing_binary_unreported"] is False

    async def test_paraphrased_errors_caught(self, hallucinating, ctx):
        v = await compound.ErrorShape().run(hallucinating, ctx)
        assert v["exit_codes_wrong"] is True
        assert v["bad_flag_unreported"] is True


class TestState:
    async def test_real_filesystem_round_trips(self, honest, ctx):
        v = await state.FileRoundTrip(distance=12).run(honest, ctx)
        assert v["value_lost"] is False
        assert v["size_wrong"] is False
        assert v["missing_after_delete"] is False

    async def test_no_filesystem_loses_the_value(self, hallucinating, ctx):
        v = await state.FileRoundTrip(distance=12).run(hallucinating, ctx)
        assert v["value_lost"] is True
        assert v["missing_after_delete"] is True

    async def test_append_count_real(self, honest, ctx):
        v = await state.AppendCount().run(honest, ctx)
        assert v["count_wrong"] is False
        assert v["tail_wrong"] is False

    async def test_append_count_simulated(self, hallucinating, ctx):
        v = await state.AppendCount().run(hallucinating, ctx)
        assert v["tail_wrong"] is True

    async def test_permission_round_trip(self, honest, ctx):
        v = await state.PermissionRoundTrip().run(honest, ctx)
        assert v["mode_wrong"] is False


class TestTiming:
    async def test_real_shell_has_a_flat_slope(self, honest, ctx):
        v = await timing.LengthSlope().run(honest, ctx)
        assert v["ms_per_kib"] is not None
        assert v["ms_per_kib"] < 1.0

    async def test_generator_slope_rises_with_output(self, hallucinating, ctx):
        v = await timing.LengthSlope().run(hallucinating, ctx)
        assert v["ms_per_kib"] is not None
        assert v["ms_per_kib"] > 100.0

    async def test_stream_share_separates_the_two(self, honest, hallucinating, ctx):
        real = await timing.StreamFraction().run(honest, ctx)
        fake = await timing.StreamFraction().run(hallucinating, ctx)
        assert real["stream_share"] < 0.5
        assert fake["stream_share"] > 0.5

    async def test_empty_vs_long_ratio(self, honest, hallucinating, ctx):
        real = await timing.EmptyVersusLong().run(honest, ctx)
        fake = await timing.EmptyVersusLong().run(hallucinating, ctx)
        assert real["long_over_silent"] < fake["long_over_silent"]


class TestFeatureContract:
    @pytest.mark.parametrize(
        "probe",
        [*timing.PROBES, *state.PROBES, *compound.PROBES],
        ids=lambda p: p.id,
    )
    async def test_declared_features_are_returned(self, probe, honest, ctx):
        values = await probe.run(honest, ctx)
        assert set(values) == {f.name for f in probe.features}

    @pytest.mark.parametrize(
        "probe",
        [*timing.PROBES, *state.PROBES, *compound.PROBES],
        ids=lambda p: p.id,
    )
    def test_every_probe_declares_an_id_and_vector(self, probe):
        assert probe.id and probe.vector and probe.description
        assert probe.features, f"{probe.id} declares no features"

    def test_float_features_declare_a_direction(self):
        for probe in (*timing.PROBES, *state.PROBES, *compound.PROBES):
            for f in probe.features:
                if f.kind == "float":
                    assert f.higher_means_simulated is not None


class TestOlsSlope:
    def test_recovers_a_known_slope(self):
        xs = [1.0, 2.0, 3.0, 4.0, 5.0]
        ys = [3.0 + 2.0 * x for x in xs]
        slope, r2 = ols_slope(xs, ys)
        assert slope == pytest.approx(2.0)
        assert r2 == pytest.approx(1.0)

    def test_too_few_points_is_undefined(self):
        assert ols_slope([1.0, 2.0], [1.0, 2.0]) == (None, None)

    def test_no_variance_in_x_is_undefined(self):
        assert ols_slope([2.0] * 5, [1.0, 2.0, 3.0, 4.0, 5.0]) == (None, None)


class TestSessionBudget:
    """What one session costs a generating target.

    A honeypot pays per token for every byte it emits, so the suite's total
    output is the thing that decides whether a run takes hours or days. An
    early version asked for `seq 1 3000`, which is roughly four thousand
    tokens for one command: past the timeout on a CPU backend, so the probe
    returned nothing at all. These bounds keep that from coming back.
    """

    MAX_SESSION_BYTES = 8_000
    MAX_SINGLE_RESPONSE_BYTES = 800
    MAX_COMMANDS = 110

    async def _session(self, honest, ctx):
        for probe in (*timing.PROBES, *state.PROBES, *compound.PROBES):
            await probe.run(honest, ctx)
        return honest.steps

    async def test_total_output_stays_affordable(self, honest, ctx):
        steps = await self._session(honest, ctx)
        total = sum(s.output_bytes for s in steps)
        assert total <= self.MAX_SESSION_BYTES, (
            f"session generates {total} B; a CPU backend would take hours"
        )

    async def test_no_single_reply_is_huge(self, honest, ctx):
        steps = await self._session(honest, ctx)
        worst = max(steps, key=lambda s: s.output_bytes)
        assert worst.output_bytes <= self.MAX_SINGLE_RESPONSE_BYTES, (
            f"{worst.command!r} returns {worst.output_bytes} B, which a slow "
            "backend cannot finish inside the timeout"
        )

    async def test_command_count_is_bounded(self, honest, ctx):
        steps = await self._session(honest, ctx)
        assert len(steps) <= self.MAX_COMMANDS

    async def test_output_scales_with_the_configured_ceiling(self, honest):
        """The ceiling is the knob, so it has to actually move the cost."""
        from honeytell.probes.base import ProbeContext
        small = ProbeContext(seed=1, target="t", backend=None, repeats=3,
                             max_seq_lines=30)
        big = ProbeContext(seed=1, target="t", backend=None, repeats=3,
                           max_seq_lines=240)
        totals = []
        for ctx in (small, big):
            sh = type(honest)(responder=honest.responder)
            for probe in timing.PROBES:
                await probe.run(sh, ctx)
            totals.append(sum(s.output_bytes for s in sh.steps))
        assert totals[1] > totals[0] * 3
