"""Calibration and the sequential decision."""

from __future__ import annotations

import math

from honeytell.detector.calibrate import Calibration, FeatureCalibration, fit_boundary
from honeytell.detector.sequential import decide


class TestFeatureCalibration:
    def test_needs_a_sample_before_it_scores(self):
        fc = FeatureCalibration("f", "float", True)
        assert fc.usable is False
        assert fc.evidence(100.0) == 0.0

    def test_value_inside_the_real_range_is_unremarkable(self):
        fc = FeatureCalibration("f", "float", True)
        for v in (1.0, 1.1, 0.9, 1.2, 1.05):
            fc.observe(v)
        assert fc.evidence(1.0) < fc.evidence(50.0)

    def test_evidence_is_bounded_by_the_sample_size(self):
        fc = FeatureCalibration("f", "float", True)
        for v in range(10):
            fc.observe(float(v))
        # The smallest attainable p-value is 1/(n+1), so evidence is capped.
        assert fc.evidence(1e9) <= math.log(11) + 1e-9

    def test_direction_is_respected(self):
        low = FeatureCalibration("f", "float", False)
        for v in (10.0, 11.0, 12.0, 9.0):
            low.observe(v)
        assert low.evidence(0.1) > low.evidence(10.5)

    def test_bool_true_is_evidence_when_real_never_shows_it(self):
        fc = FeatureCalibration("b", "bool", None)
        for _ in range(20):
            fc.observe(False)
        assert fc.evidence(True) > fc.evidence(False)
        assert fc.evidence(False) < 0.1

    def test_none_contributes_nothing(self):
        fc = FeatureCalibration("b", "bool", None)
        for _ in range(5):
            fc.observe(False)
        assert fc.evidence(None) == 0.0


class TestBoundary:
    def _cal(self) -> Calibration:
        cal = Calibration()
        fc = cal.ensure("p.a", "float", True)
        for v in (1.0, 1.1, 1.2, 0.9, 1.05):
            fc.observe(v)
        bc = cal.ensure("p.b", "bool", None)
        for _ in range(10):
            bc.observe(False)
        return cal

    def _rich_cal(self) -> Calibration:
        """A calibration with enough real values to resolve a small alpha.

        Evidence is an empirical p-value, so its resolution is 1/(n+1). With a
        handful of reference values the statistic simply cannot express a rate
        of 0.01, and the code says so instead of pretending otherwise.
        """
        cal = Calibration()
        fc = cal.ensure("p.a", "float", True)
        for i in range(200):
            fc.observe(i * 0.01)
        bc = cal.ensure("p.b", "bool", None)
        for _ in range(200):
            bc.observe(False)
        return cal

    def test_no_real_sessions_disables_the_detector(self):
        cal = fit_boundary(self._cal(), [], alpha=0.01)
        assert math.isinf(cal.boundary)
        assert "disabled" in cal.boundary_source

    def test_identical_sessions_put_the_boundary_above_them_all(self):
        """Every session on one value leaves nothing to separate, so the
        threshold lands above it and nothing real is flagged."""
        cal = self._cal()
        sessions = [[("p.a", 1.0), ("p.b", False)] for _ in range(200)]
        cal = fit_boundary(cal, sessions, alpha=0.01)
        assert math.isfinite(cal.boundary)
        assert not any(decide(cal, s).simulated for s in sessions)

    def test_threshold_is_the_conformal_order_statistic(self):
        cal = self._cal()
        sessions = [[("p.a", 1.0 + i * 0.01), ("p.b", False)] for i in range(200)]
        cal = fit_boundary(cal, sessions, alpha=0.01)
        # k = ceil((n + 1)(1 - alpha)) = ceil(201 * 0.99) = 199.
        assert "order statistic 199 of 200" in cal.boundary_source
        flagged = sum(1 for s in sessions if decide(cal, s).simulated)
        assert flagged / len(sessions) <= 0.01

    def test_rich_sample_places_a_real_boundary(self):
        cal = self._rich_cal()
        sessions = [[("p.a", i * 0.01), ("p.b", False)] for i in range(200)]
        cal = fit_boundary(cal, sessions, alpha=0.01)
        assert math.isfinite(cal.boundary)
        assert "exceedance" in cal.boundary_source
        assert "conservative" not in cal.boundary_source

    def test_too_few_sessions_cannot_express_the_rate(self):
        """A conformal threshold for alpha needs at least 1/alpha - 1
        calibration points. Twenty cannot certify one percent."""
        cal = self._rich_cal()
        sessions = [[("p.a", i * 0.05), ("p.b", False)] for i in range(20)]
        cal = fit_boundary(cal, sessions, alpha=0.01)
        assert "needs at least 99" in cal.boundary_source
        assert "0.0476" in cal.boundary_source  # the rate 20 sessions can certify
        assert not any(decide(cal, s).simulated for s in sessions)

    def test_an_achievable_rate_is_honoured_on_the_same_sessions(self):
        cal = self._rich_cal()
        sessions = [[("p.a", i * 0.05), ("p.b", False)] for i in range(20)]
        cal = fit_boundary(cal, sessions, alpha=0.05)
        assert "order statistic" in cal.boundary_source
        flagged = sum(1 for s in sessions if decide(cal, s).simulated)
        assert flagged / len(sessions) <= 0.05

    def test_the_guarantee_holds_on_held_out_sessions(self):
        """The point of a conformal threshold: fit on one sample, and a fresh
        sample from the same source exceeds it at most alpha of the time."""
        import random
        rng = random.Random(7)
        cal = Calibration()
        fc = cal.ensure("p.a", "float", True)
        for _ in range(400):
            fc.observe(rng.gauss(0, 1))
        fit = [[("p.a", rng.gauss(0, 1))] for _ in range(400)]
        cal = fit_boundary(cal, fit, alpha=0.05)
        held_out = [[("p.a", rng.gauss(0, 1))] for _ in range(400)]
        rate = sum(1 for s in held_out if decide(cal, s).simulated) / len(held_out)
        assert rate <= 0.10, f"held-out rate {rate} far above alpha 0.05"

    def test_boundary_bounds_the_false_positive_rate(self):
        """The rate on real sessions must not exceed alpha by construction."""
        cal = self._rich_cal()
        real = [[("p.a", i * 0.01), ("p.b", False)] for i in range(200)]
        cal = fit_boundary(cal, real, alpha=0.01)
        flagged = sum(1 for s in real if decide(cal, s).simulated)
        assert flagged / len(real) <= 0.01

    def test_clear_simulation_still_crosses_a_conservative_boundary(self):
        """A boundary placed above the real maximum must still catch a target
        that fails features the real system never fails."""
        cal = self._rich_cal()
        real = [[("p.a", i * 0.01), ("p.b", False)] for i in range(200)]
        cal = fit_boundary(cal, real, alpha=0.01)
        obvious = [("p.a", 99.0), ("p.b", True)]
        assert decide(cal, obvious).simulated is True


class TestDecide:
    def _cal(self) -> Calibration:
        cal = Calibration()
        fc = cal.ensure("p.a", "float", True)
        for v in (1.0, 1.1, 1.2, 0.9, 1.05, 1.0, 1.1):
            fc.observe(v)
        bc = cal.ensure("p.b", "bool", None)
        for _ in range(20):
            bc.observe(False)
        cal.boundary = 2.0
        return cal

    def test_real_looking_session_is_not_flagged(self):
        v = decide(self._cal(), [("p.a", 1.0), ("p.b", False)])
        assert v.simulated is False
        assert v.commands_to_verdict is None

    def test_clear_evidence_is_flagged(self):
        v = decide(self._cal(), [("p.a", 9999.0), ("p.b", True)])
        assert v.simulated is True
        assert v.deciding_feature is not None

    def test_cost_is_reported_in_commands(self):
        cal = self._cal()
        v = decide(cal, [("p.a", 9999.0), ("p.b", True)], {"p.a": 6, "p.b": 11})
        assert v.commands_to_verdict in (6, 11)
        assert v.probes_to_verdict is not None

    def test_stops_at_the_first_crossing(self):
        cal = self._cal()
        v = decide(cal, [("p.a", 9999.0), ("p.b", True)], {"p.a": 6, "p.b": 11})
        assert v.probes_to_verdict == 1
        assert v.commands_to_verdict == 6

    def test_unknown_features_are_ignored(self):
        v = decide(self._cal(), [("not.calibrated", 10.0)])
        assert v.score == 0.0
        assert v.features_used == 0

    def test_round_trips_through_disk(self, tmp_path):
        cal = self._cal()
        cal.save(tmp_path / "c.json")
        back = Calibration.load(tmp_path / "c.json")
        assert back.boundary == cal.boundary
        assert set(back.features) == set(cal.features)
        assert back.evidence("p.a", 9999.0) == cal.evidence("p.a", 9999.0)


class TestDecisiveFeatures:
    """A feature whose values on a real system already span the range the
    alternative occupies cannot separate them, and a real session landing at
    the edge of such a range earns the largest score the test can award. That
    is how a control gets flagged, so those features are recorded and not
    scored."""

    def test_slope_r2_is_not_decisive(self):
        from honeytell.probes import timing
        probe = next(p for p in timing.PROBES if p.id == "timing.length_slope")
        by_name = {f.name: f for f in probe.features}
        assert by_name["slope_r2"].decisive is False
        assert by_name["ms_per_kib"].decisive is True

    def test_scoring_order_excludes_non_decisive(self):
        from honeytell.analysis.report import feature_order
        scored = feature_order(decisive_only=True)
        everything = feature_order(decisive_only=False)
        assert "timing.length_slope:slope_r2" in everything
        assert "timing.length_slope:slope_r2" not in scored
        assert len(scored) < len(everything)

    def test_a_non_decisive_feature_cannot_push_a_verdict(self):
        cal = Calibration()
        fc = cal.ensure("timing.length_slope:slope_r2", "float", True)
        for v in (0.1, 0.2, 0.3):
            fc.observe(v)
        cal.boundary = 0.5
        # Present in the calibration but absent from the scored order, so an
        # extreme value contributes nothing.
        assert decide(cal, []).simulated is False

    def test_every_decisive_float_declares_a_direction(self):
        from honeytell import probes as registry
        for probe in registry.all_probes():
            for f in probe.features:
                if f.decisive and f.kind == "float":
                    assert f.higher_means_simulated is not None


class TestMeasuredRealRanges:
    """Ranges observed over 227 sessions against the real control container on
    an i7-10610U. Recorded as a guard: a feature whose real-system range grows
    to cover the alternative has stopped being a discriminator."""

    OBSERVED = {
        "ms_per_kib": (-10.716, 11.760),
        "slope_r2": (0.001, 0.977),
        "stream_share": (0.612, 0.779),
        "long_over_silent": (1.435, 4.047),
        "total_cv": (0.022, 0.708),
        "bytes_cv": (0.0, 0.0),
    }

    def test_slope_r2_covers_the_whole_unit_range(self):
        """The reason it is not decisive, stated as a fact rather than a view."""
        low, high = self.OBSERVED["slope_r2"]
        assert low < 0.05 and high > 0.95

    def test_stream_share_is_tight_and_not_near_zero(self):
        """The original rationale claimed it sits near zero on a real shell.
        It does not; what makes it work is the width of the band."""
        low, high = self.OBSERVED["stream_share"]
        assert low > 0.5
        assert (high - low) < 0.2

    def test_bytes_cv_is_degenerate_on_a_real_shell(self):
        """An identical command returns identical bytes, every time."""
        assert self.OBSERVED["bytes_cv"] == (0.0, 0.0)
