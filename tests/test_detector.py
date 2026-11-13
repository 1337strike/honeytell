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

    def test_identical_sessions_cannot_place_a_boundary(self):
        """Every session on one value leaves nothing to separate, so the
        boundary sits above the maximum and nothing real is flagged."""
        cal = self._cal()
        sessions = [[("p.a", 1.0), ("p.b", False)] for _ in range(200)]
        cal = fit_boundary(cal, sessions, alpha=0.01)
        assert math.isfinite(cal.boundary)
        assert "too coarse" in cal.boundary_source
        assert not any(decide(cal, s).simulated for s in sessions)

    def test_coarse_statistic_is_reported_rather_than_faked(self):
        cal = self._cal()
        sessions = [[("p.a", 1.0 + i * 0.01), ("p.b", False)] for i in range(200)]
        cal = fit_boundary(cal, sessions, alpha=0.01)
        # Five reference values cannot resolve one percent.
        assert "too coarse" in cal.boundary_source

    def test_rich_sample_places_a_real_boundary(self):
        cal = self._rich_cal()
        sessions = [[("p.a", i * 0.01), ("p.b", False)] for i in range(200)]
        cal = fit_boundary(cal, sessions, alpha=0.01)
        assert math.isfinite(cal.boundary)
        assert "exceedance" in cal.boundary_source
        assert "conservative" not in cal.boundary_source

    def test_too_few_sessions_cannot_express_the_rate(self):
        """With 20 sessions the smallest non-zero rate is 0.05, so a request
        for 0.01 cannot be honoured and the record has to say so."""
        cal = self._rich_cal()
        sessions = [[("p.a", i * 0.05), ("p.b", False)] for i in range(20)]
        cal = fit_boundary(cal, sessions, alpha=0.01)
        assert "too coarse" in cal.boundary_source
        assert "at least 100 are needed" in cal.boundary_source
        assert not any(decide(cal, s).simulated for s in sessions)

    def test_an_achievable_rate_is_honoured_on_the_same_sessions(self):
        cal = self._rich_cal()
        sessions = [[("p.a", i * 0.05), ("p.b", False)] for i in range(20)]
        cal = fit_boundary(cal, sessions, alpha=0.05)
        assert "exceedance" in cal.boundary_source
        flagged = sum(1 for s in sessions if decide(cal, s).simulated)
        assert flagged / len(sessions) <= 0.05

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
