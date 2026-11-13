"""Statistics used in the paper."""

from __future__ import annotations

import pytest

from honeytell.analysis.stats import (
    benjamini_hochberg,
    cliffs_delta,
    mann_whitney_p,
    wilson_interval,
)


class TestWilson:
    def test_point_estimate(self):
        ci = wilson_interval(7, 10)
        assert ci.point == pytest.approx(0.7)
        assert ci.low < 0.7 < ci.high

    def test_stays_inside_the_unit_range_at_the_edges(self):
        """The reason for Wilson over the normal approximation."""
        for successes, n in ((0, 5), (5, 5), (0, 1), (1, 1)):
            ci = wilson_interval(successes, n)
            assert 0.0 <= ci.low <= ci.high <= 1.0

    def test_interval_narrows_with_more_data(self):
        narrow = wilson_interval(50, 100)
        wide = wilson_interval(5, 10)
        assert (narrow.high - narrow.low) < (wide.high - wide.low)

    def test_empty_sample(self):
        assert wilson_interval(0, 0).n == 0


class TestCliffsDelta:
    def test_complete_separation(self):
        d, label = cliffs_delta([10.0, 11.0, 12.0], [1.0, 2.0, 3.0])
        assert d == pytest.approx(1.0)
        assert label == "large"

    def test_identical_samples(self):
        d, label = cliffs_delta([1.0, 2.0, 3.0], [1.0, 2.0, 3.0])
        assert d == pytest.approx(0.0)
        assert label == "negligible"

    def test_sign_follows_the_argument_order(self):
        d, _ = cliffs_delta([1.0, 2.0], [10.0, 20.0])
        assert d < 0

    def test_empty_is_undefined(self):
        assert cliffs_delta([], [1.0])[0] is None


class TestMannWhitney:
    def test_separated_samples_are_significant(self):
        p = mann_whitney_p([10.0, 11, 12, 13, 14], [1.0, 2, 3, 4, 5])
        assert p is not None and p < 0.05

    def test_identical_samples_are_not(self):
        p = mann_whitney_p([1.0, 2, 3, 4, 5], [1.0, 2, 3, 4, 5])
        assert p is not None and p > 0.5

    def test_tiny_samples_are_undefined(self):
        assert mann_whitney_p([1.0], [2.0]) is None


class TestBenjaminiHochberg:
    def test_adjusted_values_are_monotone(self):
        out = benjamini_hochberg({f"t{i}": p for i, p in
                                  enumerate([0.001, 0.008, 0.02, 0.04, 0.6])})
        ordered = sorted(out.values(), key=lambda d: d["rank"])
        adj = [d["p_adjusted"] for d in ordered]
        assert adj == sorted(adj)

    def test_adjusted_never_below_raw(self):
        raw = {f"t{i}": p for i, p in enumerate([0.01, 0.02, 0.03, 0.04])}
        for name, d in benjamini_hochberg(raw).items():
            assert d["p_adjusted"] >= raw[name] - 1e-12

    def test_large_p_values_are_not_significant(self):
        out = benjamini_hochberg({"a": 0.9, "b": 0.8, "c": 0.7}, q=0.05)
        assert not any(d["significant"] for d in out.values())

    def test_a_lone_small_p_among_many_nulls_is_corrected_away(self):
        """One raw 0.04 among 49 nulls should not survive correction."""
        raw = {"hit": 0.04} | {f"null{i}": 0.9 for i in range(49)}
        out = benjamini_hochberg(raw, q=0.05)
        assert out["hit"]["p_adjusted"] > 0.05
        assert not out["hit"]["significant"]

    def test_many_genuinely_small_p_values_survive(self):
        """BH is not Bonferroni: a consistent signal across tests is kept."""
        raw = {f"t{i}": 0.001 for i in range(50)}
        out = benjamini_hochberg(raw, q=0.05)
        assert all(d["significant"] for d in out.values())

    def test_empty_input(self):
        assert benjamini_hochberg({}) == {}
