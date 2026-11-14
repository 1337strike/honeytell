"""Config loading and the mistakes it must refuse."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from honeytell.config import Config, RunSpec, load

_MINIMAL = """
[[backends]]
name = "small"
model = "qwen2.5:3b-instruct-q4_K_M"

[[targets]]
name = "real"
kind = "real"
port = 2200

[[targets]]
name = "hp"
kind = "llm_honeypot"
port = 2202
backends = ["small"]

[probes]
vectors = ["timing", "compound"]

[run]
calibration_seeds = [1, 2]
evaluation_seeds = [3, 4]
"""


class TestLoad:
    def test_loads_and_hashes(self, tmp_path):
        p = tmp_path / "c.toml"
        p.write_text(_MINIMAL)
        cfg, sha = load(p)
        assert len(sha) == 64
        assert [t.name for t in cfg.targets] == ["real", "hp"]

    def test_hash_follows_the_file(self, tmp_path):
        a, b = tmp_path / "a.toml", tmp_path / "b.toml"
        a.write_text(_MINIMAL)
        b.write_text(_MINIMAL + "\n# a comment changes the hash\n")
        assert load(a)[1] != load(b)[1]

    def test_cells_expand_backends(self, tmp_path):
        p = tmp_path / "c.toml"
        p.write_text(_MINIMAL)
        cfg, _ = load(p)
        assert ("hp", "small") in cfg.cells()
        assert ("real", None) in cfg.cells()


class TestSeedSplit:
    def test_overlapping_seeds_are_refused(self):
        """Fitting thresholds on the data they are scored on is the one
        mistake that would quietly invalidate every number."""
        with pytest.raises(ValidationError, match="overlap"):
            RunSpec(calibration_seeds=[1, 2], evaluation_seeds=[2, 3])

    def test_disjoint_seeds_are_accepted(self):
        spec = RunSpec(calibration_seeds=[1, 2], evaluation_seeds=[3, 4])
        assert spec.evaluation_seeds == [3, 4]


class TestValidateReferences:
    def test_missing_real_target_is_reported(self):
        cfg = Config.model_validate({
            "targets": [{"name": "hp", "kind": "classic_honeypot"}],
        })
        problems = cfg.validate_references()
        assert any("kind 'real'" in p for p in problems)

    def test_unknown_backend_is_reported(self):
        cfg = Config.model_validate({
            "targets": [
                {"name": "real", "kind": "real"},
                {"name": "hp", "kind": "llm_honeypot", "backends": ["nope"]},
            ],
        })
        assert any("unknown backend" in p for p in cfg.validate_references())

    def test_llm_honeypot_without_backend_is_reported(self):
        cfg = Config.model_validate({
            "targets": [
                {"name": "real", "kind": "real"},
                {"name": "hp", "kind": "llm_honeypot"},
            ],
        })
        assert any("no backends" in p for p in cfg.validate_references())

    def test_duplicate_names_are_reported(self):
        cfg = Config.model_validate({
            "targets": [
                {"name": "real", "kind": "real"},
                {"name": "real", "kind": "real"},
            ],
        })
        assert any("duplicate" in p for p in cfg.validate_references())

    def test_clean_config_has_no_problems(self, tmp_path):
        p = tmp_path / "c.toml"
        p.write_text(_MINIMAL)
        cfg, _ = load(p)
        assert cfg.validate_references() == []

    def test_bad_port_is_refused(self):
        with pytest.raises(ValidationError):
            Config.model_validate({"targets": [{"name": "x", "kind": "real", "port": 0}]})


class TestShippedExample:
    def test_the_example_config_is_valid(self):
        import pathlib

        import honeytell
        example = pathlib.Path(honeytell.__file__).with_name("honeytell.example.toml")
        cfg, _ = load(example)
        assert cfg.validate_references() == []
        assert any(t.kind == "real" for t in cfg.targets)
        assert all(t.commit for t in cfg.targets if t.repo), \
            "every target with a repo must pin a commit, or results are not traceable"


class TestIdleOverride:
    def test_absent_override_falls_back_to_the_global(self, tmp_path):
        p = tmp_path / "c.toml"
        p.write_text(_MINIMAL)
        cfg, _ = load(p)
        assert cfg.target("real").idle_ms is None
        assert cfg.probes.idle_ms == 1500

    def test_override_is_read_when_present(self):
        cfg = Config.model_validate({
            "targets": [{"name": "real", "kind": "real", "idle_ms": 200}],
        })
        assert cfg.target("real").idle_ms == 200

    def test_shipped_config_gives_fast_targets_a_short_window(self):
        """The control answers in milliseconds, so the global window there is
        almost entirely waiting."""
        import pathlib

        import honeytell
        cfg, _ = load(pathlib.Path(honeytell.__file__).with_name("honeytell.example.toml"))
        real = cfg.target("real")
        assert real.idle_ms is not None
        assert real.idle_ms < cfg.probes.idle_ms
        for t in cfg.targets:
            if t.kind == "llm_honeypot":
                assert t.idle_ms is None, (
                    f"{t.name} is a generator; a short window would truncate it"
                )


class TestBackendContext:
    """A session feeds the whole conversation back on every command, so the
    context window decides whether later probes see a truncated history. The
    server does not report the value, so the config has to carry it."""

    def test_shipped_backends_declare_a_context_length(self):
        import pathlib

        import honeytell
        cfg, _ = load(pathlib.Path(honeytell.__file__).with_name("honeytell.example.toml"))
        for b in cfg.backends:
            assert b.context_length, f"backend {b.name} does not declare a context length"

    def test_declared_context_clears_a_session(self):
        """82 commands plus a honeypot system prompt runs to roughly 4,400
        tokens, so the default of 4096 is not enough."""
        import pathlib

        import honeytell
        cfg, _ = load(pathlib.Path(honeytell.__file__).with_name("honeytell.example.toml"))
        for b in cfg.backends:
            assert b.context_length >= 8192

    def test_context_reaches_provenance(self):
        from honeytell.provenance import collect
        cfg = Config.model_validate({
            "backends": [{"name": "b", "model": "m", "base_url": "http://127.0.0.1:1/v1",
                          "context_length": 8192}],
            "targets": [{"name": "real", "kind": "real"}],
        })
        rec = collect(cfg, "a" * 64, "run-1")
        assert rec["backends"][0]["context_length"] == 8192


class TestMeasurementFingerprint:
    """A run is keyed on how sessions are measured, not on the whole config.

    Targets and backends decide which cells exist; the probe settings decide
    whether two cells can be compared. Keying on the whole file meant adding a
    honeypot threw away every session already recorded, which made extending a
    study something to avoid.
    """

    def _cfg(self, **over):
        base = {
            "backends": [{"name": "a", "model": "m"}],
            "targets": [{"name": "real", "kind": "real"}],
            "probes": {"idle_ms": 1500, "repeats": 3, "max_seq_lines": 120},
        }
        base.update(over)
        return Config.model_validate(base)

    def test_adding_a_backend_keeps_the_run(self):
        one = self._cfg()
        two = self._cfg(backends=[{"name": "a", "model": "m"},
                                  {"name": "b", "model": "n"}])
        assert one.measurement_fingerprint() == two.measurement_fingerprint()

    def test_adding_a_target_keeps_the_run(self):
        one = self._cfg()
        two = self._cfg(targets=[{"name": "real", "kind": "real"},
                                 {"name": "hp", "kind": "classic_honeypot",
                                  "port": 2201}])
        assert one.measurement_fingerprint() == two.measurement_fingerprint()

    def test_changing_the_framing_starts_a_new_run(self):
        """A session read with a different framing window is not comparable
        with one read before it, so it must not land in the same run."""
        one = self._cfg()
        two = self._cfg(probes={"idle_ms": 800, "repeats": 3, "max_seq_lines": 120})
        assert one.measurement_fingerprint() != two.measurement_fingerprint()

    def test_changing_the_suite_length_starts_a_new_run(self):
        one = self._cfg()
        two = self._cfg(probes={"idle_ms": 1500, "repeats": 5, "max_seq_lines": 120})
        assert one.measurement_fingerprint() != two.measurement_fingerprint()

    def test_changing_the_seed_split_starts_a_new_run(self):
        one = self._cfg()
        two = self._cfg(run={"calibration_seeds": [1, 2, 3],
                             "evaluation_seeds": [4, 5]})
        assert one.measurement_fingerprint() != two.measurement_fingerprint()

    def test_the_full_config_hash_is_still_recorded(self, tmp_path):
        """Keyed on less, recorded in full, so a run extended under a changed
        config is auditable rather than silently mixed."""
        from honeytell.store import SESSION_COLUMNS
        assert "config_sha256" in SESSION_COLUMNS
