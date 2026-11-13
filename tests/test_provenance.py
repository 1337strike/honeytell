"""Provenance: what a run records about the software that produced it."""

from __future__ import annotations

import json

from honeytell.config import Config
from honeytell.provenance import backend_identity, collect, finalise, sha256_file


class TestBackendIdentity:
    """A model tag can be repointed upstream, so the tag alone does not
    identify the weights a run used. The digest does."""

    def test_unreachable_backend_is_recorded_as_unpinned(self):
        ident = backend_identity("http://127.0.0.1:1/v1", "qwen2.5:3b-instruct-q4_K_M")
        assert ident["resolved"] is False
        assert ident["model_digest"] is None
        assert "not pinned" in (ident["note"] or "")

    def test_openai_suffix_is_stripped_before_probing(self):
        """Honeypots talk to /v1; the admin endpoints sit at the root."""
        a = backend_identity("http://127.0.0.1:1/v1", "m")
        b = backend_identity("http://127.0.0.1:1", "m")
        assert a["resolved"] == b["resolved"] is False


class TestCollect:
    def _cfg(self) -> Config:
        return Config.model_validate({
            "backends": [{"name": "small", "model": "qwen2.5:3b-instruct-q4_K_M",
                          "base_url": "http://127.0.0.1:1/v1"}],
            "targets": [{"name": "real", "kind": "real"}],
            "probes": {"idle_ms": 1500, "max_seq_lines": 120},
        })

    def test_records_the_settings_that_shape_measurements(self):
        rec = collect(self._cfg(), "a" * 64, "run-1")
        assert rec["framing"]["idle_ms"] == 1500
        assert rec["framing"]["max_seq_lines"] == 120
        assert rec["config_sha256"] == "a" * 64

    def test_every_backend_carries_an_identity_block(self):
        rec = collect(self._cfg(), "a" * 64, "run-1")
        assert "identity" in rec["backends"][0]
        assert "server_version" in rec["backends"][0]["identity"]

    def test_finalise_checksums_the_tables(self, tmp_path):
        (tmp_path / "features.csv").write_text("a,b\n1,2\n")
        rec = finalise(collect(self._cfg(), "a" * 64, "run-1"), tmp_path)
        assert rec["artifacts"]["features.csv"] == sha256_file(tmp_path / "features.csv")
        assert rec["artifacts"]["verdicts.csv"] is None
        on_disk = json.loads((tmp_path / "provenance.json").read_text())
        assert on_disk["run_id"] == "run-1"

    def test_missing_file_checksums_to_none(self, tmp_path):
        assert sha256_file(tmp_path / "nope.csv") is None
