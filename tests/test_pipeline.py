"""End to end over the store and the report, with no network involved."""

from __future__ import annotations

import csv
import json

from honeytell import probes as registry
from honeytell.analysis.report import analyse
from honeytell.probes import compound, state, timing
from honeytell.probes.base import ProbeContext
from honeytell.store import CellResult, Store
from honeytell.transport.shell import ReplayShell  # noqa: I001
from tests.conftest import hallucinating_responder, honest_responder

PROBE_LIST = (*timing.PROBES, *state.PROBES, *compound.PROBES)


async def _cell(target: str, kind: str, backend: str | None, seed: int, role: str,
                responder) -> CellResult:
    fast = kind == "real"
    sh = ReplayShell(
        responder=responder(),
        ttfb_ms=1.0 if fast else 300.0,
        stream_ms=0.2 if fast else 50.0,
        stream_ms_per_byte=0.0 if fast else 4.0,
    )
    ctx = ProbeContext(seed=seed, target=target, backend=backend, repeats=4)
    res = CellResult(target=target, target_kind=kind, backend=backend, seed=seed, role=role)
    for probe in PROBE_LIST:
        before = len(sh.steps)
        values = await probe.run(sh, ctx)
        for name, value in values.items():
            res.features[f"{probe.id}:{name}"] = value
        for step in sh.steps[before:]:
            res.probe_of_step.append(probe.id)
            res.steps.append(step)
    return res


class TestStore:
    async def test_writes_csvs_and_is_resumable(self, tmp_path):
        store = Store(tmp_path, "run-x")
        specs = registry.feature_specs(PROBE_LIST)
        res = await _cell("real", "real", None, 1, "calibration", honest_responder)
        store.write_cell(res, specs)

        rows = list(csv.DictReader((store.dir / "features.csv").open()))
        assert rows and {r["feature"] for r in rows}
        assert (store.dir / "steps.csv").exists()
        assert res.key in store.done_cells()

        reopened = Store(tmp_path, "run-x")
        assert res.key in reopened.done_cells(), "resume must survive a restart"

    async def test_transcript_is_written_per_cell(self, tmp_path):
        store = Store(tmp_path, "run-y")
        res = await _cell("real", "real", None, 1, "calibration", honest_responder)
        store.write_cell(res, registry.feature_specs(PROBE_LIST))
        raw = store.dir / "raw" / "real-none-seed1.jsonl"
        assert raw.exists()
        first = json.loads(raw.read_text().splitlines()[0])
        assert {"probe", "command", "output_bytes"} <= set(first)


class TestAnalyse:
    async def test_separates_a_real_shell_from_a_generator(self, tmp_path):
        store = Store(tmp_path, "run-z")
        specs = registry.feature_specs(PROBE_LIST)

        # Many real calibration sessions: cheap, and the boundary quantile
        # needs them. Then real evaluation sessions to report a false
        # positive rate, and honeypot sessions to detect.
        for seed in range(1, 41):
            store.write_cell(
                await _cell("real", "real", None, seed, "calibration", honest_responder),
                specs,
            )
        for seed in range(100, 106):
            store.write_cell(
                await _cell("real", "real", None, seed, "evaluation", honest_responder),
                specs,
            )
        for seed in range(200, 206):
            store.write_cell(
                await _cell("hp", "llm_honeypot", "small", seed, "evaluation",
                            hallucinating_responder),
                specs,
            )

        out = analyse(store.dir, alpha=0.01)
        assert out["sessions"] == 52
        assert out["boundary"] is not None

        verdicts = list(csv.DictReader((store.dir / "verdicts.csv").open()))
        hp = [v for v in verdicts if v["target"] == "hp" and v["role"] == "evaluation"]
        real = [v for v in verdicts if v["target"] == "real" and v["role"] == "evaluation"]

        assert all(v["simulated"] == "1" for v in hp), "generator should be detected"
        assert all(v["simulated"] == "0" for v in real), "real shell must not be flagged"
        assert all(v["commands_to_verdict"] for v in hp), "cost must be reported"

        report = (store.dir / "report.md").read_text()
        assert "Detection by target" in report
        assert "Detection by vector" in report
        assert "false positive rate" in report
        assert (store.dir / "calibration.json").exists()

    async def test_per_vector_columns_are_present(self, tmp_path):
        store = Store(tmp_path, "run-v")
        specs = registry.feature_specs(PROBE_LIST)
        for seed in range(1, 31):
            store.write_cell(
                await _cell("real", "real", None, seed, "calibration", honest_responder),
                specs,
            )
        for seed in range(200, 204):
            store.write_cell(
                await _cell("hp", "llm_honeypot", "small", seed, "evaluation",
                            hallucinating_responder),
                specs,
            )
        analyse(store.dir, alpha=0.01)
        header = next(csv.reader((store.dir / "verdicts.csv").open()))
        for vector in ("timing", "state", "compound"):
            assert f"vector_{vector}" in header


class TestUnreachableTargets:
    """A target that was never deployed must not look like a result.

    Running the full config before the honeypots are up produces sessions with
    no features at all. Scored naively those come out as "not detected", which
    reads in the report as a honeypot that resisted every probe. It is an
    artifact of nothing listening on the port.
    """

    async def _unreachable(self, target: str, seed: int) -> CellResult:
        res = CellResult(target=target, target_kind="llm_honeypot",
                         backend="small", seed=seed, role="evaluation")
        res.errors["__connect__"] = "ConnectionRefusedError: [Errno 111] Connect call failed"
        for probe in PROBE_LIST:
            for f in probe.features:
                res.features[f"{probe.id}:{f.name}"] = None
        return res

    async def test_absent_target_is_not_reported_as_undetected(self, tmp_path):
        store = Store(tmp_path, "run-absent")
        specs = registry.feature_specs(PROBE_LIST)
        for seed in range(1, 41):
            store.write_cell(
                await _cell("real", "real", None, seed, "calibration", honest_responder),
                specs,
            )
        for seed in range(100, 105):
            store.write_cell(
                await _cell("real", "real", None, seed, "evaluation", honest_responder),
                specs,
            )
        for seed in range(200, 207):
            store.write_cell(await self._unreachable("beelzebub", seed), specs)

        analyse(store.dir, alpha=0.01)
        report = (store.dir / "report.md").read_text()

        assert "Targets that were not reachable" in report
        assert "beelzebub" in report.split("## Detection by target")[0]

        detection = report.split("## Detection by target")[1].split("##")[0]
        assert "beelzebub" not in detection, (
            "an absent target must not appear in the detection table"
        )

    async def test_sessions_csv_records_reachability(self, tmp_path):
        store = Store(tmp_path, "run-status")
        specs = registry.feature_specs(PROBE_LIST)
        store.write_cell(
            await _cell("real", "real", None, 1, "calibration", honest_responder), specs)
        store.write_cell(await self._unreachable("beelzebub", 2), specs)

        rows = list(csv.DictReader((store.dir / "sessions.csv").open()))
        by_target = {r["target"]: r for r in rows}
        assert by_target["real"]["reachable"] == "1"
        assert by_target["beelzebub"]["reachable"] == "0"
        assert "Connect call failed" in by_target["beelzebub"]["note"]

    async def test_unreachable_real_sessions_do_not_calibrate(self, tmp_path):
        """A control that was down must not quietly become the reference."""
        store = Store(tmp_path, "run-nocontrol")
        specs = registry.feature_specs(PROBE_LIST)
        for seed in range(1, 6):
            res = await self._unreachable("real", seed)
            res.target_kind = "real"
            res.role = "calibration"
            store.write_cell(res, specs)
        for seed in range(200, 204):
            store.write_cell(
                await _cell("hp", "llm_honeypot", "small", seed, "evaluation",
                            hallucinating_responder),
                specs,
            )
        out = analyse(store.dir, alpha=0.01)
        assert out["boundary"] is None, "no usable control means no boundary"
        verdicts = list(csv.DictReader((store.dir / "verdicts.csv").open()))
        assert all(v["simulated"] == "0" for v in verdicts), (
            "without a calibrated control nothing may be declared a honeypot"
        )


class TestSessionOrdering:
    """Execution order must not line up with the calibration/evaluation split.

    A first run put every evaluation session in the opening minutes and every
    calibration session over the hour that followed. The host warmed up in
    between, so the two sets differed by when they ran rather than by what they
    measured, and the timing features moved enough to push the false positive
    rate from the requested 0.01 to 0.20.
    """

    def _cfg(self):
        from honeytell.config import Config
        return Config.model_validate({
            "targets": [{"name": "real", "kind": "real"}],
            "run": {"calibration_seeds": [1, 2], "evaluation_seeds": [3, 4, 5, 6, 7]},
        })

    def test_roles_are_interleaved(self):
        from honeytell.runner import plan
        cells = plan(self._cfg(), extra_real_seeds=60, extra_real_eval_seeds=30)
        roles = [c.role for c in cells]
        first_eval = roles.index("evaluation")
        last_eval = len(roles) - 1 - roles[::-1].index("evaluation")
        # Evaluation sessions must be spread across the run, not bunched at one end.
        assert first_eval < len(roles) * 0.25
        assert last_eval > len(roles) * 0.75

    def test_evaluation_is_not_concentrated_at_the_start(self):
        from honeytell.runner import plan
        cells = plan(self._cfg(), extra_real_seeds=200, extra_real_eval_seeds=100)
        roles = [c.role for c in cells]
        opening = roles[: len(roles) // 10]
        share_overall = roles.count("evaluation") / len(roles)
        share_opening = opening.count("evaluation") / len(opening)
        assert abs(share_opening - share_overall) < 0.2

    def test_order_is_reproducible(self):
        from honeytell.runner import plan
        a = [c.key for c in plan(self._cfg(), 40, 20)]
        b = [c.key for c in plan(self._cfg(), 40, 20)]
        assert a == b, "a run must be repeatable from the config alone"

    def test_shuffle_can_be_switched_off(self):
        from honeytell.config import Config
        from honeytell.runner import plan
        cfg = Config.model_validate({
            "targets": [{"name": "real", "kind": "real"}],
            "run": {"calibration_seeds": [1, 2], "evaluation_seeds": [3, 4],
                    "shuffle_seed": None},
        })
        assert [c.seed for c in plan(cfg)] == [1, 2, 3, 4]

    def test_evaluation_extras_are_counted(self):
        from honeytell.runner import plan
        cells = plan(self._cfg(), extra_real_seeds=10, extra_real_eval_seeds=7)
        assert sum(1 for c in cells if c.role == "evaluation") == 5 + 7
        assert sum(1 for c in cells if c.role == "calibration") == 2 + 10
        assert len({c.seed for c in cells}) == len(cells), "seeds must not collide"

    def test_extras_only_go_to_the_real_control(self):
        from honeytell.config import Config
        from honeytell.runner import plan
        cfg = Config.model_validate({
            "targets": [
                {"name": "real", "kind": "real"},
                {"name": "hp", "kind": "classic_honeypot"},
            ],
            "run": {"calibration_seeds": [1], "evaluation_seeds": [2]},
        })
        cells = plan(cfg, extra_real_seeds=20, extra_real_eval_seeds=10)
        assert sum(1 for c in cells if c.target == "hp") == 2
        assert sum(1 for c in cells if c.target == "real") == 32


class TestResumeSkipsOnlyFinishedWork:
    """Running the suite before the targets are up must not consume them.

    Every unreachable cell is still written to the manifest, because the run
    needs a record of what it tried. If resume treated those as finished, a
    later run with the targets now listening would skip them and the honeypots
    would never be probed at all.
    """

    async def _unreachable(self, target: str, seed: int) -> CellResult:
        res = CellResult(target=target, target_kind="llm_honeypot",
                         backend="small", seed=seed, role="evaluation")
        res.errors["__connect__"] = "ConnectionRefusedError"
        return res

    async def test_unreachable_cells_are_retried(self, tmp_path):
        store = Store(tmp_path, "run-retry")
        specs = registry.feature_specs(PROBE_LIST)
        res = await self._unreachable("beelzebub", 3)
        store.write_cell(res, specs)
        assert res.key not in store.done_cells()
        assert res.key not in Store(tmp_path, "run-retry").done_cells()

    async def test_a_finished_cell_is_not_repeated(self, tmp_path):
        store = Store(tmp_path, "run-done")
        specs = registry.feature_specs(PROBE_LIST)
        res = await _cell("real", "real", None, 1, "calibration", honest_responder)
        store.write_cell(res, specs)
        assert res.key in store.done_cells()

    async def test_probe_errors_still_count_as_finished(self, tmp_path):
        """A probe that failed produced a result; the session is done."""
        store = Store(tmp_path, "run-probe-err")
        specs = registry.feature_specs(PROBE_LIST)
        res = await _cell("real", "real", None, 1, "calibration", honest_responder)
        res.errors["timing.length_slope"] = "TimeoutError: too slow"
        store.write_cell(res, specs)
        assert res.key in store.done_cells()

    async def test_a_later_success_replaces_an_earlier_failure(self, tmp_path):
        store = Store(tmp_path, "run-mixed")
        specs = registry.feature_specs(PROBE_LIST)
        store.write_cell(await self._unreachable("beelzebub", 3), specs)
        good = await _cell("beelzebub", "llm_honeypot", "small", 3, "evaluation",
                           hallucinating_responder)
        store.write_cell(good, specs)
        assert good.key in store.done_cells()
