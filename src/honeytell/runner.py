"""Run cells, one at a time, and record what happened.

Sequential execution is a measurement requirement, not a convenience. The
timing features are ratios, so they tolerate a slow machine, but not a machine
whose speed changes while a session is in progress. Nothing else may compete
for the CPU.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass

from honeytell import probes as registry
from honeytell.config import Config
from honeytell.probes.base import Probe, ProbeContext
from honeytell.store import CellResult, Store
from honeytell.transport.ssh import open_ssh_shell

CALIBRATION_SEED_BASE = 100_000
EVALUATION_SEED_BASE = 900_000


@dataclass(slots=True)
class CellPlan:
    """One unit of work: a target, a backend and a seed."""

    target: str
    backend: str | None
    seed: int
    role: str

    @property
    def key(self) -> str:
        return f"{self.target}|{self.backend or '-'}|{self.seed}"


def plan(
    cfg: Config,
    extra_real_seeds: int = 0,
    extra_real_eval_seeds: int = 0,
) -> list[CellPlan]:
    """Every cell a full run covers, in the order it will be executed.

    Calibration seeds go to the real control alone. It is the only target that
    shapes the rule, and every table is built from evaluation sessions, so a
    calibration run against a honeypot would cost its full generation time and
    then be read by nothing.

    Real-system cells are cheap, so the plan can carry extra seeds for them.
    The calibration extras are what make the boundary quantile meaningful; the
    evaluation extras are what make the reported false positive rate meaningful,
    since five sessions cannot measure a rate of one percent.

    Within a target the order is shuffled. Running calibration and evaluation in
    blocks lets a host that warms up over an hour separate the two sets for
    reasons of execution order rather than of what is being measured, and the
    timing features are exactly what such a drift moves.
    """
    out: list[CellPlan] = []
    for target_name, backend in cfg.cells():
        target = cfg.target(target_name)
        seeds: list[tuple[int, str]] = []
        # Only the real system shapes the decision rule, and only evaluation
        # sessions reach the tables, so a calibration session against a
        # honeypot is collected and then read by nothing. On a backend that
        # takes forty minutes a session that is most of an hour each.
        if target.kind == "real":
            seeds += [(s, "calibration") for s in cfg.run.calibration_seeds]
        seeds += [(s, "evaluation") for s in cfg.run.evaluation_seeds]
        if target.kind == "real":
            # Fixed bases, far from the configured seeds and from each other.
            # Deriving them from the counts would mean that asking for more
            # calibration sessions renumbered the evaluation ones, so seeds
            # already recorded in a run directory would change role and resume
            # would keep the stale ones.
            seeds += [(CALIBRATION_SEED_BASE + i, "calibration")
                      for i in range(extra_real_seeds)]
            seeds += [(EVALUATION_SEED_BASE + i, "evaluation")
                      for i in range(extra_real_eval_seeds)]

        if cfg.run.shuffle_seed is not None:
            rng = random.Random(f"{cfg.run.shuffle_seed}:{target_name}:{backend}")
            rng.shuffle(seeds)

        out.extend(CellPlan(target_name, backend, s, role) for s, role in seeds)
    return out


async def run_cell(cfg: Config, cell: CellPlan, probe_list: tuple[Probe, ...]) -> CellResult:
    """Open one session and walk every probe through it.

    All probes share one shell, because state probes have to survive unrelated
    commands and that is only meaningful inside a single session.
    """
    target = cfg.target(cell.target)
    result = CellResult(
        target=cell.target,
        target_kind=target.kind,
        backend=cell.backend,
        seed=cell.seed,
        role=cell.role,
    )
    ctx = ProbeContext(
        seed=cell.seed,
        target=cell.target,
        backend=cell.backend,
        repeats=cfg.probes.repeats,
        max_seq_lines=cfg.probes.max_seq_lines,
        canary_host=cfg.canary.host,
        canary_port=cfg.canary.port,
    )

    try:
        async with open_ssh_shell(
            target.host,
            port=target.port_for(cell.backend),
            username=target.username,
            password=target.password,
            client_key=target.client_key,
            idle_ms=target.idle_ms or cfg.probes.idle_ms,
            timeout_s=cfg.probes.timeout_s,
        ) as sh:
            # Not recorded. The first commands of a session pay for a cold
            # connection and a cold page cache, and that cost belongs to no
            # probe.
            for i in range(max(0, cfg.probes.warmup_commands)):
                await sh.run("printf ''" if i % 2 else "true")

            for probe in probe_list:
                before = len(sh.steps)
                try:
                    values = await probe.run(sh, ctx)
                except Exception as exc:  # noqa: BLE001 - one probe must not end a cell
                    values = probe.empty()
                    result.errors[probe.id] = f"{type(exc).__name__}: {exc}"
                for name, value in values.items():
                    result.features[f"{probe.id}:{name}"] = value
                for step in sh.steps[before:]:
                    result.probe_of_step.append(probe.id)
                    result.steps.append(step)
        idle = target.idle_ms or cfg.probes.idle_ms
        gaps = [s.max_gap_ms for s in result.steps if s.max_gap_ms is not None]
        worst = max(gaps, default=0.0)
        if worst > 0.6 * idle:
            # A gap this close to the framing window means the next reply could
            # be cut in half, which would understate output size and corrupt
            # every timing feature derived from it.
            result.errors["__idle_ms__"] = (
                f"largest gap inside a reply was {worst:.0f} ms against "
                f"idle_ms {idle}; raise idle_ms for this target or its replies "
                f"risk being truncated"
            )
    except Exception as exc:  # noqa: BLE001 - record an unreachable target and move on
        result.errors["__connect__"] = f"{type(exc).__name__}: {exc}"
        for probe in probe_list:
            for f in probe.features:
                result.features.setdefault(f"{probe.id}:{f.name}", None)

    return result


async def run_all(
    cfg: Config,
    store: Store,
    *,
    extra_real_seeds: int = 0,
    extra_real_eval_seeds: int = 0,
    only_target: str | None = None,
    only_backend: str | None = None,
    progress=print,
) -> list[CellResult]:
    """Walk the plan, skipping cells already recorded."""
    probe_list = registry.select(cfg.probes.vectors, cfg.probes.exclude)
    specs = registry.feature_specs(probe_list)
    cells = plan(cfg, extra_real_seeds, extra_real_eval_seeds)
    if only_target:
        cells = [c for c in cells if c.target == only_target]
    if only_backend:
        cells = [c for c in cells if c.backend == only_backend]

    done = store.done_cells() if cfg.run.resume else set()
    todo = [c for c in cells if c.key not in done]
    progress(
        f"{len(probe_list)} probes, {len(specs)} features, "
        f"{len(cells)} cells, {len(todo)} to run ({len(cells) - len(todo)} already recorded)"
    )

    results: list[CellResult] = []
    for i, cell in enumerate(todo, start=1):
        t0 = time.monotonic()
        progress(f"[{i}/{len(todo)}] {cell.key} ({cell.role})")
        res = await run_cell(cfg, cell, probe_list)
        store.write_cell(res, specs)
        results.append(res)
        took = time.monotonic() - t0
        if "__connect__" in res.errors:
            # No probe ran, so calling this a probe error reads as though the
            # suite failed rather than the target being absent.
            progress(f"    unreachable, will be retried: {res.errors['__connect__']}")
        else:
            bad = len([k for k in res.errors if not k.startswith("__")])
            progress(
                f"    {len(res.steps)} commands, {took:.1f}s"
                + (f", {bad} probe error(s)" if bad else "")
            )
        if "__idle_ms__" in res.errors:
            progress(f"    WARNING: {res.errors['__idle_ms__']}")
    return results
