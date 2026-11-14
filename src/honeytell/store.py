"""Where a run writes what it saw.

One rule governs the layout: the tool never computes a number that is not
written to CSV, and the figure script reads only CSV. That keeps every value in
the paper traceable to a file and a run id.
"""

from __future__ import annotations

import csv
import json
import pathlib
from dataclasses import dataclass, field

from honeytell.transport.shell import StepRecord

FEATURE_COLUMNS = (
    "run_id", "target", "target_kind", "backend", "seed", "role",
    "probe", "vector", "feature", "value", "kind", "higher_means_simulated",
)

SESSION_COLUMNS = (
    "run_id", "config_sha256", "target", "target_kind", "backend", "seed",
    "role", "reachable", "probe_errors", "commands", "note",
)

STEP_COLUMNS = (
    "run_id", "target", "backend", "seed", "probe", "index", "command",
    "output_bytes", "ttfb_ms", "total_ms", "stream_ms", "max_gap_ms", "timed_out",
)


@dataclass(slots=True)
class CellResult:
    """Everything one (target, backend, seed) produced."""

    target: str
    target_kind: str
    backend: str | None
    seed: int
    role: str
    features: dict[str, object] = field(default_factory=dict)
    steps: list[StepRecord] = field(default_factory=list)
    probe_of_step: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.target}|{self.backend or '-'}|{self.seed}"

    @property
    def reachable(self) -> bool:
        """False when the session never got a shell at all.

        A target that was not running produces no features. Scoring that as a
        confident "not a honeypot" would be an artifact, so it is recorded
        rather than inferred.
        """
        return "__connect__" not in self.errors


class Store:
    """Append-only run directory.

    Appending rather than rewriting is what makes a run resumable: a killed
    process never loses a finished cell, and a rerun skips what is recorded.
    """

    def __init__(self, out_dir: pathlib.Path, run_id: str,
                 config_sha256: str = "") -> None:
        self.dir = pathlib.Path(out_dir) / run_id
        self.raw = self.dir / "raw"
        self.run_id = run_id
        # Recorded per session, so a run extended under a changed config is
        # auditable rather than silently mixed.
        self.config_sha256 = config_sha256
        self.raw.mkdir(parents=True, exist_ok=True)
        self._init_csv(self.dir / "features.csv", FEATURE_COLUMNS)
        self._init_csv(self.dir / "steps.csv", STEP_COLUMNS)
        self._init_csv(self.dir / "sessions.csv", SESSION_COLUMNS)

    @staticmethod
    def _init_csv(path: pathlib.Path, header: tuple[str, ...]) -> None:
        if not path.exists():
            with path.open("w", newline="") as fh:
                csv.writer(fh).writerow(header)

    def done_cells(self) -> set[str]:
        """Cell keys that count as finished, read back from the manifest.

        A cell that never got a shell does not count. Running the suite before
        the targets are up would otherwise record every one of them as done,
        and a later run, with the targets now listening, would skip them.
        Probe errors are different: those are results, and the cell is finished.
        """
        manifest = self.dir / "cells.jsonl"
        if not manifest.exists():
            return set()
        keys: set[str] = set()
        for line in manifest.read_text().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                key = entry["key"]
            except (json.JSONDecodeError, KeyError):
                continue
            if "__connect__" in (entry.get("errors") or {}):
                keys.discard(key)
                continue
            keys.add(key)
        return keys

    def write_cell(self, result: CellResult, specs: dict) -> None:
        """Persist one cell: transcript, feature rows, step rows, manifest entry."""
        name = f"{result.target}-{result.backend or 'none'}-seed{result.seed}"
        transcript = {
            "run_id": self.run_id,
            "target": result.target,
            "target_kind": result.target_kind,
            "backend": result.backend,
            "seed": result.seed,
            "role": result.role,
            "errors": result.errors,
            "steps": [
                {"probe": probe, **step.to_json()}
                for probe, step in zip(result.probe_of_step, result.steps, strict=False)
            ],
        }
        (self.raw / f"{name}.jsonl").write_text(
            "\n".join(json.dumps(s) for s in transcript["steps"]) + "\n"
        )
        (self.raw / f"{name}.meta.json").write_text(json.dumps(
            {k: v for k, v in transcript.items() if k != "steps"}, indent=2
        ))

        with (self.dir / "features.csv").open("a", newline="") as fh:
            w = csv.writer(fh)
            for fq, value in sorted(result.features.items()):
                probe_id, _, feat = fq.partition(":")
                spec = specs.get(fq)
                w.writerow([
                    self.run_id, result.target, result.target_kind,
                    result.backend or "", result.seed, result.role,
                    probe_id, probe_id.split(".")[0], feat,
                    "" if value is None else value,
                    spec.kind if spec else "",
                    "" if spec is None or spec.higher_means_simulated is None
                    else int(spec.higher_means_simulated),
                ])

        with (self.dir / "steps.csv").open("a", newline="") as fh:
            w = csv.writer(fh)
            for probe, step in zip(result.probe_of_step, result.steps, strict=False):
                w.writerow([
                    self.run_id, result.target, result.backend or "", result.seed,
                    probe, step.index, step.command, step.output_bytes,
                    "" if step.ttfb_ms is None else round(step.ttfb_ms, 3),
                    "" if step.total_ms is None else round(step.total_ms, 3),
                    "" if step.stream_ms is None else round(step.stream_ms, 3),
                    "" if step.max_gap_ms is None else round(step.max_gap_ms, 3),
                    int(step.timed_out),
                ])

        with (self.dir / "sessions.csv").open("a", newline="") as fh:
            csv.writer(fh).writerow([
                self.run_id, self.config_sha256, result.target, result.target_kind,
                result.backend or "", result.seed, result.role,
                int(result.reachable),
                len([k for k in result.errors if not k.startswith("__")]),
                len(result.steps),
                result.errors.get("__connect__", "")
                or result.errors.get("__idle_ms__", ""),
            ])

        with (self.dir / "cells.jsonl").open("a") as fh:
            fh.write(json.dumps({
                "key": result.key, "target": result.target,
                "backend": result.backend, "seed": result.seed,
                "role": result.role, "features": len(result.features),
                "steps": len(result.steps), "errors": result.errors,
            }) + "\n")
