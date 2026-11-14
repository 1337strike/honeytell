"""The single config file. One run is fully described by it plus a seed."""

from __future__ import annotations

import hashlib
import pathlib
import tomllib
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class BackendSpec(BaseModel):
    """A model served locally. Nothing here reaches a paid API."""

    name: str
    model: str = Field(description="Ollama model tag, e.g. qwen2.5:7b-instruct-q4_K_M")
    base_url: str = Field(
        default="http://127.0.0.1:11434/v1",
        description="Where honeytell itself reaches the backend, from the host.",
    )
    lab_url: str | None = Field(
        default=None,
        description="Where the honeypots reach the backend, from inside the lab "
                    "network. It is a different address from base_url, because "
                    "inside a container loopback is the container. Checking only "
                    "the host address proves nothing about the path the honeypots "
                    "actually use, which is the one that breaks.",
    )
    family: str = "unknown"
    params_b: float | None = Field(default=None, description="Parameter count in billions")
    quantisation: str | None = None
    context_length: int | None = Field(
        default=None,
        description="Context window the server is configured to give this model, "
                    "in tokens. Declared here because the server does not report "
                    "it back, so it has to be stated to be recorded. Keep it equal "
                    "to OLLAMA_CONTEXT_LENGTH on the host. It matters because a "
                    "session feeds the whole conversation back on every command: "
                    "if the window is too small, later probes run against a "
                    "truncated history, and whether that happens would depend on "
                    "our setting rather than on the honeypot's design.",
    )


class TargetSpec(BaseModel):
    """One endpoint to probe."""

    name: str
    kind: Literal["llm_honeypot", "classic_honeypot", "real"]
    host: str = "127.0.0.1"
    port: int = 22
    username: str = "root"
    password: str | None = None
    client_key: str | None = None
    repo: str | None = Field(default=None, description="Upstream repo, for provenance")
    commit: str | None = Field(default=None, description="Pinned commit, for provenance")
    image: str | None = Field(default=None, description="Container image ref or digest")
    backends: list[str] = Field(
        default_factory=list,
        description="Backend names this target is run against. Empty for non-LLM targets.",
    )
    backend_ports: dict[str, int] = Field(
        default_factory=dict,
        description="Port per backend, when a honeypot runs as one container "
                    "per backend. Each pair is a separate process listening "
                    "somewhere of its own, so a single port cannot describe a "
                    "target that is run against two models. Names not listed "
                    "here fall back to `port`.",
    )
    idle_ms: int | None = Field(
        default=None,
        description="Override the global idle framing for this target. This "
                    "changes wall clock only: the last-byte timestamp is taken "
                    "when that byte arrives, not when honeytell stops waiting, "
                    "so no recorded timing moves. Lower it for a target that "
                    "answers instantly, such as the real control, where the "
                    "global value is almost pure waiting. Never set it near a "
                    "generating target's gap between tokens, or replies get cut "
                    "short and output sizes come out wrong. The run warns when "
                    "an observed gap approaches the value in use.",
    )
    notes: str | None = None

    @field_validator("port")
    @classmethod
    def _port_range(cls, v: int) -> int:
        if not 1 <= v <= 65535:
            raise ValueError("port must be between 1 and 65535")
        return v

    @field_validator("backend_ports")
    @classmethod
    def _backend_port_range(cls, v: dict[str, int]) -> dict[str, int]:
        for name, port in v.items():
            if not 1 <= port <= 65535:
                raise ValueError(f"port for backend {name!r} must be between 1 and 65535")
        return v

    def port_for(self, backend: str | None) -> int:
        """Where to reach this target when run against ``backend``."""
        if backend and backend in self.backend_ports:
            return self.backend_ports[backend]
        return self.port


class CanarySpec(BaseModel):
    """Local listener used to tell a simulated side effect from a real one."""

    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 8731
    bind_host: str = "127.0.0.1"


class ProbeSpec(BaseModel):
    """Which probes run, and the framing parameters that shape measurements."""

    vectors: list[str] = Field(
        default_factory=lambda: ["timing", "state", "interactive", "sideeffect",
                                 "compound", "injection"]
    )
    exclude: list[str] = Field(default_factory=list, description="Probe ids to skip")
    idle_ms: int = Field(
        default=1500,
        description="Silence that marks the end of a reply. Must exceed the slowest "
                    "inter-token gap of the slowest backend or replies get truncated.",
    )
    timeout_s: float = 120.0
    repeats: int = Field(default=5, description="Repetitions inside timing probes")
    warmup_commands: int = Field(
        default=5,
        description="Throwaway commands at the start of each session, not "
                    "recorded. They absorb the cost of a cold connection and a "
                    "cold page cache so the first scored probe is not measuring "
                    "setup.",
    )
    max_seq_lines: int = Field(
        default=120,
        description="Largest output the timing probes ask for, in lines of seq. "
                    "This sets the cost of a run. A generator pays per token, so "
                    "asking for 3000 lines means thousands of tokens for one "
                    "command, which on a CPU backend exceeds timeout_s and "
                    "returns nothing. The timing features are slopes and ratios, "
                    "so a small ladder measures the same thing as a large one. "
                    "Raise it only if your backend is fast enough to answer "
                    "within timeout_s.",
    )


class RunSpec(BaseModel):
    """Seeds, splits and output location."""

    out_dir: pathlib.Path = pathlib.Path("out")
    calibration_seeds: list[int] = Field(default_factory=lambda: [1, 2])
    evaluation_seeds: list[int] = Field(default_factory=lambda: [3, 4, 5, 6, 7])
    resume: bool = Field(default=True, description="Skip cells already recorded")
    shuffle_seed: int | None = Field(
        default=20261113,
        description="Deterministically interleave calibration and evaluation "
                    "sessions within a target. Without it they run in blocks, "
                    "and a machine that warms up over an hour makes the two sets "
                    "differ for reasons of execution order rather than of what "
                    "is being measured. Set to null to run in plain seed order, "
                    "which is only safe when nothing about the host drifts.",
    )

    @field_validator("evaluation_seeds")
    @classmethod
    def _no_overlap(cls, v: list[int], info) -> list[int]:
        calib = set(info.data.get("calibration_seeds") or [])
        if calib & set(v):
            raise ValueError(
                "calibration_seeds and evaluation_seeds overlap; thresholds would be "
                "fitted on the same data they are scored on"
            )
        return v


class Config(BaseModel):
    """Top-level config."""

    backends: list[BackendSpec] = Field(default_factory=list)
    targets: list[TargetSpec] = Field(default_factory=list)
    probes: ProbeSpec = Field(default_factory=ProbeSpec)
    canary: CanarySpec = Field(default_factory=CanarySpec)
    run: RunSpec = Field(default_factory=RunSpec)

    def backend(self, name: str) -> BackendSpec:
        for b in self.backends:
            if b.name == name:
                return b
        raise KeyError(f"no backend named {name!r}")

    def target(self, name: str) -> TargetSpec:
        for t in self.targets:
            if t.name == name:
                return t
        raise KeyError(f"no target named {name!r}")

    def cells(self) -> list[tuple[str, str | None]]:
        """Every (target, backend) pair a full run covers."""
        out: list[tuple[str, str | None]] = []
        for t in self.targets:
            if t.kind == "llm_honeypot" and t.backends:
                out.extend((t.name, b) for b in t.backends)
            else:
                out.append((t.name, None))
        return out

    def validate_references(self) -> list[str]:
        """Report config mistakes that would only surface mid-run."""
        problems: list[str] = []
        names = {b.name for b in self.backends}
        used: dict[int, str] = {}
        for t in self.targets:
            for b in t.backends:
                if b not in names:
                    problems.append(f"target {t.name!r} refers to unknown backend {b!r}")
            for b in t.backend_ports:
                if b not in t.backends:
                    problems.append(
                        f"target {t.name!r} maps a port for backend {b!r}, which it "
                        f"does not run against"
                    )
            for backend in (t.backends or [None]):
                port = t.port_for(backend)
                owner = f"{t.name}/{backend}" if backend else t.name
                if port in used:
                    problems.append(
                        f"{owner} and {used[port]} both listen on port {port}; "
                        f"each honeypot and backend pair is its own process"
                    )
                used[port] = owner
            if t.kind == "llm_honeypot" and not t.backends:
                problems.append(f"target {t.name!r} is an llm_honeypot with no backends")
            if t.kind != "llm_honeypot" and t.backends:
                problems.append(f"target {t.name!r} is {t.kind} but lists backends")
        if not any(t.kind == "real" for t in self.targets):
            problems.append(
                "no target of kind 'real'; false positive rates cannot be measured "
                "and no threshold can be calibrated"
            )
        seen: set[str] = set()
        for t in self.targets:
            if t.name in seen:
                problems.append(f"duplicate target name {t.name!r}")
            seen.add(t.name)
        return problems


def load(path: str | pathlib.Path) -> tuple[Config, str]:
    """Load a config and return it with the sha256 of the file as read.

    The hash goes into provenance, so a report always states which config text
    produced it.
    """
    p = pathlib.Path(path)
    data = p.read_bytes()
    cfg = Config.model_validate(tomllib.loads(data.decode("utf-8")))
    return cfg, hashlib.sha256(data).hexdigest()
