"""Shell abstraction and the per-command record every probe is scored from."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

# Terminal escape sequences. Honeypots and real shells both emit these; they are
# stripped before scoring so that a probe never keys on terminal decoration.
_ANSI = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][B0]|\x1b[=>]|\r")


def clean(raw: bytes) -> str:
    """Strip escape sequences and decode to text, never raising on bad bytes."""
    return _ANSI.sub(b"", raw).decode("utf-8", errors="replace")


@dataclass(slots=True)
class StepRecord:
    """One command sent to a target and everything observed in response.

    Timings come from a monotonic clock in nanoseconds. ``t_sent`` is when the
    last byte of the command left us, ``t_first_byte`` when the first response
    byte arrived, and ``t_last_byte`` when the stream went idle.
    """

    index: int
    command: str
    raw: bytes
    raw_full: bytes = b""
    t_sent_ns: int = 0
    t_first_byte_ns: int | None = None
    t_last_byte_ns: int | None = None
    timed_out: bool = False
    max_gap_ms: float | None = None
    note: str | None = None

    @property
    def text(self) -> str:
        return clean(self.raw)

    @property
    def output_bytes(self) -> int:
        return len(self.raw)

    @property
    def total_ms(self) -> float | None:
        """Time from command sent to stream idle."""
        if self.t_last_byte_ns is None:
            return None
        return (self.t_last_byte_ns - self.t_sent_ns) / 1e6

    @property
    def ttfb_ms(self) -> float | None:
        """Time to first response byte."""
        if self.t_first_byte_ns is None:
            return None
        return (self.t_first_byte_ns - self.t_sent_ns) / 1e6

    @property
    def stream_ms(self) -> float | None:
        """Time spent streaming, from first byte to idle.

        A real shell writes its output in one go, so this is close to zero. A
        token-by-token generator spends most of its time here.
        """
        if self.t_first_byte_ns is None or self.t_last_byte_ns is None:
            return None
        return (self.t_last_byte_ns - self.t_first_byte_ns) / 1e6

    def to_json(self) -> dict:
        return {
            "index": self.index,
            "command": self.command,
            "output": self.text,
            "output_bytes": self.output_bytes,
            "ttfb_ms": self.ttfb_ms,
            "total_ms": self.total_ms,
            "stream_ms": self.stream_ms,
            "timed_out": self.timed_out,
            "max_gap_ms": self.max_gap_ms,
            "note": self.note,
            "raw_full_bytes": len(self.raw_full) or len(self.raw),
        }


@runtime_checkable
class Shell(Protocol):
    """What a probe is allowed to do to a target.

    Deliberately small. A probe sends commands and reads what comes back. It
    cannot inspect the target's configuration, which is the whole point: the
    tool must only use what a real attacker would have.
    """

    async def run(self, command: str, *, idle_ms: int | None = None,
                  timeout_s: float | None = None) -> StepRecord:
        """Send one command and read until the stream goes idle."""
        ...

    async def send_raw(self, data: bytes, *, idle_ms: int | None = None,
                       timeout_s: float | None = None) -> StepRecord:
        """Send bytes with no trailing newline. For interactive probes."""
        ...

    @property
    def steps(self) -> list[StepRecord]:
        """Every step taken in this session, in order."""
        ...


@dataclass(slots=True)
class ReplayShell:
    """A Shell backed by canned output. Used by the tests.

    Keeps the probe suite testable without a running target, which matters
    because probe scoring is where the research claims actually live.
    """

    responses: dict[str, bytes] = field(default_factory=dict)
    responder: Callable[[str], bytes] | None = None
    default: bytes = b""
    ttfb_ms: float = 1.0
    stream_ms: float = 0.0
    stream_ms_per_byte: float = 0.0
    _steps: list[StepRecord] = field(default_factory=list)

    async def run(self, command: str, *, idle_ms: int | None = None,
                  timeout_s: float | None = None) -> StepRecord:
        if self.responder is not None:
            raw = self.responder(command)
        else:
            raw = self.responses.get(command, self.default)
        t0 = len(self._steps) * 10**9
        rec = StepRecord(
            index=len(self._steps),
            command=command,
            raw=raw,
            t_sent_ns=t0,
            t_first_byte_ns=t0 + int(self.ttfb_ms * 1e6),
            t_last_byte_ns=t0 + int(
                (self.ttfb_ms + self.stream_ms
                 + self.stream_ms_per_byte * len(raw)) * 1e6
            ),
        )
        self._steps.append(rec)
        return rec

    async def send_raw(self, data: bytes, *, idle_ms: int | None = None,
                       timeout_s: float | None = None) -> StepRecord:
        return await self.run(data.decode("utf-8", errors="replace"))

    @property
    def steps(self) -> list[StepRecord]:
        return self._steps
