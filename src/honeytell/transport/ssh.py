"""Interactive SSH shell with idle-based command framing.

Framing matters more than it looks. Honeypots do not honour ``PS1`` changes or
shell markers reliably, so we cannot ask the target to delimit its own output.
Instead we send a command and read until the stream goes quiet, which is what an
attacker's terminal does anyway.

Two consequences are recorded in provenance because they affect measurements:

``idle_ms`` must exceed the slowest inter-token gap of the slowest backend, or a
generated reply gets cut off mid-stream. The wait itself is excluded from the
timings, because the last-byte timestamp is taken when that byte arrives rather
than when we stop waiting.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from dataclasses import dataclass, field

import asyncssh

from honeytell.transport.shell import StepRecord, clean


@dataclass(slots=True)
class SSHShell:
    """One interactive shell session against one target."""

    process: asyncssh.SSHClientProcess
    conn: asyncssh.SSHClientConnection
    idle_ms: int = 1500
    timeout_s: float = 120.0
    read_chunk: int = 65536
    prompt: str = ""
    _steps: list[StepRecord] = field(default_factory=list)

    @property
    def steps(self) -> list[StepRecord]:
        return self._steps

    async def _read_until_idle(
        self, idle_ms: int, timeout_s: float, t_sent_ns: int
    ) -> tuple[bytes, int | None, int | None, bool, float | None]:
        """Read until no byte arrives for ``idle_ms``, or ``timeout_s`` elapses.

        Also returns the largest gap between chunks. If that approaches
        ``idle_ms`` the reply was nearly cut short, which is the one way a
        per-target idle setting can corrupt a measurement.
        """
        buf = bytearray()
        first: int | None = None
        last: int | None = None
        max_gap: float | None = None
        deadline = time.monotonic() + timeout_s
        timed_out = False

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            # Before the first byte we are willing to wait the whole timeout.
            # After it, a gap of idle_ms means the reply is finished.
            wait = remaining if first is None else min(idle_ms / 1000.0, remaining)
            try:
                chunk = await asyncio.wait_for(self.process.stdout.read(self.read_chunk), wait)
            except TimeoutError:
                if first is None:
                    timed_out = True
                break
            except (asyncssh.Error, ConnectionResetError, EOFError):
                break
            if not chunk:
                break
            now = time.monotonic_ns()
            if first is None:
                first = now
            else:
                gap = (now - last) / 1e6
                max_gap = gap if max_gap is None else max(max_gap, gap)
            last = now
            buf.extend(chunk if isinstance(chunk, bytes) else chunk.encode("utf-8", "replace"))

        _ = t_sent_ns
        return bytes(buf), first, last, timed_out, max_gap

    def _strip(self, raw: bytes, command: str) -> bytes:
        """Remove the PTY echo of the command and the trailing prompt.

        Applied identically to every target, so any residue is a constant and
        cannot by itself separate a honeypot from a real shell.
        """
        text = clean(raw)
        if command:
            stripped = text.lstrip("\r\n")
            if stripped.startswith(command):
                text = stripped[len(command):].lstrip("\r\n")
        if self.prompt:
            idx = text.rfind(self.prompt)
            if idx != -1 and idx >= len(text) - len(self.prompt) - 2:
                text = text[:idx]
        return text.rstrip("\n").encode("utf-8", "replace")

    async def learn_prompt(self) -> str:
        """Drain the login banner and remember the prompt string."""
        raw, *_ = await self._read_until_idle(self.idle_ms, self.timeout_s,
                                              time.monotonic_ns())
        tail = clean(raw).rstrip("\n").split("\n")[-1] if raw else ""
        self.prompt = tail.strip() if 0 < len(tail.strip()) <= 120 else ""
        return self.prompt

    async def send_raw(self, data: bytes, *, idle_ms: int | None = None,
                       timeout_s: float | None = None) -> StepRecord:
        self.process.stdin.write(data.decode("utf-8", "replace"))
        t_sent = time.monotonic_ns()
        raw, first, last, to, gap = await self._read_until_idle(
            idle_ms or self.idle_ms, timeout_s or self.timeout_s, t_sent
        )
        rec = StepRecord(
            index=len(self._steps),
            command=data.decode("utf-8", "replace"),
            raw=self._strip(raw, ""),
            raw_full=raw,
            t_sent_ns=t_sent,
            t_first_byte_ns=first,
            t_last_byte_ns=last,
            timed_out=to,
            max_gap_ms=gap,
            note="raw",
        )
        self._steps.append(rec)
        return rec

    async def run(self, command: str, *, idle_ms: int | None = None,
                  timeout_s: float | None = None) -> StepRecord:
        self.process.stdin.write(command + "\n")
        t_sent = time.monotonic_ns()
        raw, first, last, to, gap = await self._read_until_idle(
            idle_ms or self.idle_ms, timeout_s or self.timeout_s, t_sent
        )
        rec = StepRecord(
            index=len(self._steps),
            command=command,
            raw=self._strip(raw, command),
            raw_full=raw,
            t_sent_ns=t_sent,
            t_first_byte_ns=first,
            t_last_byte_ns=last,
            timed_out=to,
            max_gap_ms=gap,
        )
        self._steps.append(rec)
        return rec

    async def close(self) -> None:
        with contextlib.suppress(Exception):
            self.process.stdin.write_eof()
        with contextlib.suppress(Exception):
            self.process.close()
        with contextlib.suppress(Exception):
            self.conn.close()
            await self.conn.wait_closed()


@contextlib.asynccontextmanager
async def open_ssh_shell(
    host: str,
    port: int = 22,
    username: str = "root",
    password: str | None = None,
    client_key: str | None = None,
    *,
    idle_ms: int = 1500,
    timeout_s: float = 120.0,
    connect_timeout_s: float = 30.0,
    term_type: str = "xterm",
    term_size: tuple[int, int] = (120, 40),
):
    """Open an interactive shell against a lab target.

    Host keys are not verified. Every target is one we deployed on an isolated
    network, and a honeypot's key changes between runs anyway.
    """
    conn = await asyncio.wait_for(
        asyncssh.connect(
            host,
            port=port,
            username=username,
            password=password,
            client_keys=[client_key] if client_key else None,
            known_hosts=None,
            config=None,
        ),
        connect_timeout_s,
    )
    process = await conn.create_process(term_type=term_type, term_size=term_size)
    shell = SSHShell(process=process, conn=conn, idle_ms=idle_ms, timeout_s=timeout_s)
    try:
        await shell.learn_prompt()
        yield shell
    finally:
        await shell.close()
