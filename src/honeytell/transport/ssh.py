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

    async def _read_reply(
        self, command: str, idle_ms: int, timeout_s: float
    ) -> tuple[bytes, int | None, int | None, bool, float | None]:
        """Read one reply, telling a finished answer from a slow one.

        A pseudo-terminal echoes the command the moment it is sent, and a
        generator then takes seconds to answer. Waiting for silence cannot
        separate those: the gap while the target is thinking looks exactly
        like the end of a reply, so a reader framed on silence captures the
        echo, calls the command done, and leaves the real answer to arrive
        during the next one. Everything after that is off by one.

        So the wait is split. Until the first byte of the reply arrives we
        wait the whole timeout, because the target is entitled to think.
        After it starts we stop at a gap of ``idle_ms``, or sooner if the
        shell prints its prompt again, which is a shell saying it is ready.
        """
        buf = bytearray()
        first: int | None = None
        reply_first: int | None = None
        last: int | None = None
        max_gap: float | None = None
        echo_done = not command
        timed_out = False
        deadline = time.monotonic() + timeout_s

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            # Patient until the reply starts, strict once it is flowing.
            wait = remaining if reply_first is None else min(idle_ms / 1000.0, remaining)
            try:
                chunk = await asyncio.wait_for(self.process.stdout.read(self.read_chunk),
                                               wait)
            except TimeoutError:
                if reply_first is None:
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
            if echo_done and reply_first is None:
                reply_first = now
            last = now
            buf.extend(chunk if isinstance(chunk, bytes) else
                       chunk.encode("utf-8", "replace"))

            text = clean(bytes(buf))
            if not echo_done and command and command in text:
                echo_done = True
            if self.prompt and echo_done and text.rstrip().endswith(self.prompt):
                break

        # The echo is our own command returning, not the target answering. If
        # nothing came back beyond it, there is no time to first byte to
        # report: falling back to the echo would record a reply that never
        # arrived as the fastest one in the run.
        if reply_first is None and self._has_body(bytes(buf), command):
            reply_first = first

        return bytes(buf), reply_first, last, timed_out, max_gap

    def _has_body(self, raw: bytes, command: str) -> bool:
        """Whether anything came back beyond the echo and the prompt."""
        text = clean(raw)
        if command:
            stripped = text.lstrip("\r\n")
            if stripped.startswith(command):
                text = stripped[len(command):]
        text = text.strip()
        if self.prompt and text.endswith(self.prompt):
            text = text[: -len(self.prompt)]
        return bool(text.strip())

    async def _drain(self, idle_ms: int, timeout_s: float,
                     first_byte_wait_s: float = 60.0) -> bytes:
        """Read whatever is waiting after login, to learn the prompt.

        The first byte gets a long wait of its own. A real shell prints its
        banner at once, but a honeypot that generates one has to think first,
        and giving up early means no prompt is learned. Without a prompt every
        later command falls back to waiting for silence, which is the framing
        that cannot tell a finished reply from a slow one.
        """
        buf = bytearray()
        deadline = time.monotonic() + timeout_s
        got_any = False
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            wait = (min(idle_ms / 1000.0, remaining) if got_any
                    else min(first_byte_wait_s, remaining))
            try:
                chunk = await asyncio.wait_for(self.process.stdout.read(self.read_chunk),
                                               wait)
            except TimeoutError:
                break
            except (asyncssh.Error, ConnectionResetError, EOFError):
                break
            if not chunk:
                break
            got_any = True
            buf.extend(chunk if isinstance(chunk, bytes) else
                       chunk.encode("utf-8", "replace"))
        return bytes(buf)

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
        """Drain the login banner and remember the prompt string.

        The prompt is what later tells a finished reply from a slow one, so
        failing to learn it costs every command the full timeout instead.
        """
        raw = await self._drain(self.idle_ms, self.timeout_s)
        self.prompt = self._prompt_from(clean(raw))
        return self.prompt

    @staticmethod
    def _prompt_from(text: str) -> str:
        """Take the prompt from a banner, or nothing if it is not one.

        A string that is not prompt shaped never matches later, so framing
        falls back to waiting for silence without saying so. Returning nothing
        at least makes the fallback honest.
        """
        for line in reversed(text.rstrip("\n").split("\n")):
            candidate = line.strip()
            if not 0 < len(candidate) <= 120:
                continue
            if any(candidate.endswith(c) for c in ("$", "#", ">", "%")):
                return candidate
            if "@" in candidate and ":" in candidate:
                return candidate
        return ""

    async def send_raw(self, data: bytes, *, idle_ms: int | None = None,
                       timeout_s: float | None = None) -> StepRecord:
        self.process.stdin.write(data.decode("utf-8", "replace"))
        t_sent = time.monotonic_ns()
        raw, first, last, to, gap = await self._read_reply(
            "", idle_ms or self.idle_ms, timeout_s or self.timeout_s
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
        raw, first, last, to, gap = await self._read_reply(
            command, idle_ms or self.idle_ms, timeout_s or self.timeout_s
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
