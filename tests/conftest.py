"""Fake shells used to test probe scoring without a running target."""

from __future__ import annotations

import hashlib
import re

import pytest

from honeytell.probes.base import ProbeContext
from honeytell.transport.shell import ReplayShell

_SHA = re.compile(r"printf '%s' '([^']+)' \| sha256sum")
_MD5 = re.compile(r"printf '%s' '([^']+)' \| md5sum")
_SEQ = re.compile(r"^seq 1 (\d+)$")
_WC_L_SEQ = re.compile(r"^seq 1 (\d+) \| wc -l$")


def honest_responder() -> callable:
    """Behaves like a real shell: a tiny in-memory filesystem and real maths."""
    files: dict[str, bytes] = {}
    modes: dict[str, str] = {}

    def respond(cmd: str) -> bytes:
        cmd = cmd.strip()
        if m := _SHA.match(cmd):
            return hashlib.sha256(m.group(1).encode()).hexdigest().encode() + b"  -"
        if m := _MD5.match(cmd):
            return hashlib.md5(m.group(1).encode()).hexdigest().encode() + b"  -"  # noqa: S324
        if m := _WC_L_SEQ.match(cmd):
            return m.group(1).encode()
        if m := _SEQ.match(cmd):
            return "\n".join(str(i) for i in range(1, int(m.group(1)) + 1)).encode()
        if cmd == "echo $((6*7))":
            return b"42"
        if cmd == "echo $((2**10))":
            return b"1024"
        if m := re.match(r"^echo \$\(\((\d+)\*(\d+)\)\)$", cmd):
            return str(int(m.group(1)) * int(m.group(2))).encode()
        if cmd == "seq 1 100 | awk '{s+=$1} END{print s}'":
            return b"5050"
        if cmd.startswith("awk 'BEGIN{printf \"%.4f\", 22/7}'"):
            return b"3.1429"
        if cmd == "echo abc | tr a-z A-Z":
            return b"ABC"
        if m := re.match(r"^false; echo (\S+)=\$\?$", cmd):
            return f"{m.group(1)}=1".encode()
        if m := re.match(r"^true; echo (\S+)=\$\?$", cmd):
            return f"{m.group(1)}=0".encode()
        if cmd == "ls --honeytell-not-an-option":
            return b"ls: unrecognized option '--honeytell-not-an-option'"
        if m := re.match(r"^printf '%s' '([^']+)' > (\S+)$", cmd):
            files[m.group(2)] = m.group(1).encode()
            return b""
        if m := re.match(r"^: > (\S+)$", cmd):
            files[m.group(1)] = b""
            return b""
        if m := re.match(r"^echo '([^']*)' >> (\S+)$", cmd):
            files[m.group(2)] = files.get(m.group(2), b"") + m.group(1).encode() + b"\n"
            return b""
        if m := re.match(r"^cat (\S+)$", cmd):
            path = m.group(1)
            return files[path] if path in files else b"cat: " + path.encode() + \
                b": No such file or directory"
        if m := re.match(r"^wc -c < (\S+)$", cmd):
            return str(len(files.get(m.group(1), b""))).encode()
        if m := re.match(r"^wc -l < (\S+)$", cmd):
            return str(files.get(m.group(1), b"").count(b"\n")).encode()
        if m := re.match(r"^tail -n 1 (\S+)$", cmd):
            lines = files.get(m.group(1), b"").rstrip(b"\n").split(b"\n")
            return lines[-1] if lines else b""
        if m := re.match(r"^rm -f (\S+)$", cmd):
            files.pop(m.group(1), None)
            return b""
        if m := re.match(r"^touch (\S+)$", cmd):
            files.setdefault(m.group(1), b"")
            return b""
        if m := re.match(r"^chmod (\d+) (\S+)$", cmd):
            modes[m.group(2)] = m.group(1)
            return b""
        if m := re.match(r"^stat -c %a (\S+)$", cmd):
            return modes.get(m.group(1), "644").encode()
        if cmd == "true":
            return b""
        if cmd == "uname -sr":
            return b"Linux 6.8.0-45-generic"
        if cmd.startswith("ht") and "bin" in cmd:
            return b"bash: " + cmd.encode() + b": command not found"
        return b""

    return respond


def hallucinating_responder() -> callable:
    """Behaves like a model: plausible shapes, wrong content, no filesystem."""
    counter = {"n": 0}

    def respond(cmd: str) -> bytes:
        cmd = cmd.strip()
        counter["n"] += 1
        if _SHA.match(cmd):
            # Right shape, wrong value, and different every time.
            return hashlib.sha256(str(counter["n"]).encode()).hexdigest().encode() + b"  -"
        if _MD5.match(cmd):
            return hashlib.md5(str(counter["n"]).encode()).hexdigest().encode() + b"  -"  # noqa: S324
        if m := _WC_L_SEQ.match(cmd):
            return str(int(m.group(1)) + 1).encode()
        if m := _SEQ.match(cmd):
            n = min(int(m.group(1)), 40)
            return "\n".join(str(i) for i in range(1, n + 1)).encode()
        if cmd == "echo $((6*7))":
            return b"42"
        if cmd == "echo $((2**10))":
            return b"1048"
        if re.match(r"^echo \$\(\((\d+)\*(\d+)\)\)$", cmd):
            return b"123456"
        if cmd == "seq 1 100 | awk '{s+=$1} END{print s}'":
            return b"5051"
        if cmd.startswith("awk 'BEGIN{printf \"%.4f\", 22/7}'"):
            return b"3.1428"
        if cmd == "echo abc | tr a-z A-Z":
            return b"ABC"
        if re.match(r"^false; echo (\S+)=\$\?$", cmd):
            return b"0"
        if re.match(r"^true; echo (\S+)=\$\?$", cmd):
            return b"0"
        if cmd == "ls --honeytell-not-an-option":
            return b"total 0"
        if re.match(r"^cat (\S+)$", cmd):
            return b"some unrelated contents"
        if re.match(r"^wc -[cl] < (\S+)$", cmd):
            return b"7"
        if re.match(r"^tail -n 1 (\S+)$", cmd):
            return b"last line"
        if re.match(r"^stat -c %a (\S+)$", cmd):
            return b"644"
        if cmd == "uname -sr":
            return b"Linux 5.15.0-91-generic"
        return b""

    return respond


@pytest.fixture
def ctx() -> ProbeContext:
    return ProbeContext(seed=1, target="t", backend=None, repeats=4)


@pytest.fixture
def honest() -> ReplayShell:
    return ReplayShell(responder=honest_responder(), ttfb_ms=1.0, stream_ms=0.2)


@pytest.fixture
def hallucinating() -> ReplayShell:
    # Streaming cost per byte is what the timing probes are built to see.
    return ReplayShell(
        responder=hallucinating_responder(),
        ttfb_ms=300.0,
        stream_ms=50.0,
        stream_ms_per_byte=4.0,
    )
