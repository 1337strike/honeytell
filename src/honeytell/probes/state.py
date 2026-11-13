"""Probes that change something and check it later.

A real shell has a filesystem. A model has a conversation. Separating the two
is a matter of writing a value, filling the context with unrelated work, and
asking for the value back.
"""

from __future__ import annotations

import re

from honeytell.probes.base import (
    FeatureSpec,
    FeatureValue,
    Probe,
    ProbeContext,
    body,
    says,
)
from honeytell.transport.shell import Shell

_FILLER = (
    "whoami", "pwd", "id -u", "uname -m", "echo ok", "date +%Y",
    "ls /", "hostname", "echo $SHELL", "cat /proc/sys/kernel/ostype",
    "nproc", "echo $HOME", "ls /tmp", "umask", "echo done",
)


class FileRoundTrip(Probe):
    """Write a nonce to a file, do unrelated work, then read it back."""

    id = "state.file_roundtrip"
    vector = "state"
    description = "Write a nonce, issue filler commands, read the file again"
    features = (
        FeatureSpec("value_lost", "bool", "The file did not return the value written"),
        FeatureSpec("size_wrong", "bool", "Reported byte count did not match the value"),
        FeatureSpec("missing_after_delete", "bool",
                    "Reading a deleted file did not report it missing"),
    )

    def __init__(self, distance: int = 12) -> None:
        self.distance = distance

    async def run(self, sh: Shell, ctx: ProbeContext) -> dict[str, FeatureValue]:
        nonce = ctx.nonce()
        path = f"/tmp/.{ctx.nonce('f')}"
        write = await sh.run(f"printf '%s' '{nonce}' > {path}")
        if write.timed_out:
            return self.check(self.empty())

        for cmd in list(_FILLER)[: self.distance]:
            await sh.run(cmd)

        read = await sh.run(f"cat {path}")
        lost = None if read.timed_out else nonce not in body(read)

        size = await sh.run(f"wc -c < {path}")
        want = str(len(nonce))
        size_bad = None if size.timed_out else want not in body(size)

        await sh.run(f"rm -f {path}")
        gone = await sh.run(f"cat {path}")
        gone_bad = (
            None if gone.timed_out
            else not says(gone, "No such file", "not found", "cannot open", "does not exist")
        )
        return self.check({
            "value_lost": lost,
            "size_wrong": size_bad,
            "missing_after_delete": gone_bad,
        })


class AppendCount(Probe):
    """Append a chosen number of lines, then count them."""

    id = "state.append_count"
    vector = "state"
    description = "Append k lines across separate commands, then wc -l"
    features = (
        FeatureSpec("count_wrong", "bool", "Line count did not match what was appended"),
        FeatureSpec("tail_wrong", "bool", "The last line was not the one appended last"),
    )

    async def run(self, sh: Shell, ctx: ProbeContext) -> dict[str, FeatureValue]:
        path = f"/tmp/.{ctx.nonce('a')}"
        k = ctx.rng.randrange(4, 9)
        last = ""
        await sh.run(f": > {path}")
        for i in range(k):
            last = f"{ctx.nonce('l')}-{i}"
            step = await sh.run(f"echo '{last}' >> {path}")
            if step.timed_out:
                return self.check(self.empty())

        for cmd in list(_FILLER)[:6]:
            await sh.run(cmd)

        count = await sh.run(f"wc -l < {path}")
        count_bad = None if count.timed_out else str(k) not in body(count)

        tail = await sh.run(f"tail -n 1 {path}")
        tail_bad = None if tail.timed_out else last not in body(tail)

        await sh.run(f"rm -f {path}")
        return self.check({"count_wrong": count_bad, "tail_wrong": tail_bad})


class PermissionRoundTrip(Probe):
    """Change a file mode, then ask for it back."""

    id = "state.perm_roundtrip"
    vector = "state"
    description = "chmod to an unusual mode, then stat it"
    features = (
        FeatureSpec("mode_wrong", "bool", "stat did not report the mode that was set"),
    )

    _MODES = ("711", "604", "751", "640")

    async def run(self, sh: Shell, ctx: ProbeContext) -> dict[str, FeatureValue]:
        path = f"/tmp/.{ctx.nonce('p')}"
        mode = ctx.rng.choice(self._MODES)
        if (await sh.run(f"touch {path}")).timed_out:
            return self.check(self.empty())
        await sh.run(f"chmod {mode} {path}")
        for cmd in list(_FILLER)[:5]:
            await sh.run(cmd)
        got = await sh.run(f"stat -c %a {path}")
        bad = None if got.timed_out else not re.search(rf"\b{mode}\b", body(got))
        await sh.run(f"rm -f {path}")
        return self.check({"mode_wrong": bad})


PROBES: tuple[Probe, ...] = (FileRoundTrip(), AppendCount(), PermissionRoundTrip())
