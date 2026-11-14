"""Probes whose correct answer is known before the command is sent.

These need no baseline and no threshold. Either the target computed the thing
or it did not. The digest probe is the strongest of them: a language model
cannot evaluate SHA-256, and the input is generated per run, so the answer
cannot have been memorised.
"""

from __future__ import annotations

import hashlib
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

_HEX64 = re.compile(r"\b([0-9a-f]{64})\b")
_HEX32 = re.compile(r"\b([0-9a-f]{32})\b")


class CryptoDigest(Probe):
    """Ask for a cryptographic digest of a value invented for this run.

    A real shell runs sha256sum. A model has to produce 64 hex characters it
    cannot derive, so it either hallucinates a plausible-looking digest or
    refuses. Because the input is a fresh nonce, a memorised answer is not
    available either.
    """

    id = "compound.crypto_digest"
    vector = "compound"
    description = "sha256sum and md5sum of a per-run nonce, verified locally"
    features = (
        FeatureSpec("sha256_wrong", "bool", "sha256sum did not match the true digest"),
        FeatureSpec("md5_wrong", "bool", "md5sum did not match the true digest"),
        FeatureSpec("sha256_shaped_but_wrong", "bool",
                    "Returned 64 hex characters that were not the right ones"),
    )

    async def run(self, sh: Shell, ctx: ProbeContext) -> dict[str, FeatureValue]:
        nonce = ctx.nonce()
        want256 = hashlib.sha256(nonce.encode()).hexdigest()
        want5 = hashlib.md5(nonce.encode()).hexdigest()  # noqa: S324

        s = await sh.run(f"printf '%s' '{nonce}' | sha256sum")
        m = await sh.run(f"printf '%s' '{nonce}' | md5sum")

        got256 = _HEX64.search(s.text.lower())
        got5 = _HEX32.search(m.text.lower())

        sha_wrong = None if s.timed_out else not (got256 and got256.group(1) == want256)
        md5_wrong = None if m.timed_out else not (got5 and got5.group(1) == want5)
        shaped = (
            None if s.timed_out
            else bool(got256) and got256.group(1) != want256
        )
        return self.check({
            "sha256_wrong": sha_wrong,
            "md5_wrong": md5_wrong,
            "sha256_shaped_but_wrong": shaped,
        })


class Arithmetic(Probe):
    """Computations with one correct answer each."""

    id = "compound.arithmetic"
    vector = "compound"
    description = "Shell arithmetic, awk formatting and a pipeline sum"
    features = (
        FeatureSpec("wrong_count", "float",
                    "How many of the checks returned the wrong value",
                    higher_means_simulated=True),
        FeatureSpec("any_wrong", "bool", "At least one computation was wrong"),
    )

    async def run(self, sh: Shell, ctx: ProbeContext) -> dict[str, FeatureValue]:
        k = ctx.rng.randrange(120, 980)
        checks: list[tuple[str, str]] = [
            ("echo $((2**10))", "1024"),
            (f"echo $(({k}*{k}))", str(k * k)),
            ("seq 1 100 | awk '{s+=$1} END{print s}'", "5050"),
            ("awk 'BEGIN{printf \"%.4f\", 22/7}'", "3.1429"),
            (f"seq 1 {k} | wc -l", str(k)),
        ]
        wrong = 0
        seen = 0
        for cmd, want in checks:
            step = await sh.run(cmd)
            if step.timed_out:
                continue
            seen += 1
            if want not in body(step):
                wrong += 1
        if seen == 0:
            return self.check(self.empty())
        return self.check({"wrong_count": float(wrong), "any_wrong": wrong > 0})


class ErrorShape(Probe):
    """Do failures look like the shell's failures?

    Exit codes and error wording are fixed by coreutils and bash. A model
    paraphrases them.
    """

    id = "compound.error_shape"
    vector = "compound"
    description = "Exit codes, unrecognised options and a missing binary"
    features = (
        FeatureSpec("exit_codes_wrong", "bool", "false or true reported the wrong status"),
        FeatureSpec("bad_flag_unreported", "bool",
                    "An unrecognised option did not produce the usual message"),
        FeatureSpec("missing_binary_unreported", "bool",
                    "A nonexistent command did not produce a not-found message"),
    )

    async def run(self, sh: Shell, ctx: ProbeContext) -> dict[str, FeatureValue]:
        tag = ctx.nonce("rc")
        f = await sh.run(f"false; echo {tag}=$?")
        t = await sh.run(f"true; echo {tag}=$?")
        codes = (
            None if f.timed_out or t.timed_out
            else not (f"{tag}=1" in body(f) and f"{tag}=0" in body(t))
        )

        flag = await sh.run("ls --honeytell-not-an-option")
        flag_bad = (
            None if flag.timed_out
            else not says(flag, "unrecognized option", "unrecognised option",
                          "invalid option", "illegal option")
        )

        missing_name = ctx.nonce("bin")
        mb = await sh.run(missing_name)
        missing = (
            None if mb.timed_out
            else not says(mb, "command not found", "not found", "No such file")
        )
        return self.check({
            "exit_codes_wrong": codes,
            "bad_flag_unreported": flag_bad,
            "missing_binary_unreported": missing,
        })


PROBES: tuple[Probe, ...] = (CryptoDigest(), Arithmetic(), ErrorShape())
