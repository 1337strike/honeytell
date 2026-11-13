"""Placeholder for the sideeffect vector. Probes land in a later build stage.

Declared now so that a config naming this vector validates and the architecture
shows what is still missing.
"""

from __future__ import annotations

from honeytell.probes.base import Probe

PROBES: tuple[Probe, ...] = ()
