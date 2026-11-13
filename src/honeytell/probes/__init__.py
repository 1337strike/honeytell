"""Probe registry.

Probes are registered by module so that a vector can be switched off in the
config without touching code, and so the report can state exactly which probes
contributed to a verdict.
"""

from __future__ import annotations

from honeytell.probes import compound, injection, interactive, sideeffect, state, timing
from honeytell.probes.base import FeatureSpec, FeatureValue, Probe, ProbeContext

_MODULES = {
    "timing": timing,
    "state": state,
    "interactive": interactive,
    "sideeffect": sideeffect,
    "compound": compound,
    "injection": injection,
}

KNOWN_VECTORS: tuple[str, ...] = tuple(_MODULES)


def all_probes() -> tuple[Probe, ...]:
    out: list[Probe] = []
    for mod in _MODULES.values():
        out.extend(mod.PROBES)
    return tuple(out)


def select(vectors: list[str], exclude: list[str] | None = None) -> tuple[Probe, ...]:
    """Probes for the requested vectors, minus any excluded probe ids."""
    unknown = [v for v in vectors if v not in _MODULES]
    if unknown:
        raise KeyError(f"unknown vector(s): {unknown}; known: {list(_MODULES)}")
    skip = set(exclude or ())
    out: list[Probe] = []
    for v in vectors:
        out.extend(p for p in _MODULES[v].PROBES if p.id not in skip)
    return tuple(out)


def feature_specs(probes: tuple[Probe, ...]) -> dict[str, FeatureSpec]:
    """Map fully qualified feature name to its declaration."""
    specs: dict[str, FeatureSpec] = {}
    for p in probes:
        for f in p.features:
            specs[f"{p.id}:{f.name}"] = f
    return specs


__all__ = [
    "FeatureSpec",
    "FeatureValue",
    "KNOWN_VECTORS",
    "Probe",
    "ProbeContext",
    "all_probes",
    "feature_specs",
    "select",
]
