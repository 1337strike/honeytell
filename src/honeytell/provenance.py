"""Everything needed to say which software produced a number.

A report that cannot name its inputs is not reproducible, so the tool records
the config hash, the pinned target commits, the backend model tags, the
installed dependency versions, the framing parameters, and a checksum of the
feature table it wrote.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import platform
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from importlib import metadata

from honeytell import __version__
from honeytell.config import Config

_TRACKED = ("asyncssh", "pydantic", "numpy", "scipy", "matplotlib")


def _versions() -> dict[str, str]:
    out: dict[str, str] = {}
    for name in _TRACKED:
        try:
            out[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            out[name] = "not installed"
    return out


def _git(*args: str) -> str | None:
    try:
        r = subprocess.run(
            ["git", *args], capture_output=True, text=True, timeout=10,
            cwd=pathlib.Path(__file__).resolve().parent,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.strip() or None if r.returncode == 0 else None


def sha256_file(path: str | pathlib.Path) -> str | None:
    p = pathlib.Path(path)
    if not p.is_file():
        return None
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _get_json(url: str, timeout: float = 5.0) -> dict | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310 - local
            return json.loads(r.read())
    except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError, ValueError):
        return None


def backend_identity(base_url: str, model: str) -> dict:
    """Pin the backend to the exact weights that served a run.

    A model tag can be repointed upstream, so recording only the tag would let
    two runs claim the same model while having used different weights. The
    digest the server reports is the thing that actually identifies them. The
    server's own version matters too, because an upgrade changes throughput and
    throughput is what the timing probes measure.
    """
    root = base_url.rstrip("/").removesuffix("/v1")
    out: dict = {"server_version": None, "model_digest": None,
                 "model_size_bytes": None, "model_modified_at": None,
                 "resolved": False, "note": None}

    version = _get_json(f"{root}/api/version")
    if version:
        out["server_version"] = version.get("version")

    tags = _get_json(f"{root}/api/tags")
    if tags is None:
        out["note"] = "backend did not answer; weights are not pinned for this run"
        return out

    for m in tags.get("models", []):
        if m.get("name") == model or m.get("model") == model:
            out["model_digest"] = m.get("digest")
            out["model_size_bytes"] = m.get("size")
            out["model_modified_at"] = m.get("modified_at")
            details = m.get("details") or {}
            out["quantization_level"] = details.get("quantization_level")
            out["parameter_size"] = details.get("parameter_size")
            out["resolved"] = True
            return out

    out["note"] = f"model {model!r} is not present on the backend"
    return out


def collect(cfg: Config, config_sha256: str, run_id: str) -> dict:
    """Build the provenance record for a run."""
    return {
        "run_id": run_id,
        "recorded_at": datetime.now(UTC).isoformat(),
        "honeytell_version": __version__,
        "honeytell_commit": _git("rev-parse", "HEAD"),
        "honeytell_dirty": bool(_git("status", "--porcelain")),
        "config_sha256": config_sha256,
        "python": sys.version.split()[0],
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "processor": platform.processor() or None,
        },
        "dependencies": _versions(),
        "framing": {
            "idle_ms": cfg.probes.idle_ms,
            "timeout_s": cfg.probes.timeout_s,
            "repeats": cfg.probes.repeats,
            "max_seq_lines": cfg.probes.max_seq_lines,
            "warmup_commands": cfg.probes.warmup_commands,
            "shuffle_seed": cfg.run.shuffle_seed,
            "note": "idle_ms is part of every timing measurement and must be reported "
                    "alongside them",
        },
        "seeds": {
            "calibration": cfg.run.calibration_seeds,
            "evaluation": cfg.run.evaluation_seeds,
        },
        "backends": [
            {**b.model_dump(), "identity": backend_identity(b.base_url, b.model)}
            for b in cfg.backends
        ],
        "targets": [
            {
                "name": t.name,
                "kind": t.kind,
                "repo": t.repo,
                "commit": t.commit,
                "image": t.image,
                "backends": t.backends,
                "port": t.port,
                "backend_ports": t.backend_ports,
            }
            for t in cfg.targets
        ],
        "artifacts": {},
    }


def finalise(record: dict, out_dir: pathlib.Path) -> dict:
    """Attach checksums of the tables a run wrote, then persist the record."""
    record["artifacts"] = {
        name: sha256_file(out_dir / name)
        for name in ("features.csv", "steps.csv", "verdicts.csv")
    }
    record["completed_at"] = datetime.now(UTC).isoformat()
    (out_dir / "provenance.json").write_text(json.dumps(record, indent=2, default=str))
    return record
