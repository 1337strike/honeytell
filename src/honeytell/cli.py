"""Command line entry point."""

from __future__ import annotations

import argparse
import asyncio
import json
import pathlib
import shutil
import socket
import sys
import urllib.error
import urllib.request

from honeytell import __version__
from honeytell import probes as registry
from honeytell.analysis.report import analyse
from honeytell.config import Config, load
from honeytell.provenance import collect, finalise
from honeytell.runner import plan, run_all
from honeytell.store import Store


def _run_id(cfg_sha: str, override: str | None) -> str:
    """Default run id follows the config, so rerunning the same config resumes."""
    return override or f"run-{cfg_sha[:12]}"


def cmd_probes(_: argparse.Namespace) -> int:
    for vector in registry.KNOWN_VECTORS:
        selected = registry.select([vector])
        print(f"\n{vector}  ({len(selected)} probe(s))")
        if not selected:
            print("    not implemented yet")
        for p in selected:
            print(f"  {p.id}")
            print(f"      {p.description}")
            for f in p.features:
                direction = (
                    "bool, True means simulated" if f.kind == "bool"
                    else f"float, {'higher' if f.higher_means_simulated else 'lower'} "
                         "means simulated"
                )
                print(f"      - {f.name} ({direction})")
                print(f"          {f.description}")
    return 0


def _check_ollama(url: str) -> tuple[bool, str]:
    tags = url.rstrip("/").removesuffix("/v1") + "/api/tags"
    try:
        with urllib.request.urlopen(tags, timeout=5) as r:  # noqa: S310 - local only
            data = json.loads(r.read())
    except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError) as exc:
        return False, f"unreachable ({type(exc).__name__})"
    names = [m.get("name", "?") for m in data.get("models", [])]
    return True, f"{len(names)} model(s): {', '.join(names) if names else 'none pulled'}"


def cmd_doctor(args: argparse.Namespace) -> int:
    ok = True
    print(f"honeytell {__version__}")
    print(f"python {sys.version.split()[0]}")

    for mod in ("asyncssh", "pydantic"):
        try:
            __import__(mod)
            print(f"  {mod}: present")
        except ImportError:
            print(f"  {mod}: MISSING (pip install -e .)")
            ok = False
    for mod in ("numpy", "scipy", "matplotlib"):
        try:
            __import__(mod)
            print(f"  {mod}: present")
        except ImportError:
            print(f"  {mod}: absent (only needed for figures)")

    for tool in ("docker", "ollama"):
        path = shutil.which(tool)
        print(f"  {tool}: {path or 'not on PATH'}")
        if tool == "docker" and not path:
            ok = False

    if args.config and pathlib.Path(args.config).exists():
        cfg, sha = load(args.config)
        problems = cfg.validate_references()
        print(f"\nconfig {args.config} (sha256 {sha[:12]})")
        print(f"  backends: {[b.name for b in cfg.backends]}")
        print(f"  targets:  {[t.name for t in cfg.targets]}")
        print(f"  cells:    {len(cfg.cells())}")
        for b in cfg.backends:
            reachable, detail = _check_ollama(b.base_url)
            print(f"  backend {b.name} at {b.base_url}: "
                  f"{'ok' if reachable else 'FAILED'} ({detail})")
            if not reachable:
                ok = False
        for t in cfg.targets:
            try:
                with socket.create_connection((t.host, t.port), timeout=3):
                    print(f"  target {t.name} at {t.host}:{t.port}: open")
            except OSError as exc:
                print(f"  target {t.name} at {t.host}:{t.port}: "
                      f"closed ({type(exc).__name__})")
        for p in problems:
            print(f"  config problem: {p}")
            ok = False
    else:
        print("\nno config checked (pass --config)")

    print(f"\n{'ready' if ok else 'not ready'}")
    return 0 if ok else 1


def cmd_validate(args: argparse.Namespace) -> int:
    cfg, sha = load(args.config)
    problems = cfg.validate_references()
    try:
        selected = registry.select(cfg.probes.vectors, cfg.probes.exclude)
    except KeyError as exc:
        problems.append(str(exc))
        selected = ()
    print(f"config sha256 {sha}")
    print(f"targets {len(cfg.targets)}, backends {len(cfg.backends)}, "
          f"cells {len(cfg.cells())}, probes {len(selected)}")
    print(f"planned sessions: "
          f"{len(plan(cfg, args.extra_real_seeds, args.extra_real_eval_seeds))}")
    if problems:
        print("\nproblems:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("\nconfig is consistent")
    return 0


def _preflight(cfg: Config, cells) -> list[str]:
    """Which targets in this plan are not listening.

    Worth knowing before a long run rather than after. A target that is down
    records sessions with no features, and those are excluded from the report,
    so an overnight run against targets that were never up produces nothing.
    """
    wanted = {c.target for c in cells}
    down: list[str] = []
    for t in cfg.targets:
        if t.name not in wanted:
            continue
        try:
            with socket.create_connection((t.host, t.port), timeout=3):
                pass
        except OSError:
            down.append(f"{t.name} ({t.host}:{t.port})")
    return down


def cmd_run(args: argparse.Namespace) -> int:
    cfg, sha = load(args.config)
    problems = cfg.validate_references()
    if problems and not args.force:
        print("config problems (use --force to run anyway):")
        for p in problems:
            print(f"  - {p}")
        return 1

    cells = plan(cfg, args.extra_real_seeds, args.extra_real_eval_seeds)
    if args.target:
        cells = [c for c in cells if c.target == args.target]
    if args.backend:
        cells = [c for c in cells if c.backend == args.backend]
    down = _preflight(cfg, cells)
    if down:
        print("These targets are not listening:")
        for d in down:
            print(f"  - {d}")
        print("Their sessions will be recorded as unreachable and left out of "
              "the report.")
        if len(down) == len({c.target for c in cells}):
            print("\nNothing in this plan is reachable. Bring a target up first, "
                  "or run honeytell doctor to see what is missing.")
            if not args.force:
                return 1
        print()

    run_id = _run_id(sha, args.run_id)
    store = Store(cfg.run.out_dir, run_id)
    record = collect(cfg, sha, run_id)
    (store.dir / "provenance.json").write_text(json.dumps(record, indent=2, default=str))
    print(f"run {run_id} -> {store.dir}")

    asyncio.run(run_all(
        cfg, store,
        extra_real_seeds=args.extra_real_seeds,
        extra_real_eval_seeds=args.extra_real_eval_seeds,
        only_target=args.target,
        only_backend=args.backend,
    ))
    finalise(record, store.dir)

    if args.no_report:
        print("\nskipping analysis (--no-report)")
        return 0
    try:
        out = analyse(store.dir, alpha=args.alpha)
    except RuntimeError as exc:
        print(f"\nanalysis skipped: {exc}")
        return 0
    print(f"\n{out['sessions']} sessions analysed")
    print(f"report: {out['report']}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    out = analyse(pathlib.Path(args.run), alpha=args.alpha)
    print(f"{out['sessions']} sessions, {out['usable_features']} usable features")
    print(f"boundary: {out['boundary']}")
    print(f"report: {out['report']}")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    dest = pathlib.Path(args.output)
    if dest.exists() and not args.force:
        print(f"{dest} exists; pass --force to overwrite")
        return 1
    template = pathlib.Path(__file__).with_name("honeytell.example.toml")
    dest.write_text(template.read_text())
    print(f"wrote {dest}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="honeytell",
        description="Fingerprint LLM-powered shell honeypots from the client side.",
    )
    p.add_argument("--version", action="version", version=f"honeytell {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("doctor", help="check the environment and the config")
    d.add_argument("--config", default="honeytell.toml")
    d.set_defaults(func=cmd_doctor)

    v = sub.add_parser("validate", help="check the config without running anything")
    v.add_argument("--config", default="honeytell.toml")
    v.add_argument("--extra-real-seeds", type=int, default=0)
    v.add_argument("--extra-real-eval-seeds", type=int, default=0)
    v.set_defaults(func=cmd_validate)

    pr = sub.add_parser("probes", help="list probes and the features they produce")
    pr.set_defaults(func=cmd_probes)

    i = sub.add_parser("init", help="write a starter config")
    i.add_argument("--output", "-o", default="honeytell.toml")
    i.add_argument("--force", action="store_true")
    i.set_defaults(func=cmd_init)

    r = sub.add_parser("run", help="run the pipeline and write a report")
    r.add_argument("--config", default="honeytell.toml")
    r.add_argument("--run-id", default=None,
                   help="defaults to the config hash, so a rerun resumes")
    r.add_argument("--target", default=None, help="run one target only")
    r.add_argument("--backend", default=None, help="run one backend only")
    r.add_argument("--extra-real-seeds", type=int, default=0,
                   help="extra calibration seeds for the real control; the boundary "
                        "cannot express a rate below 1/n, so alpha 0.01 needs at "
                        "least 200 of them")
    r.add_argument("--extra-real-eval-seeds", type=int, default=0,
                   help="extra evaluation seeds for the real control; this is where "
                        "the reported false positive rate comes from, and five "
                        "sessions cannot measure a rate of one percent")
    r.add_argument("--alpha", type=float, default=0.01,
                   help="target false positive rate on the real system")
    r.add_argument("--no-report", action="store_true")
    r.add_argument("--force", action="store_true")
    r.set_defaults(func=cmd_run)

    rp = sub.add_parser("report", help="re-analyse a recorded run")
    rp.add_argument("--run", required=True, help="path to out/<run-id>")
    rp.add_argument("--alpha", type=float, default=0.01)
    rp.set_defaults(func=cmd_report)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted; finished cells are kept and a rerun resumes")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
