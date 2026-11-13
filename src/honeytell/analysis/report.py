"""Turn the recorded CSVs into verdicts, tables and a markdown report.

Real-system sessions are split three ways so that no number is produced from
the data that shaped it:

  real, role=calibration, first half   -> per-feature reference distributions
  real, role=calibration, second half  -> the stopping boundary
  real, role=evaluation                -> the reported false positive rate

Honeypot sessions never influence the decision rule.
"""

from __future__ import annotations

import csv
import json
import math
import pathlib
from collections import defaultdict
from dataclasses import dataclass

from honeytell import probes as registry
from honeytell.analysis.stats import (
    benjamini_hochberg,
    cliffs_delta,
    mann_whitney_p,
    wilson_interval,
)
from honeytell.detector.calibrate import Calibration, fit_boundary
from honeytell.detector.sequential import decide

SessionKey = tuple[str, str, int]  # target, backend, seed


@dataclass(slots=True)
class Session:
    target: str
    target_kind: str
    backend: str
    seed: int
    role: str
    values: dict[str, float | bool | None]
    commands_at_feature: dict[str, int]
    reachable: bool = True
    note: str = ""

    @property
    def key(self) -> SessionKey:
        return (self.target, self.backend, self.seed)

    @property
    def cell(self) -> str:
        return f"{self.target}/{self.backend}" if self.backend else self.target


def _parse(value: str, kind: str) -> float | bool | None:
    if value == "":
        return None
    if kind == "bool":
        return value.strip().lower() in {"1", "true", "yes"}
    try:
        f = float(value)
    except ValueError:
        return None
    return f if math.isfinite(f) else None


def load_sessions(run_dir: pathlib.Path) -> tuple[list[Session], dict[str, str]]:
    """Read features.csv and steps.csv back into sessions."""
    feat_path = run_dir / "features.csv"
    rows = list(csv.DictReader(feat_path.open()))

    kinds: dict[str, str] = {}
    for r in rows:
        kinds[f"{r['probe']}:{r['feature']}"] = r["kind"] or "float"

    cmd_at: dict[SessionKey, dict[str, int]] = defaultdict(dict)
    steps_path = run_dir / "steps.csv"
    if steps_path.exists():
        per_session: dict[SessionKey, list[tuple[str, int]]] = defaultdict(list)
        for s in csv.DictReader(steps_path.open()):
            key = (s["target"], s["backend"], int(s["seed"]))
            per_session[key].append((s["probe"], int(s["index"])))
        for key, entries in per_session.items():
            running = 0
            last_probe = None
            for probe, _ in entries:
                if last_probe is not None and probe != last_probe:
                    cmd_at[key][last_probe] = running
                running += 1
                last_probe = probe
            if last_probe is not None:
                cmd_at[key][last_probe] = running

    status: dict[SessionKey, tuple[bool, str]] = {}
    sess_path = run_dir / "sessions.csv"
    if sess_path.exists():
        for r in csv.DictReader(sess_path.open()):
            status[(r["target"], r["backend"], int(r["seed"]))] = (
                r.get("reachable", "1") == "1", r.get("note", "") or "",
            )

    grouped: dict[SessionKey, Session] = {}
    for r in rows:
        key = (r["target"], r["backend"], int(r["seed"]))
        sess = grouped.get(key)
        if sess is None:
            sess = Session(
                target=r["target"],
                target_kind=r["target_kind"],
                backend=r["backend"],
                seed=int(r["seed"]),
                role=r["role"],
                values={},
                commands_at_feature={},
            )
            grouped[key] = sess
        fq = f"{r['probe']}:{r['feature']}"
        sess.values[fq] = _parse(r["value"], r["kind"] or "float")

    for key, sess in grouped.items():
        reachable, note = status.get(key, (True, ""))
        sess.reachable = reachable
        sess.note = note
        probe_cmds = cmd_at.get(key, {})
        for fq in sess.values:
            probe_id = fq.split(":", 1)[0]
            if probe_id in probe_cmds:
                sess.commands_at_feature[fq] = probe_cmds[probe_id]

    return list(grouped.values()), kinds


def feature_order(vectors: list[str] | None = None, *,
                  decisive_only: bool = True) -> list[str]:
    """Feature names in the order the probes produce them.

    Scoring uses the decisive ones only. Everything else is still recorded, so
    a transcript can be read against the full set.
    """
    probe_list = registry.select(vectors or list(registry.KNOWN_VECTORS))
    return [
        f"{p.id}:{f.name}"
        for p in probe_list
        for f in p.features
        if f.decisive or not decisive_only
    ]


def build_calibration(
    sessions: list[Session],
    kinds: dict[str, str],
    order: list[str],
    alpha: float = 0.01,
) -> tuple[Calibration, list[Session], list[Session]]:
    """Fit the decision rule on real sessions only.

    Returns the calibration plus the two real-session groups it consumed, so the
    report can state exactly which sessions shaped the rule.
    """
    specs = registry.feature_specs(registry.select(list(registry.KNOWN_VECTORS)))
    real_calib = sorted(
        [s for s in sessions
         if s.target_kind == "real" and s.role == "calibration" and s.reachable],
        key=lambda s: s.seed,
    )
    half = max(1, len(real_calib) // 2)
    for_features, for_boundary = real_calib[:half], real_calib[half:]
    if not for_boundary:
        for_boundary = for_features

    cal = Calibration(alpha=alpha)
    for fq in order:
        spec = specs.get(fq)
        cal.ensure(
            fq,
            kinds.get(fq, spec.kind if spec else "float"),
            spec.higher_means_simulated if spec else True,
        )
    for sess in for_features:
        for fq in order:
            cal.features[fq].observe(sess.values.get(fq))

    fit_boundary(
        cal,
        [[(fq, s.values.get(fq)) for fq in order] for s in for_boundary],
        alpha=alpha,
    )
    return cal, for_features, for_boundary


def score(cal: Calibration, sessions: list[Session], order: list[str]) -> dict[SessionKey, dict]:
    """Full-suite verdict plus a per-vector verdict for attribution."""
    out: dict[SessionKey, dict] = {}
    vectors = sorted({fq.split(".", 1)[0] for fq in order})
    for sess in sessions:
        ordered = [(fq, sess.values.get(fq)) for fq in order]
        verdict = decide(cal, ordered, sess.commands_at_feature)
        per_vector: dict[str, bool] = {}
        for v in vectors:
            sub = [(fq, val) for fq, val in ordered if fq.startswith(f"{v}.")]
            per_vector[v] = decide(cal, sub, sess.commands_at_feature).simulated
        out[sess.key] = {"verdict": verdict, "per_vector": per_vector, "session": sess}
    return out


def write_verdicts(run_dir: pathlib.Path, scored: dict[SessionKey, dict]) -> pathlib.Path:
    path = run_dir / "verdicts.csv"
    vectors = sorted({v for d in scored.values() for v in d["per_vector"]})
    header = [
        "target", "target_kind", "backend", "seed", "role", "reachable",
        "simulated", "score",
        "boundary", "features_used", "probes_to_verdict", "commands_to_verdict",
        "deciding_feature", *[f"vector_{v}" for v in vectors],
    ]
    with path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        for key in sorted(scored):
            d = scored[key]
            s, v = d["session"], d["verdict"]
            w.writerow([
                s.target, s.target_kind, s.backend, s.seed, s.role,
                int(s.reachable), int(v.simulated), round(v.score, 4),
                "" if math.isinf(v.boundary) else round(v.boundary, 4),
                v.features_used, v.probes_to_verdict or "",
                v.commands_to_verdict if v.commands_to_verdict is not None else "",
                v.deciding_feature or "",
                *[int(d["per_vector"].get(x, False)) for x in vectors],
            ])
    return path


def _seed_range(sessions: list[Session]) -> str:
    """Compact seed description, so a long calibration run stays readable."""
    seeds = sorted(s.seed for s in sessions)
    if not seeds:
        return "no seeds"
    if len(seeds) <= 6:
        return f"seeds {seeds}"
    contiguous = seeds == list(range(seeds[0], seeds[-1] + 1))
    return (f"seeds {seeds[0]} to {seeds[-1]}" if contiguous
            else f"{len(seeds)} seeds between {seeds[0]} and {seeds[-1]}")


def _median(values: list[float]) -> float | None:
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    mid = len(vals) // 2
    return vals[mid] if len(vals) % 2 else (vals[mid - 1] + vals[mid]) / 2


def write_report(
    run_dir: pathlib.Path,
    cal: Calibration,
    scored: dict[SessionKey, dict],
    order: list[str],
    for_features: list[Session],
    for_boundary: list[Session],
    provenance: dict | None = None,
) -> pathlib.Path:
    """Write report.md. Every number here also exists in a CSV."""
    all_eval = [d for d in scored.values() if d["session"].role == "evaluation"]
    evaluation = [d for d in all_eval if d["session"].reachable]
    unreachable: dict[str, list[dict]] = defaultdict(list)
    for d in all_eval:
        if not d["session"].reachable:
            unreachable[d["session"].cell].append(d)
    by_cell: dict[str, list[dict]] = defaultdict(list)
    for d in evaluation:
        by_cell[d["session"].cell].append(d)

    lines: list[str] = []
    add = lines.append
    add("# honeytell run report")
    add("")
    if provenance:
        add(f"Run id `{provenance.get('run_id')}`, recorded {provenance.get('recorded_at')}.")
        add(f"Config sha256 `{provenance.get('config_sha256')}`.")
        fr = provenance.get("framing", {})
        add(f"Framing: idle_ms {fr.get('idle_ms')}, timeout_s {fr.get('timeout_s')}, "
            f"repeats {fr.get('repeats')}, max_seq_lines {fr.get('max_seq_lines')}.")
        add("")
        backends = provenance.get("backends") or []
        if backends:
            add("### Backends as served")
            add("")
            add("| Backend | Model | Digest | Context | Server |")
            add("|---|---|---|---|---|")
            for b in backends:
                ident = b.get("identity") or {}
                digest = ident.get("model_digest")
                short = digest[:16] if digest else (ident.get("note") or "not pinned")
                ctx = b.get("context_length")
                add(f"| {b.get('name')} | `{b.get('model')}` | `{short}` | "
                    f"{ctx if ctx else 'not declared'} | "
                    f"{ident.get('server_version') or 'unknown'} |")
            add("")
            if any(not (b.get("identity") or {}).get("resolved") for b in backends):
                add("A backend without a digest was not reachable when the run "
                    "started, so its weights are not pinned and this run is not "
                    "fully reproducible.")
                add("")

    add("## Decision rule")
    add("")
    add(f"- Target false positive rate (alpha): {cal.alpha}")
    add(f"- Stopping boundary: "
        f"{'not calibrated' if math.isinf(cal.boundary) else f'{cal.boundary:.4f} nats'}")
    add(f"- Boundary source: {cal.boundary_source}")
    add(f"- Real sessions shaping the reference distributions: {len(for_features)} "
        f"({_seed_range(for_features)})")
    add(f"- Real sessions shaping the boundary: {len(for_boundary)} "
        f"({_seed_range(for_boundary)})")
    add(f"- Features with a usable reference distribution: "
        f"{len(cal.usable_features())} of {len(order)} decisive")
    skipped = [f for f in feature_order(decisive_only=False) if f not in order]
    if skipped:
        add(f"- Recorded but not used for the verdict: {', '.join(f'`{s}`' for s in skipped)}")
    add("")
    add("The rule is calibrated on the real system alone. No honeypot session "
        "influences it, so adding a target never changes how the others are judged.")
    add("")
    add("The threshold is a split-conformal quantile of the accumulated evidence "
        "over real sessions, which bounds the chance that a fresh real session "
        "crosses it. The bound is finite sample and assumes nothing about how the "
        "scores are distributed, which matters because the timing features are "
        "correlated and heavy tailed. It is a guarantee in expectation over "
        "calibration draws, so a single run's observed rate scatters around alpha, "
        "and the scatter narrows as the calibration sample grows.")
    add("")

    if unreachable:
        add("## Targets that were not reachable")
        add("")
        add("These never produced a shell, so they have no result. They are left "
            "out of every table below. A rate of zero for a target that was not "
            "running would be an artifact, not a finding.")
        add("")
        add("| Target | Sessions | Reason |")
        add("|---|---|---|")
        for cell in sorted(unreachable):
            ds = unreachable[cell]
            reason = next((d["session"].note for d in ds if d["session"].note), "unknown")
            add(f"| {cell} | {len(ds)} | {reason[:110]} |")
        add("")

    add("## Detection by target")
    add("")
    if not by_cell:
        add("No target produced a session. Check `honeytell doctor` and bring the "
            "targets up before reading anything else here.")
        add("")
    add("| Target | Sessions | Detected | Rate (95% Wilson) | Median commands to verdict |")
    add("|---|---|---|---|---|")
    for cell in sorted(by_cell):
        ds = by_cell[cell]
        hits = sum(1 for d in ds if d["verdict"].simulated)
        ci = wilson_interval(hits, len(ds))
        med = _median([
            d["verdict"].commands_to_verdict for d in ds
            if d["verdict"].simulated and d["verdict"].commands_to_verdict is not None
        ])
        kind = ds[0]["session"].target_kind
        label = f"{cell} ({'control' if kind == 'real' else kind})"
        add(f"| {label} | {len(ds)} | {hits} | "
            f"{ci.point:.3f} [{ci.low:.3f}, {ci.high:.3f}] | "
            f"{'n/a' if med is None else f'{med:.0f}'} |")
    add("")
    add("The row whose kind is `control` is the real system. Its rate is the false "
        "positive rate, and it is the only rate the boundary was chosen to bound.")
    add("")

    add("## Detection by vector")
    add("")
    vectors = sorted({v for d in scored.values() for v in d["per_vector"]})
    if not by_cell:
        vectors = []
    add("| Target | " + " | ".join(vectors) + " |")
    add("|---" * (len(vectors) + 1) + "|")
    for cell in sorted(by_cell):
        ds = by_cell[cell]
        cells = []
        for v in vectors:
            hits = sum(1 for d in ds if d["per_vector"].get(v))
            cells.append(f"{hits}/{len(ds)}")
        add(f"| {cell} | " + " | ".join(cells) + " |")
    add("")
    add("Each column is the verdict reached using that vector alone, which is how "
        "much of the detection each vector can carry by itself.")
    add("")

    add("## Feature-level comparison against the real system")
    add("")
    real_eval = [d["session"] for d in evaluation if d["session"].target_kind == "real"]
    real_all = [s for s in for_features + for_boundary] + real_eval
    pvals: dict[str, float] = {}
    rows: list[tuple[str, str, str, str, float]] = []
    for cell in sorted(by_cell):
        ds = by_cell[cell]
        if ds[0]["session"].target_kind == "real":
            continue
        for fq in order:
            spec_kind = cal.features[fq].kind if fq in cal.features else "float"
            if spec_kind != "float":
                continue
            a = [d["session"].values.get(fq) for d in ds]
            b = [s.values.get(fq) for s in real_all]
            a = [float(x) for x in a if isinstance(x, (int, float)) and math.isfinite(x)]
            b = [float(x) for x in b if isinstance(x, (int, float)) and math.isfinite(x)]
            d_val, label = cliffs_delta(a, b)
            p = mann_whitney_p(a, b)
            if d_val is None or p is None:
                continue
            name = f"{cell}::{fq}"
            pvals[name] = p
            rows.append((cell, fq, f"{d_val:+.3f}", label, p))

    adj = benjamini_hochberg(pvals, q=0.05)
    if rows:
        add("Benjamini-Hochberg at q = 0.05 across "
            f"{len(pvals)} target by feature tests.")
        add("")
        add("| Target | Feature | Cliff's delta | Magnitude | p | p adjusted | Significant |")
        add("|---|---|---|---|---|---|---|")
        for cell, fq, d_str, label, p in sorted(rows, key=lambda r: pvals[f'{r[0]}::{r[1]}']):
            a = adj.get(f"{cell}::{fq}", {})
            add(f"| {cell} | `{fq}` | {d_str} | {label} | {p:.4g} | "
                f"{a.get('p_adjusted', float('nan')):.4g} | "
                f"{'yes' if a.get('significant') else 'no'} |")
    else:
        add("Not enough sessions to compare features. Run more seeds.")
    add("")

    add("## Probe errors")
    add("")
    add("Per-session status is in `sessions.csv` and the detail is in "
        "`raw/*.meta.json`. A probe that errored contributes no evidence rather "
        "than a default value, so an error lowers detection rather than "
        "inflating it. A session that never connected is excluded entirely.")
    add("")
    add("## Files")
    add("")
    for name in ("features.csv", "steps.csv", "sessions.csv", "verdicts.csv",
                 "calibration.json", "provenance.json"):
        if (run_dir / name).exists():
            add(f"- `{name}`")
    add("")

    path = run_dir / "report.md"
    path.write_text("\n".join(lines))
    return path


def analyse(run_dir: pathlib.Path, alpha: float = 0.01) -> dict:
    """Full analysis pass over a recorded run."""
    run_dir = pathlib.Path(run_dir)
    sessions, kinds = load_sessions(run_dir)
    if not sessions:
        raise RuntimeError(f"no sessions recorded in {run_dir}")
    order = feature_order(decisive_only=True)
    cal, for_features, for_boundary = build_calibration(sessions, kinds, order, alpha)
    cal.save(run_dir / "calibration.json")
    scored = score(cal, sessions, order)
    write_verdicts(run_dir, scored)
    prov_path = run_dir / "provenance.json"
    provenance = json.loads(prov_path.read_text()) if prov_path.exists() else None
    report = write_report(run_dir, cal, scored, order, for_features, for_boundary, provenance)
    return {
        "sessions": len(sessions),
        "report": str(report),
        "boundary": None if math.isinf(cal.boundary) else cal.boundary,
        "usable_features": len(cal.usable_features()),
    }
