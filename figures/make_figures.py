#!/usr/bin/env python3
"""Build the paper's figures from a run directory.

Reads only CSV. Nothing is recomputed here that the run did not already write,
so a figure cannot disagree with a table.

    python figures/make_figures.py --run out/run-abc123456789

Colours come from a palette checked with the data-visualisation validator:
adjacent-pair CVD Delta E 9.2 and normal-vision Delta E 24.0 on the light
surface. Three of the slots fall below 3:1 against the surface, so every mark
that uses one also carries a printed value or a hatch, and the run's own
report.md is the table view.
"""

from __future__ import annotations

import argparse
import csv
import math
import pathlib
from collections import defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

# Categorical slots 1 to 3, in the fixed order the palette defines.
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"
# The real system is the reference, not a series, so it takes neutral ink.
NEUTRAL = "#52514e"
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#d8d7d2"

# Sequential blue, light to dark, for magnitude.
SEQ = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#2a78d6", "#256abf",
       "#1c5cab", "#184f95", "#104281"]

KIND_COLOUR = {
    "llm_honeypot": BLUE,
    "classic_honeypot": ORANGE,
    "real": NEUTRAL,
}
KIND_HATCH = {"llm_honeypot": "", "classic_honeypot": "///", "real": "..."}
KIND_LABEL = {
    "llm_honeypot": "LLM honeypot",
    "classic_honeypot": "Classic honeypot",
    "real": "Real system (control)",
}

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 8,
    "axes.labelsize": 8,
    "axes.titlesize": 9,
    "legend.fontsize": 7,
    "xtick.labelsize": 7,
    "ytick.labelsize": 7,
    "axes.edgecolor": MUTED,
    "axes.linewidth": 0.6,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "text.color": INK,
    "axes.labelcolor": INK,
    "grid.color": GRID,
    "grid.linewidth": 0.5,
    "figure.dpi": 200,
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.02,
    "pdf.fonttype": 42,
})


def wilson(successes: int, n: int, z: float = 1.959963984540054):
    if n <= 0:
        return float("nan"), float("nan"), float("nan")
    p = successes / n
    d = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, centre - half), min(1.0, centre + half)


def read_verdicts(run: pathlib.Path) -> list[dict]:
    path = run / "verdicts.csv"
    if not path.exists():
        raise SystemExit(f"{path} not found; run honeytell report first")
    rows = [r for r in csv.DictReader(path.open()) if r["role"] == "evaluation"]
    if not rows:
        raise SystemExit("no evaluation sessions in verdicts.csv")
    return rows


def cell_name(row: dict) -> str:
    return f"{row['target']}/{row['backend']}" if row["backend"] else row["target"]


def fig_detection(run: pathlib.Path, rows: list[dict], out: pathlib.Path) -> None:
    """Magnitude with uncertainty, so a bar with a confidence interval."""
    by_cell: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_cell[cell_name(r)].append(r)

    order = sorted(by_cell, key=lambda c: (
        by_cell[c][0]["target_kind"] != "real", c))
    labels, points, los, his, colours, hatches, kinds = [], [], [], [], [], [], []
    counts: list[int] = []
    for cell in order:
        rs = by_cell[cell]
        kind = rs[0]["target_kind"]
        hits = sum(1 for r in rs if r["simulated"] == "1")
        p, lo, hi = wilson(hits, len(rs))
        labels.append(cell)
        counts.append(len(rs))
        points.append(p)
        # Clamp: at p exactly 0 or 1 the interval edge can land a float step
        # the wrong side of the point estimate, and errorbar rejects that.
        los.append(max(0.0, p - lo))
        his.append(max(0.0, hi - p))
        colours.append(KIND_COLOUR.get(kind, BLUE))
        hatches.append(KIND_HATCH.get(kind, ""))
        kinds.append(kind)

    fig, ax = plt.subplots(figsize=(3.4, 0.28 * len(labels) + 1.1),
                           layout="constrained")
    y = range(len(labels))
    bars = ax.barh(list(y), points, height=0.62, color=colours,
                   edgecolor="#fcfcfb", linewidth=1.2)
    for bar, h in zip(bars, hatches, strict=False):
        if h:
            bar.set_hatch(h)
    ax.errorbar(points, list(y), xerr=[los, his], fmt="none",
                ecolor=INK, elinewidth=0.8, capsize=2)

    # Printed values are the relief for the low-contrast slots. The sample
    # size rides along here rather than in the tick label, which would crowd
    # the axis out of a single-column figure.
    for yi, pt, hi, n in zip(y, points, his, counts, strict=False):
        ax.text(min(pt + hi + 0.03, 1.04), yi, f"{pt:.2f}  n={n}", va="center",
                ha="left", fontsize=6.5, color=INK)

    ax.set_yticks(list(y), labels)
    ax.invert_yaxis()
    ax.set_xlim(0, 1.42)
    ax.set_xticks([0, 0.5, 1.0])
    ax.set_xlabel("Detection rate (95% Wilson interval)")
    ax.xaxis.grid(True)
    ax.set_axisbelow(True)
    present = [k for k in ("llm_honeypot", "classic_honeypot", "real") if k in kinds]
    # Below the axes: inside the plot it would sit on the bars.
    ax.legend(
        handles=[Patch(facecolor=KIND_COLOUR[k], hatch=KIND_HATCH[k],
                       edgecolor=KIND_COLOUR[k], linewidth=0,
                       label=KIND_LABEL[k]) for k in present],
        loc="upper center", bbox_to_anchor=(0.5, -0.14),
        ncol=min(3, len(present)), frameon=False, handlelength=1.4,
        columnspacing=1.0, borderpad=0,
    )
    fig.savefig(out / "fig1_detection_rate.pdf")
    fig.savefig(out / "fig1_detection_rate.png")
    plt.close(fig)


def fig_vectors(run: pathlib.Path, rows: list[dict], out: pathlib.Path) -> None:
    """A target by vector grid of rates, so a single-hue sequential heatmap."""
    vectors = [k.removeprefix("vector_") for k in rows[0] if k.startswith("vector_")]
    if not vectors:
        return
    by_cell: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_cell[cell_name(r)].append(r)
    order = sorted(by_cell, key=lambda c: (
        by_cell[c][0]["target_kind"] != "real", c))

    grid = [[sum(1 for r in by_cell[c] if r[f"vector_{v}"] == "1") / len(by_cell[c])
             for v in vectors] for c in order]

    cmap = matplotlib.colors.LinearSegmentedColormap.from_list("seq_blue", SEQ)
    fig, ax = plt.subplots(figsize=(0.75 * len(vectors) + 2.2, 0.3 * len(order) + 1.0),
                           layout="constrained")
    im = ax.imshow(grid, cmap=cmap, vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(vectors)), vectors)
    ax.set_yticks(range(len(order)), order)
    for i, row in enumerate(grid):
        for j, val in enumerate(row):
            # Every cell is labelled, so magnitude never rests on colour alone.
            ax.text(j, i, f"{val:.2f}", ha="center", va="center", fontsize=6.5,
                    color="#fcfcfb" if val > 0.55 else INK)
    ax.set_xlabel("Vector used alone")
    cb = fig.colorbar(im, ax=ax, fraction=0.035, pad=0.03)
    cb.set_label("Detection rate", fontsize=7)
    cb.outline.set_visible(False)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    fig.savefig(out / "fig2_vector_breakdown.pdf")
    fig.savefig(out / "fig2_vector_breakdown.png")
    plt.close(fig)


def fig_cost(run: pathlib.Path, rows: list[dict], out: pathlib.Path) -> None:
    """Cost per target, faceted rather than overlaid.

    Six overlapping curves would make identity depend on hue separation. One
    small panel per target reads better in print and needs no legend.
    """
    costs: dict[str, list[int]] = defaultdict(list)
    for r in rows:
        if r["simulated"] == "1" and r["commands_to_verdict"]:
            costs[cell_name(r)].append(int(r["commands_to_verdict"]))
    costs = {k: sorted(v) for k, v in costs.items() if v}
    if not costs:
        return

    order = sorted(costs)
    ncol = min(3, len(order))
    nrow = math.ceil(len(order) / ncol)
    top = max(max(v) for v in costs.values())
    fig, axes = plt.subplots(nrow, ncol, figsize=(1.45 * ncol + 0.7, 1.3 * nrow + 0.6),
                             sharex=True, sharey=True, squeeze=False,
                             layout="constrained")
    for idx, cell in enumerate(order):
        ax = axes[idx // ncol][idx % ncol]
        vals = costs[cell]
        xs = [0] + vals
        ys = [0] + [(i + 1) / len(vals) for i in range(len(vals))]
        ax.step(xs, ys, where="post", color=BLUE, linewidth=1.6)
        ax.scatter(vals, [(i + 1) / len(vals) for i in range(len(vals))],
                   s=9, color=BLUE, zorder=3, edgecolor="#fcfcfb", linewidth=0.5)
        med = vals[len(vals) // 2] if len(vals) % 2 else \
            (vals[len(vals) // 2 - 1] + vals[len(vals) // 2]) / 2
        ax.set_title(cell, fontsize=7.5)
        # Top left: the curve rises to the right, so this corner stays empty.
        ax.text(0.04, 0.9, f"median {med:.0f}", transform=ax.transAxes,
                ha="left", va="top", fontsize=6.5, color=MUTED)
        ax.set_xlim(0, top * 1.08)
        ax.set_ylim(0, 1.05)
        ax.grid(True, axis="both")
        ax.set_axisbelow(True)
    for idx in range(len(order), nrow * ncol):
        axes[idx // ncol][idx % ncol].axis("off")
    fig.supxlabel("Commands issued before the verdict", fontsize=8)
    fig.supylabel("Share of sessions decided", fontsize=8)
    fig.savefig(out / "fig3_cost_to_verdict.pdf")
    fig.savefig(out / "fig3_cost_to_verdict.png")
    plt.close(fig)


def fig_timing(run: pathlib.Path, out: pathlib.Path,
               feature: str = "timing.length_slope:ms_per_kib") -> None:
    """One timing feature per target, with the control marked.

    A strip plot rather than a box: with five to seven sessions per cell the
    individual values are the honest display.
    """
    path = run / "features.csv"
    if not path.exists():
        return
    probe, _, feat = feature.partition(":")
    values: dict[str, list[float]] = defaultdict(list)
    kinds: dict[str, str] = {}
    for r in csv.DictReader(path.open()):
        if r["probe"] != probe or r["feature"] != feat or r["value"] == "":
            continue
        if r["role"] != "evaluation":
            continue
        cell = f"{r['target']}/{r['backend']}" if r["backend"] else r["target"]
        try:
            v = float(r["value"])
        except ValueError:
            continue
        if math.isfinite(v):
            # Keep non-positive values. A real shell's slope is near zero and
            # dropping it would remove the control, which is the whole
            # comparison.
            values[cell].append(v)
            kinds[cell] = r["target_kind"]
    if len(values) < 2:
        return

    order = sorted(values, key=lambda c: (kinds[c] != "real", c))
    fig, ax = plt.subplots(figsize=(3.4, 0.3 * len(order) + 1.1),
                           layout="constrained")
    for i, cell in enumerate(order):
        colour = NEUTRAL if kinds[cell] == "real" else BLUE
        marker = "s" if kinds[cell] == "real" else "o"
        ax.scatter(values[cell], [i] * len(values[cell]), s=16, color=colour,
                   marker=marker, alpha=0.85, edgecolor="#fcfcfb", linewidth=0.5,
                   zorder=3)
    # Symmetrical log: a real shell's slope sits at or below zero, which a
    # plain log axis cannot show at all.
    ax.set_xscale("symlog", linthresh=1.0, linscale=0.4)
    ax.set_yticks(range(len(order)),
                  [f"{c} (control)" if kinds[c] == "real" else c for c in order])
    ax.invert_yaxis()
    ax.set_xlabel("Streaming time per KiB of output (ms, symlog)")
    ax.xaxis.grid(True, which="major")
    ax.set_axisbelow(True)
    ax.legend(handles=[
        Patch(facecolor=BLUE, edgecolor=BLUE, linewidth=0, label="Honeypot"),
        Patch(facecolor=NEUTRAL, edgecolor=NEUTRAL, linewidth=0,
              label="Real system (control)"),
    ], loc="upper center", bbox_to_anchor=(0.5, -0.16), ncol=2,
        frameon=False, handlelength=1.4, columnspacing=1.0, borderpad=0)
    fig.savefig(out / "fig4_timing_slope.pdf")
    fig.savefig(out / "fig4_timing_slope.png")
    plt.close(fig)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run", required=True, help="path to out/<run-id>")
    ap.add_argument("--out", default=None, help="where to write (default: <run>/figures)")
    args = ap.parse_args()

    run = pathlib.Path(args.run)
    out = pathlib.Path(args.out) if args.out else run / "figures"
    out.mkdir(parents=True, exist_ok=True)

    rows = read_verdicts(run)
    fig_detection(run, rows, out)
    fig_vectors(run, rows, out)
    fig_cost(run, rows, out)
    fig_timing(run, out)

    made = sorted(p.name for p in out.glob("*.pdf"))
    print(f"wrote {len(made)} figure(s) to {out}")
    for name in made:
        print(f"  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
