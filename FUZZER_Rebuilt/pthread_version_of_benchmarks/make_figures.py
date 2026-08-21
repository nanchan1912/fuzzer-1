#!/usr/bin/env python3
"""Publication-quality figures for an AFL++ campaign.

    ./make_figures.py results/<stamp>            # writes analysis/figures/
    ./make_figures.py results/<stamp> --width 3.4

Emits vector PDF (for LaTeX \\includegraphics) plus a 600 dpi PNG preview of
each figure:

  fig1_detection_rate      how often each configuration finds any bug
  fig2_cdf_schedules       empirical CDF of schedules to first bug
  fig3_cdf_time            empirical CDF of wall time to first bug
  fig4_ttfb_distribution   per-run times, with censored runs shown explicitly
  fig5_cumulative_bugs     cumulative bugs vs schedules explored

Design constraints, all deliberate:

* Series are separated by colour *and* linestyle *and* marker, so every figure
  survives grayscale printing and CVD. The palette is a validated
  colourblind-safe pair.
* Runs that never found a bug are censored, never silently dropped. The CDFs
  simply do not reach 1.0, and fig4 draws censored runs as open markers on the
  budget line. A plot that hides censoring overstates the tool.
* Log x-axes throughout: schedules-to-first-bug spans orders of magnitude.

Requires matplotlib and numpy. The devcontainer has neither and its PyPI access
is unreliable, so run this on the host:  python3 make_figures.py <results-root>
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import matplotlib
except ImportError:
    sys.exit(
        "matplotlib is required.\n"
        "  pip install matplotlib          (host)\n"
        "This script only reads result files, so it can run anywhere the\n"
        "results tree is visible -- it does not need AFL or the container."
    )

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402

from analyze_results import (  # noqa: E402
    CONFIG_LABEL,
    CONFIG_ORDER,
    Group,
    Timeline,
    group_runs,
    load_campaign,
    log_bins,
)

# ---------------------------------------------------------------------------
# Style
# ---------------------------------------------------------------------------

# Colourblind-safe pair, distinct in grayscale by lightness as well as hue.
STYLE = {
    "feedback": dict(color="#2a78d6", linestyle="-", marker="o", hatch=""),
    "nofeedback": dict(color="#eb6834", linestyle="--", marker="s", hatch="///"),
}
INK = "#0b0b0b"
MUTED = "#6b6a66"
GRID = "#d8d7d0"

SINGLE_COL = 3.4   # inches, typical ACM/IEEE single column
DOUBLE_COL = 7.0


FONT_STACKS = {
    # Times metrics: matches LaTeX body text. Nimbus Roman is an OpenType/CFF
    # face, so poppler emits a "font type mismatch" warning on the embedded
    # subset -- harmless for rendering, but if a venue's PDF checker objects,
    # switch to --font-family dejavu.
    "times": ["Nimbus Roman", "Times New Roman", "Times", "DejaVu Serif"],
    # Bundled with matplotlib and a true TrueType face: embeds without any
    # checker complaint, at the cost of not matching a Times-set paper.
    "dejavu": ["DejaVu Serif"],
}


def apply_style(base_font: float = 8.0, family: str = "times") -> None:
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": FONT_STACKS.get(family, FONT_STACKS["times"]),
        "mathtext.fontset": "dejavuserif",
        "font.size": base_font,
        "axes.titlesize": base_font,
        "axes.labelsize": base_font,
        "xtick.labelsize": base_font - 1,
        "ytick.labelsize": base_font - 1,
        "legend.fontsize": base_font - 1,
        "axes.edgecolor": INK,
        "axes.labelcolor": INK,
        "axes.linewidth": 0.6,
        "axes.grid": True,
        "axes.axisbelow": True,
        "grid.color": GRID,
        "grid.linewidth": 0.4,
        "grid.alpha": 1.0,
        "xtick.color": INK,
        "ytick.color": INK,
        "xtick.direction": "out",
        "ytick.direction": "out",
        "xtick.major.width": 0.6,
        "ytick.major.width": 0.6,
        "xtick.major.size": 2.5,
        "ytick.major.size": 2.5,
        "lines.linewidth": 1.1,
        "lines.markersize": 3.2,
        "legend.frameon": False,
        "legend.handlelength": 2.2,
        "legend.columnspacing": 1.4,
        "figure.dpi": 150,
        "savefig.dpi": 600,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.02,
        "pdf.fonttype": 42,   # embed TrueType, not Type-3: required by most venues
        "ps.fonttype": 42,
    })


def despine(ax) -> None:
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)


def save(fig, outdir: Path, name: str) -> None:
    for ext in ("pdf", "png"):
        fig.savefig(outdir / f"{name}.{ext}")
    plt.close(fig)
    print(f"  {name}.pdf / .png")


def legend_handles(configs: list[str]) -> list[Line2D]:
    return [
        Line2D(
            [], [],
            color=STYLE[c]["color"],
            linestyle=STYLE[c]["linestyle"],
            marker=STYLE[c]["marker"],
            markersize=3.2,
            label=CONFIG_LABEL.get(c, c),
        )
        for c in configs
    ]


def panel_grid(n: int, width: float, panel_h: float = 1.35, ncols: int = 3,
               sharex: bool = False):
    ncols = min(ncols, max(1, n))
    nrows = math.ceil(n / ncols)
    fig, axes = plt.subplots(
        nrows, ncols,
        figsize=(width, panel_h * nrows + 0.55),
        squeeze=False,
        sharey=True,
        sharex=sharex,
    )
    flat = [a for row in axes for a in row]
    for ax in flat[n:]:
        ax.set_visible(False)
    return fig, flat[:n], nrows, ncols


# ---------------------------------------------------------------------------
# Figures
# ---------------------------------------------------------------------------


def fig_detection_rate(groups: dict, outdir: Path, width: float) -> None:
    """Fraction of the K runs that found any bug, per benchmark and config."""
    benches = sorted({b for b, _ in groups})
    configs = [c for c in CONFIG_ORDER if any((b, c) in groups for b in benches)]

    y = np.arange(len(benches), dtype=float)
    h = 0.36
    fig, ax = plt.subplots(figsize=(width, 0.30 * len(benches) + 1.05))

    for i, cfg in enumerate(configs):
        offs = (i - (len(configs) - 1) / 2) * h
        vals, starved = [], []
        for b in benches:
            g = groups.get((b, cfg))
            vals.append(g.n_found / g.k if g and g.k else np.nan)
            starved.append(g.n_starved if g else 0)
        ax.barh(
            y + offs, vals, height=h,
            color=STYLE[cfg]["color"], edgecolor="white", linewidth=0.5,
            hatch=STYLE[cfg]["hatch"], label=CONFIG_LABEL.get(cfg, cfg), zorder=3,
        )
        for yy, v, s in zip(y + offs, vals, starved):
            if np.isnan(v):
                ax.text(0.012, yy, "n/a", va="center", ha="left",
                        fontsize=6, color=MUTED, zorder=4)
                continue
            label = f"{v:.2f}" + (f"  ({s} starved)" if s else "")
            ax.text(v + 0.02, yy, label, va="center", ha="left",
                    fontsize=6, color=INK, zorder=4)

    ax.set_yticks(y)
    ax.set_yticklabels(benches)
    ax.set_xlim(0, 1.30)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_xlabel("fraction of runs that found a bug")
    ax.invert_yaxis()
    ax.xaxis.grid(True)
    ax.yaxis.grid(False)
    despine(ax)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0),
              ncol=len(configs), borderaxespad=0)
    save(fig, outdir, "fig1_detection_rate")


def _ecdf_panel(ax, group: Group, attr: str, cfg: str, k: int,
                xlim: tuple[float, float]) -> None:
    """Step CDF of `attr` over the K runs, spanning the full panel width.

    A proper ECDF is defined everywhere: flat at 0 left of the first event and
    flat at its final level to the right edge. Drawing only the data range
    would leave the reader guessing whether a curve is absent or just short,
    which matters here because some configurations legitimately never fire.
    """
    vals = sorted(v for v in (getattr(r, attr) for r in group.runs) if v is not None)
    st = STYLE[cfg]
    if not vals:
        # An all-censored configuration is a result, not missing data.
        ax.plot(list(xlim), [0, 0], color=st["color"], linestyle=st["linestyle"],
                linewidth=1.1, zorder=3)
        return

    xs, ys = [xlim[0]], [0.0]
    for i, v in enumerate(vals):
        xs += [v, v]
        ys += [i / k, (i + 1) / k]
    xs.append(xlim[1])
    ys.append(len(vals) / k)

    ax.plot(xs, ys, color=st["color"], linestyle=st["linestyle"],
            linewidth=1.1, zorder=3, solid_joinstyle="miter")
    ax.plot(vals, [(i + 1) / k for i in range(len(vals))], linestyle="none",
            marker=st["marker"], markersize=3.0, color=st["color"],
            markeredgecolor="white", markeredgewidth=0.4, zorder=4)


def fig_cdf(groups: dict, outdir: Path, width: float, attr: str,
            xlabel: str, name: str) -> None:
    benches = sorted({b for b, _ in groups})

    # One shared x-scale across panels: the comparison these small multiples
    # exist to support is between benchmarks, and per-panel scales would make
    # a 16-schedule bug and a 1000-schedule bug look identical.
    events = [
        v for g in groups.values() for v in (getattr(r, attr) for r in g.runs)
        if v is not None
    ]
    if not events:
        print(f"  (skipped {name}: no run found a bug)")
        return
    xlim = (max(min(events) / 2.5, 1e-3), max(events) * 2.5)

    fig, axes, nrows, ncols = panel_grid(len(benches), width, sharex=True)
    configs_seen: list[str] = []

    for ax, bench in zip(axes, benches):
        for cfg in CONFIG_ORDER:
            g = groups.get((bench, cfg))
            if g is None:
                continue
            if cfg not in configs_seen:
                configs_seen.append(cfg)
            _ecdf_panel(ax, g, attr, cfg, g.k, xlim)

        ax.set_xscale("log")
        ax.set_xlim(*xlim)
        ax.set_ylim(-0.04, 1.04)
        ax.set_yticks([0, 0.5, 1.0])
        ax.set_title(bench, pad=3)
        despine(ax)

    for i, ax in enumerate(axes):
        if i % ncols == 0:
            ax.set_ylabel("P(found)")
        if i >= len(axes) - ncols:
            # Bottom of its column in a ragged grid. sharex suppresses tick
            # labels on every row but the last, which would leave this panel
            # with an axis label and no numbers.
            ax.set_xlabel(xlabel)
            ax.tick_params(labelbottom=True)

    fig.legend(handles=legend_handles(configs_seen), loc="lower center",
               bbox_to_anchor=(0.5, 1.0), ncol=len(configs_seen), borderaxespad=0)
    fig.tight_layout(pad=0.35, w_pad=0.7, h_pad=0.8)
    save(fig, outdir, name)


def fig_ttfb_distribution(groups: dict, outdir: Path, width: float,
                          budget: float | None) -> None:
    """Every run as a point; censored runs drawn open on the budget line."""
    benches = sorted({b for b, _ in groups})
    configs = [c for c in CONFIG_ORDER if any((b, c) in groups for b in benches)]
    fig, ax = plt.subplots(figsize=(width, 2.5))
    rng = np.random.default_rng(0)   # fixed seed: jitter must be reproducible

    ceiling = budget if budget else 1.0
    for xi, bench in enumerate(benches):
        for ci, cfg in enumerate(configs):
            g = groups.get((bench, cfg))
            if g is None:
                continue
            st = STYLE[cfg]
            x0 = xi + (ci - (len(configs) - 1) / 2) * 0.30
            found = [r.t_first_bug for r in g.runs if r.t_first_bug is not None]
            miss = g.k - len(found)

            if found:
                jitter = rng.uniform(-0.055, 0.055, len(found))
                ax.plot(x0 + jitter, found, linestyle="none", marker=st["marker"],
                        markersize=3.0, color=st["color"], alpha=0.85,
                        markeredgecolor="white", markeredgewidth=0.3, zorder=3)
                m = float(np.mean(found))
                ax.plot([x0 - 0.11, x0 + 0.11], [m, m], color=st["color"],
                        linewidth=1.4, zorder=4)
            if miss:
                jitter = rng.uniform(-0.055, 0.055, miss)
                ax.plot(x0 + jitter, np.full(miss, ceiling), linestyle="none",
                        marker="^", markersize=3.4, markerfacecolor="none",
                        markeredgecolor=st["color"], markeredgewidth=0.7, zorder=3)

    if budget:
        ax.axhline(budget, color=MUTED, linestyle=":", linewidth=0.7, zorder=2)
        ax.text(len(benches) - 0.45, budget * 1.06,
                f"budget {budget:g}s — open markers: no bug found",
                fontsize=6, color=MUTED, ha="right", va="bottom")

    ax.set_yscale("log")
    ax.set_xticks(range(len(benches)))
    ax.set_xticklabels(benches, rotation=18, ha="right")
    ax.set_ylabel("time to first bug (s)")
    ax.xaxis.grid(False)
    despine(ax)
    handles = legend_handles(configs) + [
        Line2D([], [], linestyle="none", marker="^", markerfacecolor="none",
               markeredgecolor=MUTED, markersize=3.4, label="censored (no bug)")
    ]
    ax.legend(handles=handles, loc="lower center", bbox_to_anchor=(0.5, 1.0),
              ncol=len(handles), borderaxespad=0)
    fig.tight_layout(pad=0.35)
    save(fig, outdir, "fig4_ttfb_distribution")


def fig_cumulative(groups: dict, outdir: Path, width: float) -> None:
    """Mean cumulative bugs against schedules explored, log x."""
    benches = sorted({b for b, _ in groups})
    max_execs = max((r.execs for g in groups.values() for r in g.runs), default=0.0)
    bins = log_bins(max_execs)

    fig, axes, nrows, ncols = panel_grid(len(benches), width)
    configs_seen: list[str] = []

    for ax, bench in zip(axes, benches):
        for cfg in CONFIG_ORDER:
            g = groups.get((bench, cfg))
            if g is None:
                continue
            if cfg not in configs_seen:
                configs_seen.append(cfg)
            tls = [Timeline.load(r.run_dir / "timeline.csv") for r in g.runs]
            xs, ys, los, his, full = [], [], [], [], []
            for b in bins:
                vals = [
                    v for v in (
                        tl.cumulative_at(float(b), "n_crash_files",
                                         "n_race_files", "n_hang_files")
                        for tl in tls
                    ) if v is not None
                ]
                if not vals:
                    continue
                xs.append(b)
                ys.append(float(np.mean(vals)))
                los.append(min(vals))
                his.append(max(vals))
                full.append(sum(1 for tl in tls if tl.reached(float(b))) == g.k)
            if not xs:
                continue
            st = STYLE[cfg]
            # The band is the full min-max across runs, not a CI: with K this
            # small a confidence interval would imply precision we lack.
            ax.fill_between(xs, los, his, color=st["color"], alpha=0.13,
                            linewidth=0, zorder=2)

            # Solid while every run was still contributing; faded once the mean
            # is carried forward from runs that had already stopped, so the
            # extrapolated tail is never mistaken for measured data.
            cut = len(xs)
            for i, ok in enumerate(full):
                if not ok:
                    cut = i
                    break
            ax.plot(xs[:cut + 1], ys[:cut + 1], color=st["color"],
                    linestyle=st["linestyle"], linewidth=1.1, zorder=3)
            if cut < len(xs):
                ax.plot(xs[cut:], ys[cut:], color=st["color"],
                        linestyle=st["linestyle"], linewidth=1.1,
                        alpha=0.35, zorder=3)

        ax.set_xscale("log")
        ax.set_title(bench, pad=3)
        ax.margins(y=0.12)
        despine(ax)

    for i, ax in enumerate(axes):
        if i % ncols == 0:
            ax.set_ylabel("bugs found")
        if i >= len(axes) - ncols:
            ax.set_xlabel("schedules explored")

    handles = legend_handles(configs_seen) + [
        Line2D([], [], color=MUTED, linewidth=1.1, alpha=0.35,
               label="extrapolated (some runs had stopped)")
    ]
    fig.legend(handles=handles, loc="lower center", bbox_to_anchor=(0.5, 1.0),
               ncol=len(handles), borderaxespad=0)
    fig.tight_layout(pad=0.35, w_pad=0.7, h_pad=0.8)
    save(fig, outdir, "fig5_cumulative_bugs")


# ---------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("results_root")
    ap.add_argument("--width", type=float, default=DOUBLE_COL,
                    help=f"multi-panel figure width in inches [{DOUBLE_COL}]")
    ap.add_argument("--font", type=float, default=8.0, help="base font size [8]")
    ap.add_argument("--font-family", choices=sorted(FONT_STACKS), default="times",
                    help="times matches LaTeX body text; dejavu embeds without "
                         "any PDF-checker warning [times]")
    args = ap.parse_args()

    root = Path(args.results_root).resolve()
    if not root.is_dir():
        sys.exit(f"no such results root: {root}")

    runs, _ = load_campaign(root)
    if not runs:
        sys.exit(f"no runs found under {root}/runs")
    groups = group_runs(runs)

    budget = None
    try:
        budget = float(json.loads((root / "campaign.json").read_text())["max_time_s"])
    except (OSError, ValueError, KeyError):
        pass

    apply_style(args.font, args.font_family)
    outdir = root / "analysis" / "figures"
    outdir.mkdir(parents=True, exist_ok=True)

    print(f"figures -> {outdir}")
    fig_detection_rate(groups, outdir, SINGLE_COL)
    fig_cdf(groups, outdir, args.width, "e_first_bug",
            "schedules explored", "fig2_cdf_schedules")
    fig_cdf(groups, outdir, args.width, "t_first_bug",
            "time (s)", "fig3_cdf_time")
    fig_ttfb_distribution(groups, outdir, args.width, budget)
    fig_cumulative(groups, outdir, args.width)
    return 0


if __name__ == "__main__":
    sys.exit(main())
