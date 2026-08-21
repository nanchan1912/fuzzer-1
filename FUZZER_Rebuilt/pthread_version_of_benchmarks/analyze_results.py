#!/usr/bin/env python3
"""Aggregate an AFL++ campaign produced by run_all_and_record.sh.

Reads the raw per-run output tree and emits:

  analysis/per_run.csv         one row per (benchmark, config, repeat)
  analysis/summary.csv         one row per (benchmark, config), aggregated over K
  analysis/summary.md          the paper-style table with * / + / - markers
  analysis/cumulative_bugs.csv cumulative unique bugs vs schedules explored
  analysis/report.html         the same, with charts

Standard library only: the container has no numpy/matplotlib.

Metric definitions
------------------
schedules explored   AFL executions (execs_done); one execution = one schedule.
time to first bug    wall seconds from fuzzer launch to the first saved bug
                     artifact, read off the sampled timeline. Resolution is the
                     campaign's sampling interval (default 0.5 s).
execs to first bug   execs_done at that same sample.
bug                  a saved crash, a saved race, or a saved hang. Crashes and
                     races are defects; hangs are counted but flagged, since a
                     hang may be a livelock rather than a bug.
unique races         race location pairs (instruction_id, instruction_id),
                     unioned across the K runs of a configuration.

Runs that never find a bug are *censored*: they contribute to the detection
rate but not to the time/exec statistics, which are computed over the runs that
did find one. Reporting a mean over only successful runs alongside the
detection rate is the honest form; a mean that silently substitutes the time
budget for the failures is not.
"""

from __future__ import annotations

import csv
import html
import math
import os
import re
import shutil
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Palette (validated dataviz reference instance)
# ---------------------------------------------------------------------------

LIGHT = {
    "surface": "#fcfcfb",
    "plane": "#f9f9f7",
    "ink": "#0b0b0b",
    "ink2": "#52514e",
    "muted": "#898781",
    "grid": "#e1e0d9",
    "axis": "#c3c2b7",
    "s1": "#2a78d6",
    "s2": "#eb6834",
    "s3": "#1baf7a",
}
DARK = {
    "surface": "#1a1a19",
    "plane": "#0d0d0d",
    "ink": "#ffffff",
    "ink2": "#c3c2b7",
    "muted": "#898781",
    "grid": "#2c2c2a",
    "axis": "#383835",
    "s1": "#3987e5",
    "s2": "#d95926",
    "s3": "#199e70",
}

CONFIG_ORDER = ["feedback", "nofeedback"]
CONFIG_LABEL = {"feedback": "with feedback", "nofeedback": "without feedback"}
CONFIG_SLOT = {"feedback": "s1", "nofeedback": "s2"}


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def read_kv(path: Path, sep: str) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        for line in path.read_text(errors="replace").splitlines():
            if sep not in line:
                continue
            k, v = line.split(sep, 1)
            out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


ANSI = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
ABORT = re.compile(r"PROGRAM ABORT\s*:\s*(.+)")


def read_abort_reason(log: Path) -> str:
    """AFL's own reason for refusing to fuzz, if it bailed out.

    A run that aborted before executing anything is not evidence that the tool
    found no bug -- it never got to look. Reporting it as '*' (found nothing)
    would understate the tool; it belongs under '-' (could not be run).
    """
    try:
        text = ANSI.sub("", log.read_text(errors="replace"))
    except OSError:
        return ""
    matches = ABORT.findall(text)
    return matches[-1].strip().rstrip(".") if matches else ""


RACE_LINE = re.compile(
    r"race_(\d+):\s*thread_id=(-?\d+)\s+instruction_id=(-?\d+)\s+visit_id=(-?\d+)"
)


def parse_race_file(path: Path) -> tuple[int, int] | None:
    """Return the race as a canonical pair of static instruction ids.

    Thread and visit ids identify the *schedule* that exposed the race, not the
    racing code, so two runs hitting the same pair of instructions from
    different schedules must collapse to one unique bug.
    """
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return None
    ids = [int(m.group(3)) for m in RACE_LINE.finditer(text)]
    if len(ids) < 2:
        return None
    return (min(ids[0], ids[1]), max(ids[0], ids[1]))


def count_artifacts(d: Path) -> int:
    if not d.is_dir():
        return 0
    return sum(1 for p in d.iterdir() if p.name.startswith("id:"))


@dataclass
class Timeline:
    rows: list[dict[str, float]] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> "Timeline":
        rows: list[dict[str, float]] = []
        if path.is_file():
            with path.open(newline="") as fh:
                for rec in csv.DictReader(fh):
                    try:
                        rows.append({k: float(v) for k, v in rec.items() if v != ""})
                    except (TypeError, ValueError):
                        continue
        rows.sort(key=lambda r: r.get("wall_s", 0.0))
        return cls(rows)

    def first_at(self, *columns: str) -> tuple[float, float] | None:
        """(wall_s, execs_done) of the first sample where any column is >= 1."""
        for r in self.rows:
            if any(r.get(c, 0.0) >= 1 for c in columns):
                return (r.get("wall_s", 0.0), r.get("execs_done", 0.0))
        return None

    def final_execs(self) -> float:
        return self.rows[-1].get("execs_done", 0.0) if self.rows else 0.0

    def reached(self, execs: float) -> bool:
        """Did this run actually execute that many schedules?"""
        return bool(self.rows) and self.final_execs() >= execs

    def cumulative_at(self, execs: float, *columns: str) -> float | None:
        """Cumulative count at a given exec budget, last value carried forward.

        A run that stopped before `execs` holds its final count rather than
        dropping out. This matters: averaging only over the runs that reached
        each bin means runs leave the average as the bin grows and take their
        bugs with them, which makes the "cumulative" curve *decrease* — an
        obvious artifact. Carrying the last value forward keeps the mean
        monotone, at the cost of assuming a stopped run would have found
        nothing more. Callers pair this with `reached()` so the region where
        every run contributed can be distinguished from the extrapolated tail.
        """
        if not self.rows:
            return None
        value = 0.0
        for r in self.rows:
            if r.get("execs_done", 0.0) > execs:
                break
            value = sum(r.get(c, 0.0) for c in columns)
        return value


@dataclass
class Run:
    benchmark: str
    config: str
    repeat: int
    run_dir: Path
    exit_code: int = 0
    execs: float = 0.0
    duration: float = 0.0
    corpus: float = 0.0
    cycles: float = 0.0
    n_crashes: int = 0
    n_hangs: int = 0
    n_races: int = 0
    race_pairs: set[tuple[int, int]] = field(default_factory=set)
    t_first_crash: float | None = None
    e_first_crash: float | None = None
    t_first_race: float | None = None
    e_first_race: float | None = None
    t_first_hang: float | None = None
    e_first_hang: float | None = None
    t_first_bug: float | None = None
    e_first_bug: float | None = None
    incomplete: bool = False
    abort_reason: str = ""

    @property
    def n_bugs(self) -> int:
        return self.n_crashes + self.n_races + self.n_hangs

    @property
    def starved(self) -> bool:
        """Mutation never grew the corpus past the seed, yet kept cycling.

        Observed in practice: a run does ~16 executions in 45 s with
        corpus_count stuck at 2 and cycles_done in the thousands, while a
        sibling run of the same configuration reaches a corpus of ~780. Such a
        run explores almost no schedules, so it drags the detection rate down
        for a reason unrelated to the bug being hard to reach.
        """
        return self.corpus <= 2 and self.cycles > 0


def load_run(bench: str, cfg: str, rep: int, run_dir: Path) -> Run:
    run = Run(bench, cfg, rep, run_dir)
    meta = read_kv(run_dir / "meta.env", "=")
    run.exit_code = int(meta.get("exit_code", "0") or 0)

    out = run_dir / "out" / "default"
    stats = read_kv(out / "fuzzer_stats", ":")
    run.execs = float(stats.get("execs_done", 0) or 0)
    run.duration = float(stats.get("run_time", 0) or 0)
    run.corpus = float(stats.get("corpus_count", 0) or 0)
    run.cycles = float(stats.get("cycles_done", 0) or 0)

    run.n_crashes = count_artifacts(out / "crashes")
    run.n_hangs = count_artifacts(out / "hangs")
    run.n_races = count_artifacts(out / "races")

    races_dir = out / "races"
    if races_dir.is_dir():
        for p in sorted(races_dir.iterdir()):
            if not p.name.startswith("id:"):
                continue
            pair = parse_race_file(p)
            if pair is not None:
                run.race_pairs.add(pair)

    if run.execs == 0:
        run.abort_reason = read_abort_reason(run_dir / "run.log")

    tl = Timeline.load(run_dir / "timeline.csv")
    # fuzzer_stats is only written periodically; if it is missing entirely the
    # run never got far enough to be comparable.
    run.incomplete = not tl.rows or not stats

    if run.execs == 0.0:
        run.execs = tl.final_execs()

    for name, cols in (
        ("crash", ("n_crash_files",)),
        ("race", ("n_race_files",)),
        ("hang", ("n_hang_files",)),
        ("bug", ("n_crash_files", "n_race_files", "n_hang_files")),
    ):
        hit = tl.first_at(*cols)
        if hit is not None:
            setattr(run, f"t_first_{name}", hit[0])
            setattr(run, f"e_first_{name}", hit[1])

    return run


def load_campaign(root: Path) -> tuple[list[Run], dict[str, dict[str, str]]]:
    runs: list[Run] = []
    runs_root = root / "runs"
    if runs_root.is_dir():
        for bench_dir in sorted(runs_root.iterdir()):
            if not bench_dir.is_dir():
                continue
            for cfg_dir in sorted(bench_dir.iterdir()):
                if not cfg_dir.is_dir():
                    continue
                for run_dir in sorted(cfg_dir.iterdir()):
                    if not run_dir.is_dir() or not run_dir.name.startswith("run-"):
                        continue
                    try:
                        rep = int(run_dir.name.split("-", 1)[1])
                    except ValueError:
                        continue
                    runs.append(load_run(bench_dir.name, cfg_dir.name, rep, run_dir))

    benches: dict[str, dict[str, str]] = {}
    bench_csv = root / "benchmarks.csv"
    if bench_csv.is_file():
        with bench_csv.open(newline="") as fh:
            for rec in csv.DictReader(fh):
                benches[rec["benchmark"]] = rec
    return runs, benches


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


@dataclass
class Stat:
    n: int = 0
    minimum: float | None = None
    maximum: float | None = None
    mean: float | None = None
    variance: float | None = None
    stdev: float | None = None

    @classmethod
    def of(cls, values: list[float]) -> "Stat":
        vals = [v for v in values if v is not None]
        if not vals:
            return cls()
        var = statistics.variance(vals) if len(vals) > 1 else 0.0
        return cls(
            n=len(vals),
            minimum=min(vals),
            maximum=max(vals),
            mean=statistics.fmean(vals),
            variance=var,
            stdev=math.sqrt(var),
        )

    def fmt(self, unit: str = "", precision: int = 1) -> str:
        if self.n == 0:
            return "*"
        if self.minimum == self.maximum:
            return f"{self.minimum:.{precision}f}{unit}"
        return (
            f"{self.mean:.{precision}f}±{self.stdev:.{precision}f}{unit} "
            f"[{self.minimum:.{precision}f}, {self.maximum:.{precision}f}]"
        )


@dataclass
class Group:
    benchmark: str
    config: str
    runs: list[Run]

    @property
    def k(self) -> int:
        return len(self.runs)

    @property
    def n_found(self) -> int:
        return sum(1 for r in self.runs if r.n_bugs > 0)

    @property
    def found_any(self) -> bool:
        return self.n_found > 0

    @property
    def hangs_only(self) -> bool:
        """Bugs were found, but every one of them was a hang."""
        return self.found_any and all(
            r.n_crashes == 0 and r.n_races == 0 for r in self.runs
        )

    @property
    def includes_hangs(self) -> bool:
        return any(r.n_hangs > 0 for r in self.runs)

    @property
    def n_starved(self) -> int:
        return sum(1 for r in self.runs if r.starved)

    @property
    def aborted(self) -> bool:
        """Every run bailed out before fuzzing: '-', not '*'."""
        return bool(self.runs) and all(r.abort_reason for r in self.runs)

    @property
    def abort_reason(self) -> str:
        for r in self.runs:
            if r.abort_reason:
                return r.abort_reason
        return ""

    @property
    def unique_races(self) -> set[tuple[int, int]]:
        out: set[tuple[int, int]] = set()
        for r in self.runs:
            out |= r.race_pairs
        return out

    def stat(self, attr: str) -> Stat:
        return Stat.of([getattr(r, attr) for r in self.runs if getattr(r, attr) is not None])

    def total_stat(self, attr: str) -> Stat:
        return Stat.of([float(getattr(r, attr)) for r in self.runs])


def group_runs(runs: list[Run]) -> dict[tuple[str, str], Group]:
    groups: dict[tuple[str, str], Group] = {}
    for r in runs:
        groups.setdefault((r.benchmark, r.config), Group(r.benchmark, r.config, []))
        groups[(r.benchmark, r.config)].runs.append(r)
    for g in groups.values():
        g.runs.sort(key=lambda r: r.repeat)
    return groups


def log_bins(max_execs: float) -> list[int]:
    """Powers of two up to the largest budget any run reached."""
    if max_execs < 1:
        return []
    bins = []
    b = 1
    while b <= max_execs:
        bins.append(b)
        b *= 2
    if bins and bins[-1] < max_execs:
        bins.append(int(max_execs))
    return bins


def cumulative_curve(group: Group, bins: list[int]) -> list[tuple[int, float | None, int]]:
    """(exec_bin, mean cumulative bugs, #runs that reached the bin)."""
    timelines = [Timeline.load(r.run_dir / "timeline.csv") for r in group.runs]
    curve = []
    for b in bins:
        vals = [
            v for v in (
                tl.cumulative_at(
                    float(b), "n_crash_files", "n_race_files", "n_hang_files"
                )
                for tl in timelines
            ) if v is not None
        ]
        n_reached = sum(1 for tl in timelines if tl.reached(float(b)))
        curve.append((b, statistics.fmean(vals) if vals else None, n_reached))
    return curve


# ---------------------------------------------------------------------------
# SVG charts
# ---------------------------------------------------------------------------


def svg_cumulative(
    benchmark: str,
    curves: dict[str, list[tuple[int, float | None, int]]],
    width: int = 620,
    height: int = 260,
) -> str:
    """Mean cumulative bugs vs schedules explored, log x-axis."""
    pad_l, pad_r, pad_t, pad_b = 52, 16, 16, 40
    pts = [(b, v) for c in curves.values() for (b, v, n) in c if v is not None]
    if not pts:
        return ""

    xs = [p[0] for p in pts if p[0] > 0]
    ys = [p[1] for p in pts]
    x_lo, x_hi = math.log10(max(1, min(xs))), math.log10(max(xs))
    if x_hi - x_lo < 1e-9:
        x_hi = x_lo + 1
    y_hi = max(1.0, max(ys)) * 1.15

    def px(v: float) -> float:
        return pad_l + (math.log10(max(1, v)) - x_lo) / (x_hi - x_lo) * (
            width - pad_l - pad_r
        )

    def py(v: float) -> float:
        return height - pad_b - (v / y_hi) * (height - pad_t - pad_b)

    parts = [
        f'<svg viewBox="0 0 {width} {height}" width="100%" '
        f'role="img" aria-label="Cumulative bugs vs schedules explored for {html.escape(benchmark)}">'
    ]

    # Recessive grid: one hairline per y tick, log decade ticks on x.
    y_ticks = 4
    for i in range(y_ticks + 1):
        v = y_hi * i / y_ticks
        y = py(v)
        parts.append(
            f'<line x1="{pad_l}" y1="{y:.1f}" x2="{width - pad_r}" y2="{y:.1f}" '
            f'stroke="var(--viz-grid)" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{pad_l - 8}" y="{y + 4:.1f}" text-anchor="end" '
            f'font-size="11" fill="var(--viz-muted)">{v:.1f}</text>'
        )

    decade = math.floor(x_lo)
    while decade <= x_hi:
        v = 10**decade
        if v >= 10**x_lo:
            x = px(v)
            label = f"{int(v):,}" if v < 1e6 else f"{v:.0e}"
            parts.append(
                f'<text x="{x:.1f}" y="{height - pad_b + 16}" text-anchor="middle" '
                f'font-size="11" fill="var(--viz-muted)">{label}</text>'
            )
        decade += 1

    parts.append(
        f'<line x1="{pad_l}" y1="{height - pad_b}" x2="{width - pad_r}" '
        f'y2="{height - pad_b}" stroke="var(--viz-axis)" stroke-width="1"/>'
    )

    for cfg in CONFIG_ORDER:
        curve = curves.get(cfg)
        if not curve:
            continue
        pathd = []
        for b, v, _n in curve:
            if v is None:
                continue
            pathd.append(f"{'M' if not pathd else 'L'}{px(b):.1f},{py(v):.1f}")
        if not pathd:
            continue
        color = f"var(--viz-{CONFIG_SLOT[cfg]})"
        parts.append(
            f'<path d="{" ".join(pathd)}" fill="none" stroke="{color}" '
            f'stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>'
        )
        last = [(b, v) for b, v, _ in curve if v is not None][-1]
        parts.append(
            f'<circle cx="{px(last[0]):.1f}" cy="{py(last[1]):.1f}" r="4" '
            f'fill="{color}" stroke="var(--viz-surface)" stroke-width="2"/>'
        )

    parts.append(
        f'<text x="{(width) / 2:.0f}" y="{height - 4}" text-anchor="middle" '
        f'font-size="11" fill="var(--viz-ink2)">schedules explored (executions, log scale)</text>'
    )
    parts.append("</svg>")
    return "".join(parts)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

MARKER_LEGEND = (
    "`*` the tool found no bug in any run &nbsp;·&nbsp; "
    "`+` the bug count includes hangs &nbsp;·&nbsp; "
    "`-` the tool could not be run on this benchmark"
)


def cell_bugs(g: Group) -> str:
    if g.aborted:
        return "-"
    if not g.found_any:
        return "*"
    total = f"{g.n_found}/{g.k}"
    marker = "+" if g.includes_hangs else ""
    return f"{total}{marker}"


def write_per_run_csv(path: Path, runs: list[Run]) -> None:
    with path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(
            [
                "benchmark", "config", "repeat", "exit_code", "incomplete",
                "execs_done", "run_time_s", "corpus_count", "cycles_done", "starved",
                "saved_crashes", "saved_races", "saved_hangs", "unique_race_pairs",
                "time_to_first_bug_s", "execs_to_first_bug",
                "time_to_first_crash_s", "execs_to_first_crash",
                "time_to_first_race_s", "execs_to_first_race",
                "time_to_first_hang_s", "execs_to_first_hang",
            ]
        )
        for r in sorted(runs, key=lambda r: (r.benchmark, r.config, r.repeat)):
            w.writerow(
                [
                    r.benchmark, r.config, r.repeat, r.exit_code, int(r.incomplete),
                    int(r.execs), r.duration, int(r.corpus), int(r.cycles),
                    int(r.starved),
                    r.n_crashes, r.n_races, r.n_hangs, len(r.race_pairs),
                    r.t_first_bug if r.t_first_bug is not None else "",
                    int(r.e_first_bug) if r.e_first_bug is not None else "",
                    r.t_first_crash if r.t_first_crash is not None else "",
                    int(r.e_first_crash) if r.e_first_crash is not None else "",
                    r.t_first_race if r.t_first_race is not None else "",
                    int(r.e_first_race) if r.e_first_race is not None else "",
                    r.t_first_hang if r.t_first_hang is not None else "",
                    int(r.e_first_hang) if r.e_first_hang is not None else "",
                ]
            )


def write_summary_csv(path: Path, groups: dict[tuple[str, str], Group]) -> None:
    with path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(
            [
                "benchmark", "config", "runs_K", "runs_finding_bug", "detection_rate",
                "ttfb_min_s", "ttfb_max_s", "ttfb_mean_s", "ttfb_var_s2", "ttfb_stdev_s",
                "etfb_min", "etfb_max", "etfb_mean", "etfb_var", "etfb_stdev",
                "unique_race_pairs_union", "mean_saved_crashes", "mean_saved_races",
                "mean_saved_hangs", "mean_execs", "mean_corpus", "starved_runs",
                "includes_hangs",
            ]
        )
        for (bench, cfg) in sorted(groups):
            g = groups[(bench, cfg)]
            t, e = g.stat("t_first_bug"), g.stat("e_first_bug")
            w.writerow(
                [
                    bench, cfg, g.k, g.n_found,
                    f"{g.n_found / g.k:.3f}" if g.k else "",
                    *(f"{v:.3f}" if v is not None else ""
                      for v in (t.minimum, t.maximum, t.mean, t.variance, t.stdev)),
                    *(f"{v:.1f}" if v is not None else ""
                      for v in (e.minimum, e.maximum, e.mean, e.variance, e.stdev)),
                    len(g.unique_races),
                    f"{g.total_stat('n_crashes').mean:.2f}",
                    f"{g.total_stat('n_races').mean:.2f}",
                    f"{g.total_stat('n_hangs').mean:.2f}",
                    f"{g.total_stat('execs').mean:.0f}",
                    f"{g.total_stat('corpus').mean:.0f}",
                    g.n_starved,
                    int(g.includes_hangs),
                ]
            )


def write_cumulative_csv(
    path: Path, curves: dict[tuple[str, str], list[tuple[int, float | None, int]]]
) -> None:
    with path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["benchmark", "config", "schedules_explored", "mean_cumulative_bugs", "runs_reaching_bin"])
        for (bench, cfg) in sorted(curves):
            for b, v, n in curves[(bench, cfg)]:
                if v is None:
                    continue
                w.writerow([bench, cfg, b, f"{v:.3f}", n])


def collect_visualizations(root: Path, runs: list[Run]) -> tuple[Path | None, int]:
    """Gather every run's queue_visualizer.html into one browsable directory.

    Hardlinked rather than copied when the filesystem allows it: these files
    run to tens of megabytes each and a campaign has hundreds of runs, so a
    real copy would double the campaign's footprint for no benefit. The
    original stays in place under runs/<bench>/<config>/run-NN/out/default/.
    """
    outdir = root / "analysis" / "visualizations"
    outdir.mkdir(parents=True, exist_ok=True)
    n = 0

    for r in sorted(runs, key=lambda r: (r.benchmark, r.config, r.repeat)):
        src = r.run_dir / "out" / "default" / "queue_visualizer.html"
        if not src.is_file():
            continue
        dst = outdir / f"{r.benchmark}__{r.config}__run-{r.repeat:02d}.html"
        if dst.exists():
            dst.unlink()
        try:
            os.link(src, dst)
        except OSError:
            shutil.copy2(src, dst)
        n += 1

    if not n:
        return (None, 0)

    rows = []
    for r in sorted(runs, key=lambda r: (r.benchmark, r.config, r.repeat)):
        name = f"{r.benchmark}__{r.config}__run-{r.repeat:02d}.html"
        if not (outdir / name).is_file():
            continue
        tags = []
        if r.n_crashes:
            tags.append(f"{r.n_crashes} crash")
        if r.n_races:
            tags.append(f"{r.n_races} race")
        if r.n_hangs:
            tags.append(f"{r.n_hangs} hang")
        if r.starved:
            tags.append("starved")
        rows.append(
            f'<tr><td class="bench"><a href="{html.escape(name)}">{html.escape(r.benchmark)}</a></td>'
            f"<td>{html.escape(CONFIG_LABEL.get(r.config, r.config))}</td>"
            f"<td>{r.repeat}</td><td>{int(r.execs)}</td><td>{int(r.corpus)}</td>"
            f'<td>{html.escape(", ".join(tags)) or "<span class=none>-</span>"}</td></tr>'
        )

    (outdir / "index.html").write_text(f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Per-run queue visualizations</title>
<style>
body {{ margin:0; padding:32px 24px 64px; background:{LIGHT['plane']}; color:{LIGHT['ink']};
  font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif; }}
main {{ max-width:1000px; margin:0 auto; }}
h1 {{ font-size:24px; margin:0 0 4px; }}
p.sub {{ color:{LIGHT['ink2']}; margin:0 0 24px; }}
table {{ border-collapse:collapse; width:100%; font-size:13px; background:{LIGHT['surface']};
  border:1px solid {LIGHT['grid']}; border-radius:10px; font-variant-numeric:tabular-nums; }}
th,td {{ text-align:left; padding:8px 12px; border-bottom:1px solid {LIGHT['grid']}; }}
th {{ font-size:12px; text-transform:uppercase; letter-spacing:.04em; color:{LIGHT['ink2']}; }}
tbody tr:last-child td {{ border-bottom:none; }}
td.bench {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }}
a {{ color:{LIGHT['s1']}; }}
.none {{ color:{LIGHT['muted']}; }}
</style></head><body><main>
<h1>Per-run queue visualizations</h1>
<p class="sub">{n} runs &middot; one AFL queue visualization per run &middot;
<a href="../report.html">campaign report</a></p>
<table><thead><tr><th>benchmark</th><th>config</th><th>run</th><th>execs</th>
<th>corpus</th><th>findings</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table>
</main></body></html>
""")
    return (outdir, n)


def build_markdown(
    root: Path,
    groups: dict[tuple[str, str], Group],
    benches: dict[str, dict[str, str]],
) -> str:
    lines: list[str] = []
    lines.append("# AFL++ campaign results")
    lines.append("")
    lines.append(f"Results root: `{root}`")
    lines.append("")
    lines.append(MARKER_LEGEND)
    lines.append("")
    lines.append(
        "Time and exec statistics are over the runs that found a bug; the "
        "detection-rate column says how many of the K runs those were. "
        "`mean±sd [min, max]`."
    )
    lines.append("")

    lines.append(
        "A *starved* run never grew its corpus past the seed while still burning "
        "queue cycles, so it explored almost no schedules; a high starved count "
        "means the detection rate below is limited by mutation, not by the bug "
        "being hard to reach."
    )
    lines.append("")
    lines.append(
        "| benchmark | config | K | found | starved | time to first bug (s) | "
        "schedules to first bug | unique races | crashes/run | races/run | hangs/run |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|")

    all_benches = sorted(set(b for b, _ in groups) | set(benches))
    for bench in all_benches:
        present = [c for c in CONFIG_ORDER if (bench, c) in groups]
        present += sorted(
            c for (b, c) in groups if b == bench and c not in present
        )
        if not present:
            reason = benches.get(bench, {}).get("reason", "") or "not run"
            lines.append(
                f"| `{bench}` | - | - | - | - | - | - | - | - | - | - | <!-- {reason} -->"
            )
            continue
        for cfg in present:
            g = groups[(bench, cfg)]
            t, e = g.stat("t_first_bug"), g.stat("e_first_bug")
            marker = "+" if g.includes_hangs else ""
            lines.append(
                "| `{b}` | {c} | {k} | {f} | {sv} | {t} | {e} | {ur} | {cr} | {ra} | {hg} |".format(
                    b=bench,
                    c=CONFIG_LABEL.get(cfg, cfg),
                    k=g.k,
                    f=cell_bugs(g),
                    sv=g.n_starved or "",
                    t=t.fmt(precision=2),
                    e=e.fmt(precision=0),
                    ur=len(g.unique_races) or "*",
                    cr=f"{g.total_stat('n_crashes').mean:.1f}",
                    ra=f"{g.total_stat('n_races').mean:.1f}",
                    hg=f"{g.total_stat('n_hangs').mean:.1f}{marker}",
                )
            )

    unrunnable = {
        b: rec.get("reason", "") for b, rec in benches.items()
        if rec.get("status") != "ok"
    }
    for (b, _cfg), g in groups.items():
        if g.aborted and b not in unrunnable:
            unrunnable[b] = f"AFL aborted: {g.abort_reason}"
    if unrunnable:
        lines.append("")
        lines.append("## Benchmarks the tool could not be run on (`-`)")
        lines.append("")
        lines.append("| benchmark | reason |")
        lines.append("|---|---|")
        for b in sorted(unrunnable):
            lines.append(f"| `{b}` | {unrunnable[b]} |")

    lines.append("")
    return "\n".join(lines) + "\n"


def build_html(
    root: Path,
    groups: dict[tuple[str, str], Group],
    benches: dict[str, dict[str, str]],
    curves: dict[tuple[str, str], list[tuple[int, float | None, int]]],
    n_viz: int = 0,
) -> str:
    def tokens(d: dict[str, str]) -> str:
        return "".join(
            f"--viz-{k if k not in ('s1', 's2', 's3') else k}: {v};" for k, v in d.items()
        )

    css = f"""
:root {{ color-scheme: light; {tokens(LIGHT)} }}
@media (prefers-color-scheme: dark) {{
  :root:not([data-theme="light"]) {{ color-scheme: dark; {tokens(DARK)} }}
}}
:root[data-theme="dark"] {{ color-scheme: dark; {tokens(DARK)} }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; padding: 32px 24px 64px; background: var(--viz-plane);
  color: var(--viz-ink);
  font: 15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif; }}
main {{ max-width: 1100px; margin: 0 auto; }}
h1 {{ font-size: 26px; margin: 0 0 4px; letter-spacing: -0.01em; }}
h2 {{ font-size: 18px; margin: 40px 0 12px; }}
h3 {{ font-size: 15px; margin: 0 0 4px; font-weight: 600; }}
p.sub {{ color: var(--viz-ink2); margin: 0 0 24px; }}
.legend-note {{ color: var(--viz-ink2); font-size: 13px; margin: 0 0 20px; }}
.tablewrap {{ overflow-x: auto; background: var(--viz-surface);
  border: 1px solid var(--viz-grid); border-radius: 10px; }}
table {{ border-collapse: collapse; width: 100%; font-size: 13px;
  font-variant-numeric: tabular-nums; }}
th, td {{ text-align: left; padding: 9px 12px; white-space: nowrap;
  border-bottom: 1px solid var(--viz-grid); }}
th {{ color: var(--viz-ink2); font-weight: 600; font-size: 12px;
  text-transform: uppercase; letter-spacing: 0.04em; }}
tbody tr:last-child td {{ border-bottom: none; }}
td.bench {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
.none {{ color: var(--viz-muted); }}
.grid {{ display: grid; gap: 20px;
  grid-template-columns: repeat(auto-fill, minmax(330px, 1fr)); }}
.card {{ background: var(--viz-surface); border: 1px solid var(--viz-grid);
  border-radius: 10px; padding: 16px; }}
.card .cap {{ color: var(--viz-ink2); font-size: 12px; margin: 0 0 10px; }}
.key {{ display: flex; gap: 16px; flex-wrap: wrap; margin: 0 0 20px;
  font-size: 13px; color: var(--viz-ink2); }}
.key span {{ display: inline-flex; align-items: center; gap: 7px; }}
.key i {{ width: 14px; height: 3px; border-radius: 2px; display: inline-block; }}
"""

    def key_row() -> str:
        items = "".join(
            f'<span><i style="background:var(--viz-{CONFIG_SLOT[c]})"></i>'
            f"{html.escape(CONFIG_LABEL[c])}</span>"
            for c in CONFIG_ORDER
        )
        return f'<div class="key">{items}</div>'

    rows = []
    for (bench, cfg) in sorted(groups):
        g = groups[(bench, cfg)]
        t, e = g.stat("t_first_bug"), g.stat("e_first_bug")
        found = cell_bugs(g)
        found_cell = f'<span class="none">{found}</span>' if found == "*" else found
        n_uniq = len(g.unique_races)
        uniq_cell = str(n_uniq) if n_uniq else '<span class="none">*</span>'
        rows.append(
            "<tr>"
            f'<td class="bench">{html.escape(bench)}</td>'
            f"<td>{html.escape(CONFIG_LABEL.get(cfg, cfg))}</td>"
            f"<td>{g.k}</td>"
            f"<td>{found_cell}</td>"
            f"<td>{g.n_starved or ''}</td>"
            f"<td>{html.escape(t.fmt(precision=2))}</td>"
            f"<td>{html.escape(e.fmt(precision=0))}</td>"
            f"<td>{uniq_cell}</td>"
            f"<td>{g.total_stat('n_crashes').mean:.1f}</td>"
            f"<td>{g.total_stat('n_races').mean:.1f}</td>"
            f"<td>{g.total_stat('n_hangs').mean:.1f}{'+' if g.includes_hangs else ''}</td>"
            "</tr>"
        )

    unrunnable = {
        b: rec.get("reason", "") for b, rec in benches.items()
        if rec.get("status") != "ok"
    }
    for (b, _cfg), g in groups.items():
        if g.aborted and b not in unrunnable:
            unrunnable[b] = f"AFL aborted: {g.abort_reason}"
    unrunnable_rows = "".join(
        f'<tr><td class="bench">{html.escape(b)}</td>'
        f"<td>{html.escape(reason)}</td></tr>"
        for b, reason in sorted(unrunnable.items())
    )

    charts = []
    for bench in sorted(set(b for b, _ in curves)):
        per_cfg = {c: curves[(bench, c)] for (b, c) in curves if b == bench}
        svg = svg_cumulative(bench, per_cfg)
        if not svg:
            continue
        charts.append(
            f'<div class="card"><h3>{html.escape(bench)}</h3>'
            f'<p class="cap">mean cumulative bugs across K runs</p>{svg}</div>'
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AFL++ campaign results</title>
<style>{css}</style></head>
<body><main>
<h1>AFL++ campaign results</h1>
<p class="sub">{html.escape(str(root))}{
  f' &middot; <a href="visualizations/index.html">{n_viz} per-run queue visualizations</a>'
  if n_viz else ''}</p>
<p class="legend-note">
<b>*</b> the tool found no bug in any run &nbsp;·&nbsp;
<b>+</b> the bug count includes hangs &nbsp;·&nbsp;
<b>-</b> the tool could not be run on this benchmark.
Time and exec statistics cover the runs that found a bug; the <i>found</i>
column gives how many of the K runs those were. Format: mean±sd [min, max].
<br><b>starved</b> counts runs whose corpus never grew past the seed while still
burning queue cycles — those explored almost no schedules, so they cap the
detection rate for reasons unrelated to bug difficulty.
</p>

<h2>Per-benchmark summary</h2>
<div class="tablewrap"><table>
<thead><tr>
<th>benchmark</th><th>config</th><th>K</th><th>found</th><th>starved</th>
<th>time to first bug (s)</th><th>schedules to first bug</th>
<th>unique races</th><th>crashes/run</th><th>races/run</th><th>hangs/run</th>
</tr></thead>
<tbody>{"".join(rows)}</tbody>
</table></div>

<h2>Cumulative bugs vs schedules explored</h2>
{key_row()}
<div class="grid">{"".join(charts)}</div>

{'<h2>Not runnable</h2><div class="tablewrap"><table><thead><tr><th>benchmark</th><th>reason</th></tr></thead><tbody>' + unrunnable_rows + '</tbody></table></div>' if unrunnable_rows else ''}
</main></body></html>
"""


# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {os.path.basename(argv[0])} <results-root>", file=sys.stderr)
        return 2

    root = Path(argv[1]).resolve()
    if not root.is_dir():
        print(f"no such results root: {root}", file=sys.stderr)
        return 1

    runs, benches = load_campaign(root)
    if not runs:
        print(f"no runs found under {root}/runs", file=sys.stderr)
        return 1

    groups = group_runs(runs)

    max_execs = max((r.execs for r in runs), default=0.0)
    bins = log_bins(max_execs)
    curves = {key: cumulative_curve(g, bins) for key, g in groups.items()}

    out = root / "analysis"
    out.mkdir(exist_ok=True)

    write_per_run_csv(out / "per_run.csv", runs)
    write_summary_csv(out / "summary.csv", groups)
    write_cumulative_csv(out / "cumulative_bugs.csv", curves)
    vizdir, n_viz = collect_visualizations(root, runs)
    (out / "summary.md").write_text(build_markdown(root, groups, benches))
    (out / "report.html").write_text(build_html(root, groups, benches, curves, n_viz))

    print(f"{len(runs)} runs across {len(groups)} (benchmark, config) groups")
    print(f"wrote {out}/summary.md, summary.csv, per_run.csv, "
          f"cumulative_bugs.csv, report.html")
    if n_viz:
        print(f"collected {n_viz} per-run queue visualizations -> {vizdir}/index.html")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
