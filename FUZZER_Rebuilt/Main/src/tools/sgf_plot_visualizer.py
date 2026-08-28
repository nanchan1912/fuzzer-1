#!/usr/bin/env python3
"""SGF Plot Data Analyzer & Interactive Visualization Dashboard.

Parses SGF's `plot_data` (both standard and extended graph run details)
and generates a standalone interactive HTML dashboard featuring clear,
separate metrics and visualizations for:
1. Candidates Added to the Queue (Enqueued / Accepted)
2. Candidates Not Added to the Queue (Discarded / Cutoff)

Includes:
- Direct side-by-side comparative statistical tables (Mean, Variance, Std Dev, Quantiles, Deltas)
- Distinct time-series and rolling trends for Accepted vs Rejected
- Comparative distribution histograms for Potential, MO Footprint, and Combined Scores
- 2D Correlation scatter plots (Potential vs MO Score) with separate group statistics
- Quick-filter raw data explorer
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class SummaryStats:
    count: int = 0
    mean: float = 0.0
    variance: float = 0.0
    std_dev: float = 0.0
    min_val: float = 0.0
    q25: float = 0.0
    median: float = 0.0
    q75: float = 0.0
    max_val: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "count": self.count,
            "mean": round(self.mean, 4),
            "variance": round(self.variance, 4),
            "std_dev": round(self.std_dev, 4),
            "min": round(self.min_val, 4),
            "q25": round(self.q25, 4),
            "median": round(self.median, 4),
            "q75": round(self.q75, 4),
            "max": round(self.max_val, 4),
        }


def compute_stats(values: List[float]) -> SummaryStats:
    valid = [v for v in values if v is not None and not math.isnan(v) and not math.isinf(v)]
    if not valid:
        return SummaryStats()

    n = len(valid)
    mean_val = sum(valid) / n
    var_val = sum((x - mean_val) ** 2 for x in valid) / (n - 1) if n > 1 else 0.0
    std_val = math.sqrt(var_val)

    sorted_vals = sorted(valid)
    min_val = sorted_vals[0]
    max_val = sorted_vals[-1]

    def quantile(q: float) -> float:
        idx = q * (n - 1)
        low = int(math.floor(idx))
        high = int(math.ceil(idx))
        if low == high:
            return sorted_vals[low]
        return sorted_vals[low] + (sorted_vals[high] - sorted_vals[low]) * (idx - low)

    return SummaryStats(
        count=n,
        mean=mean_val,
        variance=var_val,
        std_dev=std_val,
        min_val=min_val,
        q25=quantile(0.25),
        median=quantile(0.50),
        q75=quantile(0.75),
        max_val=max_val,
    )


def compute_histogram(values: List[float], num_bins: int = 20, min_bound: Optional[float] = None, max_bound: Optional[float] = None) -> Dict[str, Any]:
    valid = [v for v in values if v is not None and not math.isnan(v) and not math.isinf(v)]
    if not valid:
        return {"bins": [], "counts": [], "labels": [], "centers": []}

    lo = min_bound if min_bound is not None else min(valid)
    hi = max_bound if max_bound is not None else max(valid)
    if lo == hi:
        hi = lo + 1.0

    bin_width = (hi - lo) / num_bins
    counts = [0] * num_bins
    bin_edges = [lo + i * bin_width for i in range(num_bins + 1)]

    for v in valid:
        if v < lo:
            counts[0] += 1
        elif v >= hi:
            counts[-1] += 1
        else:
            bin_idx = min(int((v - lo) / bin_width), num_bins - 1)
            counts[bin_idx] += 1

    labels = [f"{bin_edges[i]:.1f}-{bin_edges[i+1]:.1f}" for i in range(num_bins)]
    centers = [(bin_edges[i] + bin_edges[i+1]) / 2 for i in range(num_bins)]

    return {
        "counts": counts,
        "labels": labels,
        "centers": [round(c, 2) for c in centers],
        "bin_edges": [round(e, 2) for e in bin_edges],
    }


def compute_correlation(x: List[float], y: List[float]) -> float:
    if len(x) != len(y) or len(x) < 2:
        return 0.0
    pairs = [(a, b) for a, b in zip(x, y) if a is not None and b is not None and not math.isnan(a) and not math.isnan(b)]
    if len(pairs) < 2:
        return 0.0

    xs = [p[0] for p in pairs]
    ys = [p[1] for p in pairs]
    n = len(pairs)
    mx = sum(xs) / n
    my = sum(ys) / n

    cov = sum((a - mx) * (b - my) for a, b in pairs)
    var_x = sum((a - mx) ** 2 for a in xs)
    var_y = sum((b - my) ** 2 for b in ys)

    denom = math.sqrt(var_x * var_y)
    return cov / denom if denom > 1e-12 else 0.0


def parse_plot_data(file_path: Path) -> Dict[str, Any]:
    if not file_path.exists():
        raise FileNotFoundError(f"plot_data file not found at: {file_path}")

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    if not lines:
        raise ValueError(f"plot_data file {file_path} is empty")

    header_line = lines[0]
    headers = [col.strip().strip("#").strip() for col in header_line.split(",")]
    header_indices = {name: idx for idx, name in enumerate(headers)}

    has_graph_details = "candidate_score" in header_indices or "candidate_potential" in header_indices

    records: List[Dict[str, Any]] = []

    for line_idx, line in enumerate(lines[1:], start=2):
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < len(headers):
            parts.extend([""] * (len(headers) - len(parts)))

        rec: Dict[str, Any] = {}
        for h, val_str in zip(headers, parts):
            cleaned = val_str.replace("%", "").strip()
            try:
                if "." in cleaned or "e" in cleaned.lower():
                    rec[h] = float(cleaned)
                else:
                    rec[h] = int(cleaned) if cleaned != "" else 0
            except ValueError:
                rec[h] = val_str

        rec["_rel_time"] = float(rec.get("relative_time", 0))
        rec["_cycles"] = int(rec.get("cycles_done", 0))
        rec["_cur_item"] = int(rec.get("cur_item", 0))
        rec["_corpus_count"] = int(rec.get("corpus_count", 0))
        rec["_total_execs"] = int(rec.get("total_execs", 0))
        rec["_execs_per_sec"] = float(rec.get("execs_per_sec", 0.0))
        rec["_mo_coverage"] = int(rec.get("mo_coverage", 0))
        rec["_rf_coverage"] = int(rec.get("rf_coverage", 0))

        if has_graph_details:
            rec["_cur_item_score"] = float(rec.get("cur_item_score", 0.0))
            rec["_cur_item_potential"] = float(rec.get("cur_item_potential", 0.0))
            rec["_cur_item_mo"] = float(rec.get("cur_item_mo", 0.0))
            rec["_cur_item_children"] = int(rec.get("cur_item_children_enqueued", 0))
            rec["_cand_parent_id"] = int(rec.get("candidate_parent_id", 0))
            rec["_cand_potential"] = float(rec.get("candidate_potential", 0.0))
            rec["_cand_mo"] = float(rec.get("candidate_mo", 0.0))
            rec["_cand_score"] = float(rec.get("candidate_score", 0.0))
            rec["_cand_added"] = int(rec.get("candidate_added", 0))

        records.append(rec)

    max_chart_points = 2500
    if len(records) > max_chart_points:
        step = math.ceil(len(records) / max_chart_points)
        sampled_records = records[::step]
        if records and (not sampled_records or sampled_records[-1] != records[-1]):
            sampled_records.append(records[-1])
    else:
        sampled_records = records

    return {
        "headers": headers,
        "has_graph_details": has_graph_details,
        "total_records": len(records),
        "records": records,
        "sampled_records": sampled_records,
    }


def analyze_plot_data(parsed: Dict[str, Any]) -> Dict[str, Any]:
    records = parsed["records"]
    sampled = parsed["sampled_records"]
    has_graph_details = parsed["has_graph_details"]

    if not records:
        return {}

    time_series = {
        "rel_time": [r["_rel_time"] for r in sampled],
        "cycles": [r["_cycles"] for r in sampled],
        "corpus_count": [r["_corpus_count"] for r in sampled],
        "total_execs": [r["_total_execs"] for r in sampled],
        "execs_per_sec": [r["_execs_per_sec"] for r in sampled],
        "mo_coverage": [r["_mo_coverage"] for r in sampled],
        "rf_coverage": [r["_rf_coverage"] for r in sampled],
    }

    stats_dict: Dict[str, Any] = {
        "mo_coverage": compute_stats([r["_mo_coverage"] for r in records]).to_dict(),
        "rf_coverage": compute_stats([r["_rf_coverage"] for r in records]).to_dict(),
        "execs_per_sec": compute_stats([r["_execs_per_sec"] for r in records]).to_dict(),
        "corpus_count": compute_stats([r["_corpus_count"] for r in records]).to_dict(),
    }

    histograms: Dict[str, Any] = {
        "execs_per_sec": compute_histogram([r["_execs_per_sec"] for r in records], 15),
    }

    rolling_acc_rates = []
    window_size = 50
    accepted_window = []

    graph_stats: Dict[str, Any] = {}
    scatter_points = []
    parent_child_points = []
    comparison_table: List[Dict[str, Any]] = []

    if has_graph_details:
        cand_records = [r for r in records if r.get("_cand_score", 0.0) > 0 or r.get("_cand_potential", 0.0) > 0 or r.get("_cand_mo", 0.0) > 0]
        if not cand_records:
            cand_records = records

        accepted_cands = [r for r in cand_records if r.get("_cand_added", 0) == 1]
        rejected_cands = [r for r in cand_records if r.get("_cand_added", 0) == 0]

        total_cands = len(cand_records)
        total_accepted = len(accepted_cands)
        total_rejected = len(rejected_cands)
        acceptance_rate = (total_accepted / total_cands * 100) if total_cands > 0 else 0.0

        all_pot = [r["_cand_potential"] for r in cand_records]
        all_mo = [r["_cand_mo"] for r in cand_records]
        all_score = [r["_cand_score"] for r in cand_records]

        acc_pot = [r["_cand_potential"] for r in accepted_cands]
        acc_mo = [r["_cand_mo"] for r in accepted_cands]
        acc_score = [r["_cand_score"] for r in accepted_cands]

        rej_pot = [r["_cand_potential"] for r in rejected_cands]
        rej_mo = [r["_cand_mo"] for r in rejected_cands]
        rej_score = [r["_cand_score"] for r in rejected_cands]

        cur_scores = [r["_cur_item_score"] for r in records if r.get("_cur_item_score", 0.0) > 0]
        cur_pots = [r["_cur_item_potential"] for r in records if r.get("_cur_item_potential", 0.0) > 0]
        cur_mos = [r["_cur_item_mo"] for r in records if r.get("_cur_item_mo", 0.0) > 0]
        cur_children = [r["_cur_item_children"] for r in records]

        # Detailed stats per subset
        st_cand_score_all = compute_stats(all_score)
        st_cand_score_acc = compute_stats(acc_score)
        st_cand_score_rej = compute_stats(rej_score)

        st_cand_pot_all = compute_stats(all_pot)
        st_cand_pot_acc = compute_stats(acc_pot)
        st_cand_pot_rej = compute_stats(rej_pot)

        st_cand_mo_all = compute_stats(all_mo)
        st_cand_mo_acc = compute_stats(acc_mo)
        st_cand_mo_rej = compute_stats(rej_mo)

        st_picked_score = compute_stats(cur_scores)
        st_picked_pot = compute_stats(cur_pots)
        st_picked_mo = compute_stats(cur_mos)
        st_picked_children = compute_stats(cur_children)

        stats_dict["candidate_score_all"] = st_cand_score_all.to_dict()
        stats_dict["candidate_score_accepted"] = st_cand_score_acc.to_dict()
        stats_dict["candidate_score_rejected"] = st_cand_score_rej.to_dict()

        stats_dict["candidate_potential_all"] = st_cand_pot_all.to_dict()
        stats_dict["candidate_potential_accepted"] = st_cand_pot_acc.to_dict()
        stats_dict["candidate_potential_rejected"] = st_cand_pot_rej.to_dict()

        stats_dict["candidate_mo_all"] = st_cand_mo_all.to_dict()
        stats_dict["candidate_mo_accepted"] = st_cand_mo_acc.to_dict()
        stats_dict["candidate_mo_rejected"] = st_cand_mo_rej.to_dict()

        stats_dict["picked_item_score"] = st_picked_score.to_dict()
        stats_dict["picked_item_potential"] = st_picked_pot.to_dict()
        stats_dict["picked_item_mo"] = st_picked_mo.to_dict()
        stats_dict["picked_item_children"] = st_picked_children.to_dict()

        # Build Direct Comparative Table
        def make_comp_row(metric_name: str, st_all: SummaryStats, st_acc: SummaryStats, st_rej: SummaryStats) -> Dict[str, Any]:
            mean_delta = st_acc.mean - st_rej.mean if st_acc.count > 0 and st_rej.count > 0 else 0.0
            med_delta = st_acc.median - st_rej.median if st_acc.count > 0 and st_rej.count > 0 else 0.0
            return {
                "metric": metric_name,
                "all": st_all.to_dict(),
                "accepted": st_acc.to_dict(),
                "rejected": st_rej.to_dict(),
                "mean_delta": round(mean_delta, 4),
                "median_delta": round(med_delta, 4),
            }

        comparison_table = [
            make_comp_row("Candidate Combined Score", st_cand_score_all, st_cand_score_acc, st_cand_score_rej),
            make_comp_row("Candidate Potential Score", st_cand_pot_all, st_cand_pot_acc, st_cand_pot_rej),
            make_comp_row("Candidate MO Footprint Score", st_cand_mo_all, st_cand_mo_acc, st_cand_mo_rej),
        ]

        # Common bin edges for overlaid histograms
        histograms["candidate_score_accepted"] = compute_histogram(acc_score, 20, 0, 100)
        histograms["candidate_score_rejected"] = compute_histogram(rej_score, 20, 0, 100)
        histograms["candidate_score_all"] = compute_histogram(all_score, 20, 0, 100)

        histograms["candidate_potential_accepted"] = compute_histogram(acc_pot, 20, 0, 100)
        histograms["candidate_potential_rejected"] = compute_histogram(rej_pot, 20, 0, 100)

        histograms["candidate_mo_accepted"] = compute_histogram(acc_mo, 20, 0, 100)
        histograms["candidate_mo_rejected"] = compute_histogram(rej_mo, 20, 0, 100)

        histograms["picked_item_score"] = compute_histogram(cur_scores, 20, 0, 100)
        histograms["picked_item_children"] = compute_histogram(cur_children, 15)

        # Correlation between potential and MO score per group
        corr_pot_mo_all = compute_correlation(all_pot, all_mo)
        corr_pot_mo_acc = compute_correlation(acc_pot, acc_mo)
        corr_pot_mo_rej = compute_correlation(rej_pot, rej_mo)

        # Separate time series for accepted vs rejected
        time_series["cand_score_accepted"] = [r["_cand_score"] if r.get("_cand_added", 0) == 1 else None for r in sampled]
        time_series["cand_score_rejected"] = [r["_cand_score"] if r.get("_cand_added", 0) == 0 else None for r in sampled]

        time_series["cand_pot_accepted"] = [r["_cand_potential"] if r.get("_cand_added", 0) == 1 else None for r in sampled]
        time_series["cand_pot_rejected"] = [r["_cand_potential"] if r.get("_cand_added", 0) == 0 else None for r in sampled]

        time_series["cand_mo_accepted"] = [r["_cand_mo"] if r.get("_cand_added", 0) == 1 else None for r in sampled]
        time_series["cand_mo_rejected"] = [r["_cand_mo"] if r.get("_cand_added", 0) == 0 else None for r in sampled]

        time_series["cand_score"] = [r.get("_cand_score", 0.0) for r in sampled]
        time_series["cand_potential"] = [r.get("_cand_potential", 0.0) for r in sampled]
        time_series["cand_mo"] = [r.get("_cand_mo", 0.0) for r in sampled]
        time_series["cand_added"] = [r.get("_cand_added", 0) for r in sampled]
        time_series["cur_item_score"] = [r.get("_cur_item_score", 0.0) for r in sampled]
        time_series["cur_item_potential"] = [r.get("_cur_item_potential", 0.0) for r in sampled]
        time_series["cur_item_mo"] = [r.get("_cur_item_mo", 0.0) for r in sampled]
        time_series["cur_item_children"] = [r.get("_cur_item_children", 0) for r in sampled]

        # Rolling acceptance rate
        for r in sampled:
            added = r.get("_cand_added", 0)
            accepted_window.append(added)
            if len(accepted_window) > window_size:
                accepted_window.pop(0)
            rate = (sum(accepted_window) / len(accepted_window) * 100) if accepted_window else 0.0
            rolling_acc_rates.append(round(rate, 2))

        time_series["rolling_acc_rate"] = rolling_acc_rates

        scatter_sample = cand_records if len(cand_records) <= 1200 else cand_records[::max(1, len(cand_records) // 1200)]
        for r in scatter_sample:
            scatter_points.append({
                "x": round(r["_cand_potential"], 2),
                "y": round(r["_cand_mo"], 2),
                "score": round(r["_cand_score"], 2),
                "added": r["_cand_added"],
                "parent_id": r.get("_cand_parent_id", 0),
                "time": round(r["_rel_time"], 1),
            })
            if r.get("_cur_item_score", 0.0) > 0:
                parent_child_points.append({
                    "x": round(r["_cur_item_score"], 2),
                    "y": round(r["_cand_score"], 2),
                    "added": r["_cand_added"],
                    "parent_id": r.get("_cand_parent_id", 0),
                })

        graph_stats = {
            "total_candidates": total_cands,
            "total_accepted": total_accepted,
            "total_rejected": total_rejected,
            "acceptance_rate": round(acceptance_rate, 2),
            "pot_mo_corr_all": round(corr_pot_mo_all, 4),
            "pot_mo_corr_accepted": round(corr_pot_mo_acc, 4),
            "pot_mo_corr_rejected": round(corr_pot_mo_rej, 4),
            "accepted_mean_score": round(st_cand_score_acc.mean, 2),
            "rejected_mean_score": round(st_cand_score_rej.mean, 2),
            "accepted_mean_pot": round(st_cand_pot_acc.mean, 2),
            "rejected_mean_pot": round(st_cand_pot_rej.mean, 2),
            "accepted_mean_mo": round(st_cand_mo_acc.mean, 2),
            "rejected_mean_mo": round(st_cand_mo_rej.mean, 2),
        }

    last_rec = records[-1]
    overview = {
        "total_runtime_sec": int(last_rec["_rel_time"]),
        "total_cycles": int(last_rec["_cycles"]),
        "final_corpus_count": int(last_rec["_corpus_count"]),
        "total_execs": int(last_rec["_total_execs"]),
        "final_mo_coverage": int(last_rec["_mo_coverage"]),
        "final_rf_coverage": int(last_rec["_rf_coverage"]),
        "total_crashes": int(last_rec.get("total_crashes", 0)),
        "avg_execs_per_sec": stats_dict["execs_per_sec"]["mean"],
    }

    parent_counts: Dict[int, int] = {}
    for r in records:
        pid = r.get("_cand_parent_id", 0)
        if r.get("_cand_added", 0) == 1 and pid > 0:
            parent_counts[pid] = parent_counts.get(pid, 0) + 1

    top_parents = sorted([{"id": pid, "children": cnt} for pid, cnt in parent_counts.items()], key=lambda x: x["children"], reverse=True)[:10]

    explorer_rows = []
    step_exp = max(1, len(records) // 500)
    for r in records[::step_exp]:
        row_dict = {
            "time": int(r["_rel_time"]),
            "cycles": r["_cycles"],
            "cur_item": r["_cur_item"],
            "corpus": r["_corpus_count"],
            "execs": r["_total_execs"],
            "mo_cov": r["_mo_coverage"],
            "rf_cov": r["_rf_coverage"],
        }
        if has_graph_details:
            row_dict.update({
                "cur_score": round(r.get("_cur_item_score", 0.0), 2),
                "cur_pot": round(r.get("_cur_item_potential", 0.0), 2),
                "cur_mo": round(r.get("_cur_item_mo", 0.0), 2),
                "cur_children": r.get("_cur_item_children", 0),
                "cand_parent": r.get("_cand_parent_id", 0),
                "cand_pot": round(r.get("_cand_potential", 0.0), 2),
                "cand_mo": round(r.get("_cand_mo", 0.0), 2),
                "cand_score": round(r.get("_cand_score", 0.0), 2),
                "added": r.get("_cand_added", 0),
            })
        explorer_rows.append(row_dict)

    return {
        "has_graph_details": has_graph_details,
        "overview": overview,
        "graph_stats": graph_stats,
        "comparison_table": comparison_table,
        "stats_table": stats_dict,
        "time_series": time_series,
        "histograms": histograms,
        "scatter_points": scatter_points,
        "parent_child_points": parent_child_points,
        "top_parents": top_parents,
        "explorer_rows": explorer_rows,
    }


def render_html_dashboard(data: Dict[str, Any], title: str = "SGF Graph Run Details & Plot Analysis") -> str:
    data_json = json.dumps(data, separators=(",", ":"))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
  <style>
    :root {{
      --bg: #0f172a;
      --card-bg: #1e293b;
      --card-border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --primary: #38bdf8;
      --primary-glow: rgba(56, 189, 248, 0.15);
      --success: #34d399;
      --success-glow: rgba(52, 211, 153, 0.15);
      --warning: #fbbf24;
      --danger: #f87171;
      --danger-glow: rgba(248, 113, 113, 0.15);
      --purple: #c084fc;
      --pink: #f472b6;
      --indigo: #818cf8;
      --accent: #06b6d4;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Inter', system-ui, -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      padding: 24px;
      line-height: 1.5;
    }}
    .header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--card-border);
    }}
    .header h1 {{
      font-size: 24px;
      font-weight: 800;
      letter-spacing: -0.025em;
      background: linear-gradient(135deg, #38bdf8, #818cf8);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }}
    .header .meta {{
      font-size: 13px;
      color: var(--text-muted);
      font-family: 'JetBrains Mono', monospace;
    }}
    .badge {{
      display: inline-block;
      padding: 3px 8px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      background: var(--card-border);
      color: var(--primary);
    }}
    .badge.success {{ background: var(--success-glow); color: var(--success); }}
    .badge.danger {{ background: var(--danger-glow); color: var(--danger); }}

    /* Comparison Hero Banner */
    .comparison-hero {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}
    .comp-card {{
      background: var(--card-bg);
      border-radius: 12px;
      padding: 18px;
      position: relative;
      border: 2px solid var(--card-border);
    }}
    .comp-card.accepted {{
      border-color: rgba(52, 211, 153, 0.4);
      background: linear-gradient(180deg, rgba(52, 211, 153, 0.05), var(--card-bg));
    }}
    .comp-card.rejected {{
      border-color: rgba(248, 113, 113, 0.4);
      background: linear-gradient(180deg, rgba(248, 113, 113, 0.05), var(--card-bg));
    }}
    .comp-card .header-tag {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
    }}
    .comp-card .tag-title {{
      font-size: 15px;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .comp-card.accepted .tag-title {{ color: var(--success); }}
    .comp-card.rejected .tag-title {{ color: var(--danger); }}

    .comp-metrics-grid {{
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 12px;
    }}
    .comp-metric {{
      background: rgba(15, 23, 42, 0.5);
      border-radius: 8px;
      padding: 10px;
      text-align: center;
    }}
    .comp-metric .m-label {{
      font-size: 11px;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      margin-bottom: 4px;
    }}
    .comp-metric .m-val {{
      font-size: 18px;
      font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
    }}
    .comp-metric .m-sub {{
      font-size: 11px;
      color: var(--text-muted);
      font-family: 'JetBrains Mono', monospace;
    }}

    /* Metric Cards Grid */
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}
    .kpi-card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 16px;
      transition: transform 0.15s ease, border-color 0.15s ease;
    }}
    .kpi-card:hover {{
      transform: translateY(-2px);
      border-color: var(--primary);
    }}
    .kpi-card .label {{
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-bottom: 6px;
    }}
    .kpi-card .value {{
      font-size: 24px;
      font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
      color: var(--text);
    }}
    .kpi-card .sub {{
      font-size: 12px;
      color: var(--text-muted);
      margin-top: 4px;
    }}

    /* Tab Navigation */
    .nav-tabs {{
      display: flex;
      gap: 8px;
      border-bottom: 1px solid var(--card-border);
      margin-bottom: 24px;
    }}
    .tab-btn {{
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-family: inherit;
      font-size: 14px;
      font-weight: 600;
      padding: 10px 18px;
      border-bottom: 2px solid transparent;
      cursor: pointer;
      transition: all 0.15s ease;
    }}
    .tab-btn:hover {{
      color: var(--text);
    }}
    .tab-btn.active {{
      color: var(--primary);
      border-bottom-color: var(--primary);
    }}

    .tab-content {{
      display: none;
    }}
    .tab-content.active {{
      display: block;
    }}

    /* Grid Layout for Charts */
    .charts-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(480px, 1fr));
      gap: 20px;
      margin-bottom: 24px;
    }}
    .chart-box {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 18px;
      position: relative;
    }}
    .chart-box .title {{
      font-size: 15px;
      font-weight: 600;
      margin-bottom: 14px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}
    .chart-canvas-container {{
      position: relative;
      width: 100%;
      height: 320px;
    }}

    /* Tables */
    .table-container {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      overflow: hidden;
      margin-bottom: 24px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      text-align: left;
    }}
    th {{
      background: #172033;
      color: var(--text-muted);
      font-weight: 600;
      padding: 12px 14px;
      border-bottom: 1px solid var(--card-border);
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
    }}
    td {{
      padding: 10px 14px;
      border-bottom: 1px solid rgba(51, 65, 85, 0.5);
      font-family: 'JetBrains Mono', monospace;
    }}
    tr:last-child td {{
      border-bottom: none;
    }}
    tr:hover td {{
      background: rgba(56, 189, 248, 0.04);
    }}

    .controls-bar {{
      display: flex;
      gap: 12px;
      margin-bottom: 16px;
      align-items: center;
    }}
    .search-input {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      color: var(--text);
      padding: 8px 12px;
      border-radius: 8px;
      font-family: inherit;
      font-size: 13px;
      width: 260px;
    }}
    .search-input:focus {{
      outline: none;
      border-color: var(--primary);
    }}
    .filter-select {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      color: var(--text);
      padding: 8px 12px;
      border-radius: 8px;
      font-family: inherit;
      font-size: 13px;
      cursor: pointer;
    }}

    .pill {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 9999px;
      font-size: 11px;
      font-weight: 600;
    }}
    .pill.accepted {{ background: var(--success-glow); color: var(--success); }}
    .pill.rejected {{ background: var(--danger-glow); color: var(--danger); }}

    @media (max-width: 768px) {{
      .charts-grid {{ grid-template-columns: 1fr; }}
      .comp-metrics-grid {{ grid-template-columns: 1fr; }}
      body {{ padding: 12px; }}
    }}
  </style>
</head>
<body>
  <div class="header">
    <div>
      <h1>{title}</h1>
      <div class="meta" id="headerMeta">Loading dataset...</div>
    </div>
    <div>
      <span class="badge success" id="flagBadge">SGF_LOG_GRAPH_RUN_DETAILS: Active</span>
    </div>
  </div>

  <!-- Distinct Comparative Cards (Added to Queue vs Not Added) -->
  <div class="comparison-hero" id="comparisonHero" style="display: none;">
    <!-- Accepted Candidates -->
    <div class="comp-card accepted">
      <div class="header-tag">
        <span class="tag-title">
          <span>🟢 Added to Queue (Enqueued)</span>
        </span>
        <span class="badge success" id="accCountBadge">0 items (0%)</span>
      </div>
      <div class="comp-metrics-grid">
        <div class="comp-metric">
          <div class="m-label">Mean Score</div>
          <div class="m-val" style="color: var(--success);" id="accScoreMean">-</div>
          <div class="m-sub" id="accScoreStd">Std: -</div>
        </div>
        <div class="comp-metric">
          <div class="m-label">Mean Potential</div>
          <div class="m-val" style="color: var(--indigo);" id="accPotMean">-</div>
          <div class="m-sub" id="accPotStd">Std: -</div>
        </div>
        <div class="comp-metric">
          <div class="m-label">Mean MO Score</div>
          <div class="m-val" style="color: var(--warning);" id="accMoMean">-</div>
          <div class="m-sub" id="accMoStd">Std: -</div>
        </div>
      </div>
      <div style="margin-top: 10px; font-size: 12px; color: var(--text-muted); font-family: 'JetBrains Mono', monospace;" id="accCorrText">
        Pearson Correlation (Potential vs MO): -
      </div>
    </div>

    <!-- Rejected Candidates -->
    <div class="comp-card rejected">
      <div class="header-tag">
        <span class="tag-title">
          <span>🔴 Not Added (Rejected / Discarded)</span>
        </span>
        <span class="badge danger" id="rejCountBadge">0 items (0%)</span>
      </div>
      <div class="comp-metrics-grid">
        <div class="comp-metric">
          <div class="m-label">Mean Score</div>
          <div class="m-val" style="color: var(--danger);" id="rejScoreMean">-</div>
          <div class="m-sub" id="rejScoreStd">Std: -</div>
        </div>
        <div class="comp-metric">
          <div class="m-label">Mean Potential</div>
          <div class="m-val" style="color: var(--indigo);" id="rejPotMean">-</div>
          <div class="m-sub" id="rejPotStd">Std: -</div>
        </div>
        <div class="comp-metric">
          <div class="m-label">Mean MO Score</div>
          <div class="m-val" style="color: var(--warning);" id="rejMoMean">-</div>
          <div class="m-sub" id="rejMoStd">Std: -</div>
        </div>
      </div>
      <div style="margin-top: 10px; font-size: 12px; color: var(--text-muted); font-family: 'JetBrains Mono', monospace;" id="rejCorrText">
        Pearson Correlation (Potential vs MO): -
      </div>
    </div>
  </div>

  <!-- KPI Overview Grid -->
  <div class="kpi-grid" id="kpiGrid"></div>

  <!-- Tabs Navigation -->
  <div class="nav-tabs">
    <button class="tab-btn active" onclick="switchTab('tab-comparison', this)">Added vs Not Added Metrics</button>
    <button class="tab-btn" onclick="switchTab('tab-trends', this)">Time-Series Trends</button>
    <button class="tab-btn" onclick="switchTab('tab-scores', this)">Score Distributions</button>
    <button class="tab-btn" onclick="switchTab('tab-correlations', this)">2D Correlations</button>
    <button class="tab-btn" onclick="switchTab('tab-stats', this)">All Statistics Table</button>
    <button class="tab-btn" onclick="switchTab('tab-explorer', this)">Raw Data Explorer</button>
  </div>

  <!-- Tab 0: Direct Comparison Table -->
  <div id="tab-comparison" class="tab-content active">
    <div class="table-container">
      <div style="padding: 14px 16px; font-weight: 700; border-bottom: 1px solid var(--card-border); display: flex; justify-content: space-between; align-items: center;">
        <span>Direct Comparison: Candidates Added to Queue vs Not Added</span>
        <span class="badge">Enqueued vs Discarded</span>
      </div>
      <table id="directCompTable">
        <thead>
          <tr>
            <th>Metric</th>
            <th>Subset</th>
            <th>Count</th>
            <th>Mean</th>
            <th>Variance</th>
            <th>Std Dev</th>
            <th>Min</th>
            <th>25% (Q1)</th>
            <th>Median</th>
            <th>75% (Q3)</th>
            <th>Max</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>

    <!-- Comparative Charts in Comparison Tab -->
    <div class="charts-grid">
      <div class="chart-box">
        <div class="title">
          <span>Candidate Combined Score: Added vs Not Added Over Time</span>
          <span class="badge">Green=Added, Red=Not Added</span>
        </div>
        <div class="chart-canvas-container">
          <canvas id="chartCompScoresTimeline"></canvas>
        </div>
      </div>

      <div class="chart-box">
        <div class="title">
          <span>Score Distribution Overlay: Added vs Not Added</span>
          <span class="badge">Histogram</span>
        </div>
        <div class="chart-canvas-container">
          <canvas id="chartCompScoreDist"></canvas>
        </div>
      </div>
    </div>
  </div>

  <!-- Tab 1: Time Series Trends -->
  <div id="tab-trends" class="tab-content">
    <div class="charts-grid">
      <div class="chart-box">
        <div class="title">
          <span>Coverage Progression Over Time</span>
          <span class="badge">MO & RF Coverage</span>
        </div>
        <div class="chart-canvas-container">
          <canvas id="chartCoverage"></canvas>
        </div>
      </div>

      <div class="chart-box">
        <div class="title">
          <span>Corpus Growth & Queue Cycles</span>
          <span class="badge">Items / Cycles</span>
        </div>
        <div class="chart-canvas-container">
          <canvas id="chartCorpus"></canvas>
        </div>
      </div>

      <div class="chart-box">
        <div class="title">
          <span>Candidate Potential: Added vs Not Added Over Time</span>
          <span class="badge">Potential Evolution</span>
        </div>
        <div class="chart-canvas-container">
          <canvas id="chartCompPotTimeline"></canvas>
        </div>
      </div>

      <div class="chart-box">
        <div class="title">
          <span>Candidate MO Score: Added vs Not Added Over Time</span>
          <span class="badge">MO Evolution</span>
        </div>
        <div class="chart-canvas-container">
          <canvas id="chartCompMoTimeline"></canvas>
        </div>
      </div>

      <div class="chart-box">
        <div class="title">
          <span>Fuzzing Throughput (Execs/sec)</span>
          <span class="badge">Speed</span>
        </div>
        <div class="chart-canvas-container">
          <canvas id="chartThroughput"></canvas>
        </div>
      </div>

      <div class="chart-box">
        <div class="title">
          <span>Rolling Mutation Acceptance Rate (%)</span>
          <span class="badge">Enqueued Ratio</span>
        </div>
        <div class="chart-canvas-container">
          <canvas id="chartAcceptanceRate"></canvas>
        </div>
      </div>
    </div>
  </div>

  <!-- Tab 2: Score Analysis & Distributions -->
  <div id="tab-scores" class="tab-content">
    <div class="charts-grid">
      <div class="chart-box">
        <div class="title">
          <span>Candidate Combined Score Distribution</span>
          <span class="badge">Added vs Not Added</span>
        </div>
        <div class="chart-canvas-container">
          <canvas id="chartScoreDist"></canvas>
        </div>
      </div>

      <div class="chart-box">
        <div class="title">
          <span>Candidate Potential Score Distribution</span>
          <span class="badge">Added vs Not Added</span>
        </div>
        <div class="chart-canvas-container">
          <canvas id="chartPotDist"></canvas>
        </div>
      </div>

      <div class="chart-box">
        <div class="title">
          <span>Candidate MO Footprint Score Distribution</span>
          <span class="badge">Added vs Not Added</span>
        </div>
        <div class="chart-canvas-container">
          <canvas id="chartMoDist"></canvas>
        </div>
      </div>

      <div class="chart-box">
        <div class="title">
          <span>Picked Queue Item Scores Evolution</span>
          <span class="badge">Selected Entry Scores</span>
        </div>
        <div class="chart-canvas-container">
          <canvas id="chartPickedScoresTimeline"></canvas>
        </div>
      </div>

      <div class="chart-box">
        <div class="title">
          <span>Children Enqueued per Picked Parent</span>
          <span class="badge">Distribution</span>
        </div>
        <div class="chart-canvas-container">
          <canvas id="chartChildrenDist"></canvas>
        </div>
      </div>
    </div>
  </div>

  <!-- Tab 3: Correlations & 2D Analysis -->
  <div id="tab-correlations" class="tab-content">
    <div class="charts-grid">
      <div class="chart-box">
        <div class="title">
          <span>Candidate Potential vs MO Score (2D Scatter)</span>
          <span class="badge">Green=Added to Queue, Red=Not Added</span>
        </div>
        <div class="chart-canvas-container" style="height: 380px;">
          <canvas id="chartScatterPotMo"></canvas>
        </div>
      </div>

      <div class="chart-box">
        <div class="title">
          <span>Parent Item Score vs Child Candidate Score</span>
          <span class="badge">Parent to Child Correlation</span>
        </div>
        <div class="chart-canvas-container" style="height: 380px;">
          <canvas id="chartScatterParentChild"></canvas>
        </div>
      </div>
    </div>

    <div class="table-container">
      <div style="padding: 14px 16px; font-weight: 700; border-bottom: 1px solid var(--card-border);">
        Top Parent Items by Children Successfully Enqueued
      </div>
      <table id="topParentsTable">
        <thead>
          <tr>
            <th>Rank</th>
            <th>Parent Queue ID</th>
            <th>Children Enqueued</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <!-- Tab 4: Statistical Summary -->
  <div id="tab-stats" class="tab-content">
    <div class="table-container">
      <div style="padding: 14px 16px; font-weight: 700; border-bottom: 1px solid var(--card-border);">
        Complete Metrics Statistical Summary (All Subsets)
      </div>
      <table id="statsSummaryTable">
        <thead>
          <tr>
            <th>Metric</th>
            <th>Count</th>
            <th>Mean</th>
            <th>Variance</th>
            <th>Std Dev</th>
            <th>Min</th>
            <th>25% (Q1)</th>
            <th>Median</th>
            <th>75% (Q3)</th>
            <th>Max</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <!-- Tab 5: Raw Data Explorer -->
  <div id="tab-explorer" class="tab-content">
    <div class="controls-bar">
      <input type="text" class="search-input" id="tableSearch" placeholder="Search by ID or value..." onkeyup="filterExplorerTable()">
      <select class="filter-select" id="filterStatus" onchange="filterExplorerTable()">
        <option value="all">All Candidates</option>
        <option value="accepted">Added to Queue Only (Accepted)</option>
        <option value="rejected">Not Added Only (Rejected)</option>
      </select>
    </div>
    <div class="table-container" style="max-height: 580px; overflow-y: auto;">
      <table id="explorerTable">
        <thead>
          <tr>
            <th>Time (s)</th>
            <th>Cycles</th>
            <th>Cur Item</th>
            <th>Cur Score</th>
            <th>Cur Pot</th>
            <th>Cur MO</th>
            <th>Cur Children</th>
            <th>Cand Parent</th>
            <th>Cand Pot</th>
            <th>Cand MO</th>
            <th>Cand Score</th>
            <th>Queue Status</th>
            <th>Corpus</th>
            <th>MO Cov</th>
            <th>RF Cov</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <script>
    const DATA = {data_json};

    function switchTab(tabId, btn) {{
      document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
      document.getElementById(tabId).classList.add('active');
      btn.classList.add('active');
    }}

    function renderComparisonHero() {{
      const gs = DATA.graph_stats || {{}};
      if (!DATA.has_graph_details) return;

      const hero = document.getElementById('comparisonHero');
      hero.style.display = 'grid';

      document.getElementById('accCountBadge').innerText =
        `${{gs.total_accepted || 0}} candidates (${{gs.acceptance_rate || 0}}%)`;
      document.getElementById('rejCountBadge').innerText =
        `${{gs.total_rejected || 0}} candidates (${{(100 - (gs.acceptance_rate || 0)).toFixed(2)}}%)`;

      document.getElementById('accScoreMean').innerText = (gs.accepted_mean_score || 0).toFixed(2);
      document.getElementById('accScoreStd').innerText = 'Std: ' + (DATA.stats_table?.candidate_score_accepted?.std_dev || 0).toFixed(2);

      document.getElementById('accPotMean').innerText = (gs.accepted_mean_pot || 0).toFixed(2);
      document.getElementById('accPotStd').innerText = 'Std: ' + (DATA.stats_table?.candidate_potential_accepted?.std_dev || 0).toFixed(2);

      document.getElementById('accMoMean').innerText = (gs.accepted_mean_mo || 0).toFixed(2);
      document.getElementById('accMoStd').innerText = 'Std: ' + (DATA.stats_table?.candidate_mo_accepted?.std_dev || 0).toFixed(2);

      document.getElementById('accCorrText').innerText =
        `Pearson Correlation (Potential vs MO): r = ${{gs.pot_mo_corr_accepted !== undefined ? gs.pot_mo_corr_accepted : '-'}}`;

      document.getElementById('rejScoreMean').innerText = (gs.rejected_mean_score || 0).toFixed(2);
      document.getElementById('rejScoreStd').innerText = 'Std: ' + (DATA.stats_table?.candidate_score_rejected?.std_dev || 0).toFixed(2);

      document.getElementById('rejPotMean').innerText = (gs.rejected_mean_pot || 0).toFixed(2);
      document.getElementById('rejPotStd').innerText = 'Std: ' + (DATA.stats_table?.candidate_potential_rejected?.std_dev || 0).toFixed(2);

      document.getElementById('rejMoMean').innerText = (gs.rejected_mean_mo || 0).toFixed(2);
      document.getElementById('rejMoStd').innerText = 'Std: ' + (DATA.stats_table?.candidate_mo_rejected?.std_dev || 0).toFixed(2);

      document.getElementById('rejCorrText').innerText =
        `Pearson Correlation (Potential vs MO): r = ${{gs.pot_mo_corr_rejected !== undefined ? gs.pot_mo_corr_rejected : '-'}}`;
    }}

    function renderKPIs() {{
      const ov = DATA.overview || {{}};
      const gs = DATA.graph_stats || {{}};
      const st = DATA.stats_table || {{}};

      const items = [
        {{ label: 'Total Runtime', value: (ov.total_runtime_sec || 0) + ' s', sub: ((ov.total_runtime_sec || 0)/60).toFixed(1) + ' mins' }},
        {{ label: 'Corpus Items', value: ov.final_corpus_count || 0, sub: (ov.total_cycles || 0) + ' cycles completed' }},
        {{ label: 'MO Coverage', value: ov.final_mo_coverage || 0, sub: 'Memory ordering edges' }},
        {{ label: 'RF Coverage', value: ov.final_rf_coverage || 0, sub: 'Read-from edges' }},
        {{ label: 'Total Executions', value: (ov.total_execs || 0).toLocaleString(), sub: (ov.avg_execs_per_sec || 0).toFixed(1) + ' execs/sec avg' }},
      ];

      if (DATA.has_graph_details) {{
        items.push({{ label: 'Candidates Evaluated', value: (gs.total_candidates || 0).toLocaleString(), sub: 'Mutated graphs tested' }});
        items.push({{ label: 'Candidates Enqueued', value: (gs.total_accepted || 0).toLocaleString(), sub: (gs.acceptance_rate || 0) + '% acceptance rate' }});
        items.push({{ label: 'Accepted Mean Score', value: (gs.accepted_mean_score || 0).toFixed(2), sub: 'Rejected Mean: ' + (gs.rejected_mean_score || 0).toFixed(2) }});
      }}

      const grid = document.getElementById('kpiGrid');
      grid.innerHTML = items.map(it => `
        <div class="kpi-card">
          <div class="label">${{it.label}}</div>
          <div class="value">${{it.value}}</div>
          <div class="sub">${{it.sub}}</div>
        </div>
      `).join('');

      document.getElementById('headerMeta').innerText =
        `Runtime: ${{ov.total_runtime_sec || 0}}s | Corpus: ${{ov.final_corpus_count || 0}} | MO Cov: ${{ov.final_mo_coverage || 0}} | RF Cov: ${{ov.final_rf_coverage || 0}}`;
    }}

    function renderDirectCompTable() {{
      const comp = DATA.comparison_table || [];
      const tbody = document.querySelector('#directCompTable tbody');
      if (!tbody) return;

      let html = '';
      comp.forEach(row => {{
        const m = row.metric;
        const acc = row.accepted;
        const rej = row.rejected;
        const all = row.all;

        html += `
          <tr style="background: rgba(52, 211, 153, 0.04);">
            <td rowspan="3" style="font-weight: 700; color: var(--text); vertical-align: middle; border-right: 1px solid var(--card-border);">${{m}}</td>
            <td style="color: var(--success); font-weight: 700;">🟢 Added to Queue</td>
            <td>${{acc.count}}</td>
            <td style="color: var(--success); font-weight: 700;">${{acc.mean}}</td>
            <td>${{acc.variance}}</td>
            <td>${{acc.std_dev}}</td>
            <td>${{acc.min}}</td>
            <td>${{acc.q25}}</td>
            <td style="color: var(--warning); font-weight: 700;">${{acc.median}}</td>
            <td>${{acc.q75}}</td>
            <td>${{acc.max}}</td>
          </tr>
          <tr style="background: rgba(248, 113, 113, 0.04);">
            <td style="color: var(--danger); font-weight: 700;">🔴 Not Added</td>
            <td>${{rej.count}}</td>
            <td style="color: var(--danger); font-weight: 700;">${{rej.mean}}</td>
            <td>${{rej.variance}}</td>
            <td>${{rej.std_dev}}</td>
            <td>${{rej.min}}</td>
            <td>${{rej.q25}}</td>
            <td style="color: var(--warning); font-weight: 700;">${{rej.median}}</td>
            <td>${{rej.q75}}</td>
            <td>${{rej.max}}</td>
          </tr>
          <tr style="border-bottom: 2px solid var(--card-border);">
            <td style="color: var(--text-muted); font-weight: 600;">⚪ All Candidates</td>
            <td>${{all.count}}</td>
            <td style="color: var(--primary); font-weight: 600;">${{all.mean}}</td>
            <td>${{all.variance}}</td>
            <td>${{all.std_dev}}</td>
            <td>${{all.min}}</td>
            <td>${{all.q25}}</td>
            <td style="color: var(--warning); font-weight: 600;">${{all.median}}</td>
            <td>${{all.q75}}</td>
            <td>${{all.max}}</td>
          </tr>
        `;
      }});

      tbody.innerHTML = html;
    }}

    function renderStatsTable() {{
      const st = DATA.stats_table || {{}};
      const tbody = document.querySelector('#statsSummaryTable tbody');
      if (!tbody) return;

      const metricLabels = {{
        'candidate_score_accepted': '🟢 Candidate Combined Score (Added to Queue)',
        'candidate_score_rejected': '🔴 Candidate Combined Score (Not Added)',
        'candidate_score_all': '⚪ Candidate Combined Score (All Candidates)',
        'candidate_potential_accepted': '🟢 Candidate Potential Score (Added to Queue)',
        'candidate_potential_rejected': '🔴 Candidate Potential Score (Not Added)',
        'candidate_potential_all': '⚪ Candidate Potential Score (All Candidates)',
        'candidate_mo_accepted': '🟢 Candidate MO Footprint Score (Added to Queue)',
        'candidate_mo_rejected': '🔴 Candidate MO Footprint Score (Not Added)',
        'candidate_mo_all': '⚪ Candidate MO Footprint Score (All Candidates)',
        'picked_item_score': '🔹 Picked Queue Item Combined Score',
        'picked_item_potential': '🔹 Picked Queue Item Potential Score',
        'picked_item_mo': '🔹 Picked Queue Item MO Footprint Score',
        'picked_item_children': '🔹 Children Enqueued per Picked Item',
        'mo_coverage': '📈 MO Coverage Progression',
        'rf_coverage': '📈 RF Coverage Progression',
        'execs_per_sec': '⚡ Fuzzing Speed (Execs/sec)',
        'corpus_count': '📦 Corpus Count Progression',
      }};

      tbody.innerHTML = Object.entries(st).map(([key, s]) => `
        <tr>
          <td style="font-weight: 600; color: var(--text);">${{metricLabels[key] || key}}</td>
          <td>${{s.count}}</td>
          <td style="color: var(--primary); font-weight: 600;">${{s.mean}}</td>
          <td>${{s.variance}}</td>
          <td>${{s.std_dev}}</td>
          <td>${{s.min}}</td>
          <td>${{s.q25}}</td>
          <td style="color: var(--warning); font-weight: 600;">${{s.median}}</td>
          <td>${{s.q75}}</td>
          <td>${{s.max}}</td>
        </tr>
      `).join('');
    }}

    function renderTopParentsTable() {{
      const list = DATA.top_parents || [];
      const tbody = document.querySelector('#topParentsTable tbody');
      if (!tbody) return;
      tbody.innerHTML = list.map((p, idx) => `
        <tr>
          <td>#${{idx + 1}}</td>
          <td style="color: var(--primary); font-weight: 600;">id:${{String(p.id).padStart(6, '0')}}</td>
          <td style="color: var(--success); font-weight: 600;">${{p.children}} mutations added</td>
        </tr>
      `).join('');
    }}

    function renderExplorerTable() {{
      const rows = DATA.explorer_rows || [];
      const tbody = document.querySelector('#explorerTable tbody');
      if (!tbody) return;

      tbody.innerHTML = rows.map(r => `
        <tr data-status="${{r.added === 1 ? 'accepted' : 'rejected'}}">
          <td>${{r.time}}s</td>
          <td>${{r.cycles}}</td>
          <td style="color: var(--primary);">id:${{String(r.cur_item).padStart(6, '0')}}</td>
          <td>${{r.cur_score ?? '-'}}</td>
          <td>${{r.cur_pot ?? '-'}}</td>
          <td>${{r.cur_mo ?? '-'}}</td>
          <td>${{r.cur_children ?? '-'}}</td>
          <td>${{r.cand_parent !== undefined ? 'id:' + String(r.cand_parent).padStart(6, '0') : '-'}}</td>
          <td>${{r.cand_pot ?? '-'}}</td>
          <td>${{r.cand_mo ?? '-'}}</td>
          <td style="font-weight: 600;">${{r.cand_score ?? '-'}}</td>
          <td><span class="pill ${{r.added === 1 ? 'accepted' : 'rejected'}}">${{r.added === 1 ? 'ADDED' : 'NOT ADDED'}}</span></td>
          <td>${{r.corpus}}</td>
          <td style="color: var(--success);">${{r.mo_cov}}</td>
          <td style="color: var(--purple);">${{r.rf_cov}}</td>
        </tr>
      `).join('');
    }}

    function filterExplorerTable() {{
      const search = document.getElementById('tableSearch').value.toLowerCase();
      const status = document.getElementById('filterStatus').value;
      const rows = document.querySelectorAll('#explorerTable tbody tr');

      rows.forEach(row => {{
        const text = row.innerText.toLowerCase();
        const rowStatus = row.getAttribute('data-status');
        const matchesSearch = !search || text.includes(search);
        const matchesStatus = status === 'all' || rowStatus === status;
        row.style.display = matchesSearch && matchesStatus ? '' : 'none';
      }});
    }}

    function initCharts() {{
      Chart.defaults.color = '#94a3b8';
      Chart.defaults.borderColor = 'rgba(51, 65, 85, 0.4)';
      Chart.defaults.font.family = "'Inter', sans-serif";

      const ts = DATA.time_series || {{}};
      const hist = DATA.histograms || {{}};

      // Tab 0 Charts: Comparison
      if (ts.cand_score_accepted) {{
        new Chart(document.getElementById('chartCompScoresTimeline'), {{
          type: 'line',
          data: {{
            labels: ts.rel_time,
            datasets: [
              {{ label: '🟢 Added to Queue Score', data: ts.cand_score_accepted, borderColor: '#34d399', backgroundColor: 'rgba(52, 211, 153, 0.7)', showLine: false, pointRadius: 2.5 }},
              {{ label: '🔴 Not Added Score', data: ts.cand_score_rejected, borderColor: '#f87171', backgroundColor: 'rgba(248, 113, 113, 0.5)', showLine: false, pointRadius: 2 }},
            ]
          }},
          options: {{
            responsive: true,
            maintainAspectRatio: false,
            scales: {{ x: {{ title: {{ display: true, text: 'Time (seconds)' }} }}, y: {{ title: {{ display: true, text: 'Score' }} }} }}
          }}
        }});
      }}

      if (hist.candidate_score_accepted && hist.candidate_score_rejected) {{
        new Chart(document.getElementById('chartCompScoreDist'), {{
          type: 'bar',
          data: {{
            labels: hist.candidate_score_accepted.labels,
            datasets: [
              {{ label: '🟢 Added to Queue', data: hist.candidate_score_accepted.counts, backgroundColor: 'rgba(52, 211, 153, 0.75)' }},
              {{ label: '🔴 Not Added', data: hist.candidate_score_rejected.counts, backgroundColor: 'rgba(248, 113, 113, 0.65)' }},
            ]
          }},
          options: {{
            responsive: true,
            maintainAspectRatio: false,
            scales: {{ x: {{ title: {{ display: true, text: 'Combined Score Bins' }} }}, y: {{ title: {{ display: true, text: 'Candidate Count' }} }} }}
          }}
        }});
      }}

      // Tab 1 Charts: Trends
      new Chart(document.getElementById('chartCoverage'), {{
        type: 'line',
        data: {{
          labels: ts.rel_time,
          datasets: [
            {{ label: 'MO Coverage', data: ts.mo_coverage, borderColor: '#34d399', backgroundColor: 'rgba(52, 211, 153, 0.1)', fill: true, tension: 0.2, pointRadius: 0 }},
            {{ label: 'RF Coverage', data: ts.rf_coverage, borderColor: '#c084fc', backgroundColor: 'rgba(192, 132, 252, 0.1)', fill: true, tension: 0.2, pointRadius: 0 }},
          ]
        }},
        options: {{
          responsive: true,
          maintainAspectRatio: false,
          plugins: {{ tooltip: {{ mode: 'index', intersect: false }} }},
          scales: {{ x: {{ title: {{ display: true, text: 'Time (seconds)' }} }}, y: {{ title: {{ display: true, text: 'Edge Count' }} }} }}
        }}
      }});

      new Chart(document.getElementById('chartCorpus'), {{
        type: 'line',
        data: {{
          labels: ts.rel_time,
          datasets: [
            {{ label: 'Corpus Count', data: ts.corpus_count, borderColor: '#38bdf8', yAxisID: 'y', tension: 0.2, pointRadius: 0 }},
            {{ label: 'Queue Cycles', data: ts.cycles, borderColor: '#fbbf24', borderDash: [4, 4], yAxisID: 'y1', tension: 0.2, pointRadius: 0 }},
          ]
        }},
        options: {{
          responsive: true,
          maintainAspectRatio: false,
          scales: {{
            x: {{ title: {{ display: true, text: 'Time (seconds)' }} }},
            y: {{ type: 'linear', position: 'left', title: {{ display: true, text: 'Corpus Count' }} }},
            y1: {{ type: 'linear', position: 'right', grid: {{ drawOnChartArea: false }}, title: {{ display: true, text: 'Cycles' }} }},
          }}
        }}
      }});

      if (ts.cand_pot_accepted) {{
        new Chart(document.getElementById('chartCompPotTimeline'), {{
          type: 'line',
          data: {{
            labels: ts.rel_time,
            datasets: [
              {{ label: '🟢 Added Potential', data: ts.cand_pot_accepted, borderColor: '#818cf8', backgroundColor: 'rgba(129, 140, 248, 0.8)', showLine: false, pointRadius: 2.5 }},
              {{ label: '🔴 Not Added Potential', data: ts.cand_pot_rejected, borderColor: '#f87171', backgroundColor: 'rgba(248, 113, 113, 0.5)', showLine: false, pointRadius: 2 }},
            ]
          }},
          options: {{
            responsive: true,
            maintainAspectRatio: false,
            scales: {{ x: {{ title: {{ display: true, text: 'Time (seconds)' }} }}, y: {{ title: {{ display: true, text: 'Potential Score' }} }} }}
          }}
        }});
      }}

      if (ts.cand_mo_accepted) {{
        new Chart(document.getElementById('chartCompMoTimeline'), {{
          type: 'line',
          data: {{
            labels: ts.rel_time,
            datasets: [
              {{ label: '🟢 Added MO Score', data: ts.cand_mo_accepted, borderColor: '#fbbf24', backgroundColor: 'rgba(251, 191, 36, 0.8)', showLine: false, pointRadius: 2.5 }},
              {{ label: '🔴 Not Added MO Score', data: ts.cand_mo_rejected, borderColor: '#f87171', backgroundColor: 'rgba(248, 113, 113, 0.5)', showLine: false, pointRadius: 2 }},
            ]
          }},
          options: {{
            responsive: true,
            maintainAspectRatio: false,
            scales: {{ x: {{ title: {{ display: true, text: 'Time (seconds)' }} }}, y: {{ title: {{ display: true, text: 'MO Score' }} }} }}
          }}
        }});
      }}

      new Chart(document.getElementById('chartThroughput'), {{
        type: 'line',
        data: {{
          labels: ts.rel_time,
          datasets: [
            {{ label: 'Execs / Sec', data: ts.execs_per_sec, borderColor: '#f472b6', backgroundColor: 'rgba(244, 114, 182, 0.1)', fill: true, tension: 0.2, pointRadius: 0 }}
          ]
        }},
        options: {{
          responsive: true,
          maintainAspectRatio: false,
          scales: {{ x: {{ title: {{ display: true, text: 'Time (seconds)' }} }}, y: {{ title: {{ display: true, text: 'Execs/sec' }} }} }}
        }}
      }});

      if (ts.rolling_acc_rate) {{
        new Chart(document.getElementById('chartAcceptanceRate'), {{
          type: 'line',
          data: {{
            labels: ts.rel_time,
            datasets: [
              {{ label: 'Acceptance Rate (%)', data: ts.rolling_acc_rate, borderColor: '#34d399', tension: 0.3, pointRadius: 0, fill: true, backgroundColor: 'rgba(52, 211, 153, 0.1)' }}
            ]
          }},
          options: {{
            responsive: true,
            maintainAspectRatio: false,
            scales: {{ x: {{ title: {{ display: true, text: 'Time (seconds)' }} }}, y: {{ min: 0, max: 100, title: {{ display: true, text: 'Enqueued % (50-window)' }} }} }}
          }}
        }});
      }}

      // Tab 2 Charts: Distributions
      if (hist.candidate_score_accepted && hist.candidate_score_rejected) {{
        new Chart(document.getElementById('chartScoreDist'), {{
          type: 'bar',
          data: {{
            labels: hist.candidate_score_accepted.labels,
            datasets: [
              {{ label: '🟢 Added to Queue', data: hist.candidate_score_accepted.counts, backgroundColor: 'rgba(52, 211, 153, 0.75)' }},
              {{ label: '🔴 Not Added', data: hist.candidate_score_rejected.counts, backgroundColor: 'rgba(248, 113, 113, 0.65)' }},
            ]
          }},
          options: {{
            responsive: true,
            maintainAspectRatio: false,
            scales: {{ x: {{ stacked: false, title: {{ display: true, text: 'Combined Score Bins' }} }}, y: {{ title: {{ display: true, text: 'Count' }} }} }}
          }}
        }});
      }}

      if (hist.candidate_potential_accepted && hist.candidate_potential_rejected) {{
        new Chart(document.getElementById('chartPotDist'), {{
          type: 'bar',
          data: {{
            labels: hist.candidate_potential_accepted.labels,
            datasets: [
              {{ label: '🟢 Added to Queue', data: hist.candidate_potential_accepted.counts, backgroundColor: 'rgba(129, 140, 248, 0.75)' }},
              {{ label: '🔴 Not Added', data: hist.candidate_potential_rejected.counts, backgroundColor: 'rgba(248, 113, 113, 0.55)' }},
            ]
          }},
          options: {{
            responsive: true,
            maintainAspectRatio: false,
            scales: {{ x: {{ stacked: false, title: {{ display: true, text: 'Potential Score Bins' }} }}, y: {{ title: {{ display: true, text: 'Count' }} }} }}
          }}
        }});
      }}

      if (hist.candidate_mo_accepted && hist.candidate_mo_rejected) {{
        new Chart(document.getElementById('chartMoDist'), {{
          type: 'bar',
          data: {{
            labels: hist.candidate_mo_accepted.labels,
            datasets: [
              {{ label: '🟢 Added to Queue', data: hist.candidate_mo_accepted.counts, backgroundColor: 'rgba(251, 191, 36, 0.75)' }},
              {{ label: '🔴 Not Added', data: hist.candidate_mo_rejected.counts, backgroundColor: 'rgba(248, 113, 113, 0.55)' }},
            ]
          }},
          options: {{
            responsive: true,
            maintainAspectRatio: false,
            scales: {{ x: {{ stacked: false, title: {{ display: true, text: 'MO Score Bins' }} }}, y: {{ title: {{ display: true, text: 'Count' }} }} }}
          }}
        }});
      }}

      if (ts.cur_item_score) {{
        new Chart(document.getElementById('chartPickedScoresTimeline'), {{
          type: 'line',
          data: {{
            labels: ts.rel_time,
            datasets: [
              {{ label: 'Picked Item Score', data: ts.cur_item_score, borderColor: '#34d399', tension: 0.2, pointRadius: 1 }},
              {{ label: 'Picked Potential', data: ts.cur_item_potential, borderColor: '#c084fc', borderDash: [2, 2], tension: 0.2, pointRadius: 0 }},
              {{ label: 'Picked MO Score', data: ts.cur_item_mo, borderColor: '#06b6d4', borderDash: [2, 2], tension: 0.2, pointRadius: 0 }},
            ]
          }},
          options: {{
            responsive: true,
            maintainAspectRatio: false,
            scales: {{ x: {{ title: {{ display: true, text: 'Time (seconds)' }} }}, y: {{ title: {{ display: true, text: 'Score' }} }} }}
          }}
        }});
      }}

      if (hist.picked_item_children) {{
        new Chart(document.getElementById('chartChildrenDist'), {{
          type: 'bar',
          data: {{
            labels: hist.picked_item_children.labels,
            datasets: [
              {{ label: 'Parent Items', data: hist.picked_item_children.counts, backgroundColor: 'rgba(56, 189, 248, 0.7)' }}
            ]
          }},
          options: {{
            responsive: true,
            maintainAspectRatio: false,
            scales: {{ x: {{ title: {{ display: true, text: 'Children Enqueued Count' }} }}, y: {{ title: {{ display: true, text: 'Parent Frequency' }} }} }}
          }}
        }});
      }}

      // Tab 3 Charts: Correlations
      const sc = DATA.scatter_points || [];
      if (sc.length > 0) {{
        const accPts = sc.filter(p => p.added === 1);
        const rejPts = sc.filter(p => p.added === 0);

        new Chart(document.getElementById('chartScatterPotMo'), {{
          type: 'scatter',
          data: {{
            datasets: [
              {{ label: '🟢 Added to Queue', data: accPts, backgroundColor: 'rgba(52, 211, 153, 0.8)', pointRadius: 3.5 }},
              {{ label: '🔴 Not Added', data: rejPts, backgroundColor: 'rgba(248, 113, 113, 0.5)', pointRadius: 2.5 }},
            ]
          }},
          options: {{
            responsive: true,
            maintainAspectRatio: false,
            plugins: {{
              tooltip: {{
                callbacks: {{
                  label: function(ctx) {{
                    const raw = ctx.raw;
                    return `Parent: id:${{String(raw.parent_id).padStart(6, '0')}} | Pot: ${{raw.x}} | MO: ${{raw.y}} | Score: ${{raw.score}} (${{raw.added ? 'Added' : 'Not Added'}})`;
                  }}
                }}
              }}
            }},
            scales: {{
              x: {{ title: {{ display: true, text: 'Candidate Potential Score' }}, min: 0, max: 100 }},
              y: {{ title: {{ display: true, text: 'Candidate MO Footprint Score' }}, min: 0, max: 100 }},
            }}
          }}
        }});
      }}

      const pc = DATA.parent_child_points || [];
      if (pc.length > 0) {{
        const accPc = pc.filter(p => p.added === 1);
        const rejPc = pc.filter(p => p.added === 0);

        new Chart(document.getElementById('chartScatterParentChild'), {{
          type: 'scatter',
          data: {{
            datasets: [
              {{ label: '🟢 Added Candidate', data: accPc, backgroundColor: 'rgba(52, 211, 153, 0.8)', pointRadius: 3.5 }},
              {{ label: '🔴 Not Added Candidate', data: rejPc, backgroundColor: 'rgba(248, 113, 113, 0.5)', pointRadius: 2.5 }},
            ]
          }},
          options: {{
            responsive: true,
            maintainAspectRatio: false,
            scales: {{
              x: {{ title: {{ display: true, text: 'Parent Item Score' }}, min: 0, max: 100 }},
              y: {{ title: {{ display: true, text: 'Candidate Child Score' }}, min: 0, max: 100 }},
            }}
          }}
        }});
      }}
    }}

    document.addEventListener('DOMContentLoaded', () => {{
      renderComparisonHero();
      renderKPIs();
      renderDirectCompTable();
      renderStatsTable();
      renderTopParentsTable();
      renderExplorerTable();
      initCharts();
    }});
  </script>
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze SGF plot_data with distinct Added vs Not Added metrics and generate interactive HTML dashboard")
    parser.add_argument("--plot-data", "-p", default="./out/default/plot_data", help="Path to plot_data file or directory containing it")
    parser.add_argument("--out", "-o", default="./out/default/plot_visualizer.html", help="Path for output HTML dashboard")
    parser.add_argument("--title", "-t", default="SGF Graph Run Details & Plot Analysis", help="Title for the dashboard")
    parser.add_argument("--json", action="store_true", help="Print summary JSON statistics to stdout")

    args = parser.parse_args()

    plot_path = Path(args.plot_data)
    if plot_path.is_dir():
        candidate = plot_path / "plot_data"
        if candidate.exists():
            plot_path = candidate
        else:
            default_sub = plot_path / "default" / "plot_data"
            if default_sub.exists():
                plot_path = default_sub

    if not plot_path.exists():
        print(f"[-] Error: Could not find plot_data at {plot_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Parsing plot_data from: {plot_path}")
    parsed = parse_plot_data(plot_path)
    print(f"[+] Loaded {parsed['total_records']} records (Graph Details: {'Enabled' if parsed['has_graph_details'] else 'Disabled'})")

    print("[*] Computing statistical summaries (Added vs Not Added)...")
    analysis = analyze_plot_data(parsed)

    if args.json:
        print(json.dumps(analysis, indent=2))

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[*] Generating interactive dashboard HTML: {out_path}")
    html_content = render_html_dashboard(analysis, title=args.title)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[+] Dashboard generated successfully at: {out_path.resolve()}")


if __name__ == "__main__":
    main()
