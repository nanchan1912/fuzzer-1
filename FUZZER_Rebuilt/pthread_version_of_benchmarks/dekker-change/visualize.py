#!/usr/bin/env python3
import argparse
import re
from collections import defaultdict

EVENT_RE = re.compile(r"^E\s+(\S+)\s+(\d+)\s+(\S+)\s*(\S*)\s*(\S*)")
CF_RE = re.compile(r"^CF\s+(\S+)\s+(\S+)")

def esc(s: str) -> str:
    return s.replace('"', r'\"')

def parse_pg(path):
    events = {}  # id -> dict(tid, kind, loc, mode)
    cf_edges = []  # (src, dst)

    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()

            if not line or line.startswith("#") or line.startswith("//"):
                continue

            m_e = EVENT_RE.match(line)
            if m_e:
                eid, tid, kind, loc, mode = m_e.groups()
                # Normalize optional fields
                loc = loc if loc else "-"
                mode = mode if mode else "-"
                # Fence lines may appear as: E e14 1 F SC
                # In that case loc captured as "SC" and mode empty -> fix:
                if kind == "F" and mode == "-":
                    mode = loc
                    loc = "-"
                events[eid] = {
                    "tid": int(tid),
                    "kind": kind,
                    "loc": loc,
                    "mode": mode,
                }
                continue

            m_cf = CF_RE.match(line)
            if m_cf:
                cf_edges.append((m_cf.group(1), m_cf.group(2)))
                continue

    return events, cf_edges

def write_dot(events, cf_edges, out_path):
    tids = sorted({ev["tid"] for ev in events.values()})
    by_tid = defaultdict(list)
    for eid, ev in events.items():
        by_tid[ev["tid"]].append(eid)

    def event_sort_key(eid):
        # sort by numeric suffix if present, else lexicographic
        m = re.search(r"(\d+)$", eid)
        return (int(m.group(1)) if m else 10**9, eid)

    for t in by_tid:
        by_tid[t].sort(key=event_sort_key)

    with open(out_path, "w", encoding="utf-8") as out:
        out.write("digraph ConcurrentCFG {\n")
        out.write('  graph [rankdir=LR, fontsize=12, labelloc="t", label="Concurrent Control Flow Graph"];\n')
        out.write('  node  [shape=box, style="rounded,filled", fillcolor="#f7fbff", color="#2b2b2b", fontname="Helvetica"];\n')
        out.write('  edge  [color="#666666", arrowsize=0.8];\n\n')

        # Thread clusters
        for tid in tids:
            out.write(f'  subgraph cluster_tid_{tid} {{\n')
            out.write(f'    label="Thread {tid}";\n')
            out.write('    color="#bdbdbd";\n')
            for eid in by_tid[tid]:
                ev = events[eid]
                label = f'{eid}\\nT{ev["tid"]} {ev["kind"]} {ev["loc"]} [{ev["mode"]}]'
                fill = "#fff7ec" if ev["kind"] == "F" else "#edf8fb"
                out.write(f'    {eid} [label="{esc(label)}", fillcolor="{fill}"];\n')
            out.write("  }\n\n")

        # Control-flow edges
        for src, dst in cf_edges:
            style = "solid"
            color = "#4d4d4d"
            if src in events and dst in events and events[src]["tid"] != events[dst]["tid"]:
                # Spawn/join-like cross-thread edge
                color = "#d62728"
                style = "dashed"
            out.write(f'  {src} -> {dst} [color="{color}", style="{style}"];\n')

        out.write("}\n")

def main():
    ap = argparse.ArgumentParser(description="Convert .pg concurrent CFG into Graphviz .dot")
    ap.add_argument("input_pg", help="Path to input .pg file")
    ap.add_argument("-o", "--output", default="concurrent_cfg.dot", help="Output .dot file path")
    args = ap.parse_args()

    events, cf_edges = parse_pg(args.input_pg)
    write_dot(events, cf_edges, args.output)
    print(f"Wrote DOT file: {args.output}")
    print("Render with: dot -Tpng concurrent_cfg.dot -o concurrent_cfg.png")

if __name__ == "__main__":
    main()