#!/usr/bin/env python3
"""Validate structural invariants of serialized skeleton graphs.

    ./check_graph_invariants.py <file.json | dir> [...]
    ./check_graph_invariants.py out/default/queue          # whole AFL queue

Every graph AFL hands to the simulator must satisfy these, or the run is
rejected with WMM_EXIT_INVALID_INPUT -- which the fuzzer reads as a merely
boring input, so a violated invariant shows up as "the campaign quietly stops
finding things" rather than as an error. This checker turns that silent class
of failure into a loud one.

Invariants:

  RF-1  every read-like event has exactly one incoming rf edge
  RF-2  every rf source is write-like
  RF-3  at most one rmw-like event reads from any given write (RMW atomicity)
  MO-1  every write-like event appears exactly once in its location's mo order
  MO-2  no read-only event appears in any mo order
  ID-1  every event referenced by an edge or order exists in nodes

Event-type classification mirrors is_read_like/is_write_like/is_rmw_like in
Main/include/skeleton_graph_events.hpp -- keep the two in sync.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Mirrors skeleton_graph_events.hpp. A CAS reads unconditionally but writes
# only when it succeeds.
READ_LIKE = {"R", "RMW", "CAS_SUCCESS", "CAS_FAIL"}
WRITE_LIKE = {"W", "RMW", "CAS_SUCCESS"}
RMW_LIKE = {"RMW", "CAS_SUCCESS"}
# Bare "CAS" means "outcome undecided". It is legitimate on the two input paths
# that cannot know the outcome (the .ccfg from static analysis, and runtime
# feedback), but a skeleton graph is a fuzzer output: by then add_new_node has
# resolved every CAS. So it is a violation here rather than an alias -- reading
# it as success is what previously hid the failure half of every CAS.
UNRESOLVED = "CAS"
KNOWN = READ_LIKE | WRITE_LIKE | {"F", "EOP"}


def triple(x) -> tuple:
    """Edge endpoints are [tid, iid, vid] lists; node ids are separate fields."""
    return (int(x[0]), int(x[1]), int(x[2]))


def node_id(n: dict) -> tuple:
    return (int(n["thread_id"]), int(n["instruction_id"]), int(n.get("visit_id", 1)))


def check_graph(path: Path) -> list[str]:
    errs: list[str] = []
    try:
        g = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        return [f"unreadable: {e}"]

    nodes = {}
    for n in g.get("nodes", []):
        try:
            kind = n.get("kind", "")
            if kind == UNRESOLVED:
                errs.append(f"unresolved CAS outcome on node {node_id(n)}: a "
                            f"skeleton graph must say CAS_SUCCESS or CAS_FAIL")
            elif kind not in KNOWN:
                errs.append(f"unknown kind {n.get('kind')!r} on node {node_id(n)}")
            nodes[node_id(n)] = kind
        except (KeyError, ValueError, TypeError) as e:
            errs.append(f"malformed node {n!r}: {e}")

    def known(nid, ctx) -> bool:
        if nid not in nodes:
            errs.append(f"ID-1 {ctx} references unknown event {nid}")
            return False
        return True

    # ---- rf ----------------------------------------------------------------
    rf_sources: dict[tuple, list[tuple]] = {}   # dst -> [src]
    rf_readers: dict[tuple, list[tuple]] = {}   # src -> [dst]
    for e in g.get("rf_edges", []):
        src = triple(e["from"])
        for dst_raw in e.get("to", []):
            dst = triple(dst_raw)
            if not known(src, "rf_edges.from") or not known(dst, "rf_edges.to"):
                continue
            rf_sources.setdefault(dst, []).append(src)
            rf_readers.setdefault(src, []).append(dst)
            if nodes[src] not in WRITE_LIKE:
                errs.append(
                    f"RF-2 rf source {src} has kind {nodes[src]}, which does not write"
                )

    for nid, kind in nodes.items():
        if kind in READ_LIKE:
            n_src = len(rf_sources.get(nid, []))
            if n_src == 0:
                errs.append(f"RF-1 {kind} event {nid} has no incoming rf edge")
            elif n_src > 1:
                errs.append(f"RF-1 {kind} event {nid} has {n_src} incoming rf edges")

    for src, readers in rf_readers.items():
        rmw_readers = [r for r in readers if nodes.get(r) in RMW_LIKE]
        if len(rmw_readers) > 1:
            errs.append(
                f"RF-3 write {src} is read by {len(rmw_readers)} rmw-like events "
                f"{rmw_readers}; at most one is allowed"
            )

    # ---- mo ----------------------------------------------------------------
    seen_in_mo: dict[tuple, int] = {}
    for entry in g.get("mo_per_location", []):
        loc = entry.get("location")
        for raw in entry.get("list", []):
            nid = triple(raw)
            if not known(nid, f"mo_per_location[{loc}]"):
                continue
            seen_in_mo[nid] = seen_in_mo.get(nid, 0) + 1
            if nodes[nid] not in WRITE_LIKE:
                errs.append(
                    f"MO-2 event {nid} of kind {nodes[nid]} appears in mo for {loc} "
                    f"but does not write"
                )

    for nid, kind in nodes.items():
        if kind in WRITE_LIKE:
            count = seen_in_mo.get(nid, 0)
            if count != 1:
                errs.append(
                    f"MO-1 {kind} event {nid} appears {count} times in mo (expected 1)"
                )

    # ---- po ----------------------------------------------------------------
    for entry in g.get("po_per_thread", []):
        for raw in entry.get("list", []):
            known(triple(raw), f"po_per_thread[{entry.get('thread_id')}]")

    return errs


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2

    targets: list[Path] = []
    for a in argv[1:]:
        p = Path(a)
        if p.is_dir():
            targets += sorted(x for x in p.iterdir() if x.suffix == ".json"
                              or x.name.startswith("id:"))
        else:
            targets.append(p)

    bad = 0
    checked = 0
    for t in targets:
        errs = check_graph(t)
        checked += 1
        if errs:
            bad += 1
            print(f"FAIL {t}")
            for e in errs[:10]:
                print(f"     {e}")
            if len(errs) > 10:
                print(f"     ... and {len(errs) - 10} more")

    print(f"\n{checked - bad}/{checked} graphs satisfy all invariants")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
