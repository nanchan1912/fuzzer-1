#!/usr/bin/env python3
"""Generate an interactive visualization dashboard for AFL queue skeleton graphs.

Features:
- Left panel: parent lineage + equivalence links (set-aware normalized JSON).
- Right panel: selected queue item's skeleton graph.
- Right panel (collapsible): static CFG from a .pg file.

Equivalence normalization:
- Same set of nodes by (thread_id, instruction_id, visit_id).
- Same set of RF edges by ((from_tid, from_instruction_id, from_visit_id),
  (to_tid, to_instruction_id, to_visit_id)).
- Order does not matter; all other fields are ignored.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


QUEUE_ID_RE = re.compile(r"id:(\d+)")
SRC_ID_RE = re.compile(r"src:(\d+)(?:[,.]|$)")
IGNORED_KEYS = {
    "thread_id",
    "instruction_id",
    "visit_id",
    "event_id",
    "threadid",
    "instructionid",
    "visitid",
    "eventid",
}


@dataclass
class QueueEntry:
    corpus: str
    file_name: str
    file_path: Path
    id_num: int
    parent_src_id: Optional[int]
    raw: Dict[str, Any]
    equiv_hash: str
    mtime: float


@dataclass
class ParsedPG:
    events: Dict[str, Dict[str, str]]
    cf_edges: List[Tuple[str, str]]


def parse_queue_id(name: str) -> Optional[int]:
    match = QUEUE_ID_RE.search(name)
    return int(match.group(1)) if match else None


def parse_parent_id(name: str) -> Optional[int]:
    match = SRC_ID_RE.search(name)
    return int(match.group(1)) if match else None


def equivalence_hash(payload: Dict[str, Any]) -> str:
    node_set = set()
    raw_nodes = payload.get("nodes", [])
    if isinstance(raw_nodes, list):
        for node in raw_nodes:
            if not isinstance(node, dict):
                continue
            tid = str(node.get("thread_id", "?"))
            instruction_id = str(node.get("instruction_id", "?"))
            visit_id = str(node.get("visit_id", "?"))
            node_set.add((tid, instruction_id, visit_id))

    rf_set = set()
    rf_edges = payload.get("rf_edges", [])
    if isinstance(rf_edges, list):
        for edge in rf_edges:
            if not isinstance(edge, dict):
                continue
            src = parse_event_ref(edge.get("from"))
            tos = edge.get("to", [])
            if src is None or not isinstance(tos, list):
                continue
            for dst_ref in tos:
                dst = parse_event_ref(dst_ref)
                if dst is None:
                    continue
                rf_set.add((src, dst))

    tcj_set = set()
    tcj_edges = payload.get("tcj_edges", [])
    if isinstance(tcj_edges, list):
        for edge in tcj_edges:
            if not isinstance(edge, dict):
                continue
            src = parse_event_ref(edge.get("from"))
            tos = edge.get("to", [])
            if src is None or not isinstance(tos, list):
                continue
            for dst_ref in tos:
                dst = parse_event_ref(dst_ref)
                if dst is None:
                    continue
                tcj_set.add((src, dst))

    signature = {
        "nodes": [list(n) for n in sorted(node_set)],
        "rf_edges": [list(src) + list(dst) for src, dst in sorted(rf_set)],
        "tcj_edges": [list(src) + list(dst) for src, dst in sorted(tcj_set)],
    }

    blob = json.dumps(signature, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def parse_race_file_content(content: str) -> Dict[str, Any]:
    race_info = {}
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        match = re.match(
            r"(race_[01]):\s+thread_id=(-?\d+)\s+instruction_id=(-?\d+)\s+visit_id=(-?\d+)",
            line
        )
        if match:
            op_name = match.group(1)
            race_info[op_name] = {
                "thread_id": match.group(2),
                "instruction_id": match.group(3),
                "visit_id": match.group(4)
            }
    return race_info


def load_entries_from_dir(
    corpus: str, corpus_dir: Path, loaded_raws: Dict[Tuple[str, int], Dict[str, Any]]
) -> List[QueueEntry]:
    entries: List[QueueEntry] = []
    if not corpus_dir.exists() or not corpus_dir.is_dir():
        return entries

    for child in sorted(corpus_dir.iterdir()):
        if not child.is_file():
            continue
        if not child.name.startswith("id:"):
            continue

        qid = parse_queue_id(child.name)
        if qid is None:
            continue

        if child.suffix.lower() != ".json" and "orig:" in child.name:
            continue

        parent_src_id = parse_parent_id(child.name)

        if corpus == "races":
            try:
                text_content = child.read_text(encoding="utf-8")
                race_info = parse_race_file_content(text_content)
                parent_raw = None
                if parent_src_id is not None:
                    parent_raw = loaded_raws.get(("queue", parent_src_id))
                if parent_raw is None:
                    parent_raw = {
                        "nodes": [],
                        "rf_edges": [],
                        "po_per_thread": [],
                        "sw_edges": [],
                        "tcj_edges": [],
                        "mo_per_location": []
                    }
                raw = json.loads(json.dumps(parent_raw))
                raw["race_info"] = race_info
            except Exception as e:
                print(f"Warning: failed to parse race file {child}: {e}")
                continue
        else:
            try:
                raw = json.loads(child.read_text(encoding="utf-8"))
            except Exception:
                continue

        entries.append(
            QueueEntry(
                corpus=corpus,
                file_name=child.name,
                file_path=child,
                id_num=qid,
                parent_src_id=parent_src_id,
                raw=raw,
                equiv_hash=equivalence_hash(raw),
                mtime=child.stat().st_mtime,
            )
        )

    entries.sort(key=lambda item: item.id_num)
    return entries


def load_afl_out(afl_out_dir: Path) -> List[QueueEntry]:
    corpus_order = {"queue": 0, "hangs": 1, "crashes": 2, "races": 3, "non_instantiable": 4}
    all_entries: List[QueueEntry] = []
    loaded_raws: Dict[Tuple[str, int], Dict[str, Any]] = {}

    for corpus in ("queue", "hangs", "crashes", "non_instantiable"):
        entries = load_entries_from_dir(corpus, afl_out_dir / corpus, loaded_raws)
        all_entries.extend(entries)
        for entry in entries:
            loaded_raws[(corpus, entry.id_num)] = entry.raw

    races_entries = load_entries_from_dir("races", afl_out_dir / "races", loaded_raws)
    all_entries.extend(races_entries)

    all_entries.sort(key=lambda entry: (corpus_order.get(entry.corpus, 99), entry.id_num, entry.file_name))
    return all_entries


def parse_event_ref(ref: Any) -> Optional[Tuple[str, str, str]]:
    if isinstance(ref, list) and len(ref) >= 3:
        return str(ref[0]), str(ref[1]), str(ref[2])
    return None


def _safe_int(value: str) -> int:
    try:
        return int(value)
    except Exception:
        return 10**9


def _count_relation_edges(raw: Dict[str, Any], key: str) -> int:
    edges_raw = raw.get(key, [])
    if not isinstance(edges_raw, list):
        return 0
    total = 0
    for edge in edges_raw:
        if not isinstance(edge, dict):
            continue
        tos = edge.get("to", [])
        if isinstance(tos, list):
            total += len(tos)
    return total


def build_skeleton_graph(raw: Dict[str, Any]) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = []
    lane_nodes: List[Dict[str, Any]] = []
    node_lookup: Dict[Tuple[str, str, str], str] = {}
    node_meta: Dict[str, Dict[str, str]] = {}
    po_order: Dict[Tuple[str, str, str], int] = {}
    per_thread_nodes: Dict[str, List[Tuple[str, str, str]]] = defaultdict(list)

    raw_nodes = raw.get("nodes", []) if isinstance(raw.get("nodes", []), list) else []
    for node in raw_nodes:
        if not isinstance(node, dict):
            continue
        tid = str(node.get("thread_id", "?"))
        instruction_id = str(node.get("instruction_id", "?"))
        visit_id = str(node.get("visit_id", "?"))
        composite = (tid, instruction_id, visit_id)
        per_thread_nodes[tid].append(composite)

    po_per_thread = raw.get("po_per_thread", [])
    if isinstance(po_per_thread, list):
        for thread_entry in po_per_thread:
            if not isinstance(thread_entry, dict):
                continue
            seq = thread_entry.get("list", [])
            if not isinstance(seq, list):
                continue
            for i, ref in enumerate(seq):
                parsed = parse_event_ref(ref)
                if parsed is not None and parsed not in po_order:
                    po_order[parsed] = i

    thread_ids = sorted(per_thread_nodes.keys(), key=lambda t: (_safe_int(t), t))
    thread_lane_index = {tid: index for index, tid in enumerate(thread_ids)}

    lane_height = 170
    x_spacing = 190
    fallback_per_thread: Dict[str, int] = defaultdict(int)

    for index, node in enumerate(raw_nodes):
        if not isinstance(node, dict):
            continue
        tid = str(node.get("thread_id", "?"))
        instruction_id = str(node.get("instruction_id", "?"))
        visit_id = str(node.get("visit_id", "?"))
        event_id = str(node.get("event_id", index))
        composite = (tid, instruction_id, visit_id)
        nid = f"n{event_id}"
        node_lookup[composite] = nid

        kind = str(node.get("kind", "?"))
        loc = str(node.get("loc_id", node.get("loc", "?")))
        mode = str(node.get("access_mode", "?")).upper()
        label = f"v{visit_id} {kind}({loc},{mode})"

        if composite in po_order:
            order_idx = po_order[composite]
        else:
            order_idx = fallback_per_thread[tid]
            fallback_per_thread[tid] += 1

        lane_index = thread_lane_index.get(tid, 0)
        y_pos = lane_index * lane_height

        node_meta[nid] = {
            "event_id": event_id,
            "thread_id": tid,
            "instruction_id": instruction_id,
            "visit_id": visit_id,
            "kind": kind,
            "location": loc,
            "location_id": loc,
            "mode": mode,
            "po_index": str(order_idx),
        }

        nodes.append(
            {
                "id": nid,
                "label": label,
                "title": (
                    f"event_id={event_id}\\n"
                    f"thread_id={tid}\\n"
                    f"instruction_id={instruction_id}\\n"
                    f"visit_id={visit_id}\\n"
                    f"kind={kind}\\n"
                    f"location={loc}\\n"
                    f"mode={mode}"
                ),
                "group": f"T{tid}",
                "shape": "box" if kind.upper() == "R" else "ellipse",
                "instructionId": instruction_id,
                "threadId": tid,
                "poIndex": order_idx,
                "x": 0,
                "y": y_pos,
                "fixed": True,
                "physics": False,
            }
        )

    def ref_to_node_id(ref: Any) -> Optional[str]:
        parsed = parse_event_ref(ref)
        if parsed is None:
            return None
        return node_lookup.get(parsed)

    edges: List[Dict[str, Any]] = []

    if isinstance(po_per_thread, list):
        for thread_entry in po_per_thread:
            if not isinstance(thread_entry, dict):
                continue
            seq = thread_entry.get("list", [])
            if not isinstance(seq, list):
                continue
            for i in range(len(seq) - 1):
                src = ref_to_node_id(seq[i])
                dst = ref_to_node_id(seq[i + 1])
                if src and dst:
                    edges.append(
                        {
                            "from": src,
                            "to": dst,
                            "label": "PO",
                            "relation": "PO",
                            "color": "#111111",
                            "dashes": False,
                            "width": 3.2,
                            "smooth": False,
                            "arrows": "to",
                        }
                    )

    mo_per_location = raw.get("mo_per_location", [])
    if isinstance(mo_per_location, list):
        for mo_entry in mo_per_location:
            if not isinstance(mo_entry, dict):
                continue
            seq = mo_entry.get("list", [])
            if not isinstance(seq, list):
                continue
            for i in range(len(seq) - 1):
                src = ref_to_node_id(seq[i])
                dst = ref_to_node_id(seq[i + 1])
                if src and dst:
                    edges.append(
                        {
                            "from": src,
                            "to": dst,
                            "label": "MO",
                            "relation": "MO",
                            "color": "#ff9800",
                            "dashes": True,
                            "width": 1.2,
                            "smooth": {"enabled": True, "type": "curvedCW", "roundness": 0.22},
                            "arrows": "to",
                        }
                    )

    for edge_name, color, curve in (
        ("rf_edges", "#1f9d55", "curvedCCW"),
        ("sw_edges", "#7e57c2", "curvedCW"),
        ("tcj_edges", "#e91e63", "curvedCCW"),
    ):
        edges_raw = raw.get(edge_name, [])
        if not isinstance(edges_raw, list):
            continue
        for edge in edges_raw:
            if not isinstance(edge, dict):
                continue
            src = ref_to_node_id(edge.get("from"))
            tos = edge.get("to", [])
            if not src or not isinstance(tos, list):
                continue
            for dst_ref in tos:
                dst = ref_to_node_id(dst_ref)
                if src and dst:
                    relation = edge_name.replace("_edges", "").upper()
                    width = 2.4 if relation == "RF" else 2.8
                    edges.append(
                        {
                            "from": src,
                            "to": dst,
                            "label": relation,
                            "relation": relation,
                            "color": color,
                            "dashes": True,
                            "width": width,
                            "smooth": {"enabled": True, "type": curve, "roundness": 0.28},
                            "arrows": "to",
                        }
                    )

    hb_adjacency: Dict[str, List[str]] = defaultdict(list)
    hb_indegree: Dict[str, int] = {node["id"]: 0 for node in nodes}
    for edge in edges:
        rel = edge.get("relation")
        if rel not in {"PO", "SW", "TCJ"}:
            continue
        src = str(edge.get("from"))
        dst = str(edge.get("to"))
        if src not in hb_indegree or dst not in hb_indegree:
            continue
        hb_adjacency[src].append(dst)
        hb_indegree[dst] += 1

    hb_depth: Dict[str, int] = {node_id: 0 for node_id in hb_indegree}
    ready = [node_id for node_id, indeg in hb_indegree.items() if indeg == 0]
    processed = 0
    while ready:
        cur = ready.pop(0)
        processed += 1
        cur_depth = hb_depth.get(cur, 0)
        for nxt in hb_adjacency.get(cur, []):
            if hb_depth.get(nxt, 0) < cur_depth + 1:
                hb_depth[nxt] = cur_depth + 1
            hb_indegree[nxt] -= 1
            if hb_indegree[nxt] == 0:
                ready.append(nxt)

    if processed < len(nodes):
        for node in nodes:
            nid = str(node["id"])
            hb_depth[nid] = int(node.get("poIndex", 0))

    max_x_by_thread: Dict[str, int] = defaultdict(int)
    min_depth_by_thread: Dict[str, int] = {}
    for node in nodes:
        nid = str(node["id"])
        tid = str(node.get("threadId", "?"))
        depth = hb_depth.get(nid, int(node.get("poIndex", 0)))
        if tid not in min_depth_by_thread:
            min_depth_by_thread[tid] = depth
        else:
            min_depth_by_thread[tid] = min(min_depth_by_thread[tid], depth)

    local_x_by_node: Dict[str, int] = {}
    node_by_id: Dict[str, Dict[str, Any]] = {str(node["id"]): node for node in nodes}

    for node in nodes:
        nid = str(node["id"])
        tid = str(node.get("threadId", "?"))
        base_depth = hb_depth.get(nid, int(node.get("poIndex", 0)))
        normalized_depth = base_depth - min_depth_by_thread.get(tid, 0)
        node_x = max(0, normalized_depth) * x_spacing
        local_x_by_node[nid] = node_x

    thread_offset: Dict[str, int] = defaultdict(int)
    sw_constraints: List[Tuple[str, str, str, str]] = []
    for edge in edges:
        if edge.get("relation") != "SW":
            continue
        src = str(edge.get("from"))
        dst = str(edge.get("to"))
        src_node = node_by_id.get(src)
        dst_node = node_by_id.get(dst)
        if src_node is None or dst_node is None:
            continue
        src_tid = str(src_node.get("threadId", "?"))
        dst_tid = str(dst_node.get("threadId", "?"))
        if src_tid == dst_tid:
            continue
        if src not in local_x_by_node or dst not in local_x_by_node:
            continue
        sw_constraints.append((src_tid, dst_tid, src, dst))

    if sw_constraints:
        for _ in range(max(1, len(thread_ids) * 3)):
            changed = False
            for src_tid, dst_tid, src, dst in sw_constraints:
                src_global_x = thread_offset.get(src_tid, 0) + local_x_by_node[src]
                required_dst_offset = src_global_x + x_spacing - local_x_by_node[dst]
                if required_dst_offset > thread_offset.get(dst_tid, 0):
                    thread_offset[dst_tid] = required_dst_offset
                    changed = True
            if not changed:
                break

    max_x_by_thread = defaultdict(int)
    for node in nodes:
        nid = str(node["id"])
        tid = str(node.get("threadId", "?"))
        node_x = local_x_by_node.get(nid, 0) + thread_offset.get(tid, 0)
        node["x"] = node_x
        max_x_by_thread[tid] = max(max_x_by_thread[tid], node_x)

    for tid in thread_ids:
        lane_index = thread_lane_index[tid]
        y_pos = lane_index * lane_height
        lane_width = max(500, max_x_by_thread.get(tid, 0) + 2 * x_spacing)
        lane_nodes.append(
            {
                "id": f"lane:{tid}",
                "label": f"Thread {tid}",
                "shape": "box",
                "x": lane_width / 2 - 110,
                "y": y_pos,
                "fixed": True,
                "physics": False,
                "selectable": False,
                "font": {"color": "#64748b", "size": 12, "align": "left", "vadjust": -40},
                "color": {"background": "rgba(96, 165, 250, 0.08)", "border": "rgba(96, 165, 250, 0.25)"},
                "borderWidth": 1,
                "margin": {"top": 10, "right": 10, "bottom": 8, "left": 14},
                "widthConstraint": {"minimum": lane_width},
                "heightConstraint": {"minimum": 110},
            }
        )

    rf_count = sum(1 for edge in edges if edge.get("relation") == "RF")
    stats = {
        "threadCount": len(thread_ids),
        "nodeCount": len(nodes),
        "rfCount": rf_count,
        "swCount": sum(1 for edge in edges if edge.get("relation") == "SW"),
        "moCount": sum(1 for edge in edges if edge.get("relation") == "MO"),
        "poCount": sum(1 for edge in edges if edge.get("relation") == "PO"),
        "tcjCount": sum(1 for edge in edges if edge.get("relation") == "TCJ"),
    }

    return {
        "nodes": nodes,
        "edges": edges,
        "laneNodes": lane_nodes,
        "nodeMeta": node_meta,
        "stats": stats,
        "threadIds": thread_ids,
        "raceInfo": raw.get("race_info", {}),
    }


def parse_pg(pg_path: Path) -> ParsedPG:
    events: Dict[str, Dict[str, str]] = {}
    cf_edges: List[Tuple[str, str]] = []

    if not pg_path.exists():
        return ParsedPG(events=events, cf_edges=cf_edges)

    for raw_line in pg_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if not parts:
            continue

        if parts[0] == "E" and len(parts) >= 6:
            event_id = parts[1]
            tid = parts[2]
            if len(parts) >= 7:
                instruction_id = parts[3]
                kind = parts[4]
                loc = parts[5]
                mode = parts[6]
            else:
                instruction_id = "?"
                kind = parts[3]
                loc = parts[4]
                mode = parts[5]
            events[event_id] = {
                "event_id": event_id,
                "thread_id": tid,
                "instruction_id": instruction_id,
                "kind": kind,
                "loc": loc,
                "mode": mode,
            }
        elif parts[0] == "CF" and len(parts) >= 3:
            cf_edges.append((parts[1], parts[2]))

    return ParsedPG(events=events, cf_edges=cf_edges)


def build_cfg_graph(pg: ParsedPG) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = []
    lane_nodes: List[Dict[str, Any]] = []
    valid_edges: List[Tuple[str, str]] = []

    thread_ids = sorted({str(event.get("thread_id", "?")) for event in pg.events.values()}, key=lambda t: (_safe_int(t), t))
    thread_lane_index = {tid: idx for idx, tid in enumerate(thread_ids)}

    indegree: Dict[str, int] = {event_id: 0 for event_id in pg.events.keys()}
    adjacency: Dict[str, List[str]] = defaultdict(list)
    for src, dst in pg.cf_edges:
        if src in pg.events and dst in pg.events:
            valid_edges.append((src, dst))
            adjacency[src].append(dst)
            indegree[dst] += 1

    events_by_thread: Dict[str, List[str]] = defaultdict(list)
    for event_id, event in pg.events.items():
        tid = str(event.get("thread_id", "?"))
        events_by_thread[tid].append(event_id)

    depth_by_event: Dict[str, int] = {}
    row_by_event: Dict[str, int] = {}
    max_col_by_thread: Dict[str, int] = defaultdict(int)
    max_row_by_thread: Dict[str, int] = defaultdict(int)

    for tid in thread_ids:
        event_ids = sorted(events_by_thread.get(tid, []), key=lambda eid: (_safe_int(eid), eid))
        local_indegree: Dict[str, int] = {eid: 0 for eid in event_ids}
        local_adj: Dict[str, List[str]] = defaultdict(list)

        for src, dst in valid_edges:
            src_event = pg.events.get(src)
            dst_event = pg.events.get(dst)
            if not src_event or not dst_event:
                continue
            if str(src_event.get("thread_id", "?")) != tid or str(dst_event.get("thread_id", "?")) != tid:
                continue
            local_adj[src].append(dst)
            if dst in local_indegree:
                local_indegree[dst] += 1

        depth_local: Dict[str, int] = {eid: 0 for eid in event_ids}
        ready = sorted([eid for eid, deg in local_indegree.items() if deg == 0], key=lambda eid: (_safe_int(eid), eid))
        processed = 0
        while ready:
            cur = ready.pop(0)
            processed += 1
            cur_depth = depth_local.get(cur, 0)
            for nxt in local_adj.get(cur, []):
                if nxt not in depth_local:
                    continue
                if depth_local.get(nxt, 0) < cur_depth + 1:
                    depth_local[nxt] = cur_depth + 1
                local_indegree[nxt] -= 1
                if local_indegree[nxt] == 0:
                    ready.append(nxt)
                    ready.sort(key=lambda eid: (_safe_int(eid), eid))

        if processed < len(event_ids):
            fallback_rank = {eid: idx for idx, eid in enumerate(event_ids)}
            for eid in event_ids:
                if local_indegree.get(eid, 0) > 0:
                    depth_local[eid] = max(depth_local.get(eid, 0), fallback_rank[eid])

        per_col_events: Dict[int, List[str]] = defaultdict(list)
        for eid in event_ids:
            per_col_events[depth_local.get(eid, 0)].append(eid)

        for col in sorted(per_col_events.keys()):
            bucket = sorted(per_col_events[col], key=lambda eid: (_safe_int(eid), eid))
            for row_idx, eid in enumerate(bucket):
                depth_by_event[eid] = col
                row_by_event[eid] = row_idx
                max_col_by_thread[tid] = max(max_col_by_thread[tid], col)
                max_row_by_thread[tid] = max(max_row_by_thread[tid], row_idx)

    x_spacing = 240
    row_spacing = 84
    lane_padding_top = 44
    lane_padding_bottom = 24
    lane_gap = 24
    lane_top_by_thread: Dict[str, int] = {}
    lane_height_by_thread: Dict[str, int] = {}
    lane_center_by_thread: Dict[str, float] = {}
    max_x_by_thread: Dict[str, int] = defaultdict(int)

    next_top = 0
    for tid in thread_ids:
        rows = max_row_by_thread.get(tid, 0) + 1
        lane_height = max(140, lane_padding_top + lane_padding_bottom + rows * row_spacing)
        lane_top_by_thread[tid] = next_top
        lane_height_by_thread[tid] = lane_height
        lane_center_by_thread[tid] = next_top + lane_height / 2
        next_top += lane_height + lane_gap

    for event_id, event in pg.events.items():
        kind = event.get("kind", "?")
        loc = event.get("loc", "?")
        tid = event.get("thread_id", "?")
        mode = event.get("mode", "?")
        instruction_id = event.get("instruction_id", "?")
        tid_str = str(tid)
        col = depth_by_event.get(event_id, 0)
        row = row_by_event.get(event_id, 0)
        x_pos = max(0, col) * x_spacing
        y_pos = lane_top_by_thread.get(tid_str, thread_lane_index.get(tid_str, 0) * 170) + lane_padding_top + row * row_spacing
        max_x_by_thread[str(tid)] = max(max_x_by_thread[str(tid)], x_pos)

        label = f"{event_id}: T{tid} {kind}({loc},{mode})"
        nodes.append(
            {
                "id": event_id,
                "label": label,
                "group": f"T{tid}",
                "shape": "box" if kind.upper() == "R" else "ellipse",
                "instructionId": instruction_id,
                "threadId": str(tid),
                "locationId": str(loc),
                "x": x_pos,
                "y": y_pos,
                "fixed": True,
                "physics": False,
                "title": (
                    f"event_id={event_id}\\n"
                    f"thread_id={tid}\\n"
                    f"instruction_id={instruction_id}\\n"
                    f"kind={kind}\\n"
                    f"location={loc}\\n"
                    f"mode={mode}"
                ),
            }
        )

    edges = []
    for src, dst in valid_edges:
        edges.append(
            {
                "from": src,
                "to": dst,
                "label": "CF",
                "arrows": "to",
                "color": "#455a64",
                "dashes": False,
                "smooth": {"enabled": True, "type": "dynamic", "roundness": 0.16},
            }
        )

    for tid in thread_ids:
        y_pos = lane_center_by_thread.get(tid, thread_lane_index.get(tid, 0) * 170)
        lane_height = lane_height_by_thread.get(tid, 170)
        lane_width = max(500, max_x_by_thread.get(tid, 0) + 2 * x_spacing)
        lane_nodes.append(
            {
                "id": f"cfg-lane:{tid}",
                "label": f"CFG Thread {tid}",
                "shape": "box",
                "x": lane_width / 2 - 110,
                "y": y_pos,
                "fixed": True,
                "physics": False,
                "selectable": False,
                "chosen": False,
                "font": {"color": "#64748b", "size": 12, "align": "left", "vadjust": -int(lane_height / 2) + 18},
                "color": {
                    "background": "rgba(96, 165, 250, 0.08)",
                    "border": "rgba(96, 165, 250, 0.25)",
                    "highlight": {
                        "background": "rgba(96, 165, 250, 0.08)",
                        "border": "rgba(96, 165, 250, 0.25)",
                    },
                    "hover": {
                        "background": "rgba(96, 165, 250, 0.08)",
                        "border": "rgba(96, 165, 250, 0.25)",
                    },
                },
                "borderWidth": 1,
                "margin": {"top": 10, "right": 10, "bottom": 8, "left": 14},
                "widthConstraint": {"minimum": lane_width},
                "heightConstraint": {"minimum": lane_height},
            }
        )

    return {"nodes": nodes, "edges": edges, "laneNodes": lane_nodes, "threadIds": thread_ids}


def build_dashboard_data(
    entries: List[QueueEntry], cfg_graph: Dict[str, Any], afl_out_dir: Path
) -> Dict[str, Any]:
    by_hash: Dict[str, List[QueueEntry]] = {}
    for item in entries:
        by_hash.setdefault(item.equiv_hash, []).append(item)

    class_index: Dict[str, int] = {}
    for index, h in enumerate(sorted(by_hash.keys()), start=1):
        class_index[h] = index

    # Find fuzzer start time
    fuzzer_stats = {}
    fuzzer_start_time = 0.0
    stats_path = afl_out_dir / "fuzzer_stats"
    if stats_path.exists():
        try:
            for line in stats_path.read_text(encoding="utf-8").splitlines():
                if ":" in line:
                    key, val = line.split(":", 1)
                    fuzzer_stats[key.strip()] = val.strip()
            fuzzer_start_time = float(fuzzer_stats.get("start_time", 0.0))
        except Exception:
            pass

    if fuzzer_start_time <= 0.0:
        if entries:
            fuzzer_start_time = min(entry.mtime for entry in entries)
        else:
            fuzzer_start_time = 0.0

    # Parse plot data
    plot_data = []
    plot_path = afl_out_dir / "plot_data"
    if plot_path.exists():
        try:
            lines = plot_path.read_text(encoding="utf-8").splitlines()
            if lines:
                headers = [h.strip() for h in lines[0].split(",")]
                for line in lines[1:]:
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) == len(headers):
                        row = {}
                        for h, p in zip(headers, parts):
                            try:
                                if "." in p:
                                    row[h] = float(p)
                                elif p.endswith("%"):
                                    row[h] = float(p.replace("%", ""))
                                else:
                                    row[h] = int(p)
                            except Exception:
                                row[h] = p
                        plot_data.append(row)
        except Exception:
            pass

    lineage_nodes: List[Dict[str, Any]] = []
    lineage_edges: List[Dict[str, Any]] = []
    skeleton_by_id: Dict[str, Dict[str, Any]] = {}
    original_by_id: Dict[str, Dict[str, Any]] = {}

    entry_uid: Dict[Tuple[str, int, str], str] = {}
    entries_by_uid: Dict[str, QueueEntry] = {}
    first_uid_by_corpus_id: Dict[Tuple[str, int], str] = {}
    corpus_counts: Dict[str, int] = {"queue": 0, "hangs": 0, "crashes": 0, "races": 0, "non_instantiable": 0}

    for idx, entry in enumerate(entries):
        uid = f"{entry.corpus}:{entry.id_num}:{idx}"
        key = (entry.corpus, entry.id_num, entry.file_name)
        entry_uid[key] = uid
        entries_by_uid[uid] = entry
        if (entry.corpus, entry.id_num) not in first_uid_by_corpus_id:
            first_uid_by_corpus_id[(entry.corpus, entry.id_num)] = uid
        corpus_counts[entry.corpus] = corpus_counts.get(entry.corpus, 0) + 1

    parent_by_uid: Dict[str, Optional[str]] = {}
    children_by_uid: Dict[str, List[str]] = {uid: [] for uid in entries_by_uid.keys()}

    for uid, entry in entries_by_uid.items():
        resolved_parent: Optional[str] = None
        if entry.parent_src_id is not None:
            # The parent is always in the "queue" corpus
            resolved_parent = first_uid_by_corpus_id.get(("queue", entry.parent_src_id))
        parent_by_uid[uid] = resolved_parent

    for child_uid, parent_uid in parent_by_uid.items():
        if parent_uid is not None and parent_uid in children_by_uid:
            children_by_uid[parent_uid].append(child_uid)

    depth_cache: Dict[str, int] = {}
    visiting: Set[str] = set()

    def compute_depth(node_uid: str) -> int:
        if node_uid in depth_cache:
            return depth_cache[node_uid]
        if node_uid in visiting:
            return 0
        parent_uid = parent_by_uid.get(node_uid)
        if parent_uid is None or parent_uid == node_uid:
            depth_cache[node_uid] = 0
        else:
            visiting.add(node_uid)
            depth_cache[node_uid] = compute_depth(parent_uid) + 1
            visiting.remove(node_uid)
        return depth_cache[node_uid]

    skeleton_sizes: List[int] = []
    total_rf = 0
    depth_bucket_offsets: Dict[int, int] = defaultdict(int)
    depth_x_spacing = 190
    depth_y_spacing = 78
    depth_row_wrap = 32
    depth_wrap_x_spacing = 130

    for idx, entry in enumerate(entries):
        uid = entry_uid[(entry.corpus, entry.id_num, entry.file_name)]
        class_id = class_index[entry.equiv_hash]
        members = by_hash[entry.equiv_hash]
        skel = build_skeleton_graph(entry.raw)
        skel_stats = skel["stats"]
        skeleton_sizes.append(int(skel_stats.get("nodeCount", 0)))
        total_rf += int(skel_stats.get("rfCount", 0))

        node_count = int(skel_stats.get("nodeCount", 0))
        thread_count = int(skel_stats.get("threadCount", 0))
        rf_count = int(skel_stats.get("rfCount", 0))
        parent_uid = parent_by_uid.get(uid)
        depth = compute_depth(uid)
        is_source = parent_uid is None
        is_leaf = len(children_by_uid.get(uid, [])) == 0
        depth_col = depth_bucket_offsets[depth]
        depth_bucket_offsets[depth] += 1
        depth_wrap_col = depth_col // depth_row_wrap
        depth_row = depth_col % depth_row_wrap
        corpus_tag = {"queue": "Q", "hangs": "H", "crashes": "C", "races": "R", "non_instantiable": "N"}.get(entry.corpus, "?")

        lineage_nodes.append(
            {
                "id": uid,
                "label": f"#{entry.id_num} [{corpus_tag}]: T{thread_count} N{node_count} RF{rf_count}",
                "title": (
                    f"corpus={entry.corpus}\\n"
                    f"file={entry.file_name}\\n"
                    f"equiv_class=C{class_id} (size={len(members)})\\n"
                    f"parent={parent_uid if parent_uid is not None else 'none'}\\n"
                    f"depth={depth}\\n"
                    f"threads={thread_count}\\n"
                    f"skeleton_nodes={node_count}\\n"
                    f"rf_edges={rf_count}\\n"
                    f"is_source={is_source}\\n"
                    f"is_leaf={is_leaf}"
                ),
                "group": f"C{class_id}",
                "corpus": entry.corpus,
                "origId": entry.id_num,
                "classId": class_id,
                "classSize": len(members),
                "isSource": is_source,
                "isLeaf": is_leaf,
                "depth": depth,
                "shape": "dot",
                "size": 12 + min(12, 2 * (len(members) - 1)),
                "x": depth * depth_x_spacing + depth_wrap_col * depth_wrap_x_spacing,
                "y": depth_row * depth_y_spacing,
                "fixed": True,
                "physics": False,
                "discoveryTime": max(0.0, entry.mtime - fuzzer_start_time),
                "fileName": entry.file_name,
                "filePath": str(entry.file_path),
            }
        )
        skeleton_by_id[uid] = skel
        original_by_id[uid] = entry.raw

        if parent_uid is not None:
            lineage_edges.append(
                {
                    "from": parent_uid,
                    "to": uid,
                    "arrows": "to",
                    "color": "#344155",
                    "width": 2.0,
                    "smooth": {"enabled": True, "type": "dynamic", "roundness": 0.08},
                }
            )

    max_depth = max((compute_depth(uid) for uid in entries_by_uid.keys()), default=0)
    avg_skeleton_size = (sum(skeleton_sizes) / len(skeleton_sizes)) if skeleton_sizes else 0.0
    unique_skeleton_ratio = (len(by_hash) / len(entries)) if entries else 0.0
    total_nodes = sum(skeleton_sizes)
    rf_density = (total_rf / total_nodes) if total_nodes > 0 else 0.0

    class_members = {
        str(class_index[h]): [
            entry_uid[(member.corpus, member.id_num, member.file_name)]
            for member in sorted(
                members,
                key=lambda m: (
                    {"queue": 0, "hangs": 1, "crashes": 2, "races": 3, "non_instantiable": 4}.get(m.corpus, 99),
                    m.id_num,
                    m.file_name,
                ),
            )
        ]
        for h, members in by_hash.items()
    }

    id_to_class = {
        entry_uid[(entry.corpus, entry.id_num, entry.file_name)]: str(class_index[entry.equiv_hash]) for entry in entries
    }

    lineage_meta = {
        "parentById": {uid: (parent if parent is not None else None) for uid, parent in parent_by_uid.items()},
        "childrenById": {uid: sorted(values) for uid, values in children_by_uid.items()},
        "depthById": {uid: compute_depth(uid) for uid in entries_by_uid.keys()},
        "leafIds": [uid for uid in entries_by_uid.keys() if len(children_by_uid.get(uid, [])) == 0],
        "sourceIds": [uid for uid in entries_by_uid.keys() if parent_by_uid.get(uid) is None],
    }

    return {
        "lineage": {"nodes": lineage_nodes, "edges": lineage_edges},
        "skeletonById": skeleton_by_id,
        "originalById": original_by_id,
        "cfg": cfg_graph,
        "fuzzerStats": fuzzer_stats,
        "plotData": plot_data,
        "defaultSelection": next(
            (
                entry_uid[(entry.corpus, entry.id_num, entry.file_name)]
                for target_corpus in ["crashes", "races", "hangs", "queue", "non_instantiable"]
                for entry in reversed(entries)
                if entry.corpus == target_corpus
            ),
            None,
        ),
        "entryCount": len(entries),
        "equivClassCount": len(by_hash),
        "corpusCounts": corpus_counts,
        "classMembers": class_members,
        "idToClass": id_to_class,
        "lineageMeta": lineage_meta,
        "metrics": {
            "maxLineageDepth": max_depth,
            "avgSkeletonSize": round(avg_skeleton_size, 3),
            "uniqueSkeletonRatio": round(unique_skeleton_ratio, 5),
            "rfDensity": round(rf_density, 5),
        },
    }


def render_html(payload: Dict[str, Any]) -> str:
    data_json = json.dumps(payload, separators=(",", ":"))
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>AFL Queue Lineage & Execution Inspector</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <script src="https://unpkg.com/vis-network@9.1.9/dist/vis-network.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/jsoneditor@10.4.2/dist/jsoneditor.min.css" />
  <script src="https://cdn.jsdelivr.net/npm/jsoneditor@10.4.2/dist/jsoneditor.min.js"></script>
    <style>
        :root {{
            --bg: #f6f602;
            --panel: #ffffff;
            --subpanel: #eff2ff;
            --border: #000000;
            --text: #000000;
            --muted: #2e2e2e;
            --accent: #00d1ff;
            --ok: #14f195;
            --warn: #ff9f1c;
            --sync: #9b5de5;
            --pink: #ff4d8d;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            margin: 0;
            font-family: 'Inter', ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            height: 100vh;
            overflow: hidden;
            transition: background 0.2s ease, color 0.2s ease;
        }}
        .header {{
            border-bottom: 4px solid var(--border);
            background: #ffffff;
            padding: 12px 14px;
            display: grid;
            grid-template-columns: 1fr auto;
            gap: 12px;
            align-items: center;
            transition: background 0.2s ease, border-color 0.2s ease;
        }}
        .title {{
            font-weight: 700;
            font-size: 16px;
            margin-bottom: 2px;
        }}
        .subtitle {{
            color: var(--muted);
            font-size: 12px;
            font-weight: 700;
        }}
        .metrics {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            justify-content: flex-end;
        }}
        .metric {{
            border: 3px solid var(--border);
            background: #f1f5f9;
            border-radius: 0;
            padding: 7px 10px;
            min-width: 110px;
            backdrop-filter: blur(8px);
            transition: all 0.2s ease;
        }}
        .metric:hover {{
            border-color: var(--accent);
            transform: translateY(-2px);
        }}
        .metric .k {{ color: var(--muted); font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 2px; }}
        .metric .v {{ font-size: 15px; font-weight: 700; color: var(--text); }}
        .layout {{
            display: grid;
            grid-template-columns: 38% 62%;
            height: calc(100vh - 82px);
            min-height: 620px;
            background: var(--bg);
        }}
        .panel {{
            min-height: 0;
            display: flex;
            flex-direction: column;
            background: var(--panel);
            border-right: 1px solid var(--border);
        }}
        .panel:last-child {{ border-right: none; }}
        .panel-title {{
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
            font-size: 13px;
            font-weight: 700;
            letter-spacing: 0.2px;
            background: var(--subpanel);
            color: var(--text);
        }}
        .toolbar {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            padding: 10px 12px;
            border-bottom: 1px solid var(--border);
            background: var(--subpanel);
            align-items: center;
        }}
        .toolbar input, .toolbar select {{
            background: #ffffff;
            color: var(--text);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 6px 10px;
            font-size: 12px;
            min-width: 95px;
            font-weight: 500;
            transition: border-color 0.15s ease;
            outline: none;
        }}
        .toolbar input:focus, .toolbar select:focus {{
            border-color: var(--accent);
        }}
        .toolbar label {{
            font-size: 11px;
            color: var(--text);
            font-weight: 500;
            display: inline-flex;
            gap: 6px;
            align-items: center;
            cursor: pointer;
            user-select: none;
            background: var(--subpanel);
            padding: 4px 8px;
            border-radius: 4px;
            border: 1px solid var(--border);
            transition: all 0.15s ease;
        }}
        .toolbar label:hover {{
            border-color: var(--accent);
            background: rgba(30, 41, 59, 0.7);
        }}
        .toolbar input[type="checkbox"] {{
            accent-color: var(--accent);
            cursor: pointer;
        }}
        .toolbar-group {{ display: inline-flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-right: 8px; }}
        .btn {{
            background: #ffffff;
            color: #000000;
            border: 3px solid #000000;
            border-radius: 0;
            padding: 6px 9px;
            font-size: 12px;
            cursor: pointer;
            font-weight: 800;
            box-shadow: 3px 3px 0 #000000;
            transition: all 0.15s ease;
            outline: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
        }}
        .btn:hover {{
            background: #334155;
            border-color: var(--accent);
            transform: translateY(-1px);
        }}
        .btn:active {{
            transform: translateY(0);
        }}
        .btn-primary {{
            background: var(--accent);
            color: #0f172a;
            border-color: var(--accent);
            font-weight: 700;
        }}
        .btn-primary:hover {{
            background: #7dd3fc;
            border-color: #7dd3fc;
        }}
        .btn-accent {{
            background: var(--pink);
            color: #ffffff;
            border-color: var(--pink);
        }}
        .btn-accent:hover {{
            background: #f472b6;
            border-color: #f472b6;
        }}
        .graph {{
            flex: 1;
            min-height: 300px;
            border-bottom: 1px solid var(--border);
            background: #ffffff;
        }}
        .legend {{
            padding: 10px 12px;
            border-top: 1px solid var(--border);
            background: var(--panel);
            font-size: 11px;
            display: grid;
            grid-template-columns: repeat(2, minmax(160px, 1fr));
            gap: 6px 14px;
            color: var(--text);
            font-weight: 500;
        }}
        .chip {{
            display: inline-block;
            width: 16px;
            height: 4px;
            margin-right: 8px;
            vertical-align: middle;
            border-radius: 2px;
        }}
        .right-wrap {{
            display: grid;
            grid-template-rows: minmax(480px, 1fr) auto;
            min-height: 0;
            height: 100%;
        }}
        .inspector {{
            display: flex;
            flex-direction: column;
            min-height: 0;
        }}
        #skeleton {{ flex: 1; min-height: 360px; }}
        .selected-info {{
            padding: 10px 14px;
            font-size: 12px;
            color: var(--text);
            border-bottom: 1px solid var(--border);
            background: var(--panel);
            font-weight: 600;
        }}
        .details {{
            border-top: 1px solid var(--border);
            background: var(--panel);
            padding: 10px 12px;
            font-size: 12px;
            color: var(--text);
            display: grid;
            grid-template-columns: repeat(2, minmax(100px, 1fr));
            gap: 4px 10px;
            max-height: 160px;
            overflow: auto;
            font-weight: 500;
        }}
        .details .w {{ color: var(--muted); font-weight: 600; }}
        details {{
            border-top: 1px solid var(--border);
            background: var(--panel);
            position: relative;
            transition: all 0.2s ease;
        }}
        details[open] {{
            background: var(--panel);
        }}
        summary {{
            cursor: pointer;
            padding: 12px 16px;
            font-weight: 600;
            font-size: 13px;
            color: var(--text);
            user-select: none;
            position: relative;
            z-index: 10;
            background: var(--subpanel);
            border-bottom: 1px solid transparent;
            transition: all 0.15s ease;
        }}
        details[open] summary {{
            border-bottom: 1px solid var(--border);
        }}
        summary:hover {{
            color: var(--accent);
            background: rgba(30, 41, 59, 0.8);
        }}
        .cfg-wrap {{ display: grid; grid-template-rows: auto minmax(300px, 360px); min-height: 0; overflow: hidden; }}
        .muted {{ color: var(--muted); }}
        .slideover-backdrop {{
            position: fixed;
            inset: 0;
            background: rgba(15, 23, 42, 0.7);
            z-index: 90;
            display: none;
            backdrop-filter: blur(4px);
        }}
        .slideover-backdrop.open {{ display: block; }}
        .slideover {{
            position: fixed;
            top: 0;
            right: 0;
            height: 100vh;
            width: min(52vw, 780px);
            max-width: 92vw;
            background: var(--panel);
            border-left: 1px solid var(--border);
            box-shadow: -10px 0 30px rgba(0, 0, 0, 0.5);
            z-index: 100;
            transform: translateX(100%);
            transition: transform 200ms cubic-bezier(0.16, 1, 0.3, 1);
            display: flex;
            flex-direction: column;
        }}
        .slideover.open {{ transform: translateX(0); }}
        .slideover-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 10px;
            padding: 10px 12px;
            border-bottom: 3px solid var(--border);
            background: var(--accent);
            font-weight: 700;
            font-size: 14px;
            color: var(--text);
        }}
        .slideover-actions {{
            display: inline-flex;
            gap: 8px;
            align-items: center;
            flex-wrap: wrap;
        }}
        .slideover-body {{
            flex: 1;
            min-height: 0;
            overflow: auto;
            padding: 10px 12px;
            background: #ffffff;
        }}
        .json-view {{
            margin: 0;
            white-space: pre-wrap;
            font-family: 'JetBrains Mono', ui-monospace, monospace;
            font-size: 12px;
            line-height: 1.45;
            color: #0b1220;
        }}
        #originalJsonTree {{
            border: 3px solid #000000;
            min-height: 260px;
            background: #ffffff;
            padding: 6px;
        }}
        /* JSONEditor overrides for dark theme */
        .jsoneditor {{
            border: 1px solid var(--border) !important;
            background: #1e293b !important;
        }}
        .jsoneditor-menu {{
            background-color: var(--subpanel) !important;
            border-bottom: 1px solid var(--border) !important;
        }}
        .jsoneditor-navigationbar {{
            background-color: var(--subpanel) !important;
            border-bottom: 1px solid var(--border) !important;
            color: var(--text) !important;
        }}
        .jsoneditor-tree {{
            background-color: #1e293b !important;
            color: #cbd5e1 !important;
        }}
        .jsoneditor-readonly {{
            color: #94a3b8 !important;
        }}
        .jsoneditor-field, .jsoneditor-value {{
            color: #cbd5e1 !important;
        }}
        .jsoneditor-separator, .jsoneditor-bracket {{
            color: #64748b !important;
        }}
        .jsoneditor-contextmenu .jsoneditor-menu {{
            background: #1e293b !important;
        }}
        /* Vis.js Navigation Buttons custom styles for dark theme */
        .vis-network .vis-navigation .vis-button {{
            background-color: var(--subpanel) !important;
            border: 1px solid var(--border) !important;
            color: var(--text) !important;
            border-radius: 6px !important;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1) !important;
        }}
        .vis-network .vis-navigation .vis-button:hover {{
            background-color: var(--border) !important;
            border-color: var(--accent) !important;
        }}
        .vis-network .vis-navigation .vis-button:after {{
            color: var(--text) !important;
        }}
        /* Custom scrollbar styling */
        ::-webkit-scrollbar {{
            width: 8px;
            height: 8px;
        }}
        ::-webkit-scrollbar-track {{
            background: var(--panel);
        }}
        ::-webkit-scrollbar-thumb {{
            background: #334155;
            border-radius: 4px;
        }}
        ::-webkit-scrollbar-thumb:hover {{
            background: #475569;
        }}
        /* Range slider styling */
        input[type="range"] {{
            -webkit-appearance: none;
            width: 100%;
            height: 6px;
            background: var(--border);
            border-radius: 3px;
            outline: none;
        }}
        input[type="range"]::-webkit-slider-thumb {{
            -webkit-appearance: none;
            width: 16px;
            height: 16px;
            border-radius: 50%;
            background: var(--accent);
            cursor: pointer;
            transition: all 0.1s ease;
        }}
        input[type="range"]::-webkit-slider-thumb:hover {{
            transform: scale(1.2);
            box-shadow: 0 0 10px rgba(56, 189, 248, 0.5);
        }}
        /* Equivalent class button styling */
        .class-member-btn {{
            background: var(--subpanel);
            color: var(--text);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 2px 6px;
            font-size: 11px;
            cursor: pointer;
            transition: all 0.15s ease;
        }}
        .class-member-btn:hover {{
            border-color: var(--accent);
            background: var(--border);
        }}
        .class-member-active {{
            background: var(--accent);
            color: #0f172a;
            border: 1px solid var(--accent);
            border-radius: 4px;
            padding: 2px 6px;
            font-size: 11px;
            font-weight: 700;
            cursor: default;
        }}
        /* Custom vis-tooltip style */
        div.vis-tooltip {{
            position: absolute;
            visibility: hidden;
            padding: 10px 14px;
            font-family: 'Inter', system-ui, sans-serif;
            font-size: 12px;
            color: #f8fafc;
            background: rgba(15, 23, 42, 0.9);
            border: 1px solid #334155;
            border-radius: 8px;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3), 0 4px 6px -4px rgba(0, 0, 0, 0.3);
            pointer-events: none;
            z-index: 200;
            white-space: pre-line;
            backdrop-filter: blur(8px);
        }}
    </style>
</head>
<body>
  <div class="header">
        <div>
            <div class="title">AFL Queue Lineage & Execution Inspector</div>
            <div class="subtitle">Explore mutation history → inspect execution traces → compare with control flow</div>
        </div>
        <div class="metrics">
            <div class="metric"><div class="k">Total Inputs</div><div class="v" id="mEntries">-</div></div>
            <div class="metric"><div class="k">Queue Inputs</div><div class="v" id="mQueue">-</div></div>
            <div class="metric"><div class="k">Hangs</div><div class="v" id="mHangs">-</div></div>
            <div class="metric"><div class="k">Crashes</div><div class="v" id="mCrashes">-</div></div>
            <div class="metric" style="border-color: var(--pink);"><div class="k">Races</div><div class="v" id="mRaces">-</div></div>
            <div class="metric"><div class="k">Non-Inst</div><div class="v" id="mNonInst">-</div></div>
            <div class="metric"><div class="k">Equiv Classes</div><div class="v" id="mClasses">-</div></div>
            <div class="metric"><div class="k">Max Depth</div><div class="v" id="mDepth">-</div></div>
            <div class="metric"><div class="k">Avg Nodes</div><div class="v" id="mAvgSkel">-</div></div>
            <div class="metric"><div class="k">Unique Pattern</div><div class="v" id="mUnique">-</div></div>
            <div class="metric"><div class="k">RF Density</div><div class="v" id="mRfDensity">-</div></div>
            <button class="btn btn-primary" id="openStatsBtn" style="align-self: center; margin-left: 6px;padding: 16px; margin-top: -3px;">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 4px;"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
                Dashboard
            </button>
        </div>
  </div>

  <div class="layout">
    <section class="panel">
            <div class="panel-title">1) Mutation Lineage (Queue + Hangs + Crashes + Races + Non-Instantiable)</div>
            <div class="toolbar">
                <span class="toolbar-group">
                    <input id="searchId" type="text" placeholder="entry id: 123 or hangs:123" />
                    <button class="btn btn-primary" id="searchBtn">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                        Find
                    </button>
                    <select id="corpusFilter"><option value="all">All corpora</option><option value="queue">Queue</option><option value="hangs">Hangs</option><option value="crashes">Crashes</option><option value="races">Races</option><option value="non_instantiable">Non-Instantiable</option></select>
                    <select id="classFilter"><option value="all">All classes</option></select>
                </span>
                <span class="toolbar-group">
                    <label><input id="hideDup" type="checkbox" /> hide duplicate patterns</label>
                    <label><input id="leafOnly" type="checkbox" /> leaf mutations only</label>
                    <label><input id="collapseClasses" type="checkbox" /> collapse equivalent groups</label>
                    <label><input id="compactLabels" type="checkbox" /> compact node text</label>
                </span>
                <span class="toolbar-group" style="width: 100%; justify-content: space-between; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 8px; margin-top: 4px;">
                    <div style="display: inline-flex; align-items: center; gap: 6px; flex: 1;">
                        <button class="btn" id="playLineage">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="6 3 20 12 6 21 6 3"/></svg>
                            Play
                        </button>
                        <select id="lineagePlaySpeed" style="min-width: 60px; padding: 4px 6px;">
                            <option value="0.5">0.5x</option>
                            <option value="1" selected>1x</option>
                            <option value="2">2x</option>
                            <option value="4">4x</option>
                        </select>
                        <input id="playbackRange" type="range" min="0" value="0" style="flex: 1; max-width: 220px;" />
                        <span id="playbackStatus" style="font-size: 11px; font-weight: 600; color: var(--muted); min-width: 60px; text-align: left;"></span>
                    </div>
                    <div style="display: inline-flex; align-items: center; gap: 6px;">
                        <button class="btn" id="fitLineage">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/></svg>
                            fit
                        </button>
                        <button class="btn" id="resetLineage">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
                            reset zoom
                        </button>
                        <button class="btn" id="toggleLineagePhysics">toggle physics</button>
                        <button class="btn" id="fullLineage">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"/></svg>
                            fullscreen
                        </button>
                    </div>
                </span>
            </div>
            <div id="lineage" class="graph"></div>
            <div class="legend">
                <div><span class="chip" style="background:#06b6d4;height:10px;"></span>Queue entries</div>
                <div><span class="chip" style="background:#fbbf24;height:10px;"></span>Hangs</div>
                <div><span class="chip" style="background:#f43f5e;height:10px;"></span>Crashes</div>
                <div><span class="chip" style="background:#ec4899;height:10px;"></span>Races</div>
                <div><span class="chip" style="background:#818cf8;height:10px;"></span>Non-Instantiable</div>
                <div><span class="chip" style="background:#f97316;height:10px;"></span>Source nodes</div>
                <div><span class="chip" style="background:#64748b;height:3px;"></span>Parent mutation edge</div>
                <div><span class="chip" style="background:#ec4899;height:10px;"></span>Equivalent class highlight</div>
            </div>
    </section>

    <section class="panel">
      <div class="right-wrap">
                <div class="inspector">
                    <div class="panel-title">2) Execution Trace Inspector</div>
                    <div class="toolbar">
                        <span class="muted" style="font-weight: 700;">Trace Graph</span>
                        <label><input id="compareToggle" type="checkbox" /> compare with</label>
                        <select id="compareQueue"><option value="">entry id</option></select>
                        <button class="btn" id="fitSkeleton">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/></svg>
                            fit
                        </button>
                        <button class="btn" id="resetSkeleton">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
                            reset zoom
                        </button>
                        <button class="btn" id="toggleSkeletonPhysics">toggle physics</button>
                        <button class="btn" id="fullSkeleton">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"/></svg>
                            fullscreen
                        </button>
                        <button class="btn btn-accent" id="viewOriginal">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-right:4px;"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
                            View Raw JSON
                        </button>
                    </div>
                    <div class="selected-info" id="selectedInfo">Select a lineage node to inspect its parallel execution skeleton.</div>
                    <div class="toolbar" id="skeletonStats" style="font-size: 11px; font-weight: 700; color: var(--accent);">Threads: - | Nodes: - | RF: - | SW: - | MO: -</div>
                    <div id="skeleton" class="graph"></div>
                    <div class="details" id="eventDetails"><div class="muted">Selected Event Details</div></div>
                    <div class="toolbar">
                        <span class="muted" style="font-weight: 700;">Location alias</span>
                        <select id="locAliasSelect"><option value="">location id</option></select>
                        <input id="locAliasInput" type="text" placeholder="e.g. shared_counter" />
                        <button class="btn btn-primary" id="saveLocAlias" style="background: var(--accent); color: #0f172a; border-color: var(--accent);">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/></svg>
                            Save
                        </button>
                        <button class="btn" id="clearLocAlias">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/></svg>
                            Clear
                        </button>
                    </div>
                    <div class="legend">
                        <div><span class="chip" style="background:#cbd5e1;height:3px;"></span>PO edge: execution backbone</div>
                        <div><span class="chip" style="background:#10b981;height:3px;"></span>RF edge: causal dependency</div>
                        <div><span class="chip" style="background:#a78bfa;height:3px;"></span>SW edge: synchronization</div>
                        <div><span class="chip" style="background:#fbbf24;border-top:1px dashed #fbbf24;"></span>MO edge: memory order</div>
                        <div><span class="chip" style="background:rgba(96,165,250,0.15);height:10px;"></span>Thread lanes in skeleton</div>
                        <div><span class="chip" style="background:#f97316;height:10px;"></span>Source lineage nodes</div>
                        <div><span class="chip" style="background:#ec4899;height:10px;"></span>Equivalent nodes (selection halo)</div>
                    </div>
        </div>

                <details>
                    <summary>3) Control Flow Graph (optional)</summary>
                    <div class="cfg-wrap">
                        <div class="toolbar">
                            <button class="btn" id="fitCfg">
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/></svg>
                                fit
                            </button>
                            <button class="btn" id="resetCfg">
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
                                reset zoom
                            </button>
                            <button class="btn" id="toggleCfgPhysics">toggle physics</button>
                            <button class="btn" id="fullCfg">
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"/></svg>
                                fullscreen
                            </button>
                        </div>
                        <div id="cfg" class="graph" style="min-height:280px;"></div>
                    </div>
        </details>
      </div>
    </section>
    </div>
 
    <div id=\"statsBackdrop\" class=\"slideover-backdrop\"></div>
    <aside id=\"statsPanel\" class=\"slideover\" aria-hidden=\"true\" style=\"width: min(70vw, 980px);\">
                <div class=\"slideover-header\" style=\"background: var(--warn);\">
                        <span>📊 Fuzzer Performance & Metrics Dashboard</span>
                        <span class=\"slideover-actions\">
                            <button class=\"btn\" id=\"closeStats\">close</button>
                        </span>
                </div>
                <div class=\"slideover-body\" style=\"padding: 16px;\">
                    <h3 style=\"margin-top: 0; border-bottom: 3px solid #000; padding-bottom: 6px;\">Fuzzer Run Metadata</h3>
                    <div id=\"statsMetaGrid\" style=\"display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; margin-bottom: 24px;\"></div>
                    <h3 style=\"border-bottom: 3px solid #000; padding-bottom: 6px;\">Run Timeline Progress</h3>
                    <div style=\"display: grid; grid-template-columns: 1fr; gap: 20px; margin-bottom: 20px;\">
                        <div style=\"border: 3px solid #000; padding: 12px; background: #fff;\">
                            <h4 style=\"margin: 0 0 10px 0;\">WMM Coverage Timeline (MO & RF Edges)</h4>
                            <div style=\"position: relative; height: 260px; width: 100%;\">
                                <canvas id=\"chartCoverage\"></canvas>
                            </div>
                        </div>
                        <div style=\"border: 3px solid #000; padding: 12px; background: #fff;\">
                            <h4 style=\"margin: 0 0 10px 0;\">Fuzzer Findings Over Time (Crashes, Hangs, Races, Queue)</h4>
                            <div style=\"position: relative; height: 260px; width: 100%;\">
                                <canvas id=\"chartFindings\"></canvas>
                            </div>
                        </div>
                        <div style=\"border: 3px solid #000; padding: 12px; background: #fff;\">
                            <h4 style=\"margin: 0 0 10px 0;\">Execution Speed (execs/sec)</h4>
                            <div style=\"position: relative; height: 200px; width: 100%;\">
                                <canvas id=\"chartSpeed\"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
    </aside>

    <div id=\"originalBackdrop\" class=\"slideover-backdrop\"></div>
    <aside id=\"originalPanel\" class=\"slideover\" aria-hidden=\"true\">
                <div class=\"slideover-header\">
                        <span id=\"originalTitle\">Original JSON</span>
                        <span class=\"slideover-actions\">
                            <button class=\"btn\" id=\"expandOriginal\">expand all</button>
                            <button class=\"btn\" id=\"collapseOriginal\">collapse all</button>
                            <button class=\"btn\" id=\"closeOriginal\">close</button>
                        </span>
                </div>
                <div class=\"slideover-body\">
                    <div id=\"originalJsonTree\" class=\"json-view\"></div>
                    <pre id=\"originalJson\" class=\"json-view\">Select an entry to inspect original JSON.</pre>
                </div>
    </aside>

  <script>
    const DATA = {data_json};
        const LINEAGE_SOURCE_BG = '#f59e0b';
        const LINEAGE_SOURCE_BORDER = '#fbbf24';
        const HIGHLIGHT_SEL = '#fef08a';
        const HIGHLIGHT_ANC = '#60a5fa';
        const HIGHLIGHT_DESC = '#22c55e';
        const HIGHLIGHT_EQ = '#ec4899';

        document.getElementById('mEntries').textContent = String(DATA.entryCount);
        document.getElementById('mQueue').textContent = String((DATA.corpusCounts && DATA.corpusCounts.queue) || 0);
        document.getElementById('mHangs').textContent = String((DATA.corpusCounts && DATA.corpusCounts.hangs) || 0);
        document.getElementById('mCrashes').textContent = String((DATA.corpusCounts && DATA.corpusCounts.crashes) || 0);
        document.getElementById('mRaces').textContent = String((DATA.corpusCounts && DATA.corpusCounts.races) || 0);
        document.getElementById('mNonInst').textContent = String((DATA.corpusCounts && DATA.corpusCounts.non_instantiable) || 0);
        document.getElementById('mClasses').textContent = String(DATA.equivClassCount);
        document.getElementById('mDepth').textContent = String(DATA.metrics.maxLineageDepth);
        document.getElementById('mAvgSkel').textContent = Number(DATA.metrics.avgSkeletonSize).toFixed(2);
        document.getElementById('mUnique').textContent = `${{(Number(DATA.metrics.uniqueSkeletonRatio) * 100).toFixed(1)}}%`;
        document.getElementById('mRfDensity').textContent = Number(DATA.metrics.rfDensity).toFixed(3);

        const lineageById = new Map((DATA.lineage.nodes || []).map(n => [String(n.id), n]));
        const lineageEdgesAll = DATA.lineage.edges || [];
        const cfgNodesBase = (DATA.cfg.nodes || []).map(n => Object.assign({{}}, n));
        const cfgEdgesBase = (DATA.cfg.edges || []).map(e => Object.assign({{}}, e));
        const childrenById = DATA.lineageMeta.childrenById || {{}};
        const parentById = DATA.lineageMeta.parentById || {{}};
        const idToClass = DATA.idToClass || {{}};
        const classMembers = DATA.classMembers || {{}};
        const originalById = DATA.originalById || {{}};

        let currentSelectedQueueId = null;
        let currentSkeletonMeta = {{}};
        let currentSkeletonNodes = [];
        let currentSkeletonEdges = [];
        let skeletonBaseStyleById = new Map();
        const cfgBaseStyleById = new Map();
        const expandedClasses = new Set();
        const physicsState = {{ lineage: false, skeleton: false, cfg: false }};
        let originalJsonEditor = null;
        const lineagePlayback = {{
            timer: null,
            active: false,
            visibleCount: null,
            speed: 1,
        }};

        function classColor(classId) {{
            const raw = String(classId);
            let h = 0;
            for (let i = 0; i < raw.length; i += 1) h = (h * 31 + raw.charCodeAt(i)) % 360;
            return `hsl(${{h}}, 62%, 52%)`;
        }}

        function normalizeMultiline(text) {{
            return String(text || '').replace(/\\n/g, '<br/>');
        }}

        function baseLineageNodeStyle(node) {{
            const cls = String(node.classId || idToClass[String(node.id)] || '1');
            const c = classColor(cls);
            const isSource = Boolean(node.isSource);
            const corpus = String(node.corpus || '').toLowerCase();
            const corpusBg = corpus === 'crashes' ? '#f43f5e' : 
                             (corpus === 'hangs' ? '#fbbf24' : 
                             (corpus === 'races' ? '#ec4899' : 
                             (corpus === 'non_instantiable' ? '#818cf8' : '#06b6d4')));
            return {{
                id: String(node.id),
                label: normalizeMultiline(node.label),
                title: node.title,
                shape: 'dot',
                x: node.x,
                y: node.y,
                fixed: true,
                physics: false,
                size: node.size || 14,
                classId: cls,
                isLeaf: Boolean(node.isLeaf),
                isSource,
                borderWidth: isSource ? 4 : 2,
                color: {{
                    background: isSource ? '#f97316' : corpusBg,
                    border: isSource ? '#fdba74' : '#1e293b',
                    highlight: {{
                        background: isSource ? '#fbbf24' : c,
                        border: isSource ? '#fde68a' : '#f8fafc',
                    }},
                }},
                font: {{ color: '#f8fafc', size: 11, face: 'Inter, system-ui' }},
                fileName: node.fileName,
                filePath: node.filePath
            }};
        }}

        const lineageNodesDs = new vis.DataSet([]);
        const lineageEdgesDs = new vis.DataSet([]);

        const lineageOptions = {{
            interaction: {{ hover: true, navigationButtons: true, keyboard: true }},
            physics: {{
                enabled: false,
                forceAtlas2Based: {{ gravitationalConstant: -22, springLength: 110, springConstant: 0.04 }},
                maxVelocity: 26,
                stabilization: {{ iterations: 90 }}
            }},
            edges: {{
                arrows: {{ to: {{ enabled: true, scaleFactor: 0.7 }} }},
                color: {{ inherit: false }},
                smooth: false,
                font: {{ size: 10, color: '#cbd5e1', strokeWidth: 0, align: 'top' }},
            }},
            nodes: {{
                shadow: false,
            }},
            layout: {{ improvedLayout: true }}
        }};

        const skeletonOptions = {{
            interaction: {{ hover: true, navigationButtons: true, keyboard: true }},
            physics: {{ enabled: false }},
            edges: {{ smooth: false, font: {{ size: 10, color: '#cbd5e1' }} }},
            layout: {{ improvedLayout: false }}
        }};

        const cfgOptions = {{
            interaction: {{ hover: true, navigationButtons: true, keyboard: true }},
            physics: {{ enabled: false }},
            edges: {{ smooth: {{ enabled: true, type: 'dynamic' }}, font: {{ size: 9, color: '#cbd5e1' }} }},
            layout: {{ improvedLayout: false }}
        }};

        const lineageNetwork = new vis.Network(
            document.getElementById('lineage'),
            {{ nodes: lineageNodesDs, edges: lineageEdgesDs }},
            lineageOptions,
        );

        const skeletonNodesDs = new vis.DataSet([]);
        const skeletonEdgesDs = new vis.DataSet([]);
        const skeletonNetwork = new vis.Network(
            document.getElementById('skeleton'),
            {{ nodes: skeletonNodesDs, edges: skeletonEdgesDs }},
            skeletonOptions,
        );

        const cfgLaneNodesBase = (DATA.cfg.laneNodes || []).map(n => Object.assign({{}}, n));

        function getAliasMap() {{
            return JSON.parse(localStorage.getItem('afl_loc_alias_map_v1') || '{{}}');
        }}

        function aliasOf(locId) {{
            const aliasMap = getAliasMap();
            return aliasMap[String(locId)] || String(locId);
        }}

        function cfgLabelWithAlias(node) {{
            const rawLabel = String(node.label || '');
            const locId = String(node.locationId || '');
            if (!locId) return rawLabel;
            return normalizeMultiline(rawLabel.replace(`(${{locId}},`, `(${{aliasOf(locId)}},`));
        }}

        const cfgNodesDs = new vis.DataSet([
            ...cfgLaneNodesBase.map(n => Object.assign({{
                selectable: false,
                chosen: false,
                physics: false,
                fixed: true,
            }}, n)),
            ...cfgNodesBase.map(n => {{
                const kind = String(n.title || '').includes('kind=R') ? 'R' : (String(n.title || '').includes('kind=W') ? 'W' : '');
                let bg = '#334155';
                let border = '#475569';
                if (kind === 'R') {{
                    bg = '#1e3a8a';
                    border = '#3b82f6';
                }} else if (kind === 'W') {{
                    bg = '#581c87';
                    border = '#a855f7';
                }}
                return Object.assign({{}}, n, {{
                    label: cfgLabelWithAlias(n),
                    color: {{ 
                        border: border, 
                        background: bg, 
                        highlight: {{ border: '#fbbf24', background: bg }}, 
                        hover: {{ border: '#fbbf24', background: bg }} 
                    }},
                    borderWidth: 2,
                    font: {{ color: '#f8fafc', size: 11, face: 'Inter, system-ui' }}
                }});
            }}),
        ]);
        for (const n of cfgNodesDs.get()) {{
            if (String(n.id).startsWith('cfg-lane:')) continue;
            cfgBaseStyleById.set(String(n.id), {{
                borderWidth: Number(n.borderWidth || 2),
                color: {{
                    border: (n.color && n.color.border) ? n.color.border : '#475569',
                    background: (n.color && n.color.background) ? n.color.background : '#334155',
                }},
            }});
        }}
        const cfgEdgesDs = new vis.DataSet(cfgEdgesBase);
        const cfgNetwork = new vis.Network(
            document.getElementById('cfg'),
            {{ nodes: cfgNodesDs, edges: cfgEdgesDs }},
            cfgOptions,
        );

        function eqClassRepresentativeSet() {{
            const reps = new Set();
            for (const members of Object.values(classMembers)) {{
                if (!Array.isArray(members) || members.length === 0) continue;
                reps.add(String(members[0]));
            }}
            return reps;
        }}

        function collectVisibleNodeIds() {{
            const cls = document.getElementById('classFilter').value;
            const corpus = document.getElementById('corpusFilter').value;
            const hideDup = document.getElementById('hideDup').checked;
            const leafOnly = document.getElementById('leafOnly').checked;
            const reps = eqClassRepresentativeSet();
            const visible = new Set();
            for (const node of DATA.lineage.nodes || []) {{
                const id = String(node.id);
                const nodeClass = String(node.classId || idToClass[id] || '');
                const nodeCorpus = String(node.corpus || '');
                if (cls !== 'all' && nodeClass !== cls) continue;
                if (corpus !== 'all' && nodeCorpus !== corpus) continue;
                if (leafOnly && !node.isLeaf) continue;
                if (hideDup && !reps.has(id)) continue;
                visible.add(id);
            }}
            return visible;
        }}

        function orderedVisibleLineageIds(visibleSet) {{
            const nodes = (DATA.lineage.nodes || [])
                .filter(node => visibleSet.has(String(node.id)));
            
            const sortedNodes = nodes.slice().sort((a, b) => {{
                const ta = a.discoveryTime ?? 0;
                const tb = b.discoveryTime ?? 0;
                if (ta !== tb) return ta - tb;
                const ia = Number(a.origId || 0);
                const ib = Number(b.origId || 0);
                if (ia !== ib) return ia - ib;
                const corpusOrder = {{ queue: 0, hangs: 1, crashes: 2, races: 3, non_instantiable: 4 }};
                const ca = corpusOrder[String(a.corpus || '').toLowerCase()] ?? 99;
                const cb = corpusOrder[String(b.corpus || '').toLowerCase()] ?? 99;
                if (ca !== cb) return ca - cb;
                return String(a.id).localeCompare(String(b.id));
            }});

            const nodeIdsInSet = new Set(sortedNodes.map(n => String(n.id)));
            const visited = new Set();
            const temp = new Set();
            const result = [];

            function visit(nodeId) {{
                if (visited.has(nodeId)) return;
                if (temp.has(nodeId)) return;
                
                temp.add(nodeId);
                const parentId = parentById[nodeId];
                if (parentId && nodeIdsInSet.has(String(parentId))) {{
                    visit(String(parentId));
                }}
                
                temp.delete(nodeId);
                visited.add(nodeId);
                result.push(nodeId);
            }}

            for (const node of sortedNodes) {{
                visit(String(node.id));
            }}

            return result;
        }}

        function playbackIntervalMs() {{
            const speed = Number(lineagePlayback.speed || 1);
            const clamped = Number.isFinite(speed) && speed > 0 ? speed : 1;
            return Math.max(80, Math.floor(520 / clamped));
        }}

        function updatePlayLineageButton() {{
            const btn = document.getElementById('playLineage');
            if (lineagePlayback.active) {{
                btn.innerHTML = `
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"/></svg>
                    Stop
                `;
            }} else {{
                btn.innerHTML = `
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="6 3 20 12 6 21 6 3"/></svg>
                    Play
                `;
            }}
        }}

        function updatePlaybackSlider() {{
            const visible = collectVisibleNodeIds();
            const orderedIds = orderedVisibleLineageIds(visible);
            const slider = document.getElementById('playbackRange');
            const status = document.getElementById('playbackStatus');
            
            if (orderedIds.length === 0) {{
                slider.max = 0;
                slider.value = 0;
                slider.disabled = true;
                status.textContent = '0 / 0';
                return;
            }}
            
            slider.disabled = false;
            slider.max = orderedIds.length;
            
            const currentVal = lineagePlayback.visibleCount === null ? orderedIds.length : lineagePlayback.visibleCount;
            slider.value = currentVal;
            status.textContent = `${{currentVal}} / ${{orderedIds.length}}`;
        }}

        function stopLineagePlayback(showAll = true) {{
            if (lineagePlayback.timer !== null) {{
                clearInterval(lineagePlayback.timer);
                lineagePlayback.timer = null;
            }}
            lineagePlayback.active = false;
            if (showAll) lineagePlayback.visibleCount = null;
            updatePlayLineageButton();
            updatePlaybackSlider();
            refreshLineageGraph({{ autoNavigate: false }});
        }}

        function startLineagePlayback() {{
            const visible = collectVisibleNodeIds();
            const orderedIds = orderedVisibleLineageIds(visible);
            if (orderedIds.length === 0) return;

            if (lineagePlayback.timer !== null) {{
                clearInterval(lineagePlayback.timer);
                lineagePlayback.timer = null;
            }}

            lineagePlayback.active = true;
            if (lineagePlayback.visibleCount === null || lineagePlayback.visibleCount >= orderedIds.length) {{
                lineagePlayback.visibleCount = 0;
            }}
            updatePlayLineageButton();
            updatePlaybackSlider();
            refreshLineageGraph({{ autoNavigate: false }});

            lineagePlayback.timer = setInterval(() => {{
                const nowVisible = collectVisibleNodeIds();
                const nowOrderedIds = orderedVisibleLineageIds(nowVisible);
                if (nowOrderedIds.length === 0) {{
                    stopLineagePlayback(true);
                    return;
                }}

                const next = Number(lineagePlayback.visibleCount || 0) + 1;
                lineagePlayback.visibleCount = Math.min(next, nowOrderedIds.length);
                updatePlaybackSlider();
                refreshLineageGraph({{ autoNavigate: false }});

                if (lineagePlayback.visibleCount >= nowOrderedIds.length) {{
                    stopLineagePlayback(true);
                }}
            }}, playbackIntervalMs());
        }}

        function entityIdForRawNode(rawNode, collapseEnabled) {{
            const id = String(rawNode.id);
            const classId = String(rawNode.classId || idToClass[id] || '');
            const members = classMembers[classId] || [];
            if (!collapseEnabled || members.length <= 1 || expandedClasses.has(classId)) return id;
            return `cluster:C${{classId}}`;
        }}

        function refreshLineageGraph(options = {{}}) {{
            const autoNavigate = options.autoNavigate !== false;
            const visible = collectVisibleNodeIds();
            const orderedIds = orderedVisibleLineageIds(visible);
            const visibleForRender =
                lineagePlayback.visibleCount === null
                    ? visible
                    : new Set(orderedIds.slice(0, Math.max(0, Number(lineagePlayback.visibleCount || 0))));
            const collapseEnabled = document.getElementById('collapseClasses').checked;
            const compactLabels = document.getElementById('compactLabels').checked;
            const nodes = [];
            const added = new Set();
            for (const rawNode of DATA.lineage.nodes || []) {{
                const id = String(rawNode.id);
                if (!visibleForRender.has(id)) continue;
                const entityId = entityIdForRawNode(rawNode, collapseEnabled);
                if (entityId.startsWith('cluster:')) {{
                    if (added.has(entityId)) continue;
                    added.add(entityId);
                    const classId = String(rawNode.classId || idToClass[id] || '');
                    const members = classMembers[classId] || [];
                    const c = classColor(classId);
                    nodes.push({{
                        id: entityId,
                        label: `[C${{classId}} ×${{members.length}}]`,
                        title: `equivalence class C${{classId}}\nsize=${{members.length}}\n(click to expand/collapse)`,
                        shape: 'box',
                        x: rawNode.x,
                        y: rawNode.y,
                        fixed: true,
                        physics: false,
                        classId,
                        isCluster: true,
                        size: 24,
                        borderWidth: 3,
                        color: {{ background: c, border: '#f8fafc', highlight: {{ background: c, border: '#fef3c7' }} }},
                        font: {{ color: '#0b1220', size: 12, face: 'ui-sans-serif' }},
                    }});
                    continue;
                }}
                const styled = baseLineageNodeStyle(rawNode);
                if (compactLabels) styled.label = `#${{rawNode.origId}}`;
                nodes.push(styled);
            }}

            const edgeMap = new Map();
            for (const edge of lineageEdgesAll) {{
                const rawFrom = lineageById.get(String(edge.from));
                const rawTo = lineageById.get(String(edge.to));
                if (!rawFrom || !rawTo) continue;
                if (!visibleForRender.has(String(rawFrom.id)) || !visibleForRender.has(String(rawTo.id))) continue;
                const from = entityIdForRawNode(rawFrom, collapseEnabled);
                const to = entityIdForRawNode(rawTo, collapseEnabled);
                if (from === to) continue;
                const key = `${{from}}->${{to}}`;
                edgeMap.set(key, (edgeMap.get(key) || 0) + 1);
            }}

            const edges = [];
            for (const [key, count] of edgeMap.entries()) {{
                const [from, to] = key.split('->');
                edges.push({{
                    from,
                    to,
                    title: count > 1 ? `parent edges: ${{count}}` : 'parent',
                    arrows: 'to',
                    color: '#1f2d3d',
                    width: 1.8 + Math.min(3.6, count * 0.35),
                    smooth: false,
                }});
            }}

            lineageNodesDs.clear();
            lineageEdgesDs.clear();
            lineageNodesDs.add(nodes);
            lineageEdgesDs.add(edges);

            if (autoNavigate && currentSelectedQueueId) {{
                applyLineageSelectionHighlight(String(currentSelectedQueueId));
                lineageNetwork.focus(String(currentSelectedQueueId), {{ scale: 1.08, animation: true }});
            }} else if (autoNavigate) {{
                lineageNetwork.fit({{ animation: true }});
            }} else if (currentSelectedQueueId) {{
                applyLineageSelectionHighlight(String(currentSelectedQueueId));
            }}
        }}

        function setClassFilterOptions() {{
            const sel = document.getElementById('classFilter');
            const classes = Object.keys(classMembers).map(Number).sort((a, b) => a - b);
            for (const cls of classes) {{
                const opt = document.createElement('option');
                opt.value = String(cls);
                const members = classMembers[String(cls)] || [];
                opt.textContent = `C${{cls}} (${{members.length}})`;
                sel.appendChild(opt);
            }}
        }}

        function setCompareQueueOptions() {{
            const sel = document.getElementById('compareQueue');
            const nodes = (DATA.lineage.nodes || []).slice().sort((a, b) => {{
                const ca = String(a.corpus || 'zz');
                const cb = String(b.corpus || 'zz');
                if (ca !== cb) return ca.localeCompare(cb);
                return Number(a.origId || 0) - Number(b.origId || 0);
            }});
            for (const node of nodes) {{
                const opt = document.createElement('option');
                opt.value = String(node.id);
                const tag = String(node.corpus || '?').toUpperCase().slice(0, 1);
                opt.textContent = `#${{node.origId}} [${{tag}}]`;
                sel.appendChild(opt);
            }}
        }}

        function collectAllLocationIds() {{
            const ids = new Set();
            for (const node of (DATA.cfg.nodes || [])) {{
                if (node.locationId !== undefined) ids.add(String(node.locationId));
            }}
            for (const skel of Object.values(DATA.skeletonById || {{}})) {{
                const meta = (skel && skel.nodeMeta) ? skel.nodeMeta : {{}};
                for (const m of Object.values(meta)) {{
                    if (m && m.location_id !== undefined) ids.add(String(m.location_id));
                    else if (m && m.location !== undefined) ids.add(String(m.location));
                }}
            }}
            return Array.from(ids).sort((a, b) => (_safeNumeric(a) - _safeNumeric(b)) || a.localeCompare(b));
        }}

        function _safeNumeric(value) {{
            const n = Number(value);
            return Number.isFinite(n) ? n : Number.MAX_SAFE_INTEGER;
        }}

        function setLocationAliasOptions() {{
            const sel = document.getElementById('locAliasSelect');
            sel.innerHTML = '<option value="">location id</option>';
            for (const locId of collectAllLocationIds()) {{
                const opt = document.createElement('option');
                opt.value = locId;
                opt.textContent = `${{locId}}`;
                sel.appendChild(opt);
            }}
        }}

        function refreshCfgAliases() {{
            const aliasMap = getAliasMap();
            const updates = [];
            for (const node of cfgNodesDs.get()) {{
                const id = String(node.id);
                if (id.startsWith('cfg-lane:')) continue;
                const locId = String(node.locationId || '');
                const aliased = locId ? String(aliasMap[locId] || locId) : '';
                const rawLabel = String(node.label || '');
                const nextLabel = locId ? rawLabel.replace(/\\(([^,]+),/, `(${{aliased}},`) : rawLabel;
                updates.push({{ id: node.id, label: nextLabel }});
            }}
            if (updates.length > 0) cfgNodesDs.update(updates);
        }}

        function refreshSkeletonAliases() {{
            const aliasMap = getAliasMap();
            const updates = [];
            for (const node of skeletonNodesDs.get()) {{
                const id = String(node.id);
                if (id.startsWith('lane:')) continue;
                const meta = currentSkeletonMeta[id] || {{}};
                const kind = String(meta.kind || '?');
                const mode = String(meta.mode || '?');
                const locId = String(meta.location_id || meta.location || '?');
                const alias = String(aliasMap[locId] || locId);
                updates.push({{ id, label: `${{kind}}(${{alias}},${{mode}})` }});
            }}
            if (updates.length > 0) skeletonNodesDs.update(updates);
        }}

        function nodeSignature(meta) {{
            if (!meta) return '';
            return [meta.thread_id, meta.instruction_id, meta.visit_id, meta.kind, meta.location].join('|');
        }}

        function edgeSignature(fromSig, toSig, rel) {{
            return `${{fromSig}}->${{toSig}}:${{rel || '?'}}`;
        }}

        function buildDiffSkeleton(baseSkel, cmpSkel) {{
            const aMeta = baseSkel.nodeMeta || {{}};
            const bMeta = cmpSkel.nodeMeta || {{}};

            const aSigByNode = new Map();
            const bSigByNode = new Map();
            const nodeBySig = new Map();

            for (const n of baseSkel.nodes || []) {{
                const sig = nodeSignature(aMeta[n.id]);
                if (!sig) continue;
                aSigByNode.set(String(n.id), sig);
                if (!nodeBySig.has(sig)) nodeBySig.set(sig, Object.assign({{}}, n, {{ __origin: 'A' }}));
            }}
            for (const n of cmpSkel.nodes || []) {{
                const sig = nodeSignature(bMeta[n.id]);
                if (!sig) continue;
                bSigByNode.set(String(n.id), sig);
                if (!nodeBySig.has(sig)) nodeBySig.set(sig, Object.assign({{}}, n, {{ __origin: 'B' }}));
            }}

            const aSigs = new Set(aSigByNode.values());
            const bSigs = new Set(bSigByNode.values());

            const mergedNodes = [];
            for (const [sig, n] of nodeBySig.entries()) {{
                const inA = aSigs.has(sig);
                const inB = bSigs.has(sig);
                mergedNodes.push(Object.assign({{}}, n, {{
                    id: `d:${{sig}}`,
                    diffTag: inA && inB ? 'shared' : (inA ? 'onlyA' : 'onlyB'),
                    label: (n.label || '?'),
                }}));
            }}

            const aEdgeSet = new Set();
            const bEdgeSet = new Set();
            for (const e of baseSkel.edges || []) {{
                const fs = aSigByNode.get(String(e.from));
                const ts = aSigByNode.get(String(e.to));
                if (!fs || !ts) continue;
                aEdgeSet.add(edgeSignature(fs, ts, e.relation));
            }}
            for (const e of cmpSkel.edges || []) {{
                const fs = bSigByNode.get(String(e.from));
                const ts = bSigByNode.get(String(e.to));
                if (!fs || !ts) continue;
                bEdgeSet.add(edgeSignature(fs, ts, e.relation));
            }}

            const mergedEdges = [];
            const allEdges = new Set([...aEdgeSet, ...bEdgeSet]);
            for (const sig of allEdges) {{
                const [pair, rel] = sig.split(':');
                const [fromSig, toSig] = pair.split('->');
                const inA = aEdgeSet.has(sig);
                const inB = bEdgeSet.has(sig);
                mergedEdges.push({{
                    from: `d:${{fromSig}}`,
                    to: `d:${{toSig}}`,
                    relation: rel,
                    label: rel,
                    diffTag: inA && inB ? 'shared' : (inA ? 'onlyA' : 'onlyB'),
                    arrows: 'to',
                }});
            }}

            const mergedMeta = {{}};
            for (const [sig, n] of nodeBySig.entries()) {{
                const baseMeta = (aMeta[n.id] || bMeta[n.id] || {{}});
                mergedMeta[`d:${{sig}}`] = baseMeta;
            }}

            return {{
                nodes: mergedNodes,
                edges: mergedEdges,
                laneNodes: baseSkel.laneNodes || cmpSkel.laneNodes || [],
                nodeMeta: mergedMeta,
                stats: {{
                    threadCount: Math.max(baseSkel.stats?.threadCount || 0, cmpSkel.stats?.threadCount || 0),
                    nodeCount: mergedNodes.length,
                    poCount: mergedEdges.filter(e => e.relation === 'PO').length,
                    rfCount: mergedEdges.filter(e => e.relation === 'RF').length,
                    swCount: mergedEdges.filter(e => e.relation === 'SW').length,
                    moCount: mergedEdges.filter(e => e.relation === 'MO').length,
                    tcjCount: mergedEdges.filter(e => e.relation === 'TCJ').length,
                }},
            }};
        }}

        function ancestorsOf(nodeId) {{
            const result = new Set();
            let cur = String(nodeId);
            while (parentById[cur] !== null && parentById[cur] !== undefined) {{
                const parent = String(parentById[cur]);
                if (result.has(parent)) break;
                result.add(parent);
                cur = parent;
            }}
            return result;
        }}

        function descendantsOf(nodeId) {{
            const result = new Set();
            const queue = [String(nodeId)];
            while (queue.length > 0) {{
                const cur = queue.shift();
                const kids = childrenById[cur] || [];
                for (const kid of kids) {{
                    const k = String(kid);
                    if (result.has(k)) continue;
                    result.add(k);
                    queue.push(k);
                }}
            }}
            return result;
        }}

        function applyLineageSelectionHighlight(selectedId) {{
            const hasSelection = !!selectedId;
            const anc = ancestorsOf(selectedId);
            const desc = descendantsOf(selectedId);
            const classId = String(idToClass[selectedId] || '');
            const eq = new Set((classMembers[classId] || []).map(String));
            const collapseEnabled = document.getElementById('collapseClasses').checked;

            const updates = [];
            for (const node of lineageNodesDs.get()) {{
                const id = String(node.id);
                
                let baseNode = lineageById.get(id);
                let isCluster = id.startsWith('cluster:') && collapseEnabled;
                
                let baseStyle = isCluster ? {{
                    size: 24,
                    borderWidth: 2,
                    color: {{ background: classColor(id.replace('cluster:C', '')), border: '#334155' }},
                    font: {{ color: '#ffffff', size: 11 }}
                }} : baseLineageNodeStyle(baseNode || node);

                let bg = baseStyle.color.background;
                let border = baseStyle.color.border;
                let bw = baseStyle.borderWidth;
                let fontColor = '#f8fafc';
                
                let isRelated = !hasSelection;
                
                if (hasSelection) {{
                    if (isCluster) {{
                        const clusterClassId = String(id.replace('cluster:C', ''));
                        const members = new Set((classMembers[clusterClassId] || []).map(String));
                        const hasSel = members.has(String(selectedId));
                        const hasAnc = [...members].some(member => anc.has(member));
                        const hasDesc = [...members].some(member => desc.has(member));
                        const hasEq = [...members].some(member => eq.has(member));

                        if (hasSel) {{
                            bg = '#fbbf24';
                            border = HIGHLIGHT_SEL;
                            bw = 5;
                            isRelated = true;
                        }} else if (hasAnc) {{
                            border = HIGHLIGHT_ANC;
                            bw = 4;
                            isRelated = true;
                        }} else if (hasDesc) {{
                            border = HIGHLIGHT_DESC;
                            bw = 4;
                            isRelated = true;
                        }} else if (hasEq) {{
                            border = HIGHLIGHT_EQ;
                            bw = 4;
                            isRelated = true;
                        }}
                    }} else {{
                        if (id === String(selectedId)) {{
                            bg = '#fbbf24';
                            border = HIGHLIGHT_SEL;
                            bw = 5;
                            isRelated = true;
                        }} else if (anc.has(id)) {{
                            border = HIGHLIGHT_ANC;
                            bw = 4;
                            isRelated = true;
                        }} else if (desc.has(id)) {{
                            border = HIGHLIGHT_DESC;
                            bw = 4;
                            isRelated = true;
                        }} else if (eq.has(id)) {{
                            border = HIGHLIGHT_EQ;
                            bw = 4;
                            isRelated = true;
                        }}
                    }}
                }}

                if (hasSelection && !isRelated) {{
                    bg = 'rgba(74, 85, 104, 0.1)';
                    border = 'rgba(74, 85, 104, 0.15)';
                    fontColor = 'rgba(148, 163, 184, 0.2)';
                    bw = 1;
                }}

                updates.push({{ 
                    id, 
                    color: {{ 
                        background: bg, 
                        border,
                        highlight: baseStyle.color.highlight || {{ background: bg, border: border }}
                    }}, 
                    borderWidth: bw,
                    font: {{ color: fontColor, size: baseStyle.font.size, face: baseStyle.font.face }}
                }});
            }}
            lineageNodesDs.update(updates);
            
            const edgeUpdates = [];
            for (const edge of lineageEdgesDs.get()) {{
                const from = String(edge.from);
                const to = String(edge.to);
                
                let isEdgeRelated = !hasSelection;
                if (hasSelection) {{
                    const fromSel = from === String(selectedId) || (from.startsWith('cluster:') && (classMembers[from.replace('cluster:C', '')] || []).includes(String(selectedId)));
                    const toSel = to === String(selectedId) || (to.startsWith('cluster:') && (classMembers[to.replace('cluster:C', '')] || []).includes(String(selectedId)));
                    
                    const fromAnc = anc.has(from) || (from.startsWith('cluster:') && [...(classMembers[from.replace('cluster:C', '')] || [])].some(m => anc.has(m)));
                    const toAnc = anc.has(to) || (to.startsWith('cluster:') && [...(classMembers[to.replace('cluster:C', '')] || [])].some(m => anc.has(m)));
                    
                    const fromDesc = desc.has(from) || (from.startsWith('cluster:') && [...(classMembers[from.replace('cluster:C', '')] || [])].some(m => desc.has(m)));
                    const toDesc = desc.has(to) || (to.startsWith('cluster:') && [...(classMembers[to.replace('cluster:C', '')] || [])].some(m => desc.has(m)));
                    
                    if ((fromAnc && toAnc) || (fromAnc && toSel) || (fromSel && toDesc) || (fromDesc && toDesc)) {{
                        isEdgeRelated = true;
                    }}
                }}
                
                edgeUpdates.push({{
                    id: edge.id,
                    color: isEdgeRelated ? '#64748b' : 'rgba(74, 85, 104, 0.1)',
                    width: isEdgeRelated ? 2.5 : 1
                }});
            }}
            lineageEdgesDs.update(edgeUpdates);

            if (lineageNodesDs.get(String(selectedId))) {{
                lineageNetwork.selectNodes([String(selectedId)]);
            }}
        }}

        function edgeRelationStyle(rel) {{
            if (rel === 'PO') return {{ color: '#111111', width: 3.2, dashes: false, smooth: false }};
            if (rel === 'RF') return {{ color: '#22c55e', width: 2.4, dashes: false, smooth: {{ enabled: true, type: 'curvedCCW', roundness: 0.2 }} }};
            if (rel === 'SW') return {{ color: '#8b5cf6', width: 2.8, dashes: false, smooth: {{ enabled: true, type: 'curvedCW', roundness: 0.24 }} }};
            if (rel === 'MO') return {{ color: '#f59e0b', width: 1.2, dashes: [6, 6], smooth: {{ enabled: true, type: 'curvedCW', roundness: 0.16 }} }};
            return {{ color: '#94a3b8', width: 1.5, dashes: false, smooth: false }};
        }}

        function setSkeletonGraph(queueId) {{
            let skel = DATA.skeletonById[String(queueId)] || {{ nodes: [], edges: [], laneNodes: [], nodeMeta: {{}}, stats: {{}}, raceInfo: {{}} }};
            const cmpEnabled = document.getElementById('compareToggle').checked;
            const cmpId = (document.getElementById('compareQueue').value || '').trim();
            if (cmpEnabled && cmpId && DATA.skeletonById[String(cmpId)] && String(cmpId) !== String(queueId)) {{
                skel = buildDiffSkeleton(skel, DATA.skeletonById[String(cmpId)]);
            }}
            currentSkeletonMeta = skel.nodeMeta || {{}};
            currentSkeletonNodes = (skel.nodes || []).map(n => Object.assign({{}}, n));
            currentSkeletonEdges = (skel.edges || []).map(e => Object.assign({{}}, e));
            const raceInfo = skel.raceInfo || {{}};

            const laneNodes = (skel.laneNodes || []).map(n => Object.assign({{
                color: {{
                    background: 'rgba(96,165,250,0.08)',
                    border: 'rgba(96,165,250,0.25)',
                    highlight: {{ background: 'rgba(96,165,250,0.08)', border: 'rgba(96,165,250,0.25)' }},
                    hover: {{ background: 'rgba(96,165,250,0.08)', border: 'rgba(96,165,250,0.25)' }},
                }},
                borderWidth: 1,
                selectable: false,
                chosen: false,
            }}, n));

            const dataNodes = [
                ...laneNodes,
                ...currentSkeletonNodes.map(n => {{
                    const threadId = String(n.threadId || '?');
                    const laneColor = classColor(Number(threadId) + 1);
                    const meta = currentSkeletonMeta[String(n.id)] || {{}};
                    const locId = String(meta.location_id || meta.location || '?');
                    const aliasMap = JSON.parse(localStorage.getItem('afl_loc_alias_map_v1') || '{{}}');
                    const alias = aliasMap[locId] || locId;
                    const mode = String(meta.mode || '?');
                    const kind = String(meta.kind || '?');
                    const visitId = String(meta.visit_id || '?');
                    let bg = laneColor;
                    let border = '#334155';
                    let borderWidth = 1.5;
                    let raceLabel = '';

                    // Check if this node is a racing instruction
                    let isRaceNode = false;
                    if (raceInfo.race_0 && 
                        String(meta.thread_id) === String(raceInfo.race_0.thread_id) && 
                        String(meta.instruction_id) === String(raceInfo.race_0.instruction_id) && 
                        String(meta.visit_id) === String(raceInfo.race_0.visit_id)) {{
                        isRaceNode = true;
                        raceLabel = ' [R0]';
                    }} else if (raceInfo.race_1 && 
                        String(meta.thread_id) === String(raceInfo.race_1.thread_id) && 
                        String(meta.instruction_id) === String(raceInfo.race_1.instruction_id) && 
                        String(meta.visit_id) === String(raceInfo.race_1.visit_id)) {{
                        isRaceNode = true;
                        raceLabel = ' [R1]';
                    }}

                    if (n.diffTag === 'shared') {{ bg = '#93c5fd'; border = '#1e3a8a'; }}
                    if (n.diffTag === 'onlyA') {{ bg = '#86efac'; border = '#166534'; }}
                    if (n.diffTag === 'onlyB') {{ bg = '#fda4af'; border = '#9f1239'; }}

                    if (isRaceNode) {{
                        bg = '#7f1d1d';
                        border = '#ef4444';
                        borderWidth = 4;
                    }}

                    return Object.assign({{}}, n, {{
                        label: `v${{visitId}} ${{kind}}(${{alias}},${{mode}})${{raceLabel}}`,
                        color: {{ border, background: bg, highlight: {{ border: '#f8fafc', background: bg }} }},
                        borderWidth: borderWidth,
                        font: {{ color: '#f8fafc', size: 12, face: 'Inter, system-ui', bold: isRaceNode ? 'bold' : 'normal' }},
                    }});
                }}),
            ];

            skeletonBaseStyleById = new Map();
            for (const node of dataNodes) {{
                const nodeId = String(node.id);
                if (nodeId.startsWith('lane:')) continue;
                skeletonBaseStyleById.set(nodeId, {{
                    borderWidth: Number(node.borderWidth || 1.5),
                    color: {{
                        border: (node.color && node.color.border) ? node.color.border : '#334155',
                        background: (node.color && node.color.background) ? node.color.background : '#ffffff',
                    }},
                }});
            }}

            const dataEdges = currentSkeletonEdges.map(e => {{
                const styled = Object.assign({{ arrows: 'to', font: {{ size: 9, color: '#111111' }} }}, e, edgeRelationStyle(e.relation));
                if (e.diffTag === 'onlyA') styled.color = '#16a34a';
                if (e.diffTag === 'onlyB') styled.color = '#e11d48';
                if (e.diffTag === 'shared') styled.color = '#0f172a';
                return styled;
            }});

            skeletonNodesDs.clear();
            skeletonEdgesDs.clear();
            skeletonNodesDs.add(dataNodes);
            skeletonEdgesDs.add(dataEdges);

            const selectedNode = lineageById.get(String(queueId)) || {{}};
            const selectedCorpus = String(selectedNode.corpus || 'entry');
            const selectedOrigId = selectedNode.origId !== undefined ? selectedNode.origId : queueId;
            const fileName = selectedNode.fileName || '';
            let infoText = `selected ${{selectedCorpus}} #${{selectedOrigId}} | threads=${{skel.stats.threadCount || 0}} nodes=${{skel.stats.nodeCount || 0}} rf=${{skel.stats.rfCount || 0}}`;
            
            // Find other members of the equivalence class
            const classId = String(idToClass[String(queueId)] || '');
            const members = classMembers[classId] || [];
            let classMembersHtml = '';
            if (members.length > 1) {{
                classMembersHtml = `<div style="margin-top:6px; display:flex; align-items:center; gap:6px; flex-wrap:wrap;">` +
                    `<span style="color:var(--muted); font-size:11px;">Equivalent inputs (${{members.length}}):</span>`;
                for (const memberId of members) {{
                    const memberNode = lineageById.get(String(memberId));
                    if (!memberNode) continue;
                    const isCurrent = String(memberId) === String(queueId);
                    const tag = String(memberNode.corpus || '?').toUpperCase().slice(0, 1);
                    const btnClass = isCurrent ? 'class-member-active' : 'class-member-btn';
                    classMembersHtml += `<button class="${{btnClass}}" onclick="setSelectedQueue('${{memberId}}'); lineageNetwork.focus('${{memberId}}', {{scale:1.08, animation:true}});">${{memberNode.origId}} [${{tag}}]</button>`;
                }}
                classMembersHtml += `</div>`;
            }}

            const infoBanner = document.getElementById('selectedInfo');
            let bannerHtml = '';
            if (selectedCorpus === 'races' && (raceInfo.race_0 || raceInfo.race_1)) {{
                infoBanner.style.background = '#fee2e2';
                infoBanner.style.color = '#991b1b';
                infoBanner.style.borderLeft = '6px solid #ef4444';
                
                let raceDetails = `⚠️ RACE DETECTED! `;
                if (raceInfo.race_0) {{
                    raceDetails += `[R0] T${{raceInfo.race_0.thread_id}} I${{raceInfo.race_0.instruction_id}} V${{raceInfo.race_0.visit_id}} ⚡ `;
                }}
                if (raceInfo.race_1) {{
                    raceDetails += `[R1] T${{raceInfo.race_1.thread_id}} I${{raceInfo.race_1.instruction_id}} V${{raceInfo.race_1.visit_id}}`;
                }}
                bannerHtml = `<div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">` +
                    `<div>` +
                        `<div style="font-weight:800; margin-bottom:2px; color:#f43f5e;">${{raceDetails}}</div>` +
                        `<div style="font-size:11px; color:#fda4af;">${{infoText}}</div>` +
                    `</div>` +
                    (fileName ? `<div style="font-family:monospace; font-size:10px; padding:4px 8px; background:rgba(244,63,94,0.15); border:1px solid rgba(244,63,94,0.3); border-radius:4px; max-width:100%; word-break:break-all;">File: ${{fileName}}</div>` : '') +
                    `</div>`;
            }} else {{
                bannerHtml = `<div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">` +
                    `<div>` +
                        `<div style="font-weight:700; color:var(--text);">${{selectedCorpus.toUpperCase()}} #${{selectedOrigId}} Details</div>` +
                        `<div style="font-size:11px; color:var(--muted);">${{infoText}}</div>` +
                    `</div>` +
                    (fileName ? `<div style="font-family:monospace; font-size:10px; padding:4px 8px; background:var(--subpanel); border:1px solid var(--border); border-radius:4px; max-width:100%; word-break:break-all;">File: ${{fileName}}</div>` : '') +
                    `</div>`;
                infoBanner.style.background = 'var(--panel)';
                infoBanner.style.color = 'var(--text)';
                infoBanner.style.borderLeft = '6px solid var(--accent)';
            }}
            bannerHtml += classMembersHtml;
            infoBanner.innerHTML = bannerHtml;

            document.getElementById('skeletonStats').textContent =
                `Threads: ${{skel.stats.threadCount || 0}} | Nodes: ${{skel.stats.nodeCount || 0}} | PO: ${{skel.stats.poCount || 0}} | RF: ${{skel.stats.rfCount || 0}} | SW: ${{skel.stats.swCount || 0}} | MO: ${{skel.stats.moCount || 0}} | TCJ: ${{skel.stats.tcjCount || 0}}`;

            updateEventDetails(null, [], []);
            const fitNodeIds = (currentSkeletonNodes || []).map(n => n.id).filter(id => !String(id).startsWith('lane:'));
            if (fitNodeIds.length > 0) skeletonNetwork.fit({{ nodes: fitNodeIds, animation: true }});
            else skeletonNetwork.fit({{ animation: true }});

            refreshCfgAliases();
        }}

        function skeletonEdgesForNode(nodeId) {{
            const incoming = [];
            const outgoing = [];
            for (const e of currentSkeletonEdges) {{
                if (String(e.from) === String(nodeId)) outgoing.push(e);
                if (String(e.to) === String(nodeId)) incoming.push(e);
            }}
            return {{ incoming, outgoing }};
        }}

        function updateEventDetails(nodeId, incoming, outgoing) {{
            const el = document.getElementById('eventDetails');
            if (!nodeId || !currentSkeletonMeta[nodeId]) {{
                el.innerHTML = '<div class="muted">Selected Event Details</div>';
                document.getElementById('locAliasInput').value = '';
                document.getElementById('locAliasSelect').value = '';
                return;
            }}
            const m = currentSkeletonMeta[nodeId];
            const aliasMap = JSON.parse(localStorage.getItem('afl_loc_alias_map_v1') || '{{}}');
            const locId = String(m.location_id || m.location || '');
            document.getElementById('locAliasSelect').value = locId;
            document.getElementById('locAliasInput').value = aliasMap[locId] || '';
            const outSummary = outgoing.map(e => `${{e.relation || '?'}}→${{e.to}}`).slice(0, 8).join(', ') || 'none';
            const inSummary = incoming.map(e => `${{e.relation || '?'}}←${{e.from}}`).slice(0, 8).join(', ') || 'none';
            el.innerHTML =
                `<div><span class="w">Event ID</span><br/>${{m.event_id}}</div>` +
                `<div><span class="w">Thread</span><br/>${{m.thread_id}}</div>` +
                `<div><span class="w">Instruction</span><br/>${{m.instruction_id}}</div>` +
                `<div><span class="w">Visit ID</span><br/>${{m.visit_id}}</div>` +
                `<div><span class="w">Location</span><br/>${{m.location}}</div>` +
                `<div><span class="w">Location ID</span><br/>${{locId}}</div>` +
                `<div><span class="w">Kind</span><br/>${{m.kind}}</div>` +
                `<div><span class="w">Mode</span><br/>${{m.mode}}</div>` +
                `<div style="grid-column:1 / span 2;"><span class="w">Outgoing edges</span><br/>${{outSummary}}</div>` +
                `<div style="grid-column:1 / span 2;"><span class="w">Incoming edges</span><br/>${{inSummary}}</div>`;
        }}

        function setSelectedQueue(nodeId, highlightLineage = true) {{
            currentSelectedQueueId = nodeId ? String(nodeId) : null;
            if (highlightLineage) {{
                applyLineageSelectionHighlight(currentSelectedQueueId);
            }} else {{
                applyLineageSelectionHighlight(null);
            }}
            setSkeletonGraph(currentSelectedQueueId);
            refreshOriginalPanel();
            if (lineageNetwork) {{
                if (currentSelectedQueueId) {{
                    lineageNetwork.selectNodes([currentSelectedQueueId]);
                }} else {{
                    lineageNetwork.unselectAll();
                }}
            }}
        }}

        function openOriginalPanel() {{
            document.getElementById('originalPanel').classList.add('open');
            document.getElementById('originalBackdrop').classList.add('open');
            document.getElementById('originalPanel').setAttribute('aria-hidden', 'false');
            refreshOriginalPanel();
        }}

        function closeOriginalPanel() {{
            document.getElementById('originalPanel').classList.remove('open');
            document.getElementById('originalBackdrop').classList.remove('open');
            document.getElementById('originalPanel').setAttribute('aria-hidden', 'true');
        }}

        function renderOriginalJson(value, fallbackText) {{
            const treeEl = document.getElementById('originalJsonTree');
            const preEl = document.getElementById('originalJson');
            treeEl.innerHTML = '';
            if (originalJsonEditor) {{
                try {{
                    originalJsonEditor.destroy();
                }} catch (_err) {{
                }}
                originalJsonEditor = null;
            }}
            if (fallbackText) {{
                treeEl.style.display = 'none';
                preEl.style.display = 'block';
                preEl.textContent = fallbackText;
                return;
            }}
            if (typeof JSONEditor === 'function') {{
                try {{
                    originalJsonEditor = new JSONEditor(treeEl, {{
                        mode: 'view',
                        mainMenuBar: false,
                        navigationBar: true,
                        statusBar: false,
                    }});
                    originalJsonEditor.set(value);
                    originalJsonEditor.expandAll();
                    treeEl.style.display = 'block';
                    preEl.style.display = 'none';
                    return;
                }} catch (_err) {{
                }}
            }}
            treeEl.style.display = 'none';
            preEl.style.display = 'block';
            preEl.textContent = JSON.stringify(value, null, 2);
        }}

        function expandOriginalJson() {{
            if (originalJsonEditor && typeof originalJsonEditor.expandAll === 'function') {{
                originalJsonEditor.expandAll();
            }}
        }}

        function collapseOriginalJson() {{
            if (originalJsonEditor && typeof originalJsonEditor.collapseAll === 'function') {{
                originalJsonEditor.collapseAll();
            }}
        }}

        function refreshOriginalPanel() {{
            const titleEl = document.getElementById('originalTitle');
            if (!currentSelectedQueueId) {{
                titleEl.textContent = 'Original JSON';
                renderOriginalJson(null, 'Select an entry to inspect original JSON.');
                return;
            }}
            const node = lineageById.get(String(currentSelectedQueueId)) || {{}};
            const corpus = String(node.corpus || 'entry');
            const origId = node.origId !== undefined ? node.origId : String(currentSelectedQueueId);
            titleEl.textContent = `Original JSON · ${{corpus}} #${{origId}}`;
            const payload = originalById[String(currentSelectedQueueId)];
            if (!payload) {{
                renderOriginalJson(null, 'Original JSON is not available for this entry.');
                return;
            }}
            renderOriginalJson(payload, null);
        }}

        function resetNetworkView(network) {{
            network.moveTo({{ position: {{ x: 0, y: 0 }}, scale: 1.0, animation: true }});
        }}

        function togglePhysics(network, key) {{
            const next = !physicsState[key];
            physicsState[key] = next;
            if (key === 'lineage') {{
                const updates = [];
                for (const node of lineageNodesDs.get()) {{
                    const id = String(node.id);
                    if (id.startsWith('cluster:')) {{
                        updates.push({{ id, fixed: !next, physics: next }});
                        continue;
                    }}
                    if (next) {{
                        updates.push({{ id, fixed: false, physics: true }});
                    }} else {{
                        const raw = lineageById.get(id);
                        updates.push({{ id, fixed: true, physics: false, x: raw ? raw.x : node.x, y: raw ? raw.y : node.y }});
                    }}
                }}
                lineageNodesDs.update(updates);
            }}
            network.setOptions({{ physics: {{ enabled: next }} }});
            if (next) network.stabilize(80);
            if (!next && key === 'lineage') lineageNetwork.fit({{ animation: true }});
        }}

        function goFullscreen(elementId) {{
            const el = document.getElementById(elementId);
            if (el && el.requestFullscreen) el.requestFullscreen().catch(() => {{}});
        }}

        function highlightCfgByInstruction(instructionId) {{
            const updates = [];
            const hasHighlight = !!instructionId;
            for (const n of cfgNodesDs.get()) {{
                if (String(n.id).startsWith('cfg-lane:')) continue;
                const base = cfgBaseStyleById.get(String(n.id)) || {{
                    borderWidth: 2,
                    color: {{ border: '#475569', background: '#334155' }},
                }};
                
                let border = base.color.border;
                let bg = base.color.background;
                let bw = base.borderWidth;
                let fontColor = '#f8fafc';
                
                if (hasHighlight) {{
                    if (String(n.instructionId) === String(instructionId)) {{
                        border = '#fbbf24';
                        bw = 5;
                    }} else {{
                        bg = 'rgba(51, 65, 85, 0.2)';
                        border = 'rgba(71, 85, 105, 0.2)';
                        fontColor = 'rgba(148, 163, 184, 0.2)';
                        bw = 1;
                    }}
                }}
                
                updates.push({{ 
                    id: n.id, 
                    borderWidth: bw, 
                    color: {{ border, background: bg }},
                    font: {{ color: fontColor }}
                }});
            }}
            cfgNodesDs.update(updates);
            
            const edgeUpdates = [];
            for (const edge of cfgEdgesDs.get()) {{
                let isEdgeRelated = !hasHighlight;
                if (hasHighlight) {{
                    const fromNode = cfgNodesDs.get(edge.from);
                    const toNode = cfgNodesDs.get(edge.to);
                    if (fromNode && toNode && (String(fromNode.instructionId) === String(instructionId) || String(toNode.instructionId) === String(instructionId))) {{
                        isEdgeRelated = true;
                    }}
                }}
                edgeUpdates.push({{
                    id: edge.id,
                    color: isEdgeRelated ? '#64748b' : 'rgba(74, 85, 104, 0.15)',
                    width: isEdgeRelated ? 2.0 : 1
                }});
            }}
            cfgEdgesDs.update(edgeUpdates);
        }}

        function highlightSkeletonByInstruction(instructionId) {{
            const updates = [];
            const hasHighlight = !!instructionId;
            for (const n of skeletonNodesDs.get()) {{
                if (String(n.id).startsWith('lane:')) continue;
                const base = skeletonBaseStyleById.get(String(n.id)) || {{
                    borderWidth: 1.5,
                    color: {{ border: '#475569', background: '#1e293b' }},
                }};
                
                let border = base.color.border;
                let bg = base.color.background;
                let bw = base.borderWidth;
                let fontColor = '#f8fafc';
                
                if (hasHighlight) {{
                    if (String(n.instructionId) === String(instructionId)) {{
                        border = '#fbbf24';
                        bw = 5;
                    }} else {{
                        if (bg.startsWith('rgb') && !bg.startsWith('rgba')) {{
                            bg = bg.replace('rgb', 'rgba').replace(')', ', 0.15)');
                        }} else if (!bg.startsWith('rgba')) {{
                            bg = 'rgba(30, 41, 59, 0.15)';
                        }}
                        border = 'rgba(71, 85, 105, 0.15)';
                        fontColor = 'rgba(148, 163, 184, 0.2)';
                        bw = 1;
                    }}
                }}
                
                updates.push({{
                    id: n.id,
                    borderWidth: bw,
                    color: {{ border, background: bg }},
                    font: {{ color: fontColor }}
                }});
            }}
            skeletonNodesDs.update(updates);
            
            const edgeUpdates = [];
            for (const edge of skeletonEdgesDs.get()) {{
                let isEdgeRelated = !hasHighlight;
                if (hasHighlight) {{
                    const fromNode = skeletonNodesDs.get(edge.from);
                    const toNode = skeletonNodesDs.get(edge.to);
                    if (fromNode && toNode && (String(fromNode.instructionId) === String(instructionId) || String(toNode.instructionId) === String(instructionId))) {{
                        isEdgeRelated = true;
                    }}
                }}
                const baseStyle = edgeRelationStyle(edge.relation);
                edgeUpdates.push({{
                    id: edge.id,
                    color: isEdgeRelated ? (edge.relation === 'PO' ? '#cbd5e1' : baseStyle.color) : 'rgba(74, 85, 104, 0.1)',
                    width: isEdgeRelated ? (baseStyle.width || 2) : 1
                }});
            }}
            skeletonEdgesDs.update(edgeUpdates);
        }}

        function focusCfgByInstruction(instructionId) {{
            if (!instructionId) return;
            const ids = cfgNodesDs.get().filter(n => String(n.instructionId) === String(instructionId)).map(n => n.id);
            if (ids.length === 0) return;
            cfgNetwork.selectNodes(ids);
            cfgNetwork.focus(ids[0], {{ scale: 1.2, animation: true }});
            highlightCfgByInstruction(instructionId);
        }}

        lineageNetwork.on('click', function(params) {{
            if (params.nodes && params.nodes.length > 0) {{
                const nodeId = String(params.nodes[0]);
                if (nodeId.startsWith('cluster:C')) {{
                    const classId = nodeId.replace('cluster:C', '');
                    if (expandedClasses.has(classId)) expandedClasses.delete(classId);
                    else expandedClasses.add(classId);
                    refreshLineageGraph();
                    return;
                }}
                setSelectedQueue(nodeId);
            }} else {{
                setSelectedQueue(null);
            }}
        }});

        skeletonNetwork.on('click', function(params) {{
            if (!params.nodes || params.nodes.length === 0) return;
            const nodeId = String(params.nodes[0]);
            if (nodeId.startsWith('lane:')) return;
            const rel = skeletonEdgesForNode(nodeId);
            updateEventDetails(nodeId, rel.incoming, rel.outgoing);
            const node = skeletonNodesDs.get(nodeId);
            if (node) focusCfgByInstruction(node.instructionId);
        }});

        skeletonNetwork.on('hoverNode', function(params) {{
            const node = skeletonNodesDs.get(params.node);
            if (!node || String(node.id).startsWith('lane:')) return;
            highlightCfgByInstruction(node.instructionId);
        }});
        skeletonNetwork.on('blurNode', function() {{ highlightCfgByInstruction(null); }});

        cfgNetwork.on('hoverNode', function(params) {{
            const node = cfgNodesDs.get(params.node);
            if (!node || String(node.id).startsWith('cfg-lane:')) return;
            highlightSkeletonByInstruction(node.instructionId);
        }});
        cfgNetwork.on('blurNode', function() {{ highlightSkeletonByInstruction(null); }});

        document.getElementById('classFilter').addEventListener('change', () => stopLineagePlayback(true));
        document.getElementById('corpusFilter').addEventListener('change', () => stopLineagePlayback(true));
        document.getElementById('hideDup').addEventListener('change', () => stopLineagePlayback(true));
        document.getElementById('leafOnly').addEventListener('change', () => stopLineagePlayback(true));
        document.getElementById('compactLabels').addEventListener('change', () => stopLineagePlayback(true));
        document.getElementById('collapseClasses').addEventListener('change', function() {{
            stopLineagePlayback(true);
            if (!this.checked) expandedClasses.clear();
            refreshLineageGraph();
        }});

        document.getElementById('searchBtn').addEventListener('click', function() {{
            const raw = (document.getElementById('searchId').value || '').trim();
            const normalized = raw.replace(/^#/, '').toLowerCase();
            if (!normalized) return;

            let targetId = null;
            if (lineageById.has(normalized)) {{
                targetId = normalized;
            }} else {{
                const corpusHint = normalized.includes(':') ? normalized.split(':')[0] : '';
                const numeric = normalized.includes(':') ? normalized.split(':')[1] : normalized;
                for (const n of (DATA.lineage.nodes || [])) {{
                    const byOrig = String(n.origId) === numeric;
                    if (!byOrig) continue;
                    if (corpusHint && String(n.corpus).toLowerCase().startsWith(corpusHint)) {{
                        targetId = String(n.id);
                        break;
                    }}
                    if (!corpusHint && !targetId) targetId = String(n.id);
                }}
            }}

            if (!targetId || !lineageById.has(targetId)) return;
            setSelectedQueue(targetId);
            lineageNetwork.focus(targetId, {{ scale: 1.35, animation: true }});
        }});
        document.getElementById('searchId').addEventListener('keydown', function(evt) {{
            if (evt.key === 'Enter') document.getElementById('searchBtn').click();
        }});

        document.getElementById('fitLineage').addEventListener('click', () => lineageNetwork.fit({{ animation: true }}));
        document.getElementById('resetLineage').addEventListener('click', () => resetNetworkView(lineageNetwork));
        document.getElementById('toggleLineagePhysics').addEventListener('click', () => togglePhysics(lineageNetwork, 'lineage'));
        document.getElementById('playLineage').addEventListener('click', () => {{
            if (lineagePlayback.active) stopLineagePlayback(true);
            else startLineagePlayback();
        }});
        document.getElementById('lineagePlaySpeed').addEventListener('change', function() {{
            const parsed = Number(this.value);
            lineagePlayback.speed = Number.isFinite(parsed) && parsed > 0 ? parsed : 1;
            if (lineagePlayback.active) {{
                stopLineagePlayback(true);
                startLineagePlayback();
            }}
        }});
        document.getElementById('playbackRange').addEventListener('input', function() {{
            const val = Number(this.value);
            stopLineagePlayback(false);
            const visible = collectVisibleNodeIds();
            const orderedIds = orderedVisibleLineageIds(visible);
            if (val >= orderedIds.length) {{
                lineagePlayback.visibleCount = null;
            }} else {{
                lineagePlayback.visibleCount = val;
            }}
            updatePlaybackSlider();
            refreshLineageGraph({{ autoNavigate: false }});
        }});
        document.getElementById('fullLineage').addEventListener('click', () => goFullscreen('lineage'));

        document.getElementById('fitSkeleton').addEventListener('click', () => skeletonNetwork.fit({{ animation: true }}));
        document.getElementById('resetSkeleton').addEventListener('click', () => resetNetworkView(skeletonNetwork));
        document.getElementById('toggleSkeletonPhysics').addEventListener('click', () => togglePhysics(skeletonNetwork, 'skeleton'));
        document.getElementById('viewOriginal').addEventListener('click', () => openOriginalPanel());
        document.getElementById('fullSkeleton').addEventListener('click', () => goFullscreen('skeleton'));
        document.getElementById('expandOriginal').addEventListener('click', () => expandOriginalJson());
        document.getElementById('collapseOriginal').addEventListener('click', () => collapseOriginalJson());
        document.getElementById('closeOriginal').addEventListener('click', () => closeOriginalPanel());
        document.getElementById('originalBackdrop').addEventListener('click', () => closeOriginalPanel());
        document.getElementById('compareToggle').addEventListener('change', () => {{
            if (currentSelectedQueueId) setSkeletonGraph(currentSelectedQueueId);
        }});
        document.getElementById('compareQueue').addEventListener('change', () => {{
            if (currentSelectedQueueId) setSkeletonGraph(currentSelectedQueueId);
        }});

        document.getElementById('fitCfg').addEventListener('click', () => cfgNetwork.fit({{ animation: true }}));
        document.getElementById('resetCfg').addEventListener('click', () => resetNetworkView(cfgNetwork));
        document.getElementById('toggleCfgPhysics').addEventListener('click', () => togglePhysics(cfgNetwork, 'cfg'));
        document.getElementById('fullCfg').addEventListener('click', () => goFullscreen('cfg'));

        document.getElementById('locAliasSelect').addEventListener('change', () => {{
            const locId = (document.getElementById('locAliasSelect').value || '').trim();
            const aliasMap = getAliasMap();
            document.getElementById('locAliasInput').value = locId ? (aliasMap[locId] || '') : '';
        }});

        document.getElementById('saveLocAlias').addEventListener('click', () => {{
            const selectedLoc = (document.getElementById('locAliasSelect').value || '').trim();
            const selected = skeletonNetwork.getSelectedNodes().find(n => !String(n).startsWith('lane:'));
            const meta = selected && currentSkeletonMeta[selected] ? currentSkeletonMeta[selected] : null;
            const locId = selectedLoc || (meta ? String(meta.location_id || meta.location || '') : '');
            if (!locId) return;
            const value = (document.getElementById('locAliasInput').value || '').trim();
            const aliasMap = JSON.parse(localStorage.getItem('afl_loc_alias_map_v1') || '{{}}');
            if (value) aliasMap[locId] = value;
            else delete aliasMap[locId];
            localStorage.setItem('afl_loc_alias_map_v1', JSON.stringify(aliasMap));
            if (currentSelectedQueueId) setSkeletonGraph(currentSelectedQueueId);
            refreshSkeletonAliases();
            refreshCfgAliases();
            if (selected) {{
                const rel = skeletonEdgesForNode(String(selected));
                updateEventDetails(String(selected), rel.incoming, rel.outgoing);
            }}
        }});

        document.getElementById('clearLocAlias').addEventListener('click', () => {{
            const selectedLoc = (document.getElementById('locAliasSelect').value || '').trim();
            const selected = skeletonNetwork.getSelectedNodes().find(n => !String(n).startsWith('lane:'));
            const meta = selected && currentSkeletonMeta[selected] ? currentSkeletonMeta[selected] : null;
            const locId = selectedLoc || (meta ? String(meta.location_id || meta.location || '') : '');
            if (!locId) return;
            const aliasMap = JSON.parse(localStorage.getItem('afl_loc_alias_map_v1') || '{{}}');
            delete aliasMap[locId];
            localStorage.setItem('afl_loc_alias_map_v1', JSON.stringify(aliasMap));
            if (currentSelectedQueueId) setSkeletonGraph(currentSelectedQueueId);
            refreshSkeletonAliases();
            refreshCfgAliases();
            if (selected) {{
                const rel = skeletonEdgesForNode(String(selected));
                updateEventDetails(String(selected), rel.incoming, rel.outgoing);
            }}
        }});

        function formatRelativeTime(seconds) {{
            const sec = Math.floor(seconds);
            if (sec < 60) return `${{sec}}s`;
            if (sec < 3600) return `${{Math.floor(sec / 60)}}m ${{sec % 60}}s`;
            const hrs = Math.floor(sec / 3600);
            const mins = Math.floor((sec % 3600) / 60);
            return `${{hrs}}h ${{mins}}m`;
        }}

        function renderFuzzerStatsGrid() {{
            const grid = document.getElementById('statsMetaGrid');
            grid.innerHTML = '';
            const stats = DATA.fuzzerStats || {{}};
            
            const fields = [
                {{ k: 'AFL Version', v: stats.afl_version || '-' }},
                {{ k: 'Fuzzer Banner', v: stats.afl_banner || '-' }},
                {{ k: 'Fuzzer PID', v: stats.fuzzer_pid || '-' }},
                {{ k: 'Run Time', v: formatRelativeTime(stats.run_time || 0) }},
                {{ k: 'Cycles Done', v: stats.cycles_done || '0' }},
                {{ k: 'Execs Done', v: stats.execs_done || '0' }},
                {{ k: 'Execs/Sec', v: stats.execs_per_sec || '0' }},
                {{ k: 'Stability', v: stats.stability || '-' }},
                {{ k: 'Bitmap Coverage', v: stats.bitmap_cvg || '-' }},
                {{ k: 'Total Queue', v: stats.corpus_count || '0' }},
                {{ k: 'Saved Hangs', v: stats.saved_hangs || '0' }},
                {{ k: 'Saved Crashes', v: stats.saved_crashes || '0' }},
                {{ k: 'Saved Races', v: stats.saved_races || '0' }},
                {{ k: 'Target Mode', v: stats.target_mode || '-' }},
            ];
            
            for (const f of fields) {{
                const item = document.createElement('div');
                item.className = 'metric';
                item.style.minWidth = '140px';
                item.innerHTML = `<div class=\"k\">${{f.k}}</div><div class=\"v\">${{f.v}}</div>`;
                grid.appendChild(item);
            }}
            
            const cmdDiv = document.createElement('div');
            cmdDiv.style.gridColumn = '1 / -1';
            cmdDiv.style.border = '1px solid var(--border)';
            cmdDiv.style.padding = '10px';
            cmdDiv.style.borderRadius = '6px';
            cmdDiv.style.background = 'var(--subpanel)';
            cmdDiv.style.color = 'var(--text)';
            cmdDiv.innerHTML = `<div style=\"font-weight:800; font-size:11px; color:var(--muted); margin-bottom:4px;\">COMMAND LINE</div>
                                <code style=\"font-family:\'JetBrains Mono\', monospace; font-size:11px; white-space:pre-wrap; word-break:break-all; color:var(--text);\">${{stats.command_line || '-'}}</code>`;
            grid.appendChild(cmdDiv);
        }}

        let chartsInitialized = false;
        let chartCoverage = null;
        let chartFindings = null;
        let chartSpeed = null;

        function initCharts() {{
            if (chartsInitialized) return;
            chartsInitialized = true;
            
            const plot = DATA.plotData || [];
            
            // 1. Speed Chart
            const speedTimes = plot.map(r => r.relative_time);
            const speedVals = plot.map(r => r.execs_per_sec);
            const ctxSpeed = document.getElementById('chartSpeed').getContext('2d');
            chartSpeed = new Chart(ctxSpeed, {{
                type: 'line',
                data: {{
                    labels: speedTimes.map(formatRelativeTime),
                    datasets: [{{
                        label: 'Executions/sec',
                        data: speedVals,
                        borderColor: '#00d1ff',
                        backgroundColor: 'rgba(0, 209, 255, 0.1)',
                        borderWidth: 3,
                        pointRadius: 2,
                        fill: true,
                        tension: 0.1
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        x: {{ 
                            grid: {{ color: '#e2e8f0' }}, 
                            ticks: {{ color: '#334155' }} 
                        }},
                        y: {{ 
                            grid: {{ color: '#e2e8f0' }},
                            ticks: {{ color: '#334155' }}
                        }}
                    }},
                    plugins: {{
                        legend: {{ display: false }}
                    }}
                }}
            }});

            // 2. WMM Coverage Chart (MO & RF Edges)
            const covTimes = plot.map(r => r.relative_time);
            const moCov = plot.map(r => r.mo_coverage || 0);
            const rfCov = plot.map(r => r.rf_coverage || 0);
            const ctxCoverage = document.getElementById('chartCoverage').getContext('2d');
            chartCoverage = new Chart(ctxCoverage, {{
                type: 'line',
                data: {{
                    labels: covTimes.map(formatRelativeTime),
                    datasets: [
                        {{
                            label: 'MO Coverage',
                            data: moCov,
                            borderColor: '#ff9f1c',
                            backgroundColor: 'transparent',
                            borderWidth: 3,
                            pointRadius: 2,
                            tension: 0.1
                        }},
                        {{
                            label: 'RF Coverage',
                            data: rfCov,
                            borderColor: '#14f195',
                            backgroundColor: 'transparent',
                            borderWidth: 3,
                            pointRadius: 2,
                            tension: 0.1
                        }}
                    ]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        x: {{ 
                            grid: {{ color: '#e2e8f0' }}, 
                            ticks: {{ color: '#334155' }} 
                        }},
                        y: {{ 
                            grid: {{ color: '#e2e8f0' }},
                            ticks: {{ color: '#334155' }}
                        }}
                    }},
                    plugins: {{
                        legend: {{ 
                            position: 'top',
                            labels: {{ color: '#334155' }}
                        }}
                    }}
                }}
            }});

            // 3. Findings Chart (Queue, Crashes, Hangs, Races, Non-Instantiable)
            const nodes = (DATA.lineage.nodes || []).slice().sort((a, b) => (a.discoveryTime || 0) - (b.discoveryTime || 0));
            
            let qCount = 0;
            let hCount = 0;
            let cCount = 0;
            let rCount = 0;
            let nCount = 0;
            
            const timelineData = [{{ t: 0, q: 0, h: 0, c: 0, r: 0, n: 0 }}];
            
            for (const n of nodes) {{
                const corpus = String(n.corpus || '').toLowerCase();
                if (corpus === 'queue') qCount++;
                else if (corpus === 'hangs') hCount++;
                else if (corpus === 'crashes') cCount++;
                else if (corpus === 'races') rCount++;
                else if (corpus === 'non_instantiable') nCount++;
                
                timelineData.push({{
                    t: n.discoveryTime || 0,
                    q: qCount,
                    h: hCount,
                    c: cCount,
                    r: rCount,
                    n: nCount
                }});
            }}
            
            const maxTime = Math.max(
                parseInt((DATA.fuzzerStats && DATA.fuzzerStats.run_time) || 0),
                timelineData[timelineData.length - 1]?.t || 0
            );
            if (maxTime > (timelineData[timelineData.length - 1]?.t || 0)) {{
                const last = timelineData[timelineData.length - 1];
                timelineData.push({{
                    t: maxTime,
                    q: last.q,
                    h: last.h,
                    c: last.c,
                    r: last.r,
                    n: last.n
                }});
            }}

            const ctxFindings = document.getElementById('chartFindings').getContext('2d');
            chartFindings = new Chart(ctxFindings, {{
                type: 'line',
                data: {{
                    datasets: [
                        {{
                            label: 'Crashes',
                            data: timelineData.map(d => ({{ x: d.t, y: d.c }})),
                            borderColor: '#ff6b6b',
                            backgroundColor: 'transparent',
                            borderWidth: 2.5,
                            stepped: true,
                            pointRadius: 0
                        }},
                        {{
                            label: 'Races',
                            data: timelineData.map(d => ({{ x: d.t, y: d.r }})),
                            borderColor: '#ec4899',
                            backgroundColor: 'transparent',
                            borderWidth: 3,
                            stepped: true,
                            pointRadius: 0
                        }},
                        {{
                            label: 'Hangs',
                            data: timelineData.map(d => ({{ x: d.t, y: d.h }})),
                            borderColor: '#ffd166',
                            backgroundColor: 'transparent',
                            borderWidth: 2.5,
                            stepped: true,
                            pointRadius: 0
                        }},
                        {{
                            label: 'Queue',
                            data: timelineData.map(d => ({{ x: d.t, y: d.q }})),
                            borderColor: '#5eead4',
                            backgroundColor: 'transparent',
                            borderWidth: 2.5,
                            stepped: true,
                            pointRadius: 0
                        }},
                        {{
                            label: 'Non-Instantiable',
                            data: timelineData.map(d => ({{ x: d.t, y: d.n }})),
                            borderColor: '#93c5fd',
                            backgroundColor: 'transparent',
                            borderWidth: 2.5,
                            stepped: true,
                            pointRadius: 0
                        }}
                    ]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        x: {{
                            type: 'linear',
                            grid: {{ color: '#e2e8f0' }},
                            ticks: {{
                                color: '#334155',
                                callback: function(value) {{
                                    return formatRelativeTime(value);
                                }}
                            }}
                        }},
                        y: {{ 
                            grid: {{ color: '#e2e8f0' }},
                            ticks: {{ color: '#334155' }}
                        }}
                    }},
                    plugins: {{
                        legend: {{ 
                            position: 'top',
                            labels: {{ color: '#334155' }}
                        }}
                    }}
                }}
            }});
        }}

        function openStatsPanel() {{
            document.getElementById('statsPanel').classList.add('open');
            document.getElementById('statsBackdrop').classList.add('open');
            document.getElementById('statsPanel').setAttribute('aria-hidden', 'false');
            renderFuzzerStatsGrid();
            initCharts();
        }}

        function closeStatsPanel() {{
            document.getElementById('statsPanel').classList.remove('open');
            document.getElementById('statsBackdrop').classList.remove('open');
            document.getElementById('statsPanel').setAttribute('aria-hidden', 'true');
        }}

        document.getElementById('openStatsBtn').addEventListener('click', openStatsPanel);
        document.getElementById('closeStats').addEventListener('click', closeStatsPanel);
        document.getElementById('statsBackdrop').addEventListener('click', closeStatsPanel);

        setClassFilterOptions();
        setCompareQueueOptions();
        setLocationAliasOptions();
        updatePlayLineageButton();
        updatePlaybackSlider();
        refreshCfgAliases();
        refreshLineageGraph();
        refreshOriginalPanel();

        window.setSelectedQueue = setSelectedQueue;
        window.lineageNetwork = lineageNetwork;

        document.addEventListener('keydown', function(evt) {{
            if (evt.key === 'Escape') {{
                closeOriginalPanel();
                closeStatsPanel();
            }}
        }});

        lineageNetwork.on('stabilizationStart', function() {{
            if (lineageNodesDs.get().length > 50) {{
                document.getElementById('lineageLoading').style.display = 'flex';
                document.getElementById('lineageLoadingBar').style.width = '0%';
                document.getElementById('lineageLoadingText').innerText = '0% stabilized';
            }}
        }});

        lineageNetwork.on('stabilizationProgress', function(params) {{
            if (lineageNodesDs.get().length > 50) {{
                const percent = Math.round((params.iterations / params.total) * 100);
                document.getElementById('lineageLoadingBar').style.width = percent + '%';
                document.getElementById('lineageLoadingText').innerText = percent + '% stabilized (' + params.iterations + '/' + params.total + ')';
            }}
        }});

        lineageNetwork.on('stabilizationIterationsDone', function() {{
            document.getElementById('lineageLoadingBar').style.width = '100%';
            document.getElementById('lineageLoadingText').innerText = '100% stabilized';
            setTimeout(() => {{
                document.getElementById('lineageLoading').style.display = 'none';
            }}, 300);
        }});

        lineageNetwork.once('stabilizationIterationsDone', () => lineageNetwork.fit({{ animation: true }}));
        cfgNetwork.once('stabilizationIterationsDone', () => cfgNetwork.fit({{ animation: true }}));

        if (DATA.defaultSelection !== null) {{
            setSelectedQueue(DATA.defaultSelection, false);
        }}
  </script>
</body>
</html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Create an interactive AFL queue visualizer (HTML).")
    parser.add_argument(
        "--afl-out",
        default="out/default",
        help="AFL out directory containing queue/, hangs/, crashes/, non_instantiable/ (default: out/default)",
    )
    parser.add_argument(
        "--pg",
        default="examples/sb.c.pg",
        help="Path to original .pg file for CFG panel (default: examples/sb.c.pg)",
    )
    parser.add_argument(
        "--queue-dir",
        default=None,
        help="Deprecated alias. If provided, parent directory will be treated as AFL out directory.",
    )
    parser.add_argument(
        "--cfg",
        default=None,
        help="Deprecated alias for --pg.",
    )
    parser.add_argument(
        "--out",
        default="out/default/queue_visualizer.html",
        help="Output HTML path (default: out/default/queue_visualizer.html)",
    )

    args = parser.parse_args()

    afl_out_dir = Path(args.afl_out)
    if args.queue_dir:
        afl_out_dir = Path(args.queue_dir).parent

    cfg_path = Path(args.pg)
    if args.cfg:
        cfg_path = Path(args.cfg)

    out_path = Path(args.out)

    if not afl_out_dir.exists() or not afl_out_dir.is_dir():
        print(f"Error: AFL out directory not found: {afl_out_dir}")
        return 2
    entries = load_afl_out(afl_out_dir)
    if not entries:
        print(
            f"Error: no entries found in {afl_out_dir}/queue, {afl_out_dir}/hangs, "
            f"{afl_out_dir}/crashes, {afl_out_dir}/races, or {afl_out_dir}/non_instantiable"
        )
        return 3

    cfg_graph = build_cfg_graph(parse_pg(cfg_path))
    payload = build_dashboard_data(entries, cfg_graph, afl_out_dir)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_html(payload), encoding="utf-8")

    print(f"Generated: {out_path}")
    print("Open it in your browser (e.g. using $BROWSER).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
