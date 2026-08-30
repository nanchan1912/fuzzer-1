#!/usr/bin/env python3
"""
Convert .pg (text format) into initial seed .init.sg.json

Input .pg format:
  # Shared Locations
  LOC <loc_id> <var_name>
  ...
  # Event: ID TID Kind Loc VarName Mode ...
  E <event_id> <thread_id> <kind> <loc_id> <var_name> <mode> ...
  ...
  # Control Flow edges
  CF <from_event_id> <to_event_id>
  ...

Output .init.sg.json:
  {
    "nodes": [...],
    "rf_edges": [],
    "po_per_thread": [...],
    "mo_per_location": [...],
    "sw_edges": []
  }

The initial seed is computed by:
  1. Finding root events (no incoming CF edges)
  2. DFS forward from roots
  3. Stopping at READ or branch points
  4. Collecting WRITE-only prefix
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Tuple, Set


def parse_field_sensitive_loc_id(loc_str):
    if not loc_str:
        return 0
    idx = loc_str.find(":field_index=")
    if idx == -1:
        addr_str = loc_str
        if addr_str.lower().startswith("0x"):
            addr_str = addr_str[2:]
        try:
            return int(addr_str, 16)
        except ValueError:
            return 0
    base_str = loc_str[:idx]
    if base_str.lower().startswith("0x"):
        base_str = base_str[2:]
    try:
        base = int(base_str, 16)
    except ValueError:
        base = 0
    field_idx = loc_str[idx + 13:]
    h = 14695981039346656037
    for char in field_idx:
        h = h ^ ord(char)
        h = (h * 1099511628211) & 0xffffffffffffffff
    return base ^ h

# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_pg(pg_text: str) -> Tuple[Dict[str, dict], Dict[str, List[str]], Dict[str, List[str]], Dict[str, str]]:
    """
    Parse .pg text format.
    
    Returns:
      events: {event_id -> {tid, kind, loc_id, var_name, mode}}
      succ: {event_id -> [successor_ids]}
      pred: {event_id -> [predecessor_ids]}
      addr_to_stable_id: {addr -> stable_id}
    
    Only includes events with Call_string_context = "[: ]" (main thread events).
    Meaning all before Start of program! (before main)
    """
    
    events: Dict[str, dict] = {}
    succ: Dict[str, List[str]] = {}
    pred: Dict[str, List[str]] = {}
    addr_to_stable_id: Dict[str, str] = {}
    
    lines = pg_text.strip().split('\n')
    
    # Pre-pass: map unique Instruction_Address to the first event's numeric ID
    for line in lines:
        line_str = line.strip()
        if not line_str or line_str.startswith('#'):
            continue
        if line_str.startswith('E\t'):
            parts = line_str.split('\t')
            if len(parts) >= 8:
                old_id = parts[1]
                addr = parts[7]
                if addr not in addr_to_stable_id:
                    old_id_num = old_id[1:] if (old_id.startswith('e') or old_id.startswith('E')) else old_id
                    addr_to_stable_id[addr] = old_id_num
    
    for line in lines:
        line = line.strip()
        
        # Skip empty or comment lines
        if not line or line.startswith('#'):
            continue
        
        # Parse event line: E <id> <tid> <kind> <loc_id> <var_name> <mode> <addr> <call_context> <instruction>
        if line.startswith('E\t'):
            parts = line.split('\t')
            if len(parts) >= 8:
                eid = parts[1]
                tid = parts[2]
                kind = parts[3]
                loc_id = parts[4]
                var_name = parts[5]
                mode = parts[6]
                addr = parts[7]
                call_context = parts[8] if len(parts) >= 9 else ""
                
                # Only include events from main thread context (TID 0)
                if tid != "0":
                    continue
                
                events[eid] = {
                    'tid': tid,
                    'kind': kind,
                    'loc_id': loc_id,
                    'var_name': var_name,
                    'mode': mode,
                    'eid': eid,
                    'addr': addr,
                }
        
        # Parse control flow edge: CF <from> <to>
        elif line.startswith('CF '):
            parts = line.split()
            if len(parts) >= 3:
                src = parts[1]
                dst = parts[2]
                
                succ.setdefault(src, []).append(dst)
                pred.setdefault(dst, []).append(src)
    
    return events, succ, pred, addr_to_stable_id


# ---------------------------------------------------------------------------
# Seed generation
# ---------------------------------------------------------------------------

def create_init_seed_from_pg(events: Dict[str, dict],
                              succ: Dict[str, List[str]],
                              pred: Dict[str, List[str]],
                              addr_to_stable_id: Dict[str, str]) -> dict:
    """
    Create initial seed by DFS from roots, collecting WRITE-only prefix.
    
    Roots: events with no incoming CF edges.
    Stop conditions: READ event or branch points (multiple outgoing edges).
    """
    
    # Find roots (no incoming edges)
    roots = [eid for eid in events if eid not in pred]
    # Sort for determinism
    roots.sort(key=lambda eid: (
        int(events[eid].get('tid', 0)),
        int(eid[1:]) if eid.startswith('e') else 0
    ))
    
    visited: Set[str] = set()
    cf_seed_writes: List[dict] = []
    
    def should_stop_here(eid: str) -> bool:
        """Stop before traversing past this event."""
        ev = events.get(eid)
        if not ev:
            return True
        
        kind = ev.get('kind', '')
        
        # Stop at READ events
        if kind == 'R':
            return True
        
        # Stop at branch points (multiple outgoing edges)
        outgoing = succ.get(eid, [])
        if len(outgoing) > 1:
            return True
        
        return False
    
    def dfs(eid: str):
        """DFS to collect WRITE events."""
        if eid in visited:
            return
        visited.add(eid)
        
        ev = events.get(eid)
        if not ev:
            return
        
        kind = ev.get('kind', '')
        
        # Collect WRITE events (and RMW, FENCE, CMPXCHG as memory ops)
        if kind in ('W', 'RMW', 'CMPXCHG', 'F'):
            cf_seed_writes.append(ev)
        
        # Stop if this is a read or branch point
        if should_stop_here(eid):
            return
        
        # Continue DFS to successors
        for nxt in succ.get(eid, []):
            dfs(nxt)
    
    # Start DFS from all roots
    for root in roots:
        dfs(root)
    
    nodes = []
    po_map: Dict[str, List[List[str]]] = {}
    mo_map: Dict[str, List[List[str]]] = {}
    visit_counters: Dict[str, Dict[str, int]] = {} # tid -> {inst_id -> count}
    
    for idx, ev in enumerate(cf_seed_writes, start=1):
        tid = ev.get('tid', '0')
        loc = ev.get('loc_id', '0')
        loc_val = parse_field_sensitive_loc_id(loc)
        loc_hex = f"0x{loc_val:x}"
        eid_orig = ev.get('eid', '')
        mode = ev.get('mode', 'NA')
        
        # Extract numeric event ID (e.g. 1 from "e1") to match InstrumentWMM.cpp metadata uid
        old_id_num = eid_orig[1:] if (eid_orig.startswith('e') or eid_orig.startswith('E')) else eid_orig
        addr = ev.get('addr')
        # stable_id = addr
        stable_id = str(int(addr, 16))
        
        # Map mode to seed format
        seed_mode = map_mode_to_seed(mode)
        
        # Compute dynamic visit_id based on occurrences of the instruction in program order
        thread_counters = visit_counters.setdefault(tid, {})
        visit_num = thread_counters.get(stable_id, 0) + 1
        thread_counters[stable_id] = visit_num
        visit_id_str = str(visit_num)
        
        node = {
            'event_id': str(idx),
            'thread_id': tid,
            'kind': 'W',
            'loc_id': loc_hex,
            'instruction_id': stable_id,
            'visit_id': visit_id_str,
            'access_mode': seed_mode,
        }
        nodes.append(node)
        
        # Track program order per thread
        po_map.setdefault(tid, []).append([tid, stable_id, visit_id_str])
        
        # Track memory order per location
        mo_map.setdefault(loc_hex, []).append([tid, stable_id, visit_id_str])
    
    return {
        'nodes': nodes,
        'rf_edges': [],
        'po_per_thread': [
            {'thread_id': tid, 'list': lst}
            for tid, lst in sorted(po_map.items())
        ],
        'mo_per_location': [
            {'location': loc, 'list': lst}
            for loc, lst in sorted(mo_map.items())
        ],
        'sw_edges': [],
    }


def map_mode_to_seed(mode: str) -> str:
    """Map .pg mode strings to seed format."""
    mode_map = {
        'NA': 'NA',
        'Rlx': 'RLX',
        'Acq': 'ACQ',
        'Rel': 'REL',
        'AcqRel': 'ACQ_REL',
        'SC': 'SC',
    }
    return mode_map.get(mode, 'NA')


def infer_output_path(input_path: Path, suffix: str) -> Path:
    """Generate output filename from input."""
    name = input_path.name
    if name.endswith('.pg'):
        base = name[:-len('.pg')]
    else:
        base = name
    return input_path.with_name(base + suffix)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description='Convert .pg text format to initial seed .init.sg.json'
    )
    parser.add_argument('pg_file', help='Input .pg file')
    parser.add_argument('--out', help='Output .init.sg.json file (inferred if not given)')
    
    args = parser.parse_args()
    
    in_path = Path(args.pg_file)
    if not in_path.exists():
        print(f'Input file not found: {in_path}')
        return 1
    
    # Parse .pg
    pg_text = in_path.read_text(encoding='utf-8')
    events, succ, pred, addr_to_stable_id = parse_pg(pg_text)
    
    if not events:
        print('No events found in .pg file. Writing empty seed graph.')
        seed = {
            "nodes": [],
            "po_per_thread": {},
            "mo_per_location": {}
        }
        out_path = Path(args.out) if args.out else infer_output_path(in_path, '.init.sg.json')
        out_path.write_text(json.dumps(seed, indent=2))
        return 0
    
    # Generate seed
    seed = create_init_seed_from_pg(events, succ, pred, addr_to_stable_id)
    
    # Write output
    out_path = Path(args.out) if args.out else infer_output_path(in_path, '.init.sg.json')
    out_path.write_text(json.dumps(seed, indent=2))
    
    print(f'Wrote {out_path}')
    print(f'  nodes: {len(seed["nodes"])}')
    print(f'  po_per_thread: {len(seed["po_per_thread"])}')
    print(f'  mo_per_location: {len(seed["mo_per_location"])}')
    
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
