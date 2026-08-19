#!/usr/bin/env python3
import sys
import os
import json
import subprocess
import argparse
from pathlib import Path

def parse_ccfg(ccfg_path):
    nodes = {}
    succ = {}
    pred = {}
    global_inits = []

    if not os.path.exists(ccfg_path):
        return None, None, None, None

    with open(ccfg_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if parts[0] == 'E' and len(parts) >= 7:
                eid = parts[1]
                tid = parts[2]
                iid = parts[3]
                kind = parts[4]
                loc = parts[5]
                mode = parts[6]
                nodes[eid] = {
                    'eid': eid,
                    'tid': tid,
                    'iid': iid,
                    'kind': kind,
                    'loc': loc,
                    'mode': mode
                }
                # Check if it's a global init (no CF edges, TID 0, kind W)
                # We will identify them later during traversal.
            elif parts[0] == 'CF' and len(parts) >= 3:
                src = parts[1]
                dst = parts[2]
                succ.setdefault(src, []).append(dst)
                pred.setdefault(dst, []).append(src)

    # Global inits are TID 0 nodes
    for eid, node in nodes.items():
        if node['tid'] == '0':
            global_inits.append(node)

    return nodes, succ, pred, global_inits

def get_thread_nodes_and_edges(nodes, succ, pred, tid):
    t_nodes = {eid: node for eid, node in nodes.items() if node['tid'] == tid}
    t_succ = {}
    t_pred = {}
    for src, dsts in succ.items():
        if src in t_nodes:
            for dst in dsts:
                if dst in t_nodes:
                    t_succ.setdefault(src, []).append(dst)
                    t_pred.setdefault(dst, []).append(src)
    return t_nodes, t_succ, t_pred

def find_thread_prefixes(nodes, succ, pred, tid, max_visits=1):
    t_nodes, t_succ, t_pred = get_thread_nodes_and_edges(nodes, succ, pred, tid)
    if not t_nodes:
        return [[]]

    # Entry nodes have no incoming CF edges within the thread
    entries = [eid for eid in t_nodes if eid not in t_pred]
    if not entries:
        # If there's a loop with no entries, take any node as entry
        entries = list(t_nodes.keys())

    prefixes = []
    
    def dfs(curr_eid, path, visits):
        path.append(curr_eid)
        node = t_nodes[curr_eid]
        iid = node['iid']
        visits[iid] = visits.get(iid, 0) + 1

        if visits[iid] > max_visits:
            # Loop limit reached, stop and record path prefix
            prefixes.append(list(path[:-1]))
            path.pop()
            visits[iid] -= 1
            return

        prefixes.append(list(path))

        successors = t_succ.get(curr_eid, [])
        for succ_eid in successors:
            dfs(succ_eid, path, visits)

        path.pop()
        visits[iid] -= 1

    for entry in entries:
        dfs(entry, [], {})

    # Dedup prefixes
    unique_prefixes = []
    seen = set()
    for p in prefixes:
        tup = tuple(p)
        if tup not in seen:
            seen.add(tup)
            unique_prefixes.append(p)

    # Include empty prefix for spawned threads
    if tid != '0':
        unique_prefixes.append([])

    return unique_prefixes

def build_subgraph(prefix_combination, nodes, global_inits, rf_strategy='seq'):
    # prefix_combination is a list of lists of event_ids
    # 1. Collect all events in the selected prefixes, plus global inits
    all_events = []
    
    # Add global inits first
    for g_init in global_inits:
        all_events.append(g_init)

    # Add selected thread prefixes
    for prefix in prefix_combination:
        # Compute visit count dynamically along the prefix
        visit_counts = {}
        for eid in prefix:
            node = nodes[eid]
            iid = node['iid']
            visit_counts[iid] = visit_counts.get(iid, 0) + 1
            
            # Create a dynamic instance copy
            inst = node.copy()
            inst['visit_id'] = str(visit_counts[iid])
            all_events.append(inst)

    # 2. Build the output nodes list
    sg_nodes = []
    for idx, ev in enumerate(all_events, start=1):
        sg_nodes.append({
            "event_id": str(idx),
            "thread_id": ev['tid'],
            "kind": ev['kind'],
            "loc_id": ev['loc'],
            "instruction_id": ev['iid'],
            "visit_id": ev.get('visit_id', '1'),
            "access_mode": ev['mode'].upper() if ev['mode'] != 'NA' else 'NA'
        })

    # 3. po_per_thread
    po_map = {}
    for ev in sg_nodes:
        # Global inits (no CF edges) are not in program order per thread list in seed
        # Wait, let's check: are global inits included in po_per_thread?
        # In init.sg.json, they ARE in po_per_thread under thread 0!
        # So we include them.
        po_map.setdefault(ev['thread_id'], []).append([ev['thread_id'], ev['instruction_id'], ev['visit_id']])

    po_per_thread = [
        {"thread_id": tid, "list": lst}
        for tid, lst in sorted(po_map.items())
    ]

    # 4. mo_per_location
    mo_map = {}
    for ev in sg_nodes:
        if ev['kind'] in ('W', 'RMW', 'CMPXCHG'):
            mo_map.setdefault(ev['loc_id'], []).append([ev['thread_id'], ev['instruction_id'], ev['visit_id']])

    # Sort mo lists to avoid cycles (e.g. by thread_id, then by PO index)
    # Since po_map has the PO order, we can look up index in po_map
    for loc, lst in mo_map.items():
        lst.sort(key=lambda item: (int(item[0]), po_map[item[0]].index(item)))

    mo_per_location = [
        {"location": loc, "list": lst}
        for loc, lst in sorted(mo_map.items())
    ]

    # 5. rf_edges
    rf_edges = []
    # Find all writes/RMWs for read-from matching
    writes = [ev for ev in sg_nodes if ev['kind'] in ('W', 'RMW', 'CMPXCHG')]
    reads = [ev for ev in sg_nodes if ev['kind'] in ('R', 'RMW', 'CMPXCHG')]

    for r in reads:
        # RMW matches read parts, but wait, does it read? Yes.
        loc = r['loc_id']
        tid = r['thread_id']
        
        # Candidate writes to the same location
        candidates = []
        for w in writes:
            if w['loc_id'] != loc:
                continue
            # PO check: if same thread, write must PO-precede read
            if w['thread_id'] == tid:
                # Find indexes in po_map
                try:
                    w_idx = po_map[tid].index([w['thread_id'], w['instruction_id'], w['visit_id']])
                    r_idx = po_map[tid].index([r['thread_id'], r['instruction_id'], r['visit_id']])
                    if w_idx < r_idx:
                        candidates.append(w)
                except ValueError:
                    pass
            else:
                # Different thread writes are concurrent, always candidates
                candidates.append(w)

        if not candidates:
            continue

        selected_write = None
        if rf_strategy == 'seq':
            # Prefer the most recent PO-precede write, otherwise any write
            po_candidates = [w for w in candidates if w['thread_id'] == tid]
            if po_candidates:
                # Most recent PO-precede
                selected_write = po_candidates[-1]
            else:
                selected_write = candidates[-1]
        elif rf_strategy == 'inter':
            # Prefer inter-thread write if available, otherwise seq
            inter_candidates = [w for w in candidates if w['thread_id'] != tid]
            if inter_candidates:
                selected_write = inter_candidates[-1]
            else:
                selected_write = candidates[-1]

        if selected_write:
            rf_edges.append({
                "from": [selected_write['thread_id'], selected_write['instruction_id'], selected_write['visit_id']],
                "to": [[r['thread_id'], r['instruction_id'], r['visit_id']]]
            })

    return {
        "nodes": sg_nodes,
        "rf_edges": rf_edges,
        "po_per_thread": po_per_thread,
        "mo_per_location": mo_per_location,
        "sw_edges": []
    }

def run_test_subgraph(binary_path, sg_data, temp_file_path):
    with open(temp_file_path, 'w', encoding='utf-8') as f:
        json.dump(sg_data, f, indent=2)

    env = os.environ.copy()
    env["FUZZ_INPUT"] = str(temp_file_path)

    try:
        res = subprocess.run(
            [str(binary_path)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        return res.returncode, res.stdout.decode('utf-8', errors='ignore'), res.stderr.decode('utf-8', errors='ignore')
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout.decode('utf-8', errors='ignore') if e.stdout else ""
        stderr = e.stderr.decode('utf-8', errors='ignore') if e.stderr else ""
        return -9, stdout, stderr

def test_benchmark(benchmark_dir, max_subgraphs=20):
    print(f"\n==================================================")
    print(f" Testing Benchmark: {benchmark_dir.name}")
    print(f"==================================================")

    data_dir = benchmark_dir / "data"
    ccfg_path = data_dir / "generated_output.ccfg"
    binary_path = data_dir / f"{benchmark_dir.name}.instrumented.out"

    if not binary_path.exists():
        print(f"Error: Instrumented binary not found: {binary_path}")
        return False

    nodes, succ, pred, global_inits = parse_ccfg(ccfg_path)
    if not nodes:
        print(f"Error: Failed to parse CCFG or file missing: {ccfg_path}")
        return False

    # Extract all active thread IDs, excluding '0' which is the sequential initialization prefix
    tids = sorted(list(set(node['tid'] for node in nodes.values() if node['tid'] != '0')))
    print(f"Threads detected in CCFG: {tids}")

    # Generate prefixes for each thread
    thread_prefixes = {}
    for tid in tids:
        prefixes = find_thread_prefixes(nodes, succ, pred, tid, max_visits=1)
        thread_prefixes[tid] = prefixes
        print(f"  Thread {tid}: {len(prefixes)} execution prefixes")

    # Combine prefixes
    import itertools
    keys = sorted(thread_prefixes.keys())
    combo_iter = itertools.product(*(thread_prefixes[k] for k in keys))

    # Generate SGs (subgraphs) using both 'seq' and 'inter' strategies
    sgs = []
    seen_sgs = set()
    
    count = 0
    for combo in combo_iter:
        for strategy in ('seq', 'inter'):
            sg = build_subgraph(combo, nodes, global_inits, rf_strategy=strategy)
            
            # Serialize to check uniqueness
            sg_str = json.dumps(sg, sort_keys=True)
            if sg_str not in seen_sgs:
                seen_sgs.add(sg_str)
                sgs.append(sg)
                if len(sgs) >= max_subgraphs:
                    break
        if len(sgs) >= max_subgraphs:
            break
        count += 1
        # Hard limit to avoid infinite loop in massive products
        if count > 5000:
            break

    print(f"Generated {len(sgs)} unique candidate subgraphs for validation")

    temp_file = Path("/tmp/temp_sg.json")
    success_count = 0
    fail_count = 0

    for idx, sg in enumerate(sgs, start=1):
        print(f"  [Test {idx}/{len(sgs)}] Nodes={len(sg['nodes'])}, RF={len(sg['rf_edges'])}...", end="", flush=True)
        ret, stdout, stderr = run_test_subgraph(binary_path, sg, temp_file)
        if ret in (0, 20, 21):
            print(" SUCCESS (Code 0/20/21)")
            success_count += 1
        else:
            print(f" FAILED (Code {ret})")
            print("    --- SUBGRAPH JSON ---")
            print(json.dumps(sg, indent=2))
            print("    --- STDERR ---")
            for line in stderr.splitlines()[-100:]:
                print(f"    {line}")
            fail_count += 1

    if temp_file.exists():
        temp_file.unlink()

    print(f"Summary for {benchmark_dir.name}: {success_count} passed, {fail_count} failed.")
    return fail_count == 0

def main():
    parser = argparse.ArgumentParser(description="Exhaustive WMM execution subgraph tester")
    parser.add_argument("benchmark", nargs="?", help="Benchmark directory to test (default: all compiled)")
    parser.add_argument("--max-subgraphs", type=int, default=25, help="Max subgraphs to test per benchmark")
    parser.add_argument("--exhaustive", action="store_true", help="Run exhaustive checks without interactive prompt")
    args = parser.parse_args()

    # Interactive check
    if not args.exhaustive:
        ans = input("Run exhaustive checks? (y/n): ").strip().lower()
        if ans not in ('y', 'yes'):
            print("Exhaustive check cancelled by user.")
            return 0

    base_dir = Path("/workspaces/EGF/pthread_version_of_benchmarks")
    
    if args.benchmark:
        benchmarks = [base_dir / args.benchmark]
    else:
        # Find all directories that contain a data/generated_output.ccfg
        benchmarks = []
        for p in base_dir.iterdir():
            if p.is_dir() and (p / "data" / "generated_output.ccfg").exists():
                benchmarks.append(p)

    failed_benchmarks = []
    for bench in sorted(benchmarks):
        if not test_benchmark(bench, max_subgraphs=args.max_subgraphs):
            failed_benchmarks.append(bench.name)

    print("\n==================================================")
    print(" PIPELINE FINAL RESULTS")
    print("==================================================")
    if failed_benchmarks:
        print(f"FAILURES detected in: {failed_benchmarks}")
        sys.exit(1)
    else:
        print("All tested benchmarks instantiated successfully under all generated subgraphs!")
        sys.exit(0)

if __name__ == "__main__":
    main()
