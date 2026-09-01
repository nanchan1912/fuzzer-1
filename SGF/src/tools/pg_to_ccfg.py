#!/usr/bin/env python3
"""
Convert .pg (program graph) into .ccfg format with mapped autoincrement event IDs
and specific event fields:
E e{autoincrement} {TID} {Instruction_Address} {Kind} {Loc in number} {Mode}
"""

import sys
import os

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

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 pg_to_ccfg.py <input_pg_file> [output_ccfg_file]")
        sys.exit(1)
        
    input_file = sys.argv[1]
    if len(sys.argv) >= 3:
        output_file = sys.argv[2]
    else:
        # Infer output file name by replacing .pg with .ccfg
        if input_file.endswith('.pg'):
            output_file = input_file[:-3] + '.ccfg'
        else:
            output_file = input_file + '.ccfg'
            
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' does not exist.")
        sys.exit(1)
        
    with open(input_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        
    # Pre-pass: map unique Instruction_Address to the first event's numeric ID
    addr_to_stable_id = {}
    for line in lines:
        line_str = line.strip()
        if not line_str or line_str.startswith('#'):
            continue
        if line_str.startswith('E') and (line_str.startswith('E\t') or line_str.startswith('E ')):
            parts = line_str.split('\t')
            if len(parts) < 8:
                parts = line_str.split()
            if len(parts) >= 8:
                old_id = parts[1]
                addr = parts[7]
                if addr not in addr_to_stable_id:
                    old_id_num = old_id[1:] if (old_id.startswith('e') or old_id.startswith('E')) else old_id
                    addr_to_stable_id[addr] = old_id_num

    events_map = {}  # old_id -> new_id
    output_lines = []
    
    autoincrement = 1
    cf_edges = []
    
    for line_num, line in enumerate(lines, 1):
        line_str = line.strip()
        if not line_str or line_str.startswith('#'):
            continue
            
        # Parse event line
        if line_str.startswith('E') and (line_str.startswith('E\t') or line_str.startswith('E ')):
            # Try splitting by tab first
            parts = line_str.split('\t')
            if len(parts) < 8:
                parts = line_str.split()
                
            if len(parts) >= 8:
                old_id = parts[1]
                tid = parts[2]
                kind = parts[3]
                loc_id = parts[4]
                var_name = parts[5]
                mode = parts[6]
                addr = parts[7]
                
                new_id = f"e{autoincrement}"
                events_map[old_id] = new_id
                autoincrement += 1
                
                # Format: E e{autoincrement} {TID} {Instruction_ID} {Kind} {Loc in number} {Mode}
                stable_id = addr
                loc_val = parse_field_sensitive_loc_id(loc_id)
                loc_hex = f"0x{loc_val:x}"
                ccfg_line = f"E {new_id} {tid} {stable_id} {kind} {loc_hex} {mode}"
                output_lines.append(ccfg_line)
            else:
                print(f"Warning: line {line_num} starts with E but has fewer than 8 fields: {line_str}")
                
        # Parse control flow edge
        elif line_str.startswith('CF') and (line_str.startswith('CF\t') or line_str.startswith('CF ')):
            parts = line_str.split()
            if len(parts) >= 3:
                src = parts[1]
                dst = parts[2]
                cf_edges.append((src, dst))
                
    # Now output CF edges with mapped IDs
    for src, dst in cf_edges:
        mapped_src = events_map.get(src, src)
        mapped_dst = events_map.get(dst, dst)
        output_lines.append(f"CF {mapped_src} {mapped_dst}")
        
    # Write to the ccfg file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(output_lines) + '\n')
        
    print(f"Successfully converted '{input_file}' to '{output_file}'")
    print(f"Total events: {autoincrement - 1}")
    print(f"Total CF edges: {len(cf_edges)}")

if __name__ == '__main__':
    main()
