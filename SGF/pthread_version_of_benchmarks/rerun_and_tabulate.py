#!/usr/bin/env python3
import os
import sys
import subprocess
import argparse
from collections import defaultdict

# Mapping of exit codes to WMM Error Names
WMM_EXIT_NAMES = {
    0: "SUCCESS",
    10: "WMM_EXIT_EVENT_NOT_FOUND",
    11: "WMM_EXIT_EVENT_MISMATCH",
    12: "WMM_EXIT_RF_TYPE_MISMATCH / INVALID_INPUT",
    20: "WMM_EXIT_INSTANTIATED_BUT_NOT_DONE",
    21: "WMM_EXIT_NOT_INSTANTIABLE",
}

def get_error_name(code):
    if code in WMM_EXIT_NAMES:
        return WMM_EXIT_NAMES[code]
    if code >= 128:
        sig = code - 128
        signals = {
            1: "SIGHUP",
            2: "SIGINT",
            3: "SIGQUIT",
            4: "SIGILL",
            5: "SIGTRAP",
            6: "SIGABRT",
            8: "SIGFPE",
            9: "SIGKILL",
            11: "SIGSEGV",
            13: "SIGPIPE",
            14: "SIGALRM",
            15: "SIGTERM"
        }
        sig_name = signals.get(sig, f"Signal {sig}")
        return f"CRASH ({sig_name})"
    return f"OTHER (Exit Code {code})"

def main():
    parser = argparse.ArgumentParser(description="Rerun a target binary on AFL-generated inputs and group by WMM error/exit codes.")
    parser.add_argument("target",
                        help="Path to the instrumented target binary (example: ./barrier/data/barrier.instrumented.out)")
    parser.add_argument("afl_out", nargs="?", default="out/default",
                        help="Path to the AFL output directory (default: out/default)")
    parser.add_argument("--timeout", type=float, default=2.0,
                        help="Timeout in seconds for each execution (default: 2.0)")
    args = parser.parse_args()

    target_path = os.path.abspath(args.target)
    afl_out_dir = os.path.abspath(args.afl_out)

    if not os.path.exists(target_path):
        print(f"Error: Target binary not found at '{target_path}'", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(afl_out_dir):
        print(f"Error: AFL output directory not found at '{afl_out_dir}'", file=sys.stderr)
        sys.exit(1)

    search_dirs = ["queue", "crashes", "hangs", "non_instantiable", "races"]
    inputs_by_dir = defaultdict(list)

    # Collect all input files starting with 'id:' in each subdirectory
    for sdir in search_dirs:
        dir_path = os.path.join(afl_out_dir, sdir)
        if not os.path.isdir(dir_path):
            continue
        for fname in os.listdir(dir_path):
            if not fname.startswith("id:"):
                continue
            fpath = os.path.join(dir_path, fname)
            if os.path.isfile(fpath):
                inputs_by_dir[sdir].append(fpath)

    total_inputs = sum(len(lst) for lst in inputs_by_dir.values())
    if total_inputs == 0:
        print("No AFL-generated inputs found in the specified directories.")
        return

    print(f"Found {total_inputs} inputs to rerun:")
    for sdir in search_dirs:
        if sdir in inputs_by_dir:
            print(f"  - {sdir}: {len(inputs_by_dir[sdir])} inputs")

    print("\nRunning target binary on all inputs...")

    # Dict to group results: exit_code -> list of (subdir, file_path)
    grouped_results = defaultdict(list)
    completed_count = 0

    for sdir, files in inputs_by_dir.items():
        for fpath in files:
            env = os.environ.copy()

            input_path = fpath
            if sdir == "races":
                basename = os.path.basename(fpath)
                if ",src:" in basename:
                    src_id = basename.split(",src:")[1]
                    queue_dir = os.path.join(afl_out_dir, "queue")
                    found_src = False
                    if os.path.isdir(queue_dir):
                        for q_fname in os.listdir(queue_dir):
                            if q_fname.startswith(f"id:{src_id},") or q_fname.startswith(f"id:{src_id}."):
                                input_path = os.path.join(queue_dir, q_fname)
                                found_src = True
                                break
                    if not found_src:
                        print(f"Warning: Could not find source queue file for race file {fpath}", file=sys.stderr)

            env["FUZZ_INPUT"] = input_path
            # env["FUZZ_INPUT"] = fpath
            env["CHECK_DATA_RACE"] = "1"
            
            # Set library paths if needed
            wmm_build_lib = os.path.abspath(os.path.join(os.path.dirname(target_path), "../../../../src/build"))
            if os.path.isdir(wmm_build_lib):
                env["LD_LIBRARY_PATH"] = wmm_build_lib + ":" + env.get("LD_LIBRARY_PATH", "")

            try:
                # Run the process
                # res = subprocess.run(["taskset", "-c", "0", target_path], env=env, timeout=args.timeout,
                res = subprocess.run([target_path], env=env, timeout=args.timeout,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                ret_code = res.returncode
            except subprocess.TimeoutExpired:
                # 143 (128+15) is SIGTERM
                ret_code = 143
            except Exception as e:
                print(f"Error executing target on {fpath}: {e}")
                ret_code = -1

            grouped_results[ret_code].append((sdir, fpath))
            completed_count += 1
            if completed_count % 50 == 0 or completed_count == total_inputs:
                print(f"Progress: {completed_count}/{total_inputs} executed...", end="\r")
    
    print("\n\n" + "="*80)
    print("                           RERUN RESULTS SUMMARY")
    print("="*80)

    # Print a tabulated markdown-style table
    print(f"{'Exit Code':<10} | {'WMM Error / Category':<45} | {'Count':<6} | {'Subdirs Breakdown'}")
    print("-" * 11 + "+" + "-" * 47 + "+" + "-" * 8 + "+" + "-" * 30)

    # Sort exit codes by count descending, or by exit code
    sorted_codes = sorted(grouped_results.keys(), key=lambda c: len(grouped_results[c]), reverse=True)

    for code in sorted_codes:
        items = grouped_results[code]
        err_name = get_error_name(code)
        count = len(items)
        
        # Breakdown by subdirectory
        breakdown = defaultdict(int)
        for sdir, _ in items:
            breakdown[sdir] += 1
        breakdown_str = ", ".join(f"{k}: {v}" for k, v in sorted(breakdown.items()))

        print(f"{code:<10} | {err_name:<45} | {count:<6} | {breakdown_str}")

    print("="*80)

    # Optionally print examples for non-zero/non-success outcomes
    print("\nExample files for error/crash exit codes:")
    for code in sorted_codes:
        if code == 0:
            continue
        items = grouped_results[code]
        err_name = get_error_name(code)
        print(f"\nExit Code {code} ({err_name}) - Total {len(items)}:")
        # Show up to 5 examples
        for i, (sdir, fpath) in enumerate(items[:5]):
            print(f"  [{sdir}] {os.path.basename(fpath)}")
        if len(items) > 5:
            print(f"  ... and {len(items) - 5} more")

if __name__ == "__main__":
    main()
