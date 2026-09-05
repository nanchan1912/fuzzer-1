#!/usr/bin/env python3
"""
==============================================================================
PCTWM Store Buffering (sb-loop) Loop Scaling Experiment Runner
==============================================================================
Runs the Store Buffering (sb-loop) concurrency benchmark with variable loop bounds
across multiple independent trials to evaluate bug rate, variance, and time to first bug.

Usage:
  python3 run_sb_experiment.py [options]

Examples:
  python3 run_sb_experiment.py
  python3 run_sb_experiment.py --loop-values 1 3 5 7 10 15 --trials 5 --runs 20
  python3 run_sb_experiment.py --mode symmetric
  python3 run_sb_experiment.py --mode asymmetric
  python3 run_sb_experiment.py --mode both
  python3 run_sb_experiment.py --eval-mode any
==============================================================================
"""

import os
import sys
import time
import re
import argparse
import subprocess
import json
import csv
import math
from pathlib import Path

# Paths configuration
WORKSPACE_DIR = Path("/mnt/d/IIITH/sirji/pctwm")
SB_LOOP_DIR = WORKSPACE_DIR / "sb-loop"
SB_SRC_TEMPLATE = SB_LOOP_DIR / "sb-loop.cc"
EXPERIMENT_DIR = SB_LOOP_DIR / "experiments"
PCTWM_LIB = WORKSPACE_DIR / "benchmarks_extracted/home/vagrant/pctwmversion/c11tester"
COMPAT_LIB = WORKSPACE_DIR / "compat_libs"
LLVM_BIN = WORKSPACE_DIR / "benchmarks_extracted/home/vagrant/llvm/build/bin"
LLVM_LIB = WORKSPACE_DIR / "benchmarks_extracted/home/vagrant/llvm/build/lib"
INCLUDE_PCTWM = WORKSPACE_DIR / "benchmarks_extracted/home/vagrant/pctwmversion/include"
VERIFY_RUNTIME = WORKSPACE_DIR / "verify_runtime.cpp"
VERIFY_RUNTIME_OBJ = WORKSPACE_DIR / "verify_runtime.o"

# Setup environment
ENV = os.environ.copy()
ld_path = f"{PCTWM_LIB}:{COMPAT_LIB}:{ENV.get('LD_LIBRARY_PATH', '')}"
ENV["LD_LIBRARY_PATH"] = ld_path


def ensure_verify_runtime():
    """Ensure verify_runtime.o is compiled without CDSPass instrumentation."""
    if not VERIFY_RUNTIME_OBJ.exists() or VERIFY_RUNTIME.stat().st_mtime > VERIFY_RUNTIME_OBJ.stat().st_mtime:
        print("[SETUP] Building uninstrumented verify_runtime.o...", end=" ", flush=True)
        cmd = [
            str(LLVM_BIN / "clang++"),
            "-c", str(VERIFY_RUNTIME),
            "-o", str(VERIFY_RUNTIME_OBJ),
            "-std=c++11", "-O2"
        ]
        res = subprocess.run(cmd, env=ENV, capture_output=True, text=True)
        if res.returncode != 0:
            print("FAILED")
            print(res.stderr)
            sys.exit(1)
        print("DONE")


def generate_sb_code(t1_loop: int, t2_loop: int, eval_mode: str = "last") -> str:
    """Generate C++ source code for sb-loop with specific loop bounds and evaluation mode."""
    if eval_mode == "any":
        return f"""// Store Buffering test variant (T1 Loop: {t1_loop}, T2 Loop: {t2_loop}, Eval: ANY)
// Auto-generated for PCTWM loop scaling experiment.

#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>

extern "C" {{
__attribute__((weak)) void __VERIFY_STORE_VAR(const char *name, bool value) {{
    (void)name;
    (void)value;
}}
__attribute__((weak)) bool __VERIFY_ASSERT(const char *expr) {{
    (void)expr;
    return true;
}}
}}

static atomic_int x = 0;
static atomic_int y = 0;

void *thread_1(void *arg) {{
    bool saw_zero = false;
    for (int i = 0; i < {t1_loop}; i++) {{
        atomic_store_explicit(&x, 1, memory_order_relaxed);
        int a = atomic_load_explicit(&y, memory_order_relaxed);
        if (a == 0) saw_zero = true;
    }}
    __VERIFY_STORE_VAR("a", saw_zero);
    return NULL;
}}

void *thread_2(void *arg) {{
    bool saw_zero = false;
    for (int i = 0; i < {t2_loop}; i++) {{
        atomic_store_explicit(&y, 1, memory_order_relaxed);
        int b = atomic_load_explicit(&x, memory_order_relaxed);
        if (b == 0) saw_zero = true;
    }}
    __VERIFY_STORE_VAR("b", saw_zero);
    return NULL;
}}

int main() {{
    atomic_store_explicit(&x, 0, memory_order_relaxed);
    atomic_store_explicit(&y, 0, memory_order_relaxed);

    pthread_t t1, t2;

    pthread_create(&t1, NULL, thread_1, NULL);
    pthread_create(&t2, NULL, thread_2, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    __VERIFY_ASSERT("!(a & b)");

    return 0;
}}
"""
    else:  # "last" iteration mode (standard sb-loop.cc)
        return f"""// Store Buffering test variant (T1 Loop: {t1_loop}, T2 Loop: {t2_loop}, Eval: LAST)
// Auto-generated for PCTWM loop scaling experiment.

#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>

extern "C" {{
__attribute__((weak)) void __VERIFY_STORE_VAR(const char *name, bool value) {{
    (void)name;
    (void)value;
}}
__attribute__((weak)) bool __VERIFY_ASSERT(const char *expr) {{
    (void)expr;
    return true;
}}
}}

static atomic_int x = 0;
static atomic_int y = 0;

void *thread_1(void *arg) {{
    int a = -1;
    for (int i = 0; i < {t1_loop}; i++) {{
        atomic_store_explicit(&x, 1, memory_order_relaxed);
        a = atomic_load_explicit(&y, memory_order_relaxed);
    }}
    __VERIFY_STORE_VAR("a", a == 0);
    return NULL;
}}

void *thread_2(void *arg) {{
    int b = -1;
    for (int i = 0; i < {t2_loop}; i++) {{
        atomic_store_explicit(&y, 1, memory_order_relaxed);
        b = atomic_load_explicit(&x, memory_order_relaxed);
    }}
    __VERIFY_STORE_VAR("b", b == 0);
    return NULL;
}}

int main() {{
    atomic_store_explicit(&x, 0, memory_order_relaxed);
    atomic_store_explicit(&y, 0, memory_order_relaxed);

    pthread_t t1, t2;

    pthread_create(&t1, NULL, thread_1, NULL);
    pthread_create(&t2, NULL, thread_2, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    __VERIFY_ASSERT("!(a & b)");

    return 0;
}}
"""


def compile_variant(src_path: Path, bin_path: Path) -> bool:
    """Compile instrumented binary with Clang and CDSPass."""
    cmd = [
        str(LLVM_BIN / "clang++"),
        "-Xclang", "-load", "-Xclang", str(LLVM_LIB / "libCDSPass.so"),
        "-L" + str(PCTWM_LIB), "-lmodel",
        "-Wno-unused-command-line-argument",
        "-I" + str(INCLUDE_PCTWM),
        "-I" + str(src_path.parent),
        "-o", str(bin_path),
        str(src_path),
        str(VERIFY_RUNTIME_OBJ),
        "-std=c++0x", "-pthread", "-Wall", "-g"
    ]
    log_file = bin_path.with_suffix(".compile.log")
    with open(log_file, "w") as f:
        res = subprocess.run(cmd, env=ENV, stdout=f, stderr=subprocess.STDOUT)
    return res.returncode == 0


def run_trial(bin_path: Path, runs: int, bug_depth: int, event_bound: int, history_depth: int, log_path: Path) -> dict:
    """Execute a single trial (N runs) of the binary under PCTWM."""
    c11tester_env = f"-x1 -p1 -b{bug_depth} -i{event_bound} -y{history_depth}"
    trial_env = ENV.copy()
    trial_env["C11TESTER"] = c11tester_env

    bug_count = 0
    race_count = 0
    livelock_count = 0
    clean_count = 0
    first_bug_run = 0
    first_bug_time_ms = 0

    start_trial_time = time.time()

    with open(log_path, "w") as log:
        log.write(f"=== PCTWM Trial Log: {bin_path.name} ===\n")
        log.write(f"C11TESTER={c11tester_env}\n\n")

        for i in range(1, runs + 1):
            run_start = time.time()
            log.write(f"--- Run #{i} ---\n")
            try:
                proc = subprocess.run(
                    [str(bin_path)],
                    env=trial_env,
                    cwd=str(bin_path.parent),
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                out = proc.stdout + proc.stderr
            except subprocess.TimeoutExpired:
                out = "TIMEOUT / LIVELOCK"
            
            log.write(out + "\n\n")

            is_bug = False
            if re.search(r"assertion failed|assert|number of buggy executions:\s*[1-9]|pctwm assertion failed", out, re.IGNORECASE):
                bug_count += 1
                is_bug = True
            elif re.search(r"race", out, re.IGNORECASE):
                race_count += 1
                is_bug = True
            elif re.search(r"livelock|timeout", out, re.IGNORECASE):
                livelock_count += 1
                is_bug = True
            else:
                clean_count += 1

            if is_bug and first_bug_run == 0:
                first_bug_run = i
                first_bug_time_ms = round((time.time() - start_trial_time) * 1000)

    end_trial_time = time.time()
    total_ms = round((end_trial_time - start_trial_time) * 1000)
    avg_ms = round(total_ms / runs) if runs > 0 else 0
    total_bugs = bug_count + race_count + livelock_count
    bug_rate = (total_bugs * 100.0) / runs if runs > 0 else 0.0

    return {
        "runs": runs,
        "bugs": bug_count,
        "races": race_count,
        "livelocks": livelock_count,
        "clean": clean_count,
        "total_bugs": total_bugs,
        "bug_rate": bug_rate,
        "first_bug_run": first_bug_run,
        "first_bug_time_ms": first_bug_time_ms if first_bug_run > 0 else None,
        "total_ms": total_ms,
        "avg_ms": avg_ms
    }


def calc_stats(values):
    """Compute mean and sample standard deviation."""
    n = len(values)
    if n == 0:
        return 0.0, 0.0
    mean = sum(values) / n
    if n == 1:
        return mean, 0.0
    variance = sum((x - mean) ** 2 for x in values) / (n - 1)
    std_dev = math.sqrt(variance)
    return mean, std_dev


def main():
    parser = argparse.ArgumentParser(description="PCTWM Store Buffering Loop Scaling Experiment")
    parser.add_argument("--loop-values", nargs="+", type=int, default=[1, 3, 5, 7, 10, 15],
                        help="List of loop iteration bounds to evaluate (default: 1 3 5 7 10 15)")
    parser.add_argument("--trials", type=int, default=5,
                        help="Number of independent trial sessions per loop value (default: 5)")
    parser.add_argument("--runs", type=int, default=20,
                        help="Number of PCTWM runs per trial (default: 20)")
    parser.add_argument("--bug-depth", "-b", type=int, default=1,
                        help="PCT bug depth bound d (default: 1)")
    parser.add_argument("--history-depth", "-y", type=int, default=1,
                        help="Reads-from history bound h (default: 1)")
    parser.add_argument("--event-bound", "-i", type=int, default=None,
                        help="Event bound k (default: automatically scaled with loop size)")
    parser.add_argument("--mode", choices=["symmetric", "asymmetric", "both"], default="symmetric",
                        help="Scaling mode: symmetric (T1=N, T2=N), asymmetric (T1=N, T2=1), or both")
    parser.add_argument("--eval-mode", choices=["last", "any"], default="last",
                        help="Assertion evaluation mode: 'last' (final iteration load) or 'any' (any iteration load)")
    args = parser.parse_args()

    EXPERIMENT_DIR.mkdir(parents=True, exist_ok=True)
    ensure_verify_runtime()

    configurations = []
    if args.mode in ["symmetric", "both"]:
        for n in args.loop_values:
            configurations.append({"name": f"Symmetric (T1={n}, T2={n})", "t1": n, "t2": n, "val": n, "type": "symmetric"})
    if args.mode in ["asymmetric", "both"]:
        for n in args.loop_values:
            configurations.append({"name": f"Asymmetric (T1={n}, T2=1)", "t1": n, "t2": 1, "val": n, "type": "asymmetric"})

    print("\n" + "=" * 125)
    print("                         PCTWM STORE BUFFERING (SB-LOOP) SCALING EXPERIMENT                        ")
    print("=" * 125)
    print(f"Loop Values:          {args.loop_values}")
    print(f"Trials per Value:     {args.trials} trials (for variance / statistical confidence)")
    print(f"Runs per Trial:       {args.runs} runs (Total per loop value = {args.trials * args.runs} runs)")
    print(f"Parameters:           Bug Depth (d)={args.bug_depth} | History Bound (h)={args.history_depth}")
    print(f"Scaling Mode:         {args.mode.upper()}")
    print(f"Evaluation Mode:      {args.eval_mode.upper()} iteration")
    print("=" * 125 + "\n")

    all_results = []
    table_rows = []

    for config in configurations:
        t1, t2 = config["t1"], config["t2"]
        cfg_name = config["name"]
        
        # Determine event bound k
        k = args.event_bound if args.event_bound else max(30, (t1 + t2) * 2 + 15)

        src_file = EXPERIMENT_DIR / f"sb_loop_t1_{t1}_t2_{t2}_{args.eval_mode}.cc"
        bin_file = EXPERIMENT_DIR / f"pctwm_sb_loop_t1_{t1}_t2_{t2}_{args.eval_mode}"

        # Generate source
        src_file.write_text(generate_sb_code(t1, t2, args.eval_mode))

        # Compile
        print(f"[COMPILE] Building {cfg_name} (Event Bound k={k})...", end=" ", flush=True)
        if not compile_variant(src_file, bin_file):
            print("FAILED")
            continue
        print("DONE")

        trial_rates = []
        trial_ttfb = []
        trial_avg_times = []

        print(f"  [RUNNING] Executing {args.trials} trials x {args.runs} runs...")

        for trial_idx in range(1, args.trials + 1):
            log_path = EXPERIMENT_DIR / f"run_t1_{t1}_t2_{t2}_{args.eval_mode}_trial_{trial_idx}.log"
            res = run_trial(bin_file, args.runs, args.bug_depth, k, args.history_depth, log_path)

            trial_rates.append(res["bug_rate"])
            if res["first_bug_time_ms"] is not None:
                trial_ttfb.append(res["first_bug_time_ms"])
            trial_avg_times.append(res["avg_ms"])

            ttfb_disp = f"{res['first_bug_time_ms']}ms (Run #{res['first_bug_run']})" if res["first_bug_run"] > 0 else "N/A"
            print(f"    Trial #{trial_idx}: Bug Rate: {res['bug_rate']:5.1f}% ({res['total_bugs']}/{res['runs']}) | 1st Bug: {ttfb_disp:>16} | Avg Run: {res['avg_ms']:3d}ms")

            table_rows.append({
                "config": cfg_name,
                "loop_val": config["val"],
                "trial": f"Trial #{trial_idx}",
                "runs": res["runs"],
                "bugs": res["bugs"],
                "races": res["races"],
                "clean": res["clean"],
                "bug_rate_str": f"{res['bug_rate']:.1f}%",
                "bug_rate": res["bug_rate"],
                "ttfb_str": ttfb_disp,
                "avg_ms": res["avg_ms"]
            })

            all_results.append({
                "config": cfg_name,
                "mode": config["type"],
                "eval_mode": args.eval_mode,
                "t1_loop": t1,
                "t2_loop": t2,
                "trial": trial_idx,
                "k": k,
                **res
            })

        # Aggregated statistics
        mean_rate, std_rate = calc_stats(trial_rates)
        mean_ttfb, std_ttfb = calc_stats(trial_ttfb) if trial_ttfb else (None, None)
        mean_avg_time, _ = calc_stats(trial_avg_times)

        ttfb_summary = f"{mean_ttfb:.0f}ms ± {std_ttfb:.0f}ms" if mean_ttfb is not None else "N/A"
        rate_summary = f"{mean_rate:.1f}% ± {std_rate:.1f}%"

        print(f"  --> SUMMARY for {cfg_name}: Mean Bug Rate = {rate_summary} | Mean TTFB = {ttfb_summary} | Avg Time = {mean_avg_time:.0f}ms\n")

        table_rows.append({
            "config": f"** {cfg_name} (MEAN ± STD) **",
            "loop_val": config["val"],
            "trial": "SUMMARY",
            "runs": args.trials * args.runs,
            "bugs": sum(r["bugs"] for r in all_results[-args.trials:]),
            "races": sum(r["races"] for r in all_results[-args.trials:]),
            "clean": sum(r["clean"] for r in all_results[-args.trials:]),
            "bug_rate_str": rate_summary,
            "bug_rate": mean_rate,
            "ttfb_str": ttfb_summary,
            "avg_ms": round(mean_avg_time)
        })

    # Save Results to JSON & CSV
    json_path = EXPERIMENT_DIR / "sb_experiment_results.json"
    csv_path = EXPERIMENT_DIR / "sb_experiment_results.csv"

    with open(json_path, "w") as f:
        json.dump(all_results, f, indent=2)

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Config", "Mode", "EvalMode", "T1_Loop", "T2_Loop", "Trial", "Runs", "Bugs", "Races", "Livelocks", "Clean", "BugRate_Pct", "FirstBugRun", "FirstBugTime_ms", "TotalTime_ms", "AvgRunTime_ms"])
        for r in all_results:
            writer.writerow([
                r["config"], r["mode"], r.get("eval_mode", "last"), r["t1_loop"], r["t2_loop"], r["trial"],
                r["runs"], r["bugs"], r["races"], r["livelocks"], r["clean"],
                f"{r['bug_rate']:.1f}", r["first_bug_run"], r["first_bug_time_ms"] or "N/A",
                r["total_ms"], r["avg_ms"]
            ])

    # Print Final Summary Table
    print("\n" + "=" * 125)
    print("                                      PCTWM EXPERIMENT COMPLETE SUMMARY TABLE                                      ")
    print("=" * 125)
    printf_fmt = "%-30s | %-9s | %5s | %5s | %5s | %5s | %16s | %22s | %8s\n"
    print(printf_fmt % ("Configuration", "Trial", "Runs", "Bugs", "Races", "Clean", "Bug Rate", "Time to 1st Bug", "Avg Time"), end="")
    print("-" * 125)

    for row in table_rows:
        if row["trial"] == "SUMMARY":
            print("-" * 125)
            print(printf_fmt % (row["config"], row["trial"], row["runs"], row["bugs"], row["races"], row["clean"], row["bug_rate_str"], row["ttfb_str"], f"{row['avg_ms']}ms"), end="")
            print("-" * 125)
        else:
            print(printf_fmt % (row["config"], row["trial"], row["runs"], row["bugs"], row["races"], row["clean"], row["bug_rate_str"], row["ttfb_str"], f"{row['avg_ms']}ms"), end="")

    print("=" * 125)
    print(f"\n[DONE] All experimental data exported successfully:")
    print(f"  - CSV Data:  {csv_path}")
    print(f"  - JSON Data: {json_path}")
    print(f"  - Raw Logs:  {EXPERIMENT_DIR}/run_t1_*_t2_*.log\n")


if __name__ == "__main__":
    main()
