#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# AFL++ campaign runner: every benchmark x {feedback, no-feedback} x K repeats
#
# Per run it keeps the raw AFL output (races/, crashes/, hangs/, queue/,
# plot_data, fuzzer_stats), the queue visualization, and a sampled timeline
# that records how execs and bug counts grew over the run. analyze_results.py
# turns that tree into the summary tables and charts.
#
#   ./run_all_and_record.sh                       # full campaign, defaults
#   ./run_all_and_record.sh -k 5 -T 60            # quicker smoke campaign
#   ./run_all_and_record.sh -b barrier,ms-queue   # subset
#   ./run_all_and_record.sh --list                # what would run, and why not
#
# Time budget is roughly  (#benchmarks * #configs * K * T) / jobs.
# ============================================================================

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly INVOCATION_DIR="$PWD"

# ------------------------------------------------------------
# Defaults (all overridable by flag or environment)
# ------------------------------------------------------------

REPEATS="${REPEATS:-20}"          # K
MAX_TIME="${MAX_TIME:-300}"       # per-run budget, seconds
JOBS="${JOBS:-0}"                 # 0 => auto
RESULTS_ROOT="${RESULTS_ROOT:-}"
BENCH_FILTER="${BENCH_FILTER:-}"
CONFIGS="${CONFIGS:-feedback,nofeedback}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-0.5}"
RUN_QUEUE_VISUALIZER="${RUN_QUEUE_VISUALIZER:-1}"
KEEP_QUEUE="${KEEP_QUEUE:-1}"     # 0 => delete queue/ after visualizing
ANALYZE="${ANALYZE:-1}"
LIST_ONLY=0
DRY_RUN=0

# Benchmarks whose interesting behaviour is the array/index handling itself:
# the feedback signal does not apply, so these run in the feedback config only.
ARRAY_BENCHMARKS="${ARRAY_BENCHMARKS:-test-array check_arrays}"

# Candidate benchmarks. Anything here without a built binary is reported as
# "-" (could not run) rather than silently dropped.
BENCHMARKS_DEFAULT=(
    iris mabain silo
    _motivating-example
    barrier barrier-change barrier-ori
    chase-lev-deque chasechange
    dekker-change dekker-fences
    linuxrwchange linuxrwlocks
    mcs-change mcs-lock mcs2
    mpmc-change mpmc-queue mpmc3
    ms-queue ms-queue-tsan11 mschange
    
    ringbuffer rwqueue spsc-queue
    sb-loop test-array test-struct test-mp
    check_arrays check_loops null-deref test-sb-loop test-template-complex
    cas-simple
)

# ------------------------------------------------------------
# CLI
# ------------------------------------------------------------

usage() {
    sed -n '4,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    cat <<EOF

Options:
  -k, --repeats N       runs per (benchmark, config)        [${REPEATS}]
  -T, --time SECS       AFL budget per run                  [${MAX_TIME}]
  -j, --jobs N          parallel runs (0 = auto)            [auto]
  -o, --out DIR         results root                        [results/<stamp>]
  -b, --benchmarks LIST comma-separated subset              [all]
      --configs LIST    feedback,nofeedback                 [${CONFIGS}]
      --sample SECS     timeline sampling interval          [${SAMPLE_INTERVAL}]
      --no-viz          skip per-run queue visualization
      --no-queue        delete queue/ after visualizing (saves disk)
      --no-analyze      skip the analysis pass at the end
      --list            show the run plan and exit
      --dry-run         create the tree, do not fuzz
  -h, --help

Environment:
  PROGRESS=bar|log|none   progress display; 'auto' (default) picks bar on a
                          terminal and plain log lines when redirected
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -k|--repeats)     REPEATS="$2"; shift 2 ;;
        -T|--time)        MAX_TIME="$2"; shift 2 ;;
        -j|--jobs)        JOBS="$2"; shift 2 ;;
        -o|--out)         RESULTS_ROOT="$2"; shift 2 ;;
        -b|--benchmarks)  BENCH_FILTER="$2"; shift 2 ;;
        --configs)        CONFIGS="$2"; shift 2 ;;
        --sample)         SAMPLE_INTERVAL="$2"; shift 2 ;;
        --no-viz)         RUN_QUEUE_VISUALIZER=0; shift ;;
        --no-queue)       KEEP_QUEUE=0; shift ;;
        --no-analyze)     ANALYZE=0; shift ;;
        --list)           LIST_ONLY=1; shift ;;
        --dry-run)        DRY_RUN=1; shift ;;
        -h|--help)        usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

log()  { echo "[$(date -u +%H:%M:%S)] $*"; }
err()  { echo "[$(date -u +%H:%M:%S)] ERROR: $*" >&2; }

abspath() {
    local path="$1" base="${2:-$INVOCATION_DIR}"
    [[ -n "$path" ]] || return 0
    [[ "$path" = /* ]] || path="${base}/${path}"
    realpath -m "$path"
}

# ------------------------------------------------------------
# Plan
# ------------------------------------------------------------

if [[ "$JOBS" -le 0 ]]; then
    # Each run drives one target process at a time, so ~1 core per run; keep
    # two cores free for the fuzzers' bookkeeping and the samplers. Memory is
    # the other ceiling -- an AFL instance plus its instrumented target runs
    # around 1.5 GB on the heavier benchmarks, and overcommitting turns the
    # campaign into a swap storm that silently distorts every timing number.
    JOBS=$(( $(nproc) - 2 ))
    mem_gb="$(awk '/MemAvailable/ {printf "%d", $2 / 1048576}' /proc/meminfo 2>/dev/null || echo 0)"
    if [[ "${mem_gb:-0}" -gt 0 ]]; then
        mem_jobs=$(( mem_gb * 2 / 3 ))     # ~1.5 GB per concurrent run
        (( mem_jobs < JOBS )) && JOBS=$mem_jobs
    fi
    (( JOBS < 1 )) && JOBS=1
fi

IFS=',' read -r -a CONFIG_LIST <<< "$CONFIGS"

declare -a BENCHMARKS
if [[ -n "$BENCH_FILTER" ]]; then
    IFS=',' read -r -a BENCHMARKS <<< "$BENCH_FILTER"
else
    BENCHMARKS=("${BENCHMARKS_DEFAULT[@]}")
fi

# A benchmark is runnable only with an instrumented binary, a static graph and
# an initial seed graph. Returns the reason on stdout when it is not.
bench_blocker() {
    local name="$1"
    local dir="${SCRIPT_DIR}/${name}"
    [[ -d "$dir" ]]                                   || { echo "no benchmark directory"; return; }
    [[ -d "$dir/data" ]]                              || { echo "not built (no data/)"; return; }
    [[ -x "$dir/data/${name}.instrumented.out" ]]     || { echo "no instrumented binary"; return; }
    [[ -f "$dir/data/generated_output.ccfg" ]]        || { echo "no generated_output.ccfg"; return; }
    [[ -f "$dir/data/init.sg.json" ]]                 || { echo "no init.sg.json"; return; }
    echo ""
}

# Array benchmarks are feedback-only; see ARRAY_BENCHMARKS above.
is_array_benchmark() {
    local name="$1" b
    for b in $ARRAY_BENCHMARKS; do [[ "$b" == "$name" ]] && return 0; done
    return 1
}

configs_for() {
    local name="$1" c
    if is_array_benchmark "$name"; then
        for c in "${CONFIG_LIST[@]}"; do [[ "$c" == "feedback" ]] && echo "$c"; done
    else
        printf '%s\n' "${CONFIG_LIST[@]}"
    fi
}

if [[ -z "$RESULTS_ROOT" ]]; then
    RESULTS_ROOT="${SCRIPT_DIR}/results/$(date -u +%Y%m%dT%H%M%SZ)"
fi
RESULTS_ROOT="$(abspath "$RESULTS_ROOT")"

# Resolve the plan up front so --list and the campaign agree.
declare -a PLAN=()          # "bench|config|rep"
declare -a RUNNABLE=()
BENCH_CSV="${RESULTS_ROOT}/benchmarks.csv"

for name in "${BENCHMARKS[@]}"; do
    blocker="$(bench_blocker "$name")"
    if [[ -n "$blocker" ]]; then
        continue
    fi
    RUNNABLE+=("$name")
    while read -r cfg; do
        [[ -n "$cfg" ]] || continue
        for ((r = 1; r <= REPEATS; r++)); do
            PLAN+=("${name}|${cfg}|${r}")
        done
    done < <(configs_for "$name")
done

TOTAL_RUNS="${#PLAN[@]}"
EST_SECONDS=$(( TOTAL_RUNS * (MAX_TIME + 15) / JOBS ))

echo "======================================================================"
echo " AFL++ campaign"
echo "======================================================================"
printf "  %-22s %s\n" "results root"      "$RESULTS_ROOT"
printf "  %-22s %s\n" "benchmarks"        "${#RUNNABLE[@]} runnable of ${#BENCHMARKS[@]}"
printf "  %-22s %s\n" "configs"           "$CONFIGS (array benchmarks: feedback only)"
printf "  %-22s %s\n" "repeats (K)"       "$REPEATS"
printf "  %-22s %s\n" "budget per run"    "${MAX_TIME}s"
printf "  %-22s %s\n" "parallel jobs"     "$JOBS"
printf "  %-22s %s\n" "total runs"        "$TOTAL_RUNS"
printf "  %-22s %s\n" "rough wall clock"  "$(( EST_SECONDS / 60 )) min"
echo "----------------------------------------------------------------------"
for name in "${BENCHMARKS[@]}"; do
    blocker="$(bench_blocker "$name")"
    if [[ -n "$blocker" ]]; then
        printf "  %-26s -   %s\n" "$name" "$blocker"
    elif is_array_benchmark "$name"; then
        printf "  %-26s ok  feedback only (array benchmark)\n" "$name"
    else
        printf "  %-26s ok  %s\n" "$name" "$CONFIGS"
    fi
done
echo "======================================================================"

if [[ "$LIST_ONLY" -eq 1 ]]; then
    exit 0
fi

if [[ "$TOTAL_RUNS" -eq 0 ]]; then
    err "nothing to run"
    exit 1
fi

mkdir -p "$RESULTS_ROOT"

{
    echo "benchmark,status,reason,configs"
    for name in "${BENCHMARKS[@]}"; do
        blocker="$(bench_blocker "$name")"
        if [[ -n "$blocker" ]]; then
            echo "${name},unrunnable,\"${blocker}\","
        elif is_array_benchmark "$name"; then
            echo "${name},ok,,feedback"
        else
            echo "${name},ok,,\"${CONFIGS}\""
        fi
    done
} > "$BENCH_CSV"

cat > "${RESULTS_ROOT}/campaign.json" <<EOF
{
  "started_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "repeats": ${REPEATS},
  "max_time_s": ${MAX_TIME},
  "jobs": ${JOBS},
  "configs": "${CONFIGS}",
  "array_benchmarks": "${ARRAY_BENCHMARKS}",
  "sample_interval_s": ${SAMPLE_INTERVAL},
  "total_runs": ${TOTAL_RUNS},
  "host": "$(hostname)",
  "nproc": $(nproc),
  "git_commit": "$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)",
  "git_dirty": $(if [[ -n "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null)" ]]; then echo true; else echo false; fi)
}
EOF

# ------------------------------------------------------------
# Timeline sampler
#
# fuzzer_stats is rewritten atomically (tmp + rename) roughly once a second, so
# polling it is safe. Sampling is what gives execs-to-first-bug: the bug files
# themselves carry no exec counter, only an id.
# ------------------------------------------------------------

sample_timeline() {
    local out_default="$1" csv="$2" afl_pid="$3"
    local t0 now stats
    t0="$(date +%s.%N)"

    echo "wall_s,execs_done,corpus_count,cycles_done,saved_crashes,saved_hangs,saved_races,total_races,n_crash_files,n_hang_files,n_race_files,execs_per_sec" > "$csv"

    emit() {
        now="$(date +%s.%N)"
        stats="${out_default}/fuzzer_stats"
        [[ -f "$stats" ]] || return 0
        awk -v t="$(awk -v a="$now" -v b="$t0" 'BEGIN{printf "%.3f", a-b}')" \
            -v nc="$(find "${out_default}/crashes" -maxdepth 1 -name 'id:*' 2>/dev/null | wc -l)" \
            -v nh="$(find "${out_default}/hangs"   -maxdepth 1 -name 'id:*' 2>/dev/null | wc -l)" \
            -v nr="$(find "${out_default}/races"   -maxdepth 1 -name 'id:*' 2>/dev/null | wc -l)" '
            BEGIN { FS = "[ ]*:[ ]*" }
            { gsub(/[ \t]+$/, "", $1); v[$1] = $2 }
            END {
                printf "%s,%s,%s,%s,%s,%s,%s,%s,%d,%d,%d,%s\n", t,
                    (("execs_done"    in v) ? v["execs_done"]    : 0),
                    (("corpus_count"  in v) ? v["corpus_count"]  : 0),
                    (("cycles_done"   in v) ? v["cycles_done"]   : 0),
                    (("saved_crashes" in v) ? v["saved_crashes"] : 0),
                    (("saved_hangs"   in v) ? v["saved_hangs"]   : 0),
                    (("saved_races"   in v) ? v["saved_races"]   : 0),
                    (("total_races"   in v) ? v["total_races"]   : 0),
                    nc, nh, nr,
                    (("execs_per_sec" in v) ? v["execs_per_sec"] : 0)
            }' "$stats" >> "$csv" 2>/dev/null || true
    }

    while kill -0 "$afl_pid" 2>/dev/null; do
        emit
        sleep "$SAMPLE_INTERVAL"
    done
    emit   # final sample, after AFL has written its closing stats
}

# ------------------------------------------------------------
# One run
# ------------------------------------------------------------

do_run() {
    local name="$1" cfg="$2" rep="$3"
    local bench_dir="${SCRIPT_DIR}/${name}"
    local run_dir
    run_dir="$(printf '%s/runs/%s/%s/run-%02d' "$RESULTS_ROOT" "$name" "$cfg" "$rep")"

    mkdir -p "$run_dir"

    local enable_feedback=1
    [[ "$cfg" == "nofeedback" ]] && enable_feedback=0

    {
        echo "benchmark=${name}"
        echo "config=${cfg}"
        echo "repeat=${rep}"
        echo "max_time_s=${MAX_TIME}"
        echo "enable_feedback=${enable_feedback}"
        echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "${run_dir}/meta.env"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "dry-run" > "${run_dir}/run.log"
        return 0
    fi

    # AFL_BENCH_UNTIL_CRASH must be *empty* to be off: AFL enables it on any
    # non-empty value. We need the full budget, not a stop at the first crash.
    (
        cd "$run_dir"
        MAX_TIME="$MAX_TIME" \
        AFL_BENCH_UNTIL_CRASH="" \
        AFL_ENABLE_FEEDBACK="$enable_feedback" \
        AFL_CHECK_DATA_RACE=1 \
        RUN_QUEUE_VISUALIZER="$RUN_QUEUE_VISUALIZER" \
        COPY_LOCATIONS=0 \
        INPUT_DIR="${run_dir}/in" \
        OUTPUT_DIR="${run_dir}/out" \
        bash "${SCRIPT_DIR}/run_afl.sh" \
            "${bench_dir}/data/${name}.instrumented.out" \
            "${bench_dir}/data/generated_output.ccfg" \
            "${bench_dir}/data/init.sg.json"
    ) > "${run_dir}/run.log" 2>&1 &
    local afl_pid=$!

    sample_timeline "${run_dir}/out/default" "${run_dir}/timeline.csv" "$afl_pid" &
    local sampler_pid=$!

    local rc=0
    wait "$afl_pid" || rc=$?
    wait "$sampler_pid" 2>/dev/null || true

    echo "exit_code=${rc}" >> "${run_dir}/meta.env"
    echo "ended_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${run_dir}/meta.env"

    if [[ "$KEEP_QUEUE" -eq 0 ]]; then
        rm -rf "${run_dir}/out/default/queue"
    fi
    # The seed copy and the resume blob are large and reproducible; the raw
    # bug directories and stats are what the analysis reads.
    rm -rf "${run_dir}/in" "${run_dir}/out/default/fastresume.bin"

    return 0
}

# ------------------------------------------------------------
# Campaign
# ------------------------------------------------------------

STARTED_AT="$(date +%s)"
COMPLETED=0

# ------------------------------------------------------------
# Progress bar
#
# do_run sends all its output to run.log, so stdout is free for an in-place
# bar. A background ticker redraws every couple of seconds: with runs this
# long, completions alone would leave the bar looking frozen for minutes.
# Non-interactive stdout (nohup, CI, tee to a file) falls back to plain lines.
# ------------------------------------------------------------

PROGRESS="${PROGRESS:-auto}"        # auto | bar | log | none
if [[ "$PROGRESS" == "auto" ]]; then
    if [[ -t 1 ]]; then PROGRESS=bar; else PROGRESS=log; fi
fi

PROGRESS_STATE="$(mktemp -t afl-campaign-progress.XXXXXX)"
echo "0 0" > "$PROGRESS_STATE"

fmt_dur() {
    local s=$1
    if (( s >= 3600 )); then printf '%dh%02dm' $((s / 3600)) $((s % 3600 / 60))
    elif (( s >= 60 )); then printf '%dm%02ds' $((s / 60)) $((s % 60))
    else printf '%ds' "$s"; fi
}

render_bar() {
    local done_n="$1" active="$2" width=28
    local now elapsed pct filled bar="" eta="--"
    now="$(date +%s)"
    elapsed=$((now - STARTED_AT))
    pct=$(( TOTAL_RUNS ? done_n * 100 / TOTAL_RUNS : 0 ))
    filled=$(( TOTAL_RUNS ? done_n * width / TOTAL_RUNS : 0 ))
    for ((i = 0; i < width; i++)); do
        if (( i < filled )); then bar+="█"; else bar+="░"; fi
    done
    if (( done_n > 0 )); then
        eta="$(fmt_dur $(( elapsed * (TOTAL_RUNS - done_n) / done_n )))"
    fi
    printf '\r\033[K  %s %3d%%  %d/%d  elapsed %s  eta %s  active %d' \
        "$bar" "$pct" "$done_n" "$TOTAL_RUNS" "$(fmt_dur "$elapsed")" "$eta" "$active"
}

TICKER_PID=""
start_ticker() {
    [[ "$PROGRESS" == "bar" ]] || return 0
    (
        while [[ -f "$PROGRESS_STATE" ]]; do
            read -r d a < "$PROGRESS_STATE" 2>/dev/null || { d=0; a=0; }
            render_bar "${d:-0}" "${a:-0}"
            sleep 2
        done
    ) &
    TICKER_PID=$!
}

stop_ticker() {
    rm -f "$PROGRESS_STATE"
    if [[ -n "$TICKER_PID" ]]; then
        kill "$TICKER_PID" 2>/dev/null || true
        wait "$TICKER_PID" 2>/dev/null || true
        TICKER_PID=""
    fi
}
trap stop_ticker EXIT

note_progress() {
    echo "$COMPLETED $1" > "$PROGRESS_STATE"
    case "$PROGRESS" in
        bar) render_bar "$COMPLETED" "$1" ;;
        log)
            local elapsed=$(( $(date +%s) - STARTED_AT ))
            log "progress ${COMPLETED}/${TOTAL_RUNS} (elapsed $(fmt_dur "$elapsed"))"
            ;;
    esac
}

# Shuffle so that the K repeats of one benchmark are spread across the
# campaign: a machine that gets busy halfway through then perturbs every
# configuration equally instead of biasing one benchmark's variance.
mapfile -t PLAN_SHUFFLED < <(printf '%s\n' "${PLAN[@]}" | shuf --random-source=<(yes))

log "starting ${TOTAL_RUNS} runs, ${JOBS} at a time"
start_ticker

running=0
for entry in "${PLAN_SHUFFLED[@]}"; do
    IFS='|' read -r name cfg rep <<< "$entry"

    if (( running >= JOBS )); then
        wait -n || true
        running=$((running - 1))
        COMPLETED=$((COMPLETED + 1))
        note_progress "$running"
    fi

    do_run "$name" "$cfg" "$rep" &
    running=$((running + 1))
    note_progress "$running"
done

while (( running > 0 )); do
    wait -n || true
    running=$((running - 1))
    COMPLETED=$((COMPLETED + 1))
    note_progress "$running"
done

stop_ticker
[[ "$PROGRESS" == "bar" ]] && printf '\n'

ELAPSED=$(( $(date +%s) - STARTED_AT ))
log "all ${TOTAL_RUNS} runs finished in $(fmt_dur "$ELAPSED")"

cat > "${RESULTS_ROOT}/campaign.done.json" <<EOF
{"ended_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)", "elapsed_s": ${ELAPSED}, "runs": ${COMPLETED}}
EOF

# ------------------------------------------------------------
# Analysis
# ------------------------------------------------------------

if [[ "$ANALYZE" -eq 1 && "$DRY_RUN" -eq 0 ]]; then
    log "analyzing results"
    python3 "${SCRIPT_DIR}/analyze_results.py" "$RESULTS_ROOT" || {
        err "analysis failed; raw results are intact in $RESULTS_ROOT"
        exit 1
    }
    echo
    echo "Summary : ${RESULTS_ROOT}/analysis/summary.md"
    echo "Report  : ${RESULTS_ROOT}/analysis/report.html"
    echo "Raw CSV : ${RESULTS_ROOT}/analysis/per_run.csv"
fi

log "results root: $RESULTS_ROOT"
