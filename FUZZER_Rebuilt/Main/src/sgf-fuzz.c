/*
   american fuzzy lop++ - fuzzer code
   --------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Dominik Meier <mail@dmnk.co>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>, and
                     Heiko Eissfeldt <heiko.eissfeldt@hexco.de>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "sgf-fuzz.h"
#include "sgf-ijon-min.h"
#include "alloc-inl.h"
#include "cmplog.h"
#include <sys/stat.h>
#include <errno.h>
#include "asanfuzz.h"
#include "common.h"
#include <limits.h>
#include <stdlib.h>
#include "event_pair_set.h"
#include "skeleton_graph_mutator_wrapper.h"
#include "retgraph_shm.h"
#include "shm_next_events.h"

#ifndef USEMMAP
  #include <sys/mman.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #include <sys/ipc.h>
  #include <sys/shm.h>
#endif
#ifdef HAVE_ZLIB

  #define ck_gzread(fd, buf, len, fn)                            \
    do {                                                         \
                                                                 \
      s32 _len = (s32)(len);                                     \
      s32 _res = gzread(fd, buf, _len);                          \
      if (_res != _len) RPFATAL(_res, "Short read from %s", fn); \
                                                                 \
    } while (0)

  #define ck_gzwrite(fd, buf, len, fn)                                    \
    do {                                                                  \
                                                                          \
      if (len <= 0) break;                                                \
      s32 _written = 0, _off = 0, _len = (s32)(len);                      \
                                                                          \
      do {                                                                \
                                                                          \
        s32 _res = gzwrite(fd, (buf) + _off, _len);                       \
        if (_res != _len && (_res > 0 && _written + _res != _len)) {      \
                                                                          \
          if (_res > 0) {                                                 \
                                                                          \
            _written += _res;                                             \
            _len -= _res;                                                 \
            _off += _res;                                                 \
                                                                          \
          } else {                                                        \
                                                                          \
            RPFATAL(_res, "Short write to %s (%d of %d bytes)", fn, _res, \
                    _len);                                                \
                                                                          \
          }                                                               \
                                                                          \
        } else {                                                          \
                                                                          \
          break;                                                          \
                                                                          \
        }                                                                 \
                                                                          \
      } while (1);                                                        \
                                                                          \
                                                                          \
                                                                          \
    } while (0)

  #include <zlib.h>
  #define ZLIBOPEN gzopen
  #define ZLIBREAD ck_gzread
  #define NZLIBREAD gzread
  #define ZLIBWRITE ck_gzwrite
  #define ZLIBCLOSE gzclose
  #define ZLIB_EXTRA "9"
#else
  #define ZLIBOPEN open
  #define NZLIBREAD read
  #define ZLIBREAD ck_read
  #define ZLIBWRITE ck_write
  #define ZLIBCLOSE close
#endif

#ifdef __APPLE__
  #include <sys/qos.h>
  #include <pthread/qos.h>
#endif

#ifdef PROFILING
extern u64 time_spent_working;
#endif

static void at_exit() {

  dump_explored_locations();

  // destroy_shared_graph_c();
  //function to destroy the created shared memory fragment (g_next_events) by detaching it and marking the shm id to be destroyed
  destroy_shm_next_events_c();

  s32   i, pid1 = 0, pid2 = 0, pgrp = -1;
  char *list[4] = {SHM_ENV_VAR, SHM_FUZZ_ENV_VAR, CMPLOG_SHM_ENV_VAR, NULL};
  char *ptr;

  ptr = getenv("__AFL_TARGET_PID2");
  if (ptr && *ptr && (pid2 = atoi(ptr)) > 0) {

    /* cmplog fsrv (pid2) was not deinit'ed, so using getpgid(pid2) is fine. */
    pgrp = getpgid(pid2);
    if (pgrp > 0) { killpg(pgrp, SIGTERM); }
    kill(pid2, SIGTERM);

  }

  ptr = getenv("__AFL_TARGET_PID1");
  if (ptr && *ptr && (pid1 = atoi(ptr)) > 0) {

    /* forkserver (pid1) was deinit'ed by afl_fsrv_deinit,
     so getpgid(pid1) would fail; use pid1 directly as pgid. */
    killpg(pid1, SIGTERM);
    kill(pid1, SIGTERM);

  }

  ptr = getenv(CPU_AFFINITY_ENV_VAR);
  if (ptr && *ptr) unlink(ptr);

  i = 0;
  while (list[i] != NULL) {

    ptr = getenv(list[i]);
    if (ptr && *ptr) {

#ifdef USEMMAP

      shm_unlink(ptr);

#else

      shmctl(atoi(ptr), IPC_RMID, NULL);

#endif

    }

    i++;

  }

  int kill_signal = SIGKILL;
  /* SGF_KILL_SIGNAL should already be a valid int at this point */
  if ((ptr = getenv("SGF_KILL_SIGNAL"))) { kill_signal = atoi(ptr); }

  if (pid1 > 0) {

    killpg(pid1, kill_signal);
    kill(pid1, kill_signal);

  }

  if (pid2 > 0) {

    pgrp = getpgid(pid2);
    if (pgrp > 0) { killpg(pgrp, kill_signal); }
    kill(pid2, kill_signal);

  }

}

/* Display usage hints. */

static void usage(u8 *argv0, int more_help) {

  SAYF(
      "\n%s [ options ] -- /path/to/fuzzed_app [ ... ]\n\n"

      "Required parameters:\n"
      "  -i dir        - input directory with test cases (or '-' to resume, "
      "also see \n"
      "                  SGF_AUTORESUME)\n"
      "  -o dir        - output directory for fuzzer findings\n\n"

      "Execution control settings:\n"
      "  -P strategy   - set fix mutation strategy: explore (focus on new "
      "coverage),\n"
      "                  exploit (focus on triggering crashes). You can also "
      "set a\n"
      "                  number of seconds after without any finds it switches "
      "to\n"
      "                  exploit mode, and back on new coverage (default: %u)\n"
      "  -p schedule   - power schedules compute a seed's performance score:\n"
      "                  explore(default), fast, exploit, seek, rare, mmopt, "
      "coe, lin\n"
      "                  quad -- see docs/FAQ.md for more information\n"
      "  -f file       - location read by the fuzzed program (default: stdin "
      "or @@)\n"
      "  -t msec       - timeout for each run (auto-scaled, default %u ms). "
      "Add a '+'\n"
      "                  to auto-calculate the timeout, the value being the "
      "maximum.\n"
      "  -m megs       - memory limit for child process (%u MB, 0 = no limit "
      "[default])\n"
#if defined(__linux__) && defined(__aarch64__)
      "  -A            - use binary-only instrumentation (ARM CoreSight mode)\n"
#endif
      "  -O            - use binary-only instrumentation (FRIDA mode)\n"
#if defined(__linux__)
      "  -Q            - use binary-only instrumentation (QEMU mode)\n"
      "  -U            - use unicorn-based instrumentation (Unicorn mode)\n"
      "  -W            - use qemu-based instrumentation with Wine (Wine mode)\n"
#endif
#if defined(__linux__)
      "  -X            - use VM fuzzing (NYX mode - standalone mode)\n"
      "  -Y            - use VM fuzzing (NYX mode - multiple instances mode)\n"
#endif
#if defined(__linux__)
      "  -K dir        - use python script to interact with GUI (GUI mode)\n"
#endif
      "\n"

      "Mutator settings:\n"
      "  -a type       - target input format, \"text\" or \"binary\" (default: "
      "generic)\n"
      "  -g minlength  - set min length of generated fuzz input (default: 1)\n"
      "  -G maxlength  - set max length of generated fuzz input (default: "
      "%lu)\n"
      "  -L minutes    - use MOpt(imize) mode and set the time limit for "
      "entering the\n"
      "                  pacemaker mode (minutes of no new finds). 0 = "
      "immediately,\n"
      "                  -1 = immediately and together with normal mutation.\n"
      "                  Note: this option is usually not very effective\n"
      "  -u            - enable testcase splicing\n"
      "  -c program    - enable CmpLog by specifying a binary compiled for "
      "it.\n"
      "                  if using QEMU/FRIDA or the fuzzing target is "
      "compiled\n"
      "                  for CmpLog then use '-c 0'. To disable CMPLOG use '-c "
      "-'.\n"
      "  -l cmplog_opts - CmpLog configuration values (e.g. \"2ATR\"):\n"
      "                  1=small files, 2=larger files (default), 3=all "
      "files,\n"
      "                  A=arithmetic solving, T=transformational solving,\n"
      "                  X=extreme transform solving, R=random colorization "
      "bytes.\n\n"
      "Fuzzing behavior settings:\n"
      "  -Z             - sequential queue selection instead of weighted "
      "random\n"
      "  -N             - do not unlink the fuzzing input file (for devices "
      "etc.)\n"
      "  -n             - fuzz without instrumentation (non-instrumented "
      "mode)\n"
      "  -x dict_file   - fuzzer dictionary (see README.md, specify up to 4 "
      "times)\n"
      "  -w san_binary  - Specify the extra sanitizer instrumented binaries,\n"
      "                   can be specified multiple times.\n"
      "                   Read docs/SAND.md for details.\n\n"

      "Test settings:\n"
      "  -s seed       - use a fixed seed for the RNG\n"
      "  -V seconds    - fuzz for a specified time then terminate (fuzz time "
      "only!)\n"
      "  -E execs      - fuzz for an approx. no. of total executions then "
      "terminate\n"
      "                  Note: not precise and can have several more "
      "executions.\n\n"

      "Other stuff:\n"
      "  -M/-S id      - distributed mode (-M sets -Z and disables trimming)\n"
      "                  see docs/fuzzing_in_depth.md#c-using-multiple-cores\n"
      "                  for effective recommendations for parallel fuzzing.\n"
      "  -F path       - sync to a foreign fuzzer queue directory (requires "
      "-M, can\n"
      "                  be specified up to %u times)\n"
      "  -z            - skip the enhanced deterministic fuzzing\n"
      "                  (note that the old -d and -D flags are ignored.)\n"
      "  -T text       - text banner to show on the screen\n"
      "  -I command    - execute this command/script when a new crash is "
      "found\n"
      //"  -B bitmap.txt - mutate a specific test case, use the
      // out/default/fuzz_bitmap file\n"
      "  -C            - crash exploration mode (the peruvian rabbit thing)\n"
      "  -b cpu_id     - bind the fuzzing process to the specified CPU core "
      "(0-...)\n"
      "  -e ext        - file extension for the fuzz test input file (if "
      "needed)\n"
      "\n",
      argv0, STRATEGY_SWITCH_TIME, EXEC_TIMEOUT, MEM_LIMIT, MAX_FILE,
      FOREIGN_SYNCS_MAX);

  if (more_help > 1) {

#if defined USE_COLOR && !defined ALWAYS_COLORED
  #define DYN_COLOR \
    "SGF_NO_COLOR or SGF_NO_COLOUR: switch colored console output off\n"
#else
  #define DYN_COLOR
#endif

#ifdef SGF_PERSISTENT_RECORD
  #define PERSISTENT_MSG                                                 \
    "SGF_PERSISTENT_RECORD: record the last X inputs to every crash in " \
    "out/crashes\n"
#else
  #define PERSISTENT_MSG
#endif

    SAYF(
      "Environment variables used:\n"
      "LD_BIND_LAZY: do not set LD_BIND_NOW env var for target\n"
      "ASAN_OPTIONS: custom settings for ASAN\n"
      "              (must contain abort_on_error=1 and symbolize=0)\n"
      "MSAN_OPTIONS: custom settings for MSAN\n"
      "              (must contain exitcode="STRINGIFY(MSAN_ERROR)" and symbolize=0)\n"
      "SGF_AUTORESUME: resume fuzzing if directory specified by -o already exists\n"
      "SGF_BENCH_JUST_ONE: run the target just once\n"
      "SGF_BENCH_UNTIL_CRASH: exit soon when the first crashing input has been found\n"
      "SGF_CMPLOG_ONLY_NEW: do not run cmplog on initial testcases (good for resumes!)\n"
      "SGF_CRASH_EXITCODE: optional child exit code to be interpreted as crash\n"
      "SGF_CUSTOM_MUTATOR_LIBRARY: lib with afl_custom_fuzz() to mutate inputs\n"
      "SGF_CUSTOM_MUTATOR_ONLY: avoid AFL++'s internal mutators\n"
      "SGF_CYCLE_SCHEDULES: after completing a cycle, switch to a different -p schedule\n"
      "SGF_DEBUG: extra debugging output for Python mode trimming\n"
      "SGF_DEBUG_CHILD: do not suppress stdout/stderr from target\n"
      "SGF_DISABLE_REDUNDANT: disable any queue item that is redundant\n"
      "SGF_DISABLE_TRIM: disable the trimming of test cases\n"
      "SGF_DUMB_FORKSRV: use fork server without feedback from target\n"
      "SGF_ENABLE_FEEDBACK: use simulator-provided next-event feedback when mutating\n"
      "SGF_CHECK_DATA_RACE: set happens-before data race checking (default: 1)\n"
      "SGF_POTENTIAL_LOCATIONS_FILE: path to location file for potential calculation\n"
      "SGF_INTERESTING_LOCATIONS_FILE: path to location file for interesting locations\n"
      "SGF_CUTOFF_PERCENTILE: percentile for cutoff in graph scoring (default: 1)\n"
      "SGF_SKELETON_GRAPH_HIGHEST_STEP: set the maximum skeleton graph step size (default: 3)\n"
      "SGF_EXIT_WHEN_DONE: exit when all inputs are run and no new finds are found\n"
      "SGF_EXIT_ON_TIME: exit when no new coverage is found within the specified time\n"
      "SGF_EXIT_ON_SEED_ISSUES: exit on any kind of seed issues\n"
      "SGF_EXPAND_HAVOC_NOW: immediately enable expand havoc mode (default: after 60\n"
      "                      minutes and a cycle without finds)\n"
      "SGF_FAST_CAL: limit the calibration stage to three cycles for speedup\n"
      "SGF_FORCE_UI: force showing the status screen (for virtual consoles)\n"
      "SGF_FORKSRV_INIT_TMOUT: time spent waiting for forkserver during startup (in ms)\n"
      "SGF_HANG_TMOUT: override timeout value (in milliseconds)\n"
      "SGF_I_DONT_CARE_ABOUT_MISSING_CRASHES: don't warn about core dump handlers\n"
      "SGF_IGNORE_PROBLEMS: do not abort fuzzing if an incorrect setup is detected\n"
      "SGF_IGNORE_PROBLEMS_COVERAGE: if set in addition to SGF_IGNORE_PROBLEMS - also\n"
      "                              ignore those libs for coverage\n"
      "SGF_IGNORE_SEED_PROBLEMS: skip over crashes and timeouts in the seeds instead of\n"
      "                          exiting\n"
      "SGF_IGNORE_TIMEOUTS: do not process or save any timeouts\n"
      "SGF_IGNORE_UNKNOWN_ENVS: don't warn on unknown env vars\n"
      "SGF_IMPORT_FIRST: sync and import test cases from other fuzzer instances first\n"
      "SGF_INPUT_LEN_MIN/SGF_INPUT_LEN_MAX: like -g/-G set min/max fuzz length produced\n"
      "SGF_PIZZA_MODE: 1 - enforce pizza mode, -1 - disable for April 1st,\n"
      "                0 (default) - activate on April 1st\n"
      "SGF_KILL_SIGNAL: Signal ID delivered to child processes on timeout, etc.\n"
      "                 (default: SIGKILL)\n"
      "SGF_FORK_SERVER_KILL_SIGNAL: Kill signal for the fork server on termination\n"
      "                             (default: SIGTERM). If unset and SGF_KILL_SIGNAL is\n"
      "                             set, that value will be used.\n"
      "SGF_MAP_SIZE: the shared memory size for that target. must be >= the size\n"
      "              the target was compiled for\n"
      "SGF_MAX_DET_EXTRAS: if more entries are in the dictionary list than this value\n"
      "                    then they are randomly selected instead all of them being\n"
      "                    used. Defaults to 200.\n"
      "SGF_NO_AFFINITY: do not check for an unused cpu core to use for fuzzing\n"
      "SGF_TRY_AFFINITY: try to bind to an unused core, but don't fail if unsuccessful\n"
      "SGF_NO_ARITH: skip arithmetic mutations in deterministic stage\n"
      "SGF_NO_AUTODICT: do not load an offered auto dictionary compiled into a target\n"
      "SGF_NO_CPU_RED: avoid red color for showing very high cpu usage\n"
      "SGF_NO_FORKSRV: run target via execve instead of using the forkserver\n"
      "SGF_NO_SNAPSHOT: do not use the snapshot feature (if the snapshot lkm is loaded)\n"
      "SGF_NO_STARTUP_CALIBRATION: no initial seed calibration, start fuzzing at once\n"
      "SGF_NO_WARN_INSTABILITY: no warn about instability issues on startup calibration\n"
      "SGF_NO_UI: switch status screen off\n"
      "SGF_NYX_AUX_SIZE: size of the Nyx auxiliary buffer. Must be a multiple of 4096.\n"
      "                  Increase this value in case the crash reports are truncated.\n"
      "                  Default value is 4096.\n"
      "SGF_NYX_DISABLE_SNAPSHOT_MODE: disable snapshot mode (must be supported by the agent)\n"
      "SGF_NYX_LOG: output NYX hprintf messages to another file\n"
      "SGF_NYX_REUSE_SNAPSHOT: reuse an existing Nyx root snapshot\n"
      DYN_COLOR

      "SGF_PATH: path to AFL support binaries\n"
      "SGF_PYTHON_MODULE: mutate and trim inputs with the specified Python module\n"
      "SGF_QUIET: suppress forkserver status messages\n"

      PERSISTENT_MSG

      "SGF_POST_PROCESS_KEEP_ORIGINAL: save the file as it was prior post-processing to\n"
      "                                the queue, but execute the post-processed one\n"
      "SGF_PRELOAD: LD_PRELOAD / DYLD_INSERT_LIBRARIES settings for target\n"
      "SGF_TARGET_ENV: pass extra environment variables to target\n"
      "SGF_SHUFFLE_QUEUE: reorder the input queue randomly on startup\n"
      "SGF_SKIP_BIN_CHECK: skip sgf compatibility checks, also disables auto map size\n"
      "SGF_SKIP_CPUFREQ: do not warn about variable cpu clocking\n"
      //"SGF_SKIP_CRASHES: during initial dry run do not terminate for crashing inputs\n"
      "SGF_STATSD: enables StatsD metrics collection\n"
      "SGF_STATSD_HOST: change default statsd host (default 127.0.0.1)\n"
      "SGF_STATSD_PORT: change default statsd port (default: 8125)\n"
      "SGF_STATSD_TAGS_FLAVOR: set statsd tags format (default: disable tags)\n"
      "                        supported formats: dogstatsd, librato, signalfx, influxdb\n"
      "SGF_NO_FASTRESUME: do not read or write a fast resume file\n"
      "SGF_NO_SYNC: disables all syncing\n"
      "SGF_SYNC_TIME: sync time between fuzzing instances (in minutes)\n"
      "SGF_FINAL_SYNC: sync a final time when exiting (will delay the exit!)\n"
      "SGF_NO_CRASH_README: do not create a README in the crashes directory\n"
      "SGF_TESTCACHE_SIZE: use a cache for testcases, improves performance (in MB)\n"
      "SGF_TMPDIR: directory to use for input file generation (ramdisk recommended)\n"
      "SGF_EARLY_FORKSERVER: force an early forkserver in an sgf-clang-fast/\n"
      "                      sgf-clang-lto/sgf-gcc-fast target\n"
      "SGF_PERSISTENT: enforce persistent mode (if __AFL_LOOP is in a shared lib)\n"
      "SGF_DEFER_FORKSRV: enforced deferred forkserver (__AFL_INIT is in a shared lib)\n"
      "SGF_FUZZER_STATS_UPDATE_INTERVAL: interval to update fuzzer_stats file in\n"
      "                                  seconds (default: 60, minimum: 1)\n"
      "\n"
    );

  } else {

    SAYF(
        "To view also the supported environment variables of sgf-fuzz please "
        "use \"-hh\".\n\n");

  }

#ifdef USE_PYTHON
  SAYF("Compiled with %s module support, see docs/custom_mutators.md\n",
       (char *)PYTHON_VERSION);
#else
  SAYF("Compiled without Python module support.\n");
#endif

#ifdef SGF_PERSISTENT_RECORD
  SAYF("Compiled with SGF_PERSISTENT_RECORD support.\n");
#else
  SAYF("Compiled without SGF_PERSISTENT_RECORD support.\n");
#endif

#ifdef USEMMAP
  SAYF("Compiled with shm_open support.\n");
#else
  SAYF("Compiled with shmat support.\n");
#endif

#ifdef ASAN_BUILD
  SAYF("Compiled with ASAN_BUILD.\n");
#endif

#ifdef FANCY_BOXES_NO_UTF
  SAYF("Compiled without UTF-8 support for line rendering in status screen.\n");
#endif

#ifdef PROFILING
  SAYF("Compiled with PROFILING.\n");
#endif

#ifdef INTROSPECTION
  SAYF("Compiled with INTROSPECTION.\n");
#endif

#ifdef _DEBUG
  SAYF("Compiled with _DEBUG.\n");
#endif

#ifdef _AFL_DOCUMENT_MUTATIONS
  SAYF("Compiled with _AFL_DOCUMENT_MUTATIONS.\n");
#endif

#ifdef _AFL_SPECIAL_PERFORMANCE
  SAYF(
      "Compiled with special performance options for this specific system, it "
      "might not work on other platforms!\n");
#endif

  SAYF("For additional help please consult %s/README.md :)\n\n", doc_path);

  exit(1);
#undef PHYTON_SUPPORT

}

#ifndef SGF_LIB

static int stricmp(char const *a, char const *b) {

  if (!a || !b) { FATAL("Null reference"); }

  for (;; ++a, ++b) {

    int d;
    d = tolower((int)*a) - tolower((int)*b);
    if (d != 0 || !*a) { return d; }

  }

}

static void fasan_check_afl_preload(char *sgf_preload) {

  char   first_preload[PATH_MAX + 1] = {0};
  char  *separator = strchr(sgf_preload, ':');
  size_t first_preload_len = PATH_MAX;
  char  *basename;
  char   clang_runtime_prefix[] = "libclang_rt.asan";

  if (separator != NULL && (separator - sgf_preload) < PATH_MAX) {

    first_preload_len = separator - sgf_preload;

  }

  strncpy(first_preload, sgf_preload, first_preload_len);

  basename = strrchr(first_preload, '/');
  if (basename == NULL) {

    basename = first_preload;

  } else {

    basename = basename + 1;

  }

  if (strncmp(basename, clang_runtime_prefix,
              sizeof(clang_runtime_prefix) - 1) != 0) {

    FATAL("Address Sanitizer DSO must be the first DSO in SGF_PRELOAD");

  }

  if (access(first_preload, R_OK) != 0) {

    FATAL("Address Sanitizer DSO not found");

  }

  OKF("Found ASAN DSO: %s", first_preload);

}

/* Main entry point */

int main(int argc, char **argv_orig, char **envp) {

  s32 opt, auto_sync = 0 /*, user_set_cache = 0*/;
  u64 prev_queued = 0;
  u32 sync_interval_cnt = 0, seek_to = 0, show_help = 0, default_output = 1,
      map_size = get_map_size();
  u8 *extras_dir[4];
  u8  mem_limit_given = 0, exit_1 = 0, debug = 0,
     extras_dir_cnt = 0 /*, have_p = 0*/;
  char  *sgf_preload;
  char  *san_abstraction;
  char  *frida_afl_preload = NULL;
  char **use_argv;

  struct timeval  tv;
  struct timezone tz;

  doc_path = access(DOC_PATH, F_OK) != 0 ? (u8 *)"docs" : (u8 *)DOC_PATH;

  if (argc > 1 && strcmp(argv_orig[1], "--version") == 0) {

    printf("sgf-fuzz" VERSION "\n");
    exit(0);

  }

  if (argc > 1 && (strcmp(argv_orig[1], "--help") == 0 ||
                   strncmp(argv_orig[1], "-h", 2) == 0)) {

    if (argc == 2 && (strcmp(argv_orig[1], "--help") == 0 ||
                      strcmp(argv_orig[1], "-h") == 0)) {

      usage(argv_orig[0], 1);

    } else {

      usage(argv_orig[0], 2);

    }

    exit(0);

  }

  #if defined USE_COLOR && defined ALWAYS_COLORED
  if (getenv("SGF_NO_COLOR") || getenv("SGF_NO_COLOUR")) {

    WARNF(
        "Setting SGF_NO_COLOR has no effect (colors are configured on at "
        "compile time)");

  }

  #endif

  char **argv = argv_cpy_dup(argc, argv_orig);

  sgf_state_t *sgf = calloc(1, sizeof(sgf_state_t));
  if (!sgf) { FATAL("Could not create sgf state"); }

  if (get_afl_env("SGF_DEBUG")) { debug = sgf->debug = 1; }

  afl_state_init(sgf, map_size);
  sgf->debug = debug;
  afl_fsrv_init(&sgf->fsrv);
  if (debug) { sgf->fsrv.debug = true; }
  read_afl_environment(sgf, envp);
  set_skeleton_graph_rng_state(sgf);
  if (sgf->shm.map_size) { sgf->fsrv.map_size = sgf->shm.map_size; }

  if (sgf->sgf_env.sgf_forksrv_uid_set) {

    sgf->fsrv.uid_set = 1;
    sgf->fsrv.uid = sgf->sgf_env.sgf_forksrv_uid;

  }

  if (sgf->sgf_env.sgf_forksrv_gid_set) {

    sgf->fsrv.gid_set = 1;
    sgf->fsrv.gid = sgf->sgf_env.sgf_forksrv_gid;
    sgf->fsrv.nb_supl_gids = sgf->sgf_env.sgf_forksrv_nb_supl_gids;
    sgf->fsrv.supl_gids = sgf->sgf_env.sgf_forksrv_supl_gids;

  }

  if (sgf->fsrv.uid_set) {

    /* If the UID is modified, allow group to open files and dirs */
    sgf->perm = DEFAULT_PERMISSION | 0060;
    sgf->fsrv.perm = sgf->perm;
    sgf->dir_perm = DEFAULT_DIRS_PERMISSION | 0070;

    /* Ensure permissions will be really set*/
    umask(~(sgf->perm | sgf->dir_perm));

    /* If the GID is also modified, then change the group of files and dirs */
    if (sgf->fsrv.gid_set) {

      sgf->chown_needed = 1;
      sgf->fsrv.chown_needed = 1;

    }

  } else {

    sgf->perm = DEFAULT_PERMISSION;
    sgf->fsrv.perm = sgf->perm;
    sgf->dir_perm = DEFAULT_DIRS_PERMISSION;

  }

  exit_1 = !!sgf->sgf_env.sgf_bench_just_one;

  SAYF(cCYA "sgf-fuzz" VERSION cRST
            " based on AFL by Michal Zalewski and a large online community\n");

  gettimeofday(&tv, &tz);
  rand_set_seed(sgf, tv.tv_sec ^ tv.tv_usec ^ getpid());

  sgf->shmem_testcase_mode = 1;  // we always try to perform shmem fuzzing

  // still available: HjJkqrv
  while ((opt = getopt(
              argc, argv,
              "+a:Ab:B:c:CdDe:E:f:F:g:G:hi:I:K:l:L:m:M:nNo:Op:P:QRs:S:t:T:"
              "uUv:V:w:WXx:YzZ")) > 0) {

    switch (opt) {
      case 'v': 
        if(sgf->static_program_abstraction){ FATAL("Multiple -v options not supported");}
        if(optarg == NULL){ FATAL("Invalid -v option (got NULL)."); }
        sgf->static_program_abstraction = optarg;
        break;

      case 'a':

        if (!stricmp(optarg, "text") || !stricmp(optarg, "ascii") ||
            !stricmp(optarg, "txt") || !stricmp(optarg, "asc")) {

          sgf->input_mode = 1;

        } else if (!stricmp(optarg, "bin") || !stricmp(optarg, "binary")) {

          sgf->input_mode = 2;

        } else if (!stricmp(optarg, "def") || !stricmp(optarg, "default")) {

          sgf->input_mode = 0;

        } else {

          FATAL("-a input mode needs to be \"text\" or \"binary\".");

        }

        break;

      case 'P':
        if (!stricmp(optarg, "explore") || !stricmp(optarg, "exploration")) {

          sgf->fuzz_mode = 0;
          sgf->switch_fuzz_mode = 0;

        } else if (!stricmp(optarg, "exploit") ||

                   !stricmp(optarg, "exploitation")) {

          sgf->fuzz_mode = 1;
          sgf->switch_fuzz_mode = 0;

        } else {

          if ((sgf->switch_fuzz_mode = (u32)atoi(optarg)) > INT_MAX) {

            FATAL(
                "Parameter for option -P must be \"explore\", \"exploit\" or a "
                "number!");

          } else {

            sgf->switch_fuzz_mode *= 1000;

          }

        }

        break;

      case 'g':
        sgf->min_length = atoi(optarg);

        if (sgf->min_length < 1) { sgf->min_length = 1; }
        if (sgf->min_length >= MAX_FILE) {

          FATAL("Option -g must be below %lu", (long unsigned int)MAX_FILE);

        }

        break;

      case 'G':
        sgf->max_length = atoi(optarg);
        if (sgf->max_length < 4) { sgf->max_length = 4; }
        if (sgf->max_length > MAX_FILE) {

          FATAL(
              "Option -G max value is %lu, change by editing config.h and "
              "recompiling sgf-fuzz.",
              (long unsigned int)MAX_FILE);

        }

        break;

      case 'Z':
        sgf->old_seed_selection = 1;
        break;

      case 'u':
        sgf->use_splicing = 1;
        break;

      case 'I':
        sgf->infoexec = optarg;
        break;

      case 'b': {                                          /* bind CPU core */

        if (sgf->cpu_to_bind != -1) FATAL("Multiple -b options not supported");

        if (sscanf(optarg, "%d", &sgf->cpu_to_bind) < 0) {

          FATAL("Bad syntax used for -b");

        }

        break;

      }

      case 'w': {

        if (sgf->san_binary_length == MAX_EXTRA_SAN_BINARY) {

          FATAL("Only %d extra sanitizer instrumented binaries are supported.",
                MAX_EXTRA_SAN_BINARY);

        }

        sgf->shm.sanfuzz_mode = 1;
        sgf->san_binary[sgf->san_binary_length++] = optarg;
        break;

      }

      case 's': {

        if (optarg == NULL) { FATAL("No valid seed provided. Got NULL."); }
        rand_set_seed(sgf, strtoul(optarg, 0L, 10));
        sgf->fixed_seed = 1;
        break;

      }

      case 'p':                                           /* Power schedule */

        if (!stricmp(optarg, "fast")) {

          sgf->schedule = FAST;

        } else if (!stricmp(optarg, "coe")) {

          sgf->schedule = COE;

        } else if (!stricmp(optarg, "exploit")) {

          sgf->schedule = EXPLOIT;

        } else if (!stricmp(optarg, "lin")) {

          sgf->schedule = LIN;

        } else if (!stricmp(optarg, "quad")) {

          sgf->schedule = QUAD;

        } else if (!stricmp(optarg, "mopt") || !stricmp(optarg, "mmopt")) {

          sgf->schedule = MMOPT;

        } else if (!stricmp(optarg, "rare")) {

          sgf->schedule = RARE;

        } else if (!stricmp(optarg, "explore") || !stricmp(optarg, "sgf") ||

                   !stricmp(optarg, "default") ||

                   !stricmp(optarg, "normal")) {

          sgf->schedule = EXPLORE;

        } else if (!stricmp(optarg, "seek")) {

          sgf->schedule = SEEK;

        } else {

          FATAL("Unknown -p power schedule");

        }

        // have_p = 1;

        break;

      case 'e':

        if (sgf->file_extension) { FATAL("Multiple -e options not supported"); }

        sgf->file_extension = optarg;

        break;

      case 'i':                                                /* input dir */

        if (sgf->in_dir) { FATAL("Multiple -i options not supported"); }
        if (optarg == NULL) { FATAL("Invalid -i option (got NULL)."); }
        sgf->in_dir = optarg;

        if (!strcmp(sgf->in_dir, "-")) { sgf->in_place_resume = 1; }

        break;

      case 'o':                                               /* output dir */

        if (sgf->out_dir) { FATAL("Multiple -o options not supported"); }
        sgf->out_dir = optarg;
        break;

      case 'M': {                                           /* main sync ID */

        u8 *c;

        if (sgf->non_instrumented_mode) {

          FATAL("-M is not supported in non-instrumented mode");

        }

        if (sgf->fsrv.cs_mode) {

          FATAL("-M is not supported in ARM CoreSight mode");

        }

        if (sgf->sync_id) { FATAL("Multiple -S or -M options not supported"); }

        /* sanity check for argument: should not begin with '-' (possible
         * option) */
        if (optarg && *optarg == '-') {

          FATAL(
              "argument for -M started with a dash '-', which is used for "
              "options");

        }

        sgf->sync_id = ck_strdup(optarg);
        sgf->old_seed_selection = 1;  // force old queue walking seed selection
        sgf->disable_trim = 1;        // disable trimming

        if ((c = strchr(sgf->sync_id, ':'))) {

          *c = 0;

          if (sscanf(c + 1, "%u/%u", &sgf->main_node_id, &sgf->main_node_max) !=
                  2 ||
              !sgf->main_node_id || !sgf->main_node_max ||
              sgf->main_node_id > sgf->main_node_max ||
              sgf->main_node_max > 1000000) {

            FATAL("Bogus main node ID passed to -M");

          }

        }

        sgf->is_main_node = 1;

      }

      break;

      case 'S':                                        /* secondary sync id */

        if (sgf->non_instrumented_mode) {

          FATAL("-S is not supported in non-instrumented mode");

        }

        if (sgf->fsrv.cs_mode) {

          FATAL("-S is not supported in ARM CoreSight mode");

        }

        if (sgf->sync_id) { FATAL("Multiple -S or -M options not supported"); }

        /* sanity check for argument: should not begin with '-' (possible
         * option) */
        if (optarg && *optarg == '-') {

          FATAL(
              "argument for -M started with a dash '-', which is used for "
              "options");

        }

        sgf->sync_id = ck_strdup(optarg);
        sgf->is_secondary_node = 1;
        break;

      case 'F':                                         /* foreign sync dir */

        if (!optarg) { FATAL("Missing path for -F"); }
        if (!sgf->is_main_node) {

          FATAL(
              "Option -F can only be specified after the -M option for the "
              "main fuzzer of a fuzzing campaign");

        }

        if (sgf->foreign_sync_cnt >= FOREIGN_SYNCS_MAX) {

          FATAL("Maximum %u entried of -F option can be specified",
                FOREIGN_SYNCS_MAX);

        }

        sgf->foreign_syncs[sgf->foreign_sync_cnt].dir = optarg;
        while (sgf->foreign_syncs[sgf->foreign_sync_cnt]
                   .dir[strlen(sgf->foreign_syncs[sgf->foreign_sync_cnt].dir) -
                        1] == '/') {

          sgf->foreign_syncs[sgf->foreign_sync_cnt]
              .dir[strlen(sgf->foreign_syncs[sgf->foreign_sync_cnt].dir) - 1] =
              0;

        }

        sgf->foreign_sync_cnt++;
        break;

      case 'f':                                              /* target file */

        if (sgf->fsrv.out_file) { FATAL("Multiple -f options not supported"); }

        sgf->fsrv.out_file = ck_strdup(optarg);
        sgf->fsrv.use_stdin = 0;
        default_output = 0;
        break;

      case 'x':                                               /* dictionary */

        if (extras_dir_cnt >= 4) {

          FATAL("More than four -x options are not supported");

        }

        extras_dir[extras_dir_cnt++] = optarg;
        break;

      case 't': {                                                /* timeout */

        u8 suffix = 0;

        if (sgf->timeout_given) { FATAL("Multiple -t options not supported"); }

        if (!optarg ||
            sscanf(optarg, "%u%c", &sgf->fsrv.exec_tmout, &suffix) < 1 ||
            optarg[0] == '-') {

          FATAL("Bad syntax used for -t");

        }

        if (sgf->fsrv.exec_tmout < 5) { FATAL("Dangerously low value of -t"); }

        if (suffix == '+') {

          sgf->timeout_given = 2;

        } else {

          sgf->timeout_given = 1;

        }

        break;

      }

      case 'm': {                                              /* mem limit */

        u8 suffix = 'M';

        if (mem_limit_given) {

          WARNF("Overriding previous -m option.");

        } else {

          mem_limit_given = 1;

        }

        if (!optarg) { FATAL("Wrong usage of -m"); }

        if (!strcmp(optarg, "none")) {

          sgf->fsrv.mem_limit = 0;
          break;

        }

        if (sscanf(optarg, "%llu%c", &sgf->fsrv.mem_limit, &suffix) < 1 ||
            optarg[0] == '-') {

          FATAL("Bad syntax used for -m");

        }

        switch (suffix) {

          case 'T':
            sgf->fsrv.mem_limit *= 1024 * 1024;
            break;
          case 'G':
            sgf->fsrv.mem_limit *= 1024;
            break;
          case 'k':
            sgf->fsrv.mem_limit /= 1024;
            break;
          case 'M':
            break;

          default:
            FATAL("Unsupported suffix or bad syntax for -m");

        }

        if (sgf->fsrv.mem_limit && sgf->fsrv.mem_limit < 5) {

          FATAL("Dangerously low value of -m");

        }

        if (sizeof(rlim_t) == 4 && sgf->fsrv.mem_limit > 2000) {

          FATAL("Value of -m out of range on 32-bit systems");

        }

      }

      break;

      case 'd':
      case 'D':                                        /* old deterministic */

        WARNF(
            "Parameters -d and -D are deprecated, a new enhanced deterministic "
            "fuzzing is active by default, to disable it use -z");
        break;

      case 'z':                                         /* no deterministic */

        sgf->skip_deterministic = 1;
        break;

      case 'B':                                              /* load bitmap */

        /* This is a secret undocumented option! It is useful if you find
           an interesting test case during a normal fuzzing process, and want
           to mutate it without rediscovering any of the test cases already
           found during an earlier run.

           To use this mode, you need to point -B to the fuzz_bitmap produced
           by an earlier run for the exact same binary... and that's it.

           I only used this once or twice to get variants of a particular
           file, so I'm not making this an official setting. */

        if (sgf->in_bitmap) { FATAL("Multiple -B options not supported"); }

        sgf->in_bitmap = optarg;
        break;

      case 'C':                                               /* crash mode */

        if (sgf->crash_mode) { FATAL("Multiple -C options not supported"); }
        sgf->crash_mode = FSRV_RUN_CRASH;
        break;

      case 'n':                                                /* dumb mode */

        if (sgf->is_main_node || sgf->is_secondary_node) {

          FATAL("Non instrumented mode is not supported with -M / -S");

        }

        if (sgf->non_instrumented_mode) {

          FATAL("Multiple -n options not supported");

        }

        if (sgf->sgf_env.sgf_dumb_forksrv) {

          sgf->non_instrumented_mode = 2;

        } else {

          sgf->non_instrumented_mode = 1;

        }

        break;

      case 'T':                                                   /* banner */

        if (sgf->use_banner) { FATAL("Multiple -T options not supported"); }
        sgf->use_banner = optarg;
        break;

  #ifdef __linux__
      case 'X':                                                 /* NYX mode */

        if (sgf->fsrv.nyx_mode) { FATAL("Multiple -X options not supported"); }

        sgf->fsrv.nyx_parent = true;
        sgf->fsrv.nyx_standalone = true;
        sgf->fsrv.nyx_mode = 1;
        sgf->fsrv.nyx_id = 0;

        break;

      case 'Y':                                     /* NYX distributed mode */
        if (sgf->fsrv.nyx_mode) { FATAL("Multiple -Y options not supported"); }

        sgf->fsrv.nyx_mode = 1;

        break;
  #else
      case 'X':
      case 'Y':
        FATAL("Nyx mode is only available on linux...");
        break;
  #endif
      case 'A':                                           /* CoreSight mode */

  #if !defined(__aarch64__) || !defined(__linux__)
        FATAL("-A option is not supported on this platform");
  #endif

        if (sgf->is_main_node || sgf->is_secondary_node) {

          FATAL("ARM CoreSight mode is not supported with -M / -S");

        }

        if (sgf->fsrv.cs_mode) { FATAL("Multiple -A options not supported"); }

        sgf->fsrv.cs_mode = 1;

        break;

      case 'O':                                               /* FRIDA mode */

        if (sgf->fsrv.frida_mode) {

          FATAL("Multiple -O options not supported");

        }

        sgf->fsrv.frida_mode = 1;
        if (get_afl_env("SGF_USE_FASAN")) { sgf->fsrv.frida_asan = 1; }

        break;

      case 'Q':                                                /* QEMU mode */

        if (sgf->fsrv.qemu_mode) { FATAL("Multiple -Q options not supported"); }

        sgf->fsrv.qemu_mode = 1;

        if (!mem_limit_given) { sgf->fsrv.mem_limit = MEM_LIMIT_QEMU; }

        break;

      case 'N':                                             /* Unicorn mode */

        if (sgf->no_unlink) { FATAL("Multiple -N options not supported"); }
        sgf->fsrv.no_unlink = (sgf->no_unlink = true);

        break;

      case 'U':                                             /* Unicorn mode */

        if (sgf->unicorn_mode) { FATAL("Multiple -U options not supported"); }
        sgf->unicorn_mode = 1;
        sgf->fsrv.unicorn_mode = 1;

        if (!mem_limit_given) { sgf->fsrv.mem_limit = MEM_LIMIT_UNICORN; }

        break;

      case 'W':                                           /* Wine+QEMU mode */

        if (sgf->use_wine) { FATAL("Multiple -W options not supported"); }
        sgf->fsrv.qemu_mode = 1;
        sgf->use_wine = 1;

        if (!mem_limit_given) { sgf->fsrv.mem_limit = 0; }

        break;

      case 'V': {

        sgf->most_time_key = 1;
        if (!optarg || sscanf(optarg, "%llu", &sgf->most_time) < 1 ||
            optarg[0] == '-') {

          FATAL("Bad syntax used for -V");

        }

      } break;

      case 'E': {

        sgf->most_execs_key = 1;
        if (!optarg || sscanf(optarg, "%llu", &sgf->most_execs) < 1 ||
            optarg[0] == '-') {

          FATAL("Bad syntax used for -E");

        }

      } break;

      case 'h':
        show_help++;
        break;  // not needed

      case 'R':

        FATAL(
            "Radamsa is now a custom mutator, please use that "
            "(custom_mutators/radamsa/).");

        break;

  #ifdef __linux__
      case 'K':                                                 /* GUI mode */
        if (sgf->fsrv.gui_mode) { FATAL("Multiple -K options not supported"); }
        if (!optarg || optarg[0] == '-') {

          FATAL(
              "No directory provided for GUI interaction script. "
              "Use custom_mutators/guifuzz/guifuzz_clicks.py");

        } else {

          sgf->fsrv.gui_python_dir = ck_strdup(optarg);
          sgf->fsrv.gui_mode = 1;

        }

        break;

  #else
      case 'K':
        FATAL("GUI mode is only available on linux...");
        break;

  #endif

      default:
        if (!show_help) { show_help = 1; }

    }

  }

  if (sgf->sync_id && strcmp(sgf->sync_id, "addseeds") == 0) {

    FATAL("-M/-S name 'addseeds' is a reserved name, choose something else");

  }

  if (sgf->is_main_node == 1 && sgf->schedule != FAST &&
      sgf->schedule != EXPLORE) {

    WARNF(
        "When using -M, it is recommended to use only fast or explore -p power "
        "schedules");

  }

  if (optind == argc || !sgf->in_dir || !sgf->out_dir || show_help) {

    usage(argv[0], show_help);

  }

  if (unlikely(sgf->sgf_env.sgf_persistent_record)) {

  #ifdef SGF_PERSISTENT_RECORD

    sgf->fsrv.persistent_record = atoi(sgf->sgf_env.sgf_persistent_record);

    if (sgf->fsrv.persistent_record < 2) {

      FATAL(
          "SGF_PERSISTENT_RECORD value must be be at least 2, recommended is "
          "100 or 1000.");

    }

  #else

    FATAL(
        "sgf-fuzz was not compiled with SGF_PERSISTENT_RECORD enabled in "
        "config.h!");

  #endif

  }

  if (sgf->fsrv.mem_limit && sgf->shm.cmplog_mode) sgf->fsrv.mem_limit += 260;

  OKF("AFL++ is maintained by Marc \"van Hauser\" Heuse, Dominik Maier, Andrea "
      "Fioraldi and Heiko \"hexcoder\" Eißfeldt");
  OKF("AFL++ is open source, get it at "
      "https://github.com/AFLplusplus/AFLplusplus");
  OKF("NOTE: AFL++ >= v3 has changed defaults and behaviours - see README.md");

  #ifdef __linux__
  if (sgf->fsrv.nyx_mode) {

    OKF("AFL++ Nyx mode is enabled (developed and maintained by Sergej "
        "Schumilo)");
    OKF("Nyx is open source, get it at https://github.com/Nyx-Fuzz");

  }

  #endif

  if (sgf->fixed_seed) {

    OKF("Running with fixed seed: %u", (u32)sgf->init_seed);

  }

  #if defined(__SANITIZE_ADDRESS__)
  if (sgf->fsrv.mem_limit) {

    WARNF("in the ASAN build we disable all memory limits");
    sgf->fsrv.mem_limit = 0;

  }

  #endif

  configure_afl_kill_signals(
      &sgf->fsrv, sgf->sgf_env.sgf_child_kill_signal,
      sgf->sgf_env.sgf_fsrv_kill_signal,
      (sgf->fsrv.qemu_mode || sgf->unicorn_mode || sgf->fsrv.use_fauxsrv
  #ifdef __linux__
       || sgf->fsrv.nyx_mode
  #endif
       )
          ? SIGKILL
          : SIGTERM);

  setup_signal_handlers();
  check_asan_opts(sgf);

  sgf->power_name = power_names[sgf->schedule];

  if (!sgf->non_instrumented_mode && !sgf->sync_id) {

    auto_sync = 1;
    sgf->sync_id = ck_strdup("default");
    sgf->is_secondary_node = 1;
    OKF("No -M/-S set, autoconfiguring for \"-S %s\"", sgf->sync_id);

  }

  #ifdef __linux__
  if (sgf->fsrv.nyx_mode) {

    if (sgf->fsrv.nyx_standalone && strcmp(sgf->sync_id, "default") != 0) {

      FATAL(
          "distributed fuzzing is not supported in this Nyx mode (use -Y "
          "instead)");

    }

    if (!sgf->fsrv.nyx_standalone) {

      if (sgf->is_main_node) {

        if (strcmp("0", sgf->sync_id) != 0) {

          FATAL(
              "for Nyx -Y mode, the Main (-M) parameter has to be set to 0 (-M "
              "0)");

        }

        sgf->fsrv.nyx_parent = true;
        sgf->fsrv.nyx_id = 0;

      }

      if (sgf->is_secondary_node) {

        long nyx_id = strtol(sgf->sync_id, NULL, 10);

        if (nyx_id == 0 || nyx_id == LONG_MAX) {

          FATAL(
              "for Nyx -Y mode, the Secondary (-S) parameter has to be a "
              "numeric value and >= 1 (e.g. -S 1)");

        }

        sgf->fsrv.nyx_id = nyx_id;

      }

    }

  }

  #endif

  if (sgf->sync_id) { fix_up_sync(sgf); }

  if (!strcmp(sgf->in_dir, sgf->out_dir)) {

    FATAL("Input and output directories can't be the same");

  }

  if (sgf->non_instrumented_mode) {

    if (sgf->crash_mode) { FATAL("-C and -n are mutually exclusive"); }
    if (sgf->fsrv.frida_mode) { FATAL("-O and -n are mutually exclusive"); }
    if (sgf->fsrv.qemu_mode) { FATAL("-Q and -n are mutually exclusive"); }
    if (sgf->fsrv.cs_mode) { FATAL("-A and -n are mutually exclusive"); }
    if (sgf->unicorn_mode) { FATAL("-U and -n are mutually exclusive"); }

  }

  setenv("__AFL_OUT_DIR", sgf->out_dir, 1);
  setenv("__SGF_OUT_DIR", sgf->out_dir, 1);
  setenv("SGF_CUSTOM_INFO_OUT", sgf->out_dir, 1);

  if (get_afl_env("SGF_DISABLE_TRIM") || get_afl_env("SGF_NO_TRIM")) {

    sgf->disable_trim = 1;

  }

  if (getenv("SGF_NO_UI") && getenv("SGF_FORCE_UI")) {

    FATAL("SGF_NO_UI and SGF_FORCE_UI are mutually exclusive");

  }

  if (unlikely(sgf->sgf_env.sgf_statsd)) { statsd_setup_format(sgf); }

  if (!sgf->use_banner) { sgf->use_banner = argv[optind]; }

  if (sgf->shm.cmplog_mode && strcmp("0", sgf->cmplog_binary) == 0) {

    sgf->cmplog_binary = strdup(argv[optind]);

  }

  if (strchr(argv[optind], '/') == NULL && !sgf->unicorn_mode) {

    WARNF(cLRD
          "Target binary called without a prefixed path, make sure you are "
          "fuzzing the right binary: " cRST "%s",
          argv[optind]);

  }

  ACTF("Getting to work...");

  switch (sgf->schedule) {

    case FAST:
      OKF("Using exponential power schedule (FAST)");
      break;
    case COE:
      OKF("Using cut-off exponential power schedule (COE)");
      break;
    case EXPLOIT:
      OKF("Using exploitation-based constant power schedule (EXPLOIT)");
      break;
    case LIN:
      OKF("Using linear power schedule (LIN)");
      break;
    case QUAD:
      OKF("Using quadratic power schedule (QUAD)");
      break;
    case MMOPT:
      OKF("Using modified MOpt power schedule (MMOPT)");
      break;
    case RARE:
      OKF("Using rare edge focus power schedule (RARE)");
      break;
    case SEEK:
      OKF("Using seek power schedule (SEEK)");
      break;
    case EXPLORE:
      OKF("Using exploration-based constant power schedule (EXPLORE)");
      break;
    default:
      FATAL("Unknown power schedule");
      break;

  }

  if (sgf->shm.cmplog_mode) { OKF("CmpLog level: %u", sgf->cmplog_lvl); }

  /* Dynamically allocate memory for AFLFast schedules */
  if (sgf->schedule >= FAST && sgf->schedule <= RARE) {

    sgf->n_fuzz = ck_alloc(N_FUZZ_SIZE * sizeof(u32));

  }

  if (sgf->cycle_schedules) {

    sgf->top_rated_candidates = ck_alloc(map_size * sizeof(u32 *));

  }

  if (sgf->san_binary_length) {

    if (sgf->san_abstraction == UNIQUE_TRACE) {

      sgf->n_fuzz_dup = ck_alloc(N_FUZZ_SIZE_BITMAP * sizeof(u8));

    }

    if (sgf->san_abstraction == SIMPLIFY_TRACE) {

      sgf->simplified_n_fuzz = ck_alloc(N_FUZZ_SIZE_BITMAP * sizeof(u8));

    }

  }

  if (get_afl_env("SGF_NO_FORKSRV")) { sgf->no_forkserver = 1; }
  if (get_afl_env("SGF_NO_CPU_RED")) { sgf->no_cpu_meter_red = 1; }
  if (get_afl_env("SGF_NO_ARITH")) { sgf->no_arith = 1; }
  if (get_afl_env("SGF_SHUFFLE_QUEUE")) { sgf->shuffle_queue = 1; }
  if (get_afl_env("SGF_EXPAND_HAVOC_NOW")) { sgf->expand_havoc = 1; }

  if (sgf->sgf_env.sgf_autoresume) { sgf->autoresume = 1; }

  if (sgf->sgf_env.sgf_hang_tmout) {

    s32 hang_tmout = atoi(sgf->sgf_env.sgf_hang_tmout);
    if (hang_tmout < 1) { FATAL("Invalid value for SGF_HANG_TMOUT"); }
    sgf->hang_tmout = (u32)hang_tmout;

  }

  if (sgf->sgf_env.sgf_exit_on_time) {

    u64 exit_on_time = atoi(sgf->sgf_env.sgf_exit_on_time);
    sgf->exit_on_time = (u64)exit_on_time * 1000;

  }

  if (sgf->sgf_env.sgf_max_det_extras) {

    s32 max_det_extras = atoi(sgf->sgf_env.sgf_max_det_extras);
    if (max_det_extras < 1) { FATAL("Invalid value for SGF_MAX_DET_EXTRAS"); }
    sgf->max_det_extras = (u32)max_det_extras;

  } else {

    sgf->max_det_extras = MAX_DET_EXTRAS;

  }

  if (sgf->sgf_env.sgf_testcache_size) {

    sgf->q_testcase_max_cache_size =
        (u64)atoi(sgf->sgf_env.sgf_testcache_size) * 1048576;

  }

  if (sgf->sgf_env.sgf_testcache_entries) {

    sgf->q_testcase_max_cache_entries =
        (u32)atoi(sgf->sgf_env.sgf_testcache_entries);

    // user_set_cache = 1;

  }

  if (!sgf->sgf_env.sgf_testcache_size || !sgf->sgf_env.sgf_testcache_entries) {

    sgf->sgf_env.sgf_testcache_entries = 0;
    sgf->sgf_env.sgf_testcache_size = 0;

  }

  if (!sgf->q_testcase_max_cache_size) {

    ACTF(
        "No testcache was configured. it is recommended to use a testcache, it "
        "improves performance: set SGF_TESTCACHE_SIZE=(value in MB)");

  } else if (sgf->q_testcase_max_cache_size < 2 * MAX_FILE) {

    FATAL("SGF_TESTCACHE_SIZE must be set to %ld or more, or 0 to disable",
          (2 * MAX_FILE) % 1048576 == 0 ? (2 * MAX_FILE) / 1048576
                                        : 1 + ((2 * MAX_FILE) / 1048576));

  } else {

    OKF("Enabled testcache with %llu MB",
        sgf->q_testcase_max_cache_size / 1048576);

  }

  if (sgf->sgf_env.sgf_forksrv_init_tmout) {

    sgf->fsrv.init_tmout = atoi(sgf->sgf_env.sgf_forksrv_init_tmout);
    if (!sgf->fsrv.init_tmout) {

      FATAL("Invalid value of SGF_FORKSRV_INIT_TMOUT");

    }

  } else {

    sgf->fsrv.init_tmout = sgf->fsrv.exec_tmout * FORK_WAIT_MULT;

  }

  if (sgf->sgf_env.sgf_crash_exitcode) {

    long exitcode = strtol(sgf->sgf_env.sgf_crash_exitcode, NULL, 10);
    if ((!exitcode && (errno == EINVAL || errno == ERANGE)) ||
        exitcode < -127 || exitcode > 128) {

      FATAL("Invalid crash exitcode, expected -127 to 128, but got %s",
            sgf->sgf_env.sgf_crash_exitcode);

    }

    sgf->fsrv.uses_crash_exitcode = true;
    // WEXITSTATUS is 8 bit unsigned
    sgf->fsrv.crash_exitcode = (u8)exitcode;

  }

  if (sgf->non_instrumented_mode == 2 && sgf->no_forkserver) {

    FATAL("SGF_DUMB_FORKSRV and SGF_NO_FORKSRV are mutually exclusive");

  }

  // Marker: ADD_TO_INJECTIONS
  if (getenv("SGF_LLVM_INJECTIONS_ALL") || getenv("SGF_LLVM_INJECTIONS_SQL") ||
      getenv("SGF_LLVM_INJECTIONS_LDAP") || getenv("SGF_LLVM_INJECTIONS_XSS")) {

    OKF("Adding injection tokens to dictionary.");
    if (getenv("SGF_LLVM_INJECTIONS_ALL") ||
        getenv("SGF_LLVM_INJECTIONS_SQL")) {

      add_extra(sgf, "'\"\"'", 4);

    }

    if (getenv("SGF_LLVM_INJECTIONS_ALL") ||
        getenv("SGF_LLVM_INJECTIONS_LDAP")) {

      add_extra(sgf, "*)(1=*))(|", 10);

    }

    if (getenv("SGF_LLVM_INJECTIONS_ALL") ||
        getenv("SGF_LLVM_INJECTIONS_XSS")) {

      add_extra(sgf, "1\"><\"", 5);

    }

  }

  OKF("Generating fuzz data with a length of min=%u max=%u", sgf->min_length,
      sgf->max_length);
  u32 min_alloc = MAX(64U, sgf->min_length);
  afl_realloc(SGF_BUF_PARAM(in_scratch), min_alloc);
  afl_realloc(SGF_BUF_PARAM(in), min_alloc);
  afl_realloc(SGF_BUF_PARAM(out_scratch), min_alloc);
  afl_realloc(SGF_BUF_PARAM(out), min_alloc);
  afl_realloc(SGF_BUF_PARAM(eff), min_alloc);
  afl_realloc(SGF_BUF_PARAM(ex), min_alloc);

  sgf->fsrv.use_fauxsrv = sgf->non_instrumented_mode == 1 || sgf->no_forkserver;
  sgf->fsrv.max_length = sgf->max_length;

  #ifdef __linux__
  if (!sgf->fsrv.nyx_mode) {

    check_crash_handling();
    check_cpu_governor(sgf);

  } else {

    u8 *libnyx_binary = find_afl_binary(argv[0], "libnyx.so");
    sgf->fsrv.nyx_handlers = afl_load_libnyx_plugin(libnyx_binary);
    if (sgf->fsrv.nyx_handlers == NULL) {

      FATAL("failed to initialize libnyx.so...");

    }

  }

  #else
  check_crash_handling();
  check_cpu_governor(sgf);
  #endif

  #ifdef __APPLE__
  setenv("DYLD_NO_PIE", "1", 0);
  #endif

  if (getenv("LD_PRELOAD")) {

    WARNF(
        "LD_PRELOAD is set, are you sure that is what you want to do "
        "instead of using SGF_PRELOAD?");

  }

  if (sgf->sgf_env.sgf_preload) {

    if (sgf->fsrv.qemu_mode) {

      /* sgf-qemu-trace takes care of converting SGF_PRELOAD. */

    } else if (sgf->fsrv.frida_mode) {

      sgf_preload = getenv("SGF_PRELOAD");
      u8 *frida_binary = find_afl_binary(argv[0], "sgf-frida-trace.so");
      OKF("Injecting %s ...", frida_binary);
      if (sgf_preload) {

        if (sgf->fsrv.frida_asan) {

          OKF("Using Frida Address Sanitizer Mode");

          if (sgf->fsrv.mem_limit) {

            WARNF(
                "in the Frida Address Sanitizer Mode we disable all memory "
                "limits");
            sgf->fsrv.mem_limit = 0;

          }

          fasan_check_afl_preload(sgf_preload);

          setenv("ASAN_OPTIONS", "detect_leaks=false", 1);

        }

        u8 *frida_binary = find_afl_binary(argv[0], "sgf-frida-trace.so");
        OKF("Injecting %s ...", frida_binary);
        frida_afl_preload = alloc_printf("%s:%s", sgf_preload, frida_binary);

        ck_free(frida_binary);

        setenv("LD_PRELOAD", frida_afl_preload, 1);
  #ifdef __APPLE__
        setenv("DYLD_INSERT_LIBRARIES", frida_afl_preload, 1);
  #endif

      }

    } else {

      /* CoreSight mode uses the default behavior. */

      setenv("LD_PRELOAD", getenv("SGF_PRELOAD"), 1);
  #ifdef __APPLE__
      setenv("DYLD_INSERT_LIBRARIES", getenv("SGF_PRELOAD"), 1);
  #endif

    }

  } else if (sgf->fsrv.frida_mode) {

    if (sgf->fsrv.frida_asan) {

      OKF("Using Frida Address Sanitizer Mode");
      FATAL(
          "Address Sanitizer DSO must be loaded using SGF_PRELOAD in Frida "
          "Address Sanitizer Mode");

    } else {

      u8 *frida_binary = find_afl_binary(argv[0], "sgf-frida-trace.so");
      OKF("Injecting %s ...", frida_binary);
      setenv("LD_PRELOAD", frida_binary, 1);
  #ifdef __APPLE__
      setenv("DYLD_INSERT_LIBRARIES", frida_binary, 1);
  #endif
      ck_free(frida_binary);

    }

  }

  if (getenv("SGF_LD_PRELOAD")) {

    FATAL("Use SGF_PRELOAD instead of SGF_LD_PRELOAD");

  }

  if (sgf->sgf_env.sgf_target_env &&
      !extract_and_set_env(sgf->sgf_env.sgf_target_env)) {

    FATAL("Bad value of SGF_TARGET_ENV");

  }

  save_cmdline(sgf, argc, argv);
  check_if_tty(sgf);
  if (sgf->sgf_env.sgf_force_ui) { sgf->not_on_tty = 0; }

  get_core_count(sgf);

  atexit(at_exit);

  setup_dirs_fds(sgf);

  #ifdef HAVE_AFFINITY
  bind_to_free_cpu(sgf);
  #endif                                                   /* HAVE_AFFINITY */

  #ifdef __linux__
  if (sgf->fsrv.nyx_mode && sgf->fsrv.nyx_bind_cpu_id == 0xFFFFFFFF) {

    sgf->fsrv.nyx_bind_cpu_id = 0;

  }

  #endif

  #ifdef __HAIKU__
  /* Prioritizes performance over power saving */
  set_scheduler_mode(SCHEDULER_MODE_LOW_LATENCY);
  #endif

  #ifdef __APPLE__
  if (pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0) != 0) {

    WARNF("general thread priority settings failed");

  }

  #endif

  init_count_class16();

  if (sgf->is_main_node && check_main_node_exists(sgf) == 1) {

    WARNF("it is wasteful to run more than one main node!");
    sleep(1);

  } else if (!auto_sync && sgf->is_secondary_node &&

             check_main_node_exists(sgf) == 0) {

    WARNF(
        "no -M main node found. It is recommended to run exactly one main "
        "instance.");
    sleep(1);

  }

  #ifdef RAND_TEST_VALUES
  u32 counter;
  for (counter = 0; counter < 100000; counter++)
    printf("DEBUG: rand %06d is %u\n", counter, rand_below(sgf, 65536));
  #endif

  if (!getenv("SGF_CUSTOM_INFO_PROGRAM")) {

    setenv("SGF_CUSTOM_INFO_PROGRAM", argv[optind], 1);

  }

  if (!getenv("SGF_CUSTOM_INFO_PROGRAM_INPUT") && sgf->fsrv.out_file) {

    setenv("SGF_CUSTOM_INFO_PROGRAM_INPUT", sgf->fsrv.out_file, 1);

  }

  if (!getenv("SGF_CUSTOM_INFO_PROGRAM_ARGV")) {

    u8 envbuf[8096] = "", tmpbuf[8096] = "";
    for (s32 i = optind + 1; i < argc; ++i) {

      strcpy(tmpbuf, envbuf);
      if (strchr(argv[i], ' ') && !strchr(argv[i], '"') &&
          !strchr(argv[i], '\'')) {

        if (!strchr(argv[i], '\'')) {

          snprintf(envbuf, sizeof(tmpbuf), "%s '%s'", tmpbuf, argv[i]);

        } else {

          snprintf(envbuf, sizeof(tmpbuf), "%s \"%s\"", tmpbuf, argv[i]);

        }

      } else {

        snprintf(envbuf, sizeof(tmpbuf), "%s %s", tmpbuf, argv[i]);

      }

    }

    setenv("SGF_CUSTOM_INFO_PROGRAM_ARGV", envbuf + 1, 1);

  }

  if (!getenv("SGF_CUSTOM_INFO_OUT")) {

    setenv("SGF_CUSTOM_INFO_OUT", sgf->out_dir, 1);  // same as __AFL_OUT_DIR

  }

  setup_custom_mutators(sgf);

  if (sgf->sgf_env.sgf_custom_mutator_only) {

    if (!sgf->custom_mutators_count) {

      if (sgf->shm.cmplog_mode) {

        WARNF(
            "No custom mutator loaded, using SGF_CUSTOM_MUTATOR_ONLY is "
            "pointless and only allowed now to allow experiments with CMPLOG.");

      } else {

        FATAL(
            "No custom mutator loaded but SGF_CUSTOM_MUTATOR_ONLY specified.");

      }

    }

    /* This ensures we don't proceed to havoc/splice */
    sgf->custom_only = 1;

    /* Ensure we also skip all deterministic steps */
    sgf->skip_deterministic = 1;

  }

  if (sgf->custom_mutators_count && sgf->sgf_env.sgf_custom_mutator_late_send) {

    u32 count_send = 0;
    LIST_FOREACH(&sgf->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_fuzz_send) {

        if (count_send) {

          FATAL(
              "You can only have one custom send() function if you are using "
              "SGF_CUSTOM_MUTATOR_LATE_SEND!");

        }

        sgf->fsrv.late_send = el->afl_custom_fuzz_send;
        sgf->fsrv.custom_data_ptr = el->data;
        count_send = 1;

      }

    });

  }

  if (sgf->limit_time_sig > 0 && sgf->custom_mutators_count) {

    if (sgf->custom_only) {

      FATAL("Custom mutators are incompatible with MOpt (-L)");

    }

    u32 custom_fuzz = 0;
    LIST_FOREACH(&sgf->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_fuzz) { custom_fuzz = 1; }

    });

    if (custom_fuzz) {

      WARNF("afl_custom_fuzz is incompatible with MOpt (-L)");

    }

  }

  /* Simply code if SGF_TMPDIR is used or not */
  if (!sgf->sgf_env.sgf_tmpdir) {

    sgf->tmp_dir = sgf->out_dir;

  } else {

    sgf->tmp_dir = sgf->sgf_env.sgf_tmpdir;

  }

  setup_cmdline_file(sgf, argv + optind);

  // Let's check SAND sanitizers binaries a bit earlier
  // so that we won't overwrite target_path.
  // Lazymio: why does cmplog fsrv even work?!
  for (u8 i = 0; i < sgf->san_binary_length; i++) {

    check_binary(sgf, sgf->san_binary[i]);

  }

  check_binary(sgf, argv[optind]);

  u64 prev_target_hash = 0;
  s32 fast_resume = 0;
  u8  is_ijon_fastresume = 0;
  #ifdef HAVE_ZLIB
  gzFile fr_fd = NULL;
  #else
  s32 fr_fd = -1;
  #endif

  if (sgf->in_place_resume && !sgf->sgf_env.sgf_no_fastresume) {

    u8 fn[PATH_MAX], buf[32];
    snprintf(fn, PATH_MAX, "%s/target_hash", sgf->out_dir);
    s32 fd = open(fn, O_RDONLY);
    if (fd >= 0) {

      if (read(fd, buf, 32) >= 16) {

        sscanf(buf, "%p", (void **)&prev_target_hash);

      }

      close(fd);

    }

  }

  write_setup_file(sgf, argc, argv);

  if (sgf->in_place_resume && !sgf->sgf_env.sgf_no_fastresume) {

  #ifdef __linux__
    u64 target_hash = 0;
    if (sgf->fsrv.nyx_mode) {

      nyx_load_target_hash(&sgf->fsrv);
      target_hash = sgf->fsrv.nyx_target_hash64;

    } else {

      target_hash = get_binary_hash(sgf->fsrv.target_path);

    }

  #else
    u64 target_hash = get_binary_hash(sgf->fsrv.target_path);
  #endif

    if (!target_hash || prev_target_hash != target_hash) {

      ACTF("Target binary is different, cannot perform FAST RESUME!");

    } else {

      u8 fn[PATH_MAX];
      snprintf(fn, PATH_MAX, "%s/fastresume.bin", sgf->out_dir);
  #ifdef HAVE_ZLIB
      if ((fr_fd = ZLIBOPEN(fn, "rb")) != NULL) {

  #else
      if (likely((fr_fd = open(fn, O_RDONLY)) >= 0)) {

  #endif

        u8   ver_string[8];
        u64 *ver = (u64 *)ver_string;
        /* Try both version calculations to handle IJON/non-IJON compatibility
         */
        u64 expect_ver_no_ijon = FAST_RESUME_VERSION + sgf->shm.cmplog_mode +
                                 (sizeof(struct queue_entry) << 1);
        u64 expect_ver_with_ijon =
            expect_ver_no_ijon + sizeof(u32) + sizeof(ijon_fastresume_state_t);

        if (NZLIBREAD(fr_fd, ver_string, sizeof(ver_string)) !=
            sizeof(ver_string)) {

          WARNF("Empty fastresume.bin, ignoring, cannot perform FAST RESUME");

        } else {

          if (*ver != expect_ver_no_ijon && *ver != expect_ver_with_ijon) {

            WARNF(
                "Different AFL++ version or feature usage, cannot perform FAST "
                "RESUME");

          } else {

            OKF("Will perform FAST RESUME");
            fast_resume = 1;

            /* Detect if this is an IJON fastresume file */
            is_ijon_fastresume = (*ver == expect_ver_with_ijon);

          }

        }

      } else {

        ACTF("fastresume.bin not found, cannot perform FAST RESUME!");
        /* Clear any saved IJON state since we're not doing fastresume */
        if (unlikely(sgf->fsrv.use_ijon)) { clear_saved_ijon_state(); }

      }

      // If the fast resume file is not valid we will be unable to start, so
      // we remove the file but keep the file descriptor open.
      unlink(fn);

    }

  }

  read_testcases(sgf, NULL);

  pivot_inputs(sgf);

  if (!sgf->timeout_given) { find_timeout(sgf); }  // only for resumes!

  if (sgf->sgf_env.sgf_tmpdir && !sgf->in_place_resume) {

    char tmpfile[PATH_MAX];

    if (sgf->file_extension) {

      snprintf(tmpfile, PATH_MAX, "%s/.cur_input.%s", sgf->tmp_dir,
               sgf->file_extension);

    } else {

      snprintf(tmpfile, PATH_MAX, "%s/.cur_input", sgf->tmp_dir);

    }

    /* there is still a race condition here, but well ... */
    if (access(tmpfile, F_OK) != -1) {

      FATAL(
          "SGF_TMPDIR already has an existing temporary input file: %s - if "
          "this is not from another instance, then just remove the file.",
          tmpfile);

    }

  }

  // read_foreign_testcases(sgf, 1); for the moment dont do this
  OKF("Loaded a total of %u seeds.", sgf->queued_items);

  /* If we don't have a file name chosen yet, use a safe default. */

  if (!sgf->fsrv.out_file) {

    u32 j = optind + 1;
    while (argv[j]) {

      u8 *aa_loc = strstr(argv[j], "@@");

      if (aa_loc && !sgf->fsrv.out_file) {

        sgf->fsrv.use_stdin = 0;
        default_output = 0;

        if (sgf->file_extension) {

          sgf->fsrv.out_file = alloc_printf("%s/.cur_input.%s", sgf->tmp_dir,
                                            sgf->file_extension);

        } else {

          sgf->fsrv.out_file = alloc_printf("%s/.cur_input", sgf->tmp_dir);

        }

        detect_file_args(argv + optind + 1, sgf->fsrv.out_file,
                         &sgf->fsrv.use_stdin);
        break;

      }

      ++j;

    }

  }

  if (!sgf->fsrv.out_file) { setup_stdio_file(sgf); }


  #ifdef SGF_PERSISTENT_RECORD
  if (unlikely(sgf->fsrv.persistent_record)) {

    if (!getenv(PERSIST_ENV_VAR) && !getenv("SGF_FRIDA_PERSISTENT_ADDR") &&
        !getenv("SGF_QEMU_PERSISTENT_ADDR")) {

      FATAL(
          "Target binary is not compiled/run in persistent mode, "
          "SGF_PERSISTENT_RECORD makes no sense.");

    }

    sgf->fsrv.persistent_record_dir = alloc_printf("%s", sgf->out_dir);

  }

  #endif

  if (sgf->shmem_testcase_mode) { setup_testcase_shmem(sgf); }

  sgf->start_time = get_cur_time();

  if (sgf->fsrv.qemu_mode) {

    if (sgf->use_wine) {

      use_argv = get_wine_argv(argv[0], &sgf->fsrv.target_path, argc - optind,
                               argv + optind);

    } else {

      use_argv = get_qemu_argv(argv[0], &sgf->fsrv.target_path, argc - optind,
                               argv + optind);

    }

  } else if (sgf->fsrv.cs_mode) {

    use_argv = get_cs_argv(argv[0], &sgf->fsrv.target_path, argc - optind,
                           argv + optind);

  } else {

    use_argv = argv + optind;

  }

  if (sgf->non_instrumented_mode || sgf->fsrv.frida_mode || sgf->fsrv.cs_mode ||
      sgf->unicorn_mode) {

    map_size = sgf->fsrv.real_map_size = sgf->fsrv.map_size = MAP_SIZE;
    afl_resize_map_buffers(sgf, map_size, MAP_SIZE);

  }

  sgf->argv = use_argv;

  sgf->fsrv.trace_bits =
      afl_shm_init(&sgf->shm, sgf->fsrv.map_size, sgf->non_instrumented_mode,
                   sgf->perm, sgf->chown_needed ? sgf->fsrv.gid : -1);

  // create_shared_graph_c();
  // calling a func to create a shared memory segment for getting next events as feedback from the execution of the instrumented target
  create_shm_next_events_c();
  if (!sgf->non_instrumented_mode && !sgf->unicorn_mode &&
      !sgf->fsrv.frida_mode && !sgf->fsrv.cs_mode &&
      !sgf->sgf_env.sgf_skip_bin_check) {

    if (map_size <= DEFAULT_SHMEM_SIZE) {

      sgf->fsrv.map_size = DEFAULT_SHMEM_SIZE;  // dummy temporary value
      char vbuf[16];
      snprintf(vbuf, sizeof(vbuf), "%u", DEFAULT_SHMEM_SIZE);
      setenv("SGF_MAP_SIZE", vbuf, 1);

    }

    u32 new_map_size = afl_fsrv_get_mapsize(
        &sgf->fsrv, sgf->argv, &sgf->stop_soon, sgf->sgf_env.sgf_debug_child);

    // only reinitialize if the map needs to be larger than what we have.
    if (map_size < new_map_size) {

      OKF("Re-initializing maps to %u bytes", new_map_size);
      afl_resize_map_buffers(sgf, map_size, new_map_size);

      afl_fsrv_kill(&sgf->fsrv);
      afl_shm_deinit(&sgf->shm);
      sgf->fsrv.map_size = new_map_size;

      sgf->fsrv.trace_bits =
          afl_shm_init(&sgf->shm, new_map_size, sgf->non_instrumented_mode,
                       sgf->perm, sgf->chown_needed ? sgf->fsrv.gid : -1);
      setenv("SGF_NO_AUTODICT", "1", 1);  // loaded already
      afl_fsrv_start(&sgf->fsrv, sgf->argv, &sgf->stop_soon,
                     sgf->sgf_env.sgf_debug_child);

      map_size = new_map_size;

    }

  }

  /* Set up IJON state if enabled - MOVED here to use correct map size from
   * forkserver handshake */
  if (unlikely(sgf->fsrv.use_ijon)) {

  #ifdef __linux__
    if (sgf->fsrv.nyx_mode) {

      FATAL(
          "IJON mode is not compatible with nyx mode (-X/-Y). Nyx uses full "
          "system emulation with different memory management.");

    }

  #endif

    if (sgf->fsrv.map_size <= 4 + MAP_SIZE_IJON_BYTES + MAP_SIZE_IJON_MAP) {

      FATAL("target forkserver reports too small map for IJON - BUG!");

    }

    // For fastresume: target already has full map allocated, use it as-is
    // For fresh sessions: subtract IJON bytes from total map to get coverage
    // map size
    if (!fast_resume) {

      sgf->fsrv.map_size -= MAP_SIZE_IJON_BYTES;
      sgf->fsrv.real_map_size -= MAP_SIZE_IJON_BYTES;

    }

    OKF("IJON map: coverage bytes %u, ijon map bytes %u, ijon max size %u",
        (u32)(sgf->fsrv.map_size - MAP_SIZE_IJON_MAP), (u32)MAP_SIZE_IJON_MAP,
        (u32)MAP_SIZE_IJON_BYTES);

    /* Calculate IJON offset based on mode */
    sgf->ijon_bits = (u64 *)(sgf->fsrv.trace_bits + sgf->fsrv.map_size);

    char *max_dir = alloc_printf("%s/ijon_max", sgf->out_dir);
    sgf->ijon_state = new_ijon_min_state(max_dir);
    ck_free(max_dir);

    setenv("SGF_NO_IJON", "1", 1);

    // Initialize IJON shared access for dynamic offset calculation
    sgf->ijon_shared_access = setup_dynamic_shared_access(
        sgf->fsrv.trace_bits, sgf->fsrv.map_size, sgf->fsrv.real_map_size);

  }

  san_abstraction = getenv("SGF_SAN_ABSTRACTION");
  if (!san_abstraction || !strcmp(san_abstraction, "simplify_trace")) {

    sgf->san_abstraction = SIMPLIFY_TRACE;

  } else if (!strcmp(san_abstraction, "coverage_increase")) {

    sgf->san_abstraction = COVERAGE_INCREASE;

  } else if (!strcmp(san_abstraction, "unique_trace")) {

    sgf->san_abstraction = UNIQUE_TRACE;

  } else {

    WARNF("Unknown abstraction: %s, fallback to simplified trace.\n",
          san_abstraction);
    sgf->san_abstraction = SIMPLIFY_TRACE;

  }

  if (!sgf->san_binary_length && san_abstraction) {

    WARNF(
        "No extra sanitizer instrumented binaries are given, do you forget "
        "-a?\n");

  }

  /* Maybe merge with cmplog but much cmplog code was already copy-paste
   * style... */
  if (sgf->san_binary_length) {

    for (u8 i = 0; i < sgf->san_binary_length; i++) {

      ACTF("Spawning SAND forkserver for %s", sgf->san_binary[i]);
      afl_fsrv_init_dup(&sgf->san_fsrvs[i], &sgf->fsrv);

      /*
       * We don't really collect trace bits for sanitizer instrumented binary so
       * we just allocate some dummy memory here.
       */
      sgf->san_fsrvs[i].trace_bits = ck_alloc(
          sgf->fsrv.map_size + 8); /* One more u64 according to afl_shm_init*/
      sgf->san_fsrvs[i].san_but_not_instrumented = 1;
      sgf->san_fsrvs[i].cs_mode = sgf->fsrv.cs_mode;
      sgf->san_fsrvs[i].qemu_mode = sgf->fsrv.qemu_mode;
      sgf->san_fsrvs[i].frida_mode = sgf->fsrv.frida_mode;
      sgf->san_fsrvs[i].asanfuzz_binary = sgf->san_binary[i];
      sgf->san_fsrvs[i].target_path = sgf->san_binary[i];
      sgf->san_fsrvs[i].init_child_func = sanfuzz_exec_child;

      if ((map_size <= DEFAULT_SHMEM_SIZE ||
           sgf->san_fsrvs[i].map_size < map_size) &&
          !sgf->non_instrumented_mode && !sgf->fsrv.qemu_mode &&
          !sgf->fsrv.frida_mode && !sgf->unicorn_mode && !sgf->fsrv.cs_mode &&
          !sgf->sgf_env.sgf_skip_bin_check) {

        sgf->san_fsrvs[i].map_size = MAX(map_size, (u32)DEFAULT_SHMEM_SIZE);
        char vbuf[16];
        snprintf(vbuf, sizeof(vbuf), "%u", sgf->san_fsrvs[i].map_size);
        setenv("SGF_MAP_SIZE", vbuf, 1);

      }

      u32 new_map_size =
          afl_fsrv_get_mapsize(&sgf->san_fsrvs[i], sgf->argv, &sgf->stop_soon,
                               sgf->sgf_env.sgf_debug_child);

      // only reinitialize when it needs to be larger
      if (map_size < new_map_size) {

        OKF("Re-initializing maps to %u bytes due to SAN instrumented binary",
            new_map_size);
        afl_resize_map_buffers(sgf, map_size, new_map_size);

        afl_fsrv_kill(&sgf->fsrv);
        afl_fsrv_kill(&sgf->san_fsrvs[i]);
        afl_shm_deinit(&sgf->shm);

        sgf->san_fsrvs[i].map_size = new_map_size;  // non-cmplog stays the same
        map_size = new_map_size;

        setenv("SGF_NO_AUTODICT", "1", 1);  // loaded already
        sgf->fsrv.trace_bits =
            afl_shm_init(&sgf->shm, new_map_size, sgf->non_instrumented_mode,
                         sgf->perm, sgf->chown_needed ? sgf->fsrv.gid : -1);
        ck_free(sgf->san_fsrvs[i].trace_bits);
        sgf->san_fsrvs[i].trace_bits = ck_alloc(sgf->fsrv.map_size + 8);
        sgf->san_fsrvs[i].map_size = sgf->fsrv.map_size;
        afl_fsrv_start(&sgf->fsrv, sgf->argv, &sgf->stop_soon,
                       sgf->sgf_env.sgf_debug_child);
        afl_fsrv_start(&sgf->san_fsrvs[i], sgf->argv, &sgf->stop_soon,
                       sgf->sgf_env.sgf_debug_child);

      }

      OKF("SAND forkserver for %s successfully started", sgf->san_binary[i]);

    }

    OKF("All forkservers for extra sanitizers instrumented binaries are up and "
        "we have abstraction = %d",
        sgf->san_abstraction);

  }

  load_auto(sgf);

  if (extras_dir_cnt) {

    for (u8 i = 0; i < extras_dir_cnt; i++) {

      load_extras(sgf, extras_dir[i]);

    }

  }

  if (sgf->fsrv.out_file && sgf->fsrv.use_shmem_fuzz) {

    unlink(sgf->fsrv.out_file);
    sgf->fsrv.out_file = NULL;
    sgf->fsrv.use_stdin = 0;
    close(sgf->fsrv.out_fd);
    sgf->fsrv.out_fd = -1;

    if (!sgf->unicorn_mode && !sgf->fsrv.use_stdin && !default_output) {

      WARNF(
          "You specified -f or @@ on the command line but the target harness "
          "specified fuzz cases via shmem, switching to shmem!");

    }

  }

  deunicode_extras(sgf);
  dedup_extras(sgf);
  if (sgf->extras_cnt) { OKF("Loaded a total of %u extras.", sgf->extras_cnt); }

  if (unlikely(fast_resume)) {

    u64 resume_start = get_cur_time_us();
    // if we get here then we should abort on errors

    u32 stored_map_size;

    if (unlikely(is_ijon_fastresume)) {

      // IJON fastresume: Read the stored map size from the fastresume file
      ZLIBREAD(fr_fd, &stored_map_size, sizeof(stored_map_size),
               "stored_map_size");
      ZLIBREAD(fr_fd, sgf->virgin_bits, stored_map_size, "virgin_bits");
      ZLIBREAD(fr_fd, sgf->virgin_tmout, stored_map_size, "virgin_tmout");
      ZLIBREAD(fr_fd, sgf->virgin_crash, stored_map_size, "virgin_crash");
      ZLIBREAD(fr_fd, sgf->var_bytes, stored_map_size, "var_bytes");

      // Load IJON state from fastresume file
      ijon_fastresume_state_t saved_ijon_state;

      // Initialize with clean state
      memset(&saved_ijon_state, 0, sizeof(saved_ijon_state));

      ZLIBREAD(fr_fd, &saved_ijon_state, sizeof(ijon_fastresume_state_t),
               "ijon_state");

      if (saved_ijon_state.is_initialized) {

        // IJON will be enabled after forkserver handshake confirms capability

        // Restore IJON state for consistent offset calculation
        save_ijon_state_for_fastresume(
            saved_ijon_state.ijon_offset, saved_ijon_state.map_size,
            saved_ijon_state.real_map_size, saved_ijon_state.target_map_size);

        // Update sgf->ijon_bits to use the saved offset
        sgf->ijon_bits =
            (u64 *)(sgf->fsrv.trace_bits + saved_ijon_state.ijon_offset);

      }

    } else {

      /* Normal fuzzing: use current map_size directly */
      stored_map_size = sgf->fsrv.map_size;
      ZLIBREAD(fr_fd, sgf->virgin_bits, stored_map_size, "virgin_bits");
      ZLIBREAD(fr_fd, sgf->virgin_tmout, stored_map_size, "virgin_tmout");
      ZLIBREAD(fr_fd, sgf->virgin_crash, stored_map_size, "virgin_crash");
      ZLIBREAD(fr_fd, sgf->var_bytes, stored_map_size, "var_bytes");

    }

    u8  res[1] = {0};
    u8 *o_start = (u8 *)&(sgf->queue_buf[0]->colorized);
    u8 *o_end = (u8 *)&(sgf->queue_buf[0]->mother);

    // Use stored map size for queue reading calculations (matches what was
    // saved)
    u32 r, m_len;
    u32 queue_map_size =
        stored_map_size;  // Use the map size that was used during save
    r = 8 + (sgf->fsrv.use_ijon ? sizeof(u32) : 0) +
        queue_map_size *
            4;         /* +sizeof(u32) for map_size field only in IJON mode */
    m_len = ((queue_map_size + 7) >> 3);

    u32                 q_len = o_end - o_start;
    struct queue_entry *q;

    for (u32 i = 0; i < sgf->queued_items; i++) {

      q = sgf->queue_buf[i];
      // this is very dirty and assumes nice memory :-)
      ZLIBREAD(fr_fd, (u8 *)&(q->colorized), q_len, "queue data");
      ZLIBREAD(fr_fd, res, 1, "check map");
      if (res[0]) {

        q->trace_mini = ck_alloc(m_len);
        ZLIBREAD(fr_fd, q->trace_mini, m_len, "trace_mini");
        r += q_len + m_len + 1;

      } else {

        r += q_len + 1;

      }

      sgf->total_bitmap_size += q->bitmap_size;
      ++sgf->total_bitmap_entries;
      update_bitmap_score(sgf, q, false);

      if (q->was_fuzzed) { --sgf->pending_not_fuzzed; }

      if (q->disabled) {

        if (!q->was_fuzzed) { --sgf->pending_not_fuzzed; }
        --sgf->active_items;

      }

      if (q->var_behavior) { ++sgf->queued_variable; }
      if (q->favored) {

        ++sgf->queued_favored;
        if (!q->was_fuzzed) { ++sgf->pending_favored; }

      }

    }

    u8  buf[4];
    int trailing_bytes = NZLIBREAD(fr_fd, buf, 3);
    if (trailing_bytes > 0) {

      // Check if trailing bytes are just ZLIB padding (all zeros) - only for
      // IJON mode
      if (is_ijon_fastresume) {

        u8 all_zeros = 1;
        for (int i = 0; i < trailing_bytes; i++) {

          if (buf[i] != 0) {

            all_zeros = 0;
            break;

          }

        }

        if (!all_zeros || trailing_bytes > 4) {

          FATAL("invalid trailing data in fastresume.bin");

        }

      } else {

        // Non-IJON mode - strict check, no tolerance for trailing data
        FATAL("invalid trailing data in fastresume.bin");

      }

    }

    OKF("Successfully loaded fastresume.bin (%u bytes)!", r);
    ZLIBCLOSE(fr_fd);
    sgf->reinit_table = 1;
    update_calibration_time(sgf, &resume_start);

    // For IJON fastresume: temporarily unset SGF_NO_IJON so target can allocate
    // IJON map
    u8 need_restore_no_ijon = 0;
    if (has_saved_ijon_state()) {

      if (getenv("SGF_NO_IJON")) {

        unsetenv("SGF_NO_IJON");
        need_restore_no_ijon = 1;

      }

    }

    afl_fsrv_start(&sgf->fsrv, sgf->argv, &sgf->stop_soon,
                   sgf->sgf_env.sgf_debug_child);

    // Restore SGF_NO_IJON for subsequent processes (cmplog/asan)
    if (need_restore_no_ijon) { setenv("SGF_NO_IJON", "1", 1); }

    // Enable IJON after forkserver handshake (for IJON fastresume)
    if (has_saved_ijon_state()) {

      ijon_fastresume_state_t *restored_state = get_saved_ijon_state();
      if (restored_state && restored_state->is_initialized) {

        // Enable IJON now that forkserver handshake is complete
        sgf->fsrv.use_ijon = 1;

        // Don't override the new forkserver map_size, just update ijon_bits
        // pointer Use the saved offset to maintain consistency
        sgf->ijon_bits =
            (u64 *)(sgf->fsrv.trace_bits + restored_state->ijon_offset);

        // Initialize IJON shared access with saved offset for fastresume
        sgf->ijon_shared_access = (dynamic_shared_access_t *)ck_alloc(
            sizeof(dynamic_shared_access_t));
        sgf->ijon_shared_access->ijon_offset = restored_state->ijon_offset;
        sgf->ijon_shared_access->ijon_max_area =
            (u64 *)(sgf->fsrv.trace_bits + restored_state->ijon_offset);

      }

    }

    if (sgf->fsrv.support_shmem_fuzz && !sgf->fsrv.use_shmem_fuzz) {

      afl_shm_deinit(sgf->shm_fuzz);
      ck_free(sgf->shm_fuzz);
      sgf->shm_fuzz = NULL;
      sgf->fsrv.support_shmem_fuzz = 0;
      sgf->fsrv.shmem_fuzz = NULL;

    }

  } else {

    // after we have the correct bitmap size we can read the bitmap -B option
    // and set the virgin maps
    if (sgf->in_bitmap) {

      read_bitmap(sgf->in_bitmap, sgf->virgin_bits, sgf->fsrv.map_size);

    } else {

      memset(sgf->virgin_bits, 255, map_size + SKELETON_GRAPH_MAP_SIZE);

    }

    memset(sgf->virgin_tmout, 255, map_size + SKELETON_GRAPH_MAP_SIZE);
    memset(sgf->virgin_crash, 255, map_size + SKELETON_GRAPH_MAP_SIZE);

    if (likely(!sgf->sgf_env.sgf_no_startup_calibration)) {

      perform_dry_run(sgf);

    } else {

      ACTF("Skipping initial seed calibration due option override!");
      usleep(1000);

    }

  }

  if (sgf->q_testcase_max_cache_entries) {

    sgf->q_testcase_cache =
        ck_alloc(sgf->q_testcase_max_cache_entries * sizeof(size_t));
    if (!sgf->q_testcase_cache) { PFATAL("malloc failed for cache entries"); }

  }

  if (sgf->sgf_env.sgf_sha1_filenames) {

    WARNF(
        "Using SGF_SHA1_FILENAMES disables any syncing to other AFL "
        "instances!");

  }

  cull_queue(sgf);

  // ensure we have at least one seed that is not disabled.
  u32 entry, valid_seeds = 0;
  for (entry = 0; entry < sgf->queued_items; ++entry)
    if (!sgf->queue_buf[entry]->disabled) { ++valid_seeds; }

  if (!valid_seeds) {

    FATAL("We need at least one valid input seed that does not crash!");

  }

  /* Seed the bounded queue with the initial corpus. Without this the queue
     starts empty, so the original seeds could never be selected again after
     the first cycle -- only mutated children would ever be candidates. */
  if (sgf->bounded_queue) {

    u32 seeded = 0;
    for (entry = 0; entry < sgf->queued_items; ++entry) {

      struct queue_entry *q = sgf->queue_buf[entry];
      if (!q || q->disabled) { continue; }
      if (sgf_queue_enqueue(sgf->bounded_queue, q->id, q,
                            q->perf_score) == 0) {
        ++seeded;
      }

    }

    ACTF("Bounded queue '%s': seeded %u/%u initial entries",
         sgf->queue_impl_name ? sgf->queue_impl_name : "?", seeded,
         valid_seeds);

  }

  if (sgf->timeout_given == 2) {  // -t ...+ option

    if (valid_seeds == 1) {

      WARNF(
          "Only one valid seed is present, auto-calculating the timeout is "
          "disabled!");
      sgf->timeout_given = 1;

    } else {

      u64 max_ms = 0;

      for (entry = 0; entry < sgf->queued_items; ++entry)
        if (!sgf->queue_buf[entry]->disabled)
          if ((sgf->queue_buf[entry]->exec_us / 1000) > max_ms)
            max_ms = sgf->queue_buf[entry]->exec_us / 1000;

      // Add 20% as a safety margin, capped to exec_tmout given in -t option
      max_ms *= 1.2;
      if (max_ms > sgf->fsrv.exec_tmout) max_ms = sgf->fsrv.exec_tmout;

      // Ensure that there is a sensible timeout even for very fast binaries
      if (max_ms < 5) max_ms = 5;

      sgf->fsrv.exec_tmout = max_ms;
      sgf->timeout_given = 1;

    }

  }

  show_init_stats(sgf);

  if (!getenv("SGF_NO_UI") && !sgf->not_on_tty) { make_space_for_stats(); }

  if (unlikely(sgf->old_seed_selection)) seek_to = find_start_position(sgf);

  sgf->start_time = get_cur_time();
  if (sgf->in_place_resume || sgf->sgf_env.sgf_autoresume) {

    load_stats_file(sgf);

  }

  if (!sgf->non_instrumented_mode) { write_stats_file(sgf, 0, 0, 0, 0); }
  maybe_update_plot_file(sgf, 0, 0, 0);
  save_auto(sgf);

  if (sgf->stop_soon) { goto stop_fuzzing; }

  if (!sgf->in_place_resume && sgf->sync_dir) { check_sync_fuzzers(sgf); }

  /* Woop woop woop */

  if (!sgf->not_on_tty) {

    sleep(1);
    if (sgf->stop_soon) { goto stop_fuzzing; }

  }

  // (void)nice(-20);  // does not improve the speed

  #ifdef INTROSPECTION
  u32 prev_saved_crashes = 0, prev_saved_tmouts = 0, stat_prev_queued_items = 0;
  #endif
  u32 prev_queued_items = 0, runs_in_current_cycle = (u32)-1;
  u8  skipped_fuzz;

  #ifdef INTROSPECTION
  char ifn[4096];
  snprintf(ifn, sizeof(ifn), "%s/introspection.txt", sgf->out_dir);
  if ((sgf->introspection_file = fopen(ifn, "w")) == NULL) {

    PFATAL("could not create '%s'", ifn);

  }

  setvbuf(sgf->introspection_file, NULL, _IONBF, 0);
  OKF("Writing mutation introspection to '%s'", ifn);
  #endif

  // real start time, we reset, so this works correctly with -V
  sgf->start_time = get_cur_time();
  u8 very_first_run = 1;

  while (likely(!sgf->stop_soon)) {

    cull_queue(sgf);

    if (unlikely((!sgf->old_seed_selection &&
                  runs_in_current_cycle > sgf->queued_items) ||
                 (sgf->old_seed_selection && !sgf->queue_cur))) {

      if (unlikely((sgf->last_sync_cycle < sgf->queue_cycle ||
                    (!sgf->queue_cycle && sgf->sgf_env.sgf_import_first)) &&
                   sgf->sync_id)) {

        if (unlikely(very_first_run && sgf->sgf_env.sgf_import_first)) {

          OKF("Syncing queues from other fuzzer instances first ...");
          very_first_run = 0;

        }

        sync_fuzzers(sgf);

      }

      ++sgf->queue_cycle;
      if (sgf->sgf_env.sgf_no_ui) {

        ACTF("Entering queue cycle %llu\n", sgf->queue_cycle);

      }

      runs_in_current_cycle = (u32)-1;
      sgf->cur_skipped_items = 0;

      // 1st april fool joke - enable pizza mode
      // to not waste time on checking the date we only do this when the
      // queue is fully cycled.
      time_t     cursec = time(NULL);
      struct tm *curdate = localtime(&cursec);
      if (unlikely(!sgf->sgf_env.sgf_pizza_mode)) {

        if (unlikely(curdate->tm_mon == 3 && curdate->tm_mday == 1)) {

          sgf->pizza_is_served = 1;

        } else {

          sgf->pizza_is_served = 0;

        }

      }

      if (unlikely(sgf->old_seed_selection)) {

        sgf->current_entry = 0;
        while (unlikely(sgf->current_entry < sgf->queued_items &&
                        sgf->queue_buf[sgf->current_entry]->disabled)) {

          ++sgf->current_entry;

        }

        if (sgf->current_entry >= sgf->queued_items) { sgf->current_entry = 0; }

        sgf->queue_cur = sgf->queue_buf[sgf->current_entry];

        if (unlikely(seek_to)) {

          if (unlikely(seek_to >= sgf->queued_items)) {

            // This should never happen.
            FATAL("BUG: seek_to location out of bounds!\n");

          }

          sgf->current_entry = seek_to;
          sgf->queue_cur = sgf->queue_buf[seek_to];
          seek_to = 0;

        }

      }

      /* If we had a full queue cycle with no new finds, try
         recombination strategies next. */

      if (unlikely(sgf->queued_items == prev_queued
                   /* FIXME TODO BUG: && (get_cur_time() - sgf->start_time) >=
                      3600 */
                   )) {

        ++sgf->cycles_wo_finds;

        if (unlikely(sgf->shm.cmplog_mode &&
                     sgf->cmplog_max_filesize < MAX_FILE)) {

          sgf->cmplog_max_filesize <<= 4;

        }

        switch (sgf->expand_havoc) {

          case 0:
            // do nothing the first time
            sgf->expand_havoc = 1;
            break;
          case 1:
            // add MOpt mutator
            /*
            if (sgf->limit_time_sig == 0 && !sgf->custom_only &&
                !sgf->python_only) {

              sgf->limit_time_sig = -1;
              sgf->limit_time_puppet = 0;

            }

            */
            /* increase cmplog level to 2 if we run with level 1 */
            if (sgf->cmplog_lvl && sgf->cmplog_lvl < 2) sgf->cmplog_lvl = 2;
            sgf->expand_havoc = 2;
            break;
          case 2:
            // increase havoc mutations per fuzz attempt
            sgf->havoc_stack_pow2++;
            sgf->expand_havoc = 3;
            break;
          case 3:
            // further increase havoc mutations per fuzz attempt
            sgf->havoc_stack_pow2++;
            sgf->expand_havoc = 4;
            break;
          case 4:
            // if (sgf->cmplog_lvl && sgf->cmplog_lvl < 3) sgf->cmplog_lvl =
            // 3;
            sgf->expand_havoc = 5;
            break;
          case 5:
            // nothing else currently
            break;

        }

      } else {

        sgf->cycles_wo_finds = 0;

      }

  #ifdef INTROSPECTION
      {

        u64 cur_time = get_cur_time();
        fprintf(sgf->introspection_file,
                "CYCLE cycle=%llu cycle_wo_finds=%llu time_wo_finds=%llu "
                "expand_havoc=%u queue=%u\n",
                sgf->queue_cycle, sgf->cycles_wo_finds,
                sgf->longest_find_time > cur_time - sgf->last_find_time
                    ? sgf->longest_find_time / 1000
                    : ((sgf->start_time == 0 || sgf->last_find_time == 0)
                           ? 0
                           : (cur_time - sgf->last_find_time) / 1000),
                sgf->expand_havoc, sgf->queued_items);

      }

  #endif

      if (sgf->cycle_schedules) {

        /* we cannot mix non-AFLfast schedules with others */

        switch (sgf->schedule) {

          case EXPLORE:
            sgf->schedule = EXPLOIT;
            break;
          case EXPLOIT:
            sgf->schedule = MMOPT;
            break;
          case MMOPT:
            sgf->schedule = SEEK;
            break;
          case SEEK:
            sgf->schedule = EXPLORE;
            break;
          case FAST:
            sgf->schedule = COE;
            break;
          case COE:
            sgf->schedule = LIN;
            break;
          case LIN:
            sgf->schedule = QUAD;
            break;
          case QUAD:
            sgf->schedule = RARE;
            break;
          case RARE:
            sgf->schedule = FAST;
            break;

        }

        // we must recalculate the scores of all queue entries
        recalculate_all_scores(sgf);

      }

      prev_queued = sgf->queued_items;

    }

    ++runs_in_current_cycle;

    do {

      if (likely(!sgf->old_seed_selection)) {

        if (likely(sgf->pending_favored && sgf->smallest_favored >= 0)) {

          sgf->current_entry = sgf->smallest_favored;

          /*

                    } else {

                      for (s32 iter = sgf->queued_items - 1; iter >= 0; --iter)
             {

                        if (unlikely(sgf->queue_buf[iter]->favored &&
                                     !sgf->queue_buf[iter]->was_fuzzed)) {

                          sgf->current_entry = iter;
                          break;

                        }

                      }

          */

          sgf->queue_cur = sgf->queue_buf[sgf->current_entry];

        } else {

          if (unlikely(prev_queued_items < sgf->queued_items ||
                       sgf->reinit_table)) {
            if(sgf->reinit_table){
              // ACTF("reinit_table is set, recreating alias table");
            }else{
              // ACTF("New queue entries since last run, recreating alias table");
              // ACTF("prev_queued_items: %u, sgf->queued_items: %u", prev_queued_items, sgf->queued_items);
            }
            // we have new queue entries since the last run, recreate alias
            // table
            prev_queued_items = sgf->queued_items;
            // ACTF("Calling create_alias_table func");
            // sleep(10);

            create_alias_table(sgf);
            // ACTF("create_alias_table func returned");
            // sleep(10);

          }

          do {

            sgf->current_entry = select_next_queue_entry(sgf);

          } while (unlikely(sgf->current_entry >= sgf->queued_items));

          sgf->queue_cur = sgf->queue_buf[sgf->current_entry];

        }

      }
      
      /* Bounded queue selection. This overrides the alias-table pick made
         above. The stock selection is deliberately left to run first so that
         current_entry, the alias table and the stats counters stay consistent;
         we only substitute the entry actually handed to fuzz_one(). If the
         bounded queue is empty or hands back a disabled entry we silently keep
         AFL's own choice. */
      if (sgf->bounded_queue && sgf_queue_size(sgf->bounded_queue) > 0) {

        SgfQueueEntry *bq = sgf_queue_dequeue(sgf->bounded_queue);
        if (bq && bq->graph_data) {

          struct queue_entry *sel = (struct queue_entry *)bq->graph_data;
          if (!sel->disabled) {

            sgf->queue_cur = sel;
            sgf->current_entry = sel->id;

          }

        }

      }

      // Toggle phase after every 5 SGF cycles
      if (sgf->queue_cycle == 0 || ((sgf->queue_cycle - 1) / 5) % 2 == 0) {
        sgf->current_phase = MO_FOOTPRINT_DRIVEN_PHASE;
      } else {
        sgf->current_phase = POTENTIAL_DRIVEN_PHASE;
      }
      skipped_fuzz = fuzz_one(sgf);
      // ACTF("fuzz_one returned with skipped_fuzz = %d", skipped_fuzz);
      // sleep(10);
      #ifdef INTROSPECTION
      ++sgf->queue_cur->stats_selected;

      if (unlikely(skipped_fuzz)) {

        ++sgf->queue_cur->stats_skipped;

      } else {

        if (unlikely(sgf->queued_items > stat_prev_queued_items)) {

          sgf->queue_cur->stats_finds +=
              sgf->queued_items - stat_prev_queued_items;
          stat_prev_queued_items = sgf->queued_items;

        }

        if (unlikely(sgf->saved_crashes > prev_saved_crashes)) {

          sgf->queue_cur->stats_crashes +=
              sgf->saved_crashes - prev_saved_crashes;
          prev_saved_crashes = sgf->saved_crashes;

        }

        if (unlikely(sgf->saved_tmouts > prev_saved_tmouts)) {

          sgf->queue_cur->stats_tmouts += sgf->saved_tmouts - prev_saved_tmouts;
          prev_saved_tmouts = sgf->saved_tmouts;

        }

      }

  #endif

      if (unlikely(!sgf->stop_soon && exit_1)) { sgf->stop_soon = 2; }

      if (unlikely(sgf->old_seed_selection)) {

        while (++sgf->current_entry < sgf->queued_items &&
               sgf->queue_buf[sgf->current_entry]->disabled) {};
        if (unlikely(sgf->current_entry >= sgf->queued_items ||
                     sgf->queue_buf[sgf->current_entry] == NULL ||
                     sgf->queue_buf[sgf->current_entry]->disabled)) {

          sgf->queue_cur = NULL;

        } else {

          sgf->queue_cur = sgf->queue_buf[sgf->current_entry];

        }

      }

    } while (skipped_fuzz && sgf->queue_cur && !sgf->stop_soon);

    u64 cur_time = get_cur_time();

    if (likely(sgf->switch_fuzz_mode && sgf->fuzz_mode == 0 &&
               !sgf->non_instrumented_mode) &&
        unlikely(cur_time > (likely(sgf->last_find_time) ? sgf->last_find_time
                                                         : sgf->start_time) +
                                sgf->switch_fuzz_mode)) {

      if (sgf->sgf_env.sgf_no_ui) {

        ACTF(
            "No new coverage found for %llu seconds, switching to exploitation "
            "strategy.",
            sgf->switch_fuzz_mode / 1000);

      }

      sgf->fuzz_mode = 1;

    }

    if (likely(!sgf->stop_soon && sgf->sync_id)) {

      if (unlikely(sgf->is_main_node)) {

        if (unlikely(cur_time > (sgf->sync_time >> 1) + sgf->last_sync_time)) {

          if (!(sync_interval_cnt++ % (SYNC_INTERVAL / 3))) {

            sync_fuzzers(sgf);

          }

        }

      } else {

        if (unlikely(cur_time > sgf->sync_time + sgf->last_sync_time)) {

          if (!(sync_interval_cnt++ % SYNC_INTERVAL)) { sync_fuzzers(sgf); }

        }

      }

    }

  }

stop_fuzzing:

  sgf->force_ui_update = 1;  // ensure the screen is reprinted
  sgf->stop_soon = 1;        // ensure everything is written
  show_stats(sgf);           // print the screen one last time
  write_bitmap(sgf);
  save_auto(sgf);

  #ifdef __AFL_CODE_COVERAGE
  if (sgf->fsrv.persistent_trace_bits) {

    char cfn[4096];
    snprintf(cfn, sizeof(cfn), "%s/covmap.dump", sgf->out_dir);

    FILE *cov_fd;
    if ((cov_fd = fopen(cfn, "w")) == NULL) {

      PFATAL("could not create '%s'", cfn);

    }

    // Write the real map size, as the map size must exactly match the pointer
    // map in length.
    fwrite(sgf->fsrv.persistent_trace_bits, 1, sgf->fsrv.real_map_size, cov_fd);
    fclose(cov_fd);

  }

  #endif

  if (sgf->pizza_is_served) {

    SAYF(CURSOR_SHOW cLRD "\n\n+++ Baking aborted %s +++\n" cRST,
         sgf->stop_soon == 2 ? "programmatically" : "by the chef");

  } else {

    //printing out the freq of exploring each edge
    // Print MO edge exploration frequencies
    if (get_mo_coverage_count() > 0) {
      SAYF("\nMO Edge Exploration Frequencies:\n");
      // for_each_mo_edge(print_edge_frequency, NULL);
      print_mo_edge_frequencies();
    }

    SAYF(CURSOR_SHOW cLRD "\n\n+++ Testing aborted %s +++\n" cRST,
         sgf->stop_soon == 2 ? "programmatically" : "by user");

  }

  if (sgf->most_time_key == 2) {

    SAYF(cYEL "[!] " cRST "Time limit was reached\n");

  }

  if (sgf->most_execs_key == 2) {

    SAYF(cYEL "[!] " cRST "Execution limit was reached\n");

  }

  /* Running for more than 30 minutes but still doing first cycle? */

  if (sgf->queue_cycle == 1 &&
      get_cur_time() - sgf->start_time > 30 * 60 * 1000) {

    SAYF("\n" cYEL "[!] " cRST
         "Stopped during the first cycle, results may be incomplete.\n"
         "    (For info on resuming, see %s/README.md)\n",
         doc_path);

  }

  if (sgf->not_on_tty) {

    u32 t_bytes = count_non_255_bytes(sgf, sgf->virgin_bits);
    u8  time_tmp[64];
    u_stringify_time_diff(time_tmp, get_cur_time(), sgf->start_time);
    ACTF(
        "Statistics: %u new corpus items found, %.02f%% coverage achieved, "
        "%llu crashes saved, %llu timeouts saved, total runtime %s",
        sgf->queued_discovered,
        ((double)t_bytes * 100) / sgf->fsrv.real_map_size, sgf->saved_crashes,
        sgf->saved_hangs, time_tmp);

  }

  #ifdef PROFILING
  SAYF(cYEL "[!] " cRST
            "Profiling information: %llu ms total work, %llu ns/run\n",
       time_spent_working / 1000000,
       time_spent_working / sgf->fsrv.total_execs);
  #endif

  if (sgf->sgf_env.sgf_final_sync) {

    SAYF(cYEL "[!] " cRST
              "\nPerforming final sync, this make take some time ...\n");
    sync_fuzzers(sgf);
    write_bitmap(sgf);
    SAYF(cYEL "[!] " cRST "Done!\n\n");

  }

  if (sgf->is_main_node) {

    u8 path[PATH_MAX];
    sprintf(path, "%s/is_main_node", sgf->out_dir);
    unlink(path);

  }

  if (frida_afl_preload) { ck_free(frida_afl_preload); }

  fclose(sgf->fsrv.plot_file);

  #ifdef INTROSPECTION
  fclose(sgf->fsrv.det_plot_file);
  #endif

  if (!sgf->sgf_env.sgf_no_fastresume) {

    /* create fastresume.bin */
    u8 fr[PATH_MAX];
    snprintf(fr, PATH_MAX, "%s/fastresume.bin", sgf->out_dir);
    ACTF("Writing %s ...", fr);
  #ifdef HAVE_ZLIB
    if ((fr_fd = ZLIBOPEN(fr, "wb9")) != NULL) {

  #else
    if ((fr_fd = open(fr, O_WRONLY | O_TRUNC | O_CREAT, sgf->perm)) >= 0) {

      if (sgf->chown_needed) {

        if (fchown(fr_fd, -1, sgf->fsrv.gid) == -1) {

          PFATAL("fchown() failed");

        }

      }

  #endif

      u8   ver_string[8];
      u32  w = 0;
      u64 *ver = (u64 *)ver_string;
      /* Include IJON state size in version only when IJON is used */
      *ver = FAST_RESUME_VERSION + sgf->shm.cmplog_mode +
             (sizeof(struct queue_entry) << 1) +
             (sgf->fsrv.use_ijon ? sizeof(u32) + sizeof(ijon_fastresume_state_t)
                                 : 0);

      ZLIBWRITE(fr_fd, ver_string, sizeof(ver_string), "ver_string");

      /* Write the map size first so it can be read during load (IJON only) */
      if (unlikely(sgf->fsrv.use_ijon)) {

        ZLIBWRITE(fr_fd, &sgf->fsrv.map_size, sizeof(sgf->fsrv.map_size),
                  "map_size");

      }

      ZLIBWRITE(fr_fd, sgf->virgin_bits, sgf->fsrv.map_size, "virgin_bits");
      ZLIBWRITE(fr_fd, sgf->virgin_tmout, sgf->fsrv.map_size, "virgin_tmout");
      ZLIBWRITE(fr_fd, sgf->virgin_crash, sgf->fsrv.map_size, "virgin_crash");
      ZLIBWRITE(fr_fd, sgf->var_bytes, sgf->fsrv.map_size, "var_bytes");

      /* Save IJON state only when IJON is enabled */
      if (unlikely(sgf->fsrv.use_ijon)) {

        // Force IJON state to be saved if not already saved
        if (!has_saved_ijon_state()) {

          // Calculate current IJON parameters - use same logic as fresh session
          u32 current_ijon_offset = sgf->fsrv.map_size;
          save_ijon_state_for_fastresume(
              current_ijon_offset, sgf->fsrv.map_size, sgf->fsrv.real_map_size,
              sgf->fsrv.real_map_size);

        }

        ijon_fastresume_state_t *ijon_state = get_saved_ijon_state();
        if (ijon_state) {

          // Only update map sizes to current values for consistency with virgin
          // arrays
          ijon_state->map_size = sgf->fsrv.map_size;
          ijon_state->real_map_size = sgf->fsrv.real_map_size;
          ijon_state->target_map_size = sgf->fsrv.real_map_size;

          ZLIBWRITE(fr_fd, ijon_state, sizeof(ijon_fastresume_state_t),
                    "ijon_state");
          w += sizeof(ijon_fastresume_state_t);

        }

      }

      w += sizeof(ver_string) + (sgf->fsrv.use_ijon ? sizeof(u32) : 0) +
           sgf->fsrv.map_size * 4;

      u8                  on[1] = {1}, off[1] = {0};
      u8                 *o_start = (u8 *)&(sgf->queue_buf[0]->colorized);
      u8                 *o_end = (u8 *)&(sgf->queue_buf[0]->mother);
      u32                 q_len = o_end - o_start;
      u32                 m_len = ((sgf->fsrv.map_size + 7) >> 3);
      struct queue_entry *q;

      sgf->pending_not_fuzzed = sgf->queued_items;
      sgf->active_items = sgf->queued_items;

      for (u32 i = 0; i < sgf->queued_items; i++) {

        q = sgf->queue_buf[i];
        ZLIBWRITE(fr_fd, (u8 *)&(q->colorized), q_len, "queue data");
        if (!q->trace_mini) {

          ZLIBWRITE(fr_fd, off, 1, "no_mini");
          w += q_len + 1;

        } else {

          ZLIBWRITE(fr_fd, on, 1, "yes_mini");
          ZLIBWRITE(fr_fd, q->trace_mini, m_len, "trace_mini");
          w += q_len + m_len + 1;

        }

      }

      ZLIBCLOSE(fr_fd);
      sgf->var_byte_count = count_bytes(sgf, sgf->var_bytes);
      OKF("fastresume.bin successfully written with %u bytes.", w);

    } else {

      WARNF("Could not create fastresume.bin");

    }

  }

  destroy_queue(sgf);
  destroy_extras(sgf);
  destroy_custom_mutators(sgf);
  afl_shm_deinit(&sgf->shm);

  if (sgf->shm_fuzz) {

    afl_shm_deinit(sgf->shm_fuzz);
    ck_free(sgf->shm_fuzz);

  }

  afl_fsrv_deinit(&sgf->fsrv);

  for (u8 i = 0; i < sgf->san_binary_length; i++) {

    ck_free(sgf->san_fsrvs[i].trace_bits);
    afl_fsrv_deinit(&sgf->san_fsrvs[i]);

  }

  if (sgf->cmplog_binary) { afl_fsrv_deinit(&sgf->cmplog_fsrv); }

  /* remove tmpfile */
  if (!sgf->in_place_resume && sgf->fsrv.out_file) {

    (void)unlink(sgf->fsrv.out_file);

  }

  ck_free(sgf->n_fuzz);
  ck_free(sgf->n_fuzz_dup);
  ck_free(sgf->simplified_n_fuzz);

  if (sgf->orig_cmdline) { ck_free(sgf->orig_cmdline); }
  ck_free(sgf->fsrv.target_path);
  ck_free(sgf->fsrv.out_file);
  ck_free(sgf->sync_id);
  if (sgf->q_testcase_cache) { ck_free(sgf->q_testcase_cache); }
  afl_state_deinit(sgf);
  free(sgf);                                                 /* not tracked */

  argv_cpy_free(argv);

  alloc_report();

  OKF("We're done here. Have a nice day!\n");

  exit(0);

}

#endif                                                          /* !SGF_LIB */

