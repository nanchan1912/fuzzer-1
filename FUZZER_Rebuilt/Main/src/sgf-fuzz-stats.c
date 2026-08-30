/*
   american fuzzy lop++ - stats related routines
   ---------------------------------------------

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
#include "envs.h"
#include <limits.h>

//  7 is the number of characters in a color control code
// 11 is the number of characters in the fuzzing state itself
//  5 is the number of characters in `cRST`
//  1 is for the null character
static char fuzzing_state[4][7 + 11 + 5 + 1] = {

    "started :-)", "in progress", "final phase", cRED "finished..." cRST};

char *get_fuzzing_state(sgf_state_t *sgf) {

  u64 cur_ms = get_cur_time();
  u64 last_find = cur_ms - sgf->last_find_time;
  u64 cur_run_time = cur_ms - sgf->start_time;
  u64 cur_total_run_time = sgf->prev_run_time + cur_run_time;

  if (unlikely(sgf->non_instrumented_mode)) {

    return fuzzing_state[1];

  } else if (unlikely(cur_run_time < 60 * 3 * 1000 ||

                      cur_total_run_time < 60 * 5 * 1000)) {

    return fuzzing_state[0];

  } else {

    u64 last_find_100 = 100 * last_find;
    u64 percent_cur = last_find_100 / cur_run_time;
    u64 percent_total = last_find_100 / cur_total_run_time;

    if (unlikely(percent_cur >= 75 && percent_total >= 75)) {

      if (unlikely(sgf->sgf_env.sgf_exit_when_done)) { sgf->stop_soon = 2; }

      return fuzzing_state[3];

    } else if (unlikely(percent_cur >= 50 && percent_total >= 50)) {

      return fuzzing_state[2];

    } else {

      return fuzzing_state[1];

    }

  }

}

/* Write fuzzer setup file */

void write_setup_file(sgf_state_t *sgf, u32 argc, char **argv) {

  u8 fn[PATH_MAX], fn2[PATH_MAX];

  snprintf(fn2, PATH_MAX, "%s/target_hash", sgf->out_dir);
  FILE *f2 = create_ffile(fn2, sgf->perm);

  if (sgf->chown_needed) {

    if (chown(fn2, -1, sgf->fsrv.gid) == -1) { PFATAL("chown() failed"); }

  }

#ifdef __linux__
  if (sgf->fsrv.nyx_mode) {

    nyx_load_target_hash(&sgf->fsrv);
    fprintf(f2, "%llx\n", sgf->fsrv.nyx_target_hash64);

  } else {

    fprintf(f2, "%p\n", (void *)get_binary_hash(sgf->fsrv.target_path));

  }

#else
  fprintf(f2, "%p\n", (void *)get_binary_hash(sgf->fsrv.target_path));
#endif
  fclose(f2);

  snprintf(fn, PATH_MAX, "%s/fuzzer_setup", sgf->out_dir);
  FILE *f = create_ffile(fn, sgf->perm);
  u32   i;

  if (sgf->chown_needed) {

    if (chown(fn, -1, sgf->fsrv.gid) == -1) { PFATAL("chown() failed"); }

  }

  fprintf(f, "# environment variables:\n");
  u32 s_afl_env = (u32)sizeof(sgf_environment_variables) /
                      sizeof(sgf_environment_variables[0]) -
                  1U;

  for (i = 0; i < s_afl_env; ++i) {

    char *val;
    if ((val = getenv(sgf_environment_variables[i])) != NULL) {

      fprintf(f, "%s=%s\n", sgf_environment_variables[i], val);

    }

  }

  fprintf(f, "# command line:\n");

  size_t j;
  for (i = 0; i < argc; ++i) {

    if (i) fprintf(f, " ");
#ifdef __ANDROID__
    if (memchr(argv[i], '\'', strlen(argv[i]))) {

#else
    if (strchr(argv[i], '\'')) {

#endif

      fprintf(f, "'");
      for (j = 0; j < strlen(argv[i]); j++)
        if (argv[i][j] == '\'')
          fprintf(f, "'\"'\"'");
        else
          fprintf(f, "%c", argv[i][j]);
      fprintf(f, "'");

    } else {

      fprintf(f, "'%s'", argv[i]);

    }

  }

  fprintf(f, "\n");

  fclose(f);
  (void)(sgf_environment_deprecated);

}

static bool starts_with(char *key, char *line) {

  return strncmp(key, line, strlen(key)) == 0;

}

/* load some of the existing stats file when resuming.*/
void load_stats_file(sgf_state_t *sgf) {

  FILE *f;
  u8    buf[MAX_LINE];
  u8   *lptr;
  u8    fn[PATH_MAX];
  u32   lineno = 0;
  snprintf(fn, PATH_MAX, "%s/fuzzer_stats", sgf->out_dir);
  f = fopen(fn, "r");
  if (!f) {

    WARNF("Unable to load stats file '%s'", fn);
    return;

  }

  while ((lptr = fgets(buf, MAX_LINE, f))) {

    lineno++;
    u8 *lstartptr = lptr;
    u8 *rptr = lptr + strlen(lptr) - 1;
    u8  keystring[MAX_LINE];
    while (*lptr != ':' && lptr < rptr) {

      lptr++;

    }

    if (*lptr == '\n' || !*lptr) {

      WARNF("Unable to read line %d of stats file", lineno);
      continue;

    }

    if (*lptr == ':') {

      *lptr = 0;
      strcpy(keystring, lstartptr);
      lptr++;
      char *nptr;
      if (starts_with("run_time", keystring)) {

        sgf->prev_run_time = 1000 * strtoull(lptr, &nptr, 10);

      }

      if (starts_with("cycles_done", keystring)) {

        sgf->queue_cycle =
            strtoull(lptr, &nptr, 10) ? strtoull(lptr, &nptr, 10) + 1 : 0;

      }

      if (starts_with("calibration_time", keystring)) {

        sgf->calibration_time_us = strtoull(lptr, &nptr, 10) * 1000000;

      }

      if (starts_with("sync_time", keystring)) {

        sgf->sync_time_us = strtoull(lptr, &nptr, 10) * 1000000;

      }

      if (starts_with("cmplog_time", keystring)) {

        sgf->cmplog_time_us = strtoull(lptr, &nptr, 10) * 1000000;

      }

      if (starts_with("trim_time", keystring)) {

        sgf->trim_time_us = strtoull(lptr, &nptr, 10) * 1000000;

      }

      if (starts_with("execs_done", keystring)) {

        sgf->fsrv.total_execs = strtoull(lptr, &nptr, 10);

      }

      if (starts_with("corpus_count", keystring)) {

        u32 corpus_count = strtoul(lptr, &nptr, 10);
        if (corpus_count != sgf->queued_items) {

          WARNF(
              "queue/ has been modified -- things might not work, you're "
              "on your own!");
          sleep(3);

        }

      }

      if (starts_with("corpus_found", keystring)) {

        sgf->queued_discovered = strtoul(lptr, &nptr, 10);

      }

      if (starts_with("corpus_imported", keystring)) {

        sgf->queued_imported = strtoul(lptr, &nptr, 10);

      }

      if (starts_with("max_depth", keystring)) {

        sgf->max_depth = strtoul(lptr, &nptr, 10);

      }

      if (starts_with("saved_crashes", keystring)) {

        sgf->saved_crashes = strtoull(lptr, &nptr, 10);

      }

      if (starts_with("saved_hangs", keystring)) {

        sgf->saved_hangs = strtoull(lptr, &nptr, 10);

      }

      if (starts_with("saved_races", keystring)) {

        sgf->saved_races = strtoull(lptr, &nptr, 10);

      }

      if (starts_with("last_race", keystring)) {

        sgf->last_race_time = strtoull(lptr, &nptr, 10) * 1000;

      }

    }

  }

  if (sgf->saved_crashes) { write_crash_readme(sgf); }

  return;

}

/* Update stats file for unattended monitoring. */

void write_stats_file(sgf_state_t *sgf, u32 t_bytes, double bitmap_cvg,
                      double stability, double eps) {

#ifndef __HAIKU__
  struct rusage rus;
#endif

  u64   cur_time = get_cur_time();
  u8    fn_tmp[PATH_MAX];
  u8    fn_final[PATH_MAX];
  FILE *f;

  snprintf(fn_tmp, PATH_MAX, "%s/.fuzzer_stats_tmp", sgf->out_dir);
  snprintf(fn_final, PATH_MAX, "%s/fuzzer_stats", sgf->out_dir);
  f = create_ffile(fn_tmp, sgf->perm);

  if (sgf->chown_needed) {

    if (chown(fn_tmp, -1, sgf->fsrv.gid) == -1) { PFATAL("fchown() failed"); }

  }

  /* Keep last values in case we're called from another context
     where exec/sec stats and such are not readily available. */

  if (!bitmap_cvg && !stability && !eps) {

    bitmap_cvg = sgf->last_bitmap_cvg;
    stability = sgf->last_stability;

  } else {

    sgf->last_bitmap_cvg = bitmap_cvg;
    sgf->last_stability = stability;
    sgf->last_eps = eps;

  }

  if ((unlikely(!sgf->last_avg_exec_update ||
                cur_time - sgf->last_avg_exec_update >= 60000))) {

    sgf->last_avg_execs_saved =
        (double)(1000 * (sgf->fsrv.total_execs - sgf->last_avg_total_execs)) /
        (double)(cur_time - sgf->last_avg_exec_update);
    sgf->last_avg_total_execs = sgf->fsrv.total_execs;
    sgf->last_avg_exec_update = cur_time;

  }

#ifndef __HAIKU__
  if (getrusage(RUSAGE_CHILDREN, &rus)) { rus.ru_maxrss = 0; }
#endif
  u64 runtime_ms = sgf->prev_run_time + cur_time - sgf->start_time;
  u64 overhead_ms = (sgf->calibration_time_us + sgf->sync_time_us +
                     sgf->trim_time_us + sgf->cmplog_time_us) /
                    1000;
  if (!runtime_ms) { runtime_ms = 1; }

  fprintf(f,
          "start_time        : %llu\n"
          "last_update       : %llu\n"
          "run_time          : %llu\n"
          "fuzzer_pid        : %u\n"
          "cycles_done       : %llu\n"
          "cycles_wo_finds   : %llu\n"
          "time_wo_finds     : %llu\n"
          "fuzz_time         : %llu\n"
          "calibration_time  : %llu\n"
          "cmplog_time       : %llu\n"
          "sync_time         : %llu\n"
          "trim_time         : %llu\n"
          "execs_done        : %llu\n"
          "execs_per_sec     : %0.02f\n"
          "execs_ps_last_min : %0.02f\n"
          "corpus_count      : %u\n"
          "corpus_favored    : %u\n"
          "corpus_found      : %u\n"
          "corpus_imported   : %u\n"
          "corpus_variable   : %u\n"
          "max_depth         : %u\n"
          "cur_item          : %u\n"
          "pending_favs      : %u\n"
          "pending_total     : %u\n"
          "stability         : %0.02f%%\n"
          "bitmap_cvg        : %0.02f%%\n"
          "saved_crashes     : %llu\n"
          "saved_hangs       : %llu\n"
          "total_tmout       : %llu\n"
          "last_find         : %llu\n"
          "last_crash        : %llu\n"
          "last_hang         : %llu\n"
          "execs_since_crash : %llu\n"
          "exec_timeout      : %u\n"
          "slowest_exec_ms   : %u\n"
          "peak_rss_mb       : %lu\n"
          "cpu_affinity      : %d\n"
          "edges_found       : %u\n"
          "total_edges       : %u\n"
          "var_byte_count    : %u\n"
          "havoc_expansion   : %u\n"
          "auto_dict_entries : %u\n"
          "testcache_size    : %llu\n"
          "testcache_count   : %u\n"
          "testcache_evict   : %u\n"
          "sgf_banner        : %s\n"
          "sgf_version       : " VERSION
          "\n"
          "target_mode       : %s%s%s%s%s%s%s%s%s%s\n"
          "command_line      : %s\n",
          (sgf->start_time /*- sgf->prev_run_time*/) / 1000, cur_time / 1000,
          runtime_ms / 1000, (u32)getpid(),
          sgf->queue_cycle ? (sgf->queue_cycle - 1) : 0, sgf->cycles_wo_finds,
          sgf->longest_find_time > cur_time - sgf->last_find_time
              ? sgf->longest_find_time / 1000
              : ((sgf->start_time == 0 || sgf->last_find_time == 0)
                     ? 0
                     : (cur_time - sgf->last_find_time) / 1000),
          (runtime_ms - MIN(runtime_ms, overhead_ms)) / 1000,
          sgf->calibration_time_us / 1000000, sgf->cmplog_time_us / 1000000,
          sgf->sync_time_us / 1000000, sgf->trim_time_us / 1000000,
          sgf->fsrv.total_execs,
          sgf->fsrv.total_execs / ((double)(runtime_ms) / 1000),
          sgf->last_avg_execs_saved, sgf->queued_items, sgf->queued_favored,
          sgf->queued_discovered, sgf->queued_imported, sgf->queued_variable,
          sgf->max_depth, sgf->current_entry, sgf->pending_favored,
          sgf->pending_not_fuzzed, stability, bitmap_cvg, sgf->saved_crashes,
          sgf->saved_hangs, sgf->total_tmouts, sgf->last_find_time / 1000,
          sgf->last_crash_time / 1000, sgf->last_hang_time / 1000,
          sgf->fsrv.total_execs - sgf->last_crash_execs, sgf->fsrv.exec_tmout,
          sgf->slowest_exec_ms,
#ifndef __HAIKU__
  #ifdef __APPLE__
          (unsigned long int)(rus.ru_maxrss >> 20),
  #else
          (unsigned long int)(rus.ru_maxrss >> 10),
  #endif
#else
          -1UL,
#endif
#ifdef HAVE_AFFINITY
          sgf->cpu_aff,
#else
          -1,
#endif
          t_bytes, sgf->fsrv.real_map_size, sgf->var_byte_count,
          sgf->expand_havoc, sgf->a_extras_cnt, sgf->q_testcase_cache_size,
          sgf->q_testcase_cache_count, sgf->q_testcase_evictions,
          sgf->use_banner, sgf->unicorn_mode ? "unicorn" : "",
          sgf->fsrv.qemu_mode ? "qemu " : "",
          sgf->fsrv.cs_mode ? "coresight" : "",
          sgf->non_instrumented_mode ? " non_instrumented " : "",
          sgf->no_forkserver ? "no_fsrv " : "", sgf->crash_mode ? "crash " : "",
          sgf->persistent_mode ? "persistent " : "",
          sgf->shmem_testcase_mode ? "shmem_testcase " : "",
          sgf->deferred_mode ? "deferred " : "",
          (sgf->unicorn_mode || sgf->fsrv.qemu_mode || sgf->fsrv.cs_mode ||
           sgf->non_instrumented_mode || sgf->no_forkserver ||
           sgf->crash_mode || sgf->persistent_mode || sgf->deferred_mode)
              ? ""
              : "default",
          sgf->orig_cmdline);

  if (sgf->check_data_race) {

    fprintf(f,
            "saved_races       : %llu\n"
            "last_race         : %llu\n"
            "execs_since_race  : %llu\n",
            sgf->saved_races, sgf->last_race_time / 1000,
            sgf->fsrv.total_execs - sgf->last_race_execs);

  }

  if (sgf->san_binary_length) {

    for (u8 i = 0; i < sgf->san_binary_length; i++) {

      fprintf(f,
              "extra_binary      : %s\n"
              "total_execs       : %llu\n",
              sgf->san_binary[i], sgf->san_fsrvs[i].total_execs);

    }

  }

  /* ignore errors */

  if (sgf->debug) {

    u32 i = 0;
    fprintf(f, "virgin_bytes     :");
    for (i = 0; i < sgf->fsrv.real_map_size; i++) {

      if (sgf->virgin_bits[i] != 0xff) {

        fprintf(f, " %u[%02x]", i, sgf->virgin_bits[i]);

      }

    }

    fprintf(f, "\n");
    fprintf(f, "var_bytes        :");
    for (i = 0; i < sgf->fsrv.real_map_size; i++) {

      if (sgf->var_bytes[i]) { fprintf(f, " %u", i); }

    }

    fprintf(f, "\n");

  }

  fclose(f);
  rename(fn_tmp, fn_final);

}

#ifdef INTROSPECTION
void write_queue_stats(sgf_state_t *sgf) {

  FILE *f;
  u8   *fn = alloc_printf("%s/queue_data", sgf->out_dir);
  if ((f = fopen(fn, "w")) != NULL) {

    u32 id;
    fprintf(f,
            "# filename, length, exec_us, selected, skipped, mutations, finds, "
            "crashes, timeouts, bitmap_size, perf_score, weight, colorized, "
            "favored, disabled\n");
    for (id = 0; id < sgf->queued_items; ++id) {

      struct queue_entry *q = sgf->queue_buf[id];
      fprintf(f, "\"%s\",%u,%llu,%u,%u,%llu,%u,%u,%u,%u,%.3f,%.3f,%u,%u,%u\n",
              q->fname, q->len, q->exec_us, q->stats_selected, q->stats_skipped,
              q->stats_mutated, q->stats_finds, q->stats_crashes,
              q->stats_tmouts, q->bitmap_size, q->perf_score, q->weight,
              q->colorized, q->favored, q->disabled);

    }

    fclose(f);

  }

  ck_free(fn);

}

#endif

/* Update the plot file if there is a reason to. */

void maybe_update_plot_file(sgf_state_t *sgf, u32 t_bytes, double bitmap_cvg,
                            double eps) {

  if((sgf->plot_prev_mo_cov == sgf->mo_coverage) &&
     (sgf->plot_prev_rf_cov == sgf->rf_coverage)) {
    // update only if mo or rf coverage changed - otherwise, return from the function
    return;
  }

  //TODO: Temporarily commented this to log whenever there is an increase in mo or rf coverage - uncomment this later

  if (unlikely(!sgf->force_ui_update &&
               (sgf->stop_soon ||
                (sgf->plot_prev_qp == sgf->queued_items &&
                 sgf->plot_prev_pf == sgf->pending_favored &&
                 sgf->plot_prev_pnf == sgf->pending_not_fuzzed &&
                 sgf->plot_prev_ce == sgf->current_entry &&
                 sgf->plot_prev_qc == sgf->queue_cycle &&
                 sgf->plot_prev_uc == sgf->saved_crashes &&
                 sgf->plot_prev_uh == sgf->saved_hangs &&
                 sgf->plot_prev_md == sgf->max_depth &&
                 sgf->plot_prev_ed == sgf->fsrv.total_execs) ||
                !sgf->queue_cycle ||
                get_cur_time() - sgf->start_time <= 60000))) {

    return;

  }

  sgf->plot_prev_qp = sgf->queued_items;
  sgf->plot_prev_pf = sgf->pending_favored;
  sgf->plot_prev_pnf = sgf->pending_not_fuzzed;
  sgf->plot_prev_ce = sgf->current_entry;
  sgf->plot_prev_qc = sgf->queue_cycle;
  sgf->plot_prev_uc = sgf->saved_crashes;
  sgf->plot_prev_uh = sgf->saved_hangs;
  sgf->plot_prev_md = sgf->max_depth;
  sgf->plot_prev_ed = sgf->fsrv.total_execs;
  sgf->plot_prev_mo_cov = sgf->mo_coverage;
  sgf->plot_prev_rf_cov = sgf->rf_coverage;

  /* Fields in the file:

     relative_time, sgf->cycles_done, cur_item, corpus_count, corpus_not_fuzzed,
     favored_not_fuzzed, saved_crashes, saved_hangs, max_depth,
     execs_per_sec, edges_found */

  if (sgf->log_graph_run_details) {

    double cur_score = sgf->queue_cur ? sgf->queue_cur->perf_score : 0.0;
    double cur_pot = (sgf->queue_cur && sgf->queue_cur->graph_data) ?
                       sgf->queue_cur->graph_data->potential_score : 0.0;
    double cur_mo = (sgf->queue_cur && sgf->queue_cur->graph_data) ?
                      sgf->queue_cur->graph_data->mo_footprint_score : 0.0;
    double cur_rf = (sgf->queue_cur && sgf->queue_cur->graph_data) ?
                      sgf->queue_cur->graph_data->rf_footprint_score : 0.0;
    u32 cur_children = (sgf->queue_cur && sgf->queue_cur->graph_data) ?
                         sgf->queue_cur->graph_data->children_enqueued : 0;

    fprintf(sgf->fsrv.plot_file,
            "%llu, %llu, %u, %u, %u, %u, %0.02f%%, %llu, %llu, %u, %0.02f, %llu, "
            "%u, %llu, %u, %u, %u, %0.04f, %0.04f, %0.04f, %0.04f, %u, %u, %0.04f, %0.04f, %0.04f, %0.04f, %u",
            ((sgf->prev_run_time + get_cur_time() - sgf->start_time) / 1000),
            sgf->queue_cycle ? sgf->queue_cycle - 1 : 0, sgf->current_entry, sgf->queued_items,
            sgf->pending_not_fuzzed, sgf->pending_favored, bitmap_cvg,
            sgf->saved_crashes, sgf->saved_hangs, sgf->max_depth, eps,
            sgf->plot_prev_ed, t_bytes, sgf->total_crashes,
            (u32)sgf->san_binary_length, sgf->mo_coverage, sgf->rf_coverage,
            cur_score, cur_pot, cur_mo, cur_rf, cur_children,
            0, 0.0, 0.0, 0.0, 0.0, 0);

  } else {

    fprintf(sgf->fsrv.plot_file,
            "%llu, %llu, %u, %u, %u, %u, %0.02f%%, %llu, %llu, %u, %0.02f, %llu, "
            "%u, %llu, %u, %u, %u",
            ((sgf->prev_run_time + get_cur_time() - sgf->start_time) / 1000),
            sgf->queue_cycle ? sgf->queue_cycle - 1 : 0, sgf->current_entry, sgf->queued_items,
            sgf->pending_not_fuzzed, sgf->pending_favored, bitmap_cvg,
            sgf->saved_crashes, sgf->saved_hangs, sgf->max_depth, eps,
            sgf->plot_prev_ed, t_bytes, sgf->total_crashes,
            (u32)sgf->san_binary_length, sgf->mo_coverage, sgf->rf_coverage);                    /* ignore errors */

  }

  for (u32 i = 0; i < sgf->san_binary_length; i++) {

    fprintf(sgf->fsrv.plot_file, ", %llu", sgf->san_fsrvs[i].total_execs);

  }

  fprintf(sgf->fsrv.plot_file, "\n");

  fflush(sgf->fsrv.plot_file);

}

void log_graph_candidate_to_plot_file(sgf_state_t *sgf,
                                     struct queue_entry *parent,
                                     struct SkeletonGraphData *mutated_graph_metadata,
                                     double new_score,
                                     u8 added_to_queue) {

  if (!sgf || !sgf->log_graph_run_details || !sgf->fsrv.plot_file) return;

  double cur_score = sgf->queue_cur ? sgf->queue_cur->perf_score : 0.0;
  double cur_pot = (sgf->queue_cur && sgf->queue_cur->graph_data) ?
                     sgf->queue_cur->graph_data->potential_score : 0.0;
  double cur_mo = (sgf->queue_cur && sgf->queue_cur->graph_data) ?
                    sgf->queue_cur->graph_data->mo_footprint_score : 0.0;
  double cur_rf = (sgf->queue_cur && sgf->queue_cur->graph_data) ?
                    sgf->queue_cur->graph_data->rf_footprint_score : 0.0;
  u32 cur_children = (sgf->queue_cur && sgf->queue_cur->graph_data) ?
                       sgf->queue_cur->graph_data->children_enqueued : 0;

  u32 parent_id = parent ? parent->id : 0;
  double cand_pot = mutated_graph_metadata ? mutated_graph_metadata->potential_score : 0.0;
  double cand_mo = mutated_graph_metadata ? mutated_graph_metadata->mo_footprint_score : 0.0;
  double cand_rf = mutated_graph_metadata ? mutated_graph_metadata->rf_footprint_score : 0.0;
  double cand_score = new_score;

  fprintf(sgf->fsrv.plot_file,
          "%llu, %llu, %u, %u, %u, %u, %0.02f%%, %llu, %llu, %u, %0.02f, %llu, "
          "%u, %llu, %u, %u, %u, %0.04f, %0.04f, %0.04f, %0.04f, %u, %u, %0.04f, %0.04f, %0.04f, %0.04f, %u",
          ((sgf->prev_run_time + get_cur_time() - sgf->start_time) / 1000),
          sgf->queue_cycle ? sgf->queue_cycle - 1 : 0,
          sgf->queue_cur ? sgf->queue_cur->id : sgf->current_entry,
          sgf->queued_items,
          sgf->pending_not_fuzzed,
          sgf->pending_favored,
          0.0,
          sgf->saved_crashes,
          sgf->saved_hangs,
          sgf->max_depth,
          sgf->stats_avg_exec,
          sgf->fsrv.total_execs,
          0,
          sgf->total_crashes,
          (u32)sgf->san_binary_length,
          sgf->mo_coverage,
          sgf->rf_coverage,
          cur_score,
          cur_pot,
          cur_mo,
          cur_rf,
          cur_children,
          parent_id,
          cand_pot,
          cand_mo,
          cand_rf,
          cand_score,
          (u32)added_to_queue);

  for (u32 i = 0; i < sgf->san_binary_length; i++) {

    fprintf(sgf->fsrv.plot_file, ", %llu", sgf->san_fsrvs[i].total_execs);

  }

  fprintf(sgf->fsrv.plot_file, "\n");
  fflush(sgf->fsrv.plot_file);

}

/* Log deterministic stage efficiency */

void plot_profile_data(sgf_state_t *sgf, struct queue_entry *q) {

  if (sgf->skip_deterministic) { return; }

  u64 current_ms = get_cur_time() - sgf->start_time;

  u32    current_edges = count_non_255_bytes(sgf, sgf->virgin_bits);
  double det_finding_rate = (double)sgf->havoc_prof->total_det_edge * 100.0 /
                            (double)current_edges,
         det_time_rate = (double)sgf->havoc_prof->total_det_time * 100.0 /
                         (double)current_ms;

  u32 ndet_bits = 0;
  for (u32 i = 0; i < sgf->fsrv.map_size; i++) {

    if (sgf->skipdet_g->virgin_det_bits[i]) ndet_bits += 1;

  }

  double det_fuzzed_rate = (double)ndet_bits * 100.0 / (double)current_edges;

  fprintf(sgf->fsrv.det_plot_file,
          "[%02lld:%02lld:%02lld] fuzz %d (%d), find %d/%d among %d(%02.2f) "
          "and spend %lld/%lld(%02.2f), cover %02.2f yet, %d/%d undet bits, "
          "continue %d.\n",
          current_ms / 1000 / 3600, (current_ms / 1000 / 60) % 60,
          (current_ms / 1000) % 60, sgf->current_entry, q->fuzz_level,
          sgf->havoc_prof->edge_det_stage, sgf->havoc_prof->edge_havoc_stage,
          current_edges, det_finding_rate,
          sgf->havoc_prof->det_stage_time / 1000,
          sgf->havoc_prof->havoc_stage_time / 1000, det_time_rate,
          det_fuzzed_rate, q->skipdet_e->undet_bits,
          sgf->skipdet_g->undet_bits_threshold, q->skipdet_e->continue_inf);

  fflush(sgf->fsrv.det_plot_file);

}

/* Scroll the terminal so when the stats clear the screen
   we don't delete anything. */

void make_space_for_stats() {

  struct winsize ws;

  if (ioctl(1, TIOCGWINSZ, &ws)) { return; }

  SAYF("\x1b[%dS", ws.ws_row);

}

/* Check terminal dimensions after resize. */

static void check_term_size(sgf_state_t *sgf) {

  struct winsize ws;

  sgf->term_too_small = 0;

  if (ioctl(1, TIOCGWINSZ, &ws)) { return; }

  if (ws.ws_row == 0 || ws.ws_col == 0) { return; }
  if (ws.ws_row < 24 || ws.ws_col < 79) { sgf->term_too_small = 1; }

}

/* A spiffy retro stats screen! This is called every sgf->stats_update_freq
   execve() calls, plus in several other circumstances. */

void show_stats(sgf_state_t *sgf) {

  if (sgf->pizza_is_served) {

    show_stats_pizza(sgf);

  } else {

    show_stats_normal(sgf);

  }

}

void show_stats_normal(sgf_state_t *sgf) {

  double t_byte_ratio, stab_ratio;

  u64 cur_ms;
  u32 t_bytes, t_bits;

  static u8 banner[128];
  u32       banner_len, banner_pad;
  u8        tmp[256];
  u8        time_tmp[64];

  u8 val_buf[8][STRINGIFY_VAL_SIZE_MAX];
#define IB(i) (val_buf[(i)])

  cur_ms = get_cur_time();

  if (sgf->most_time_key && sgf->queue_cycle) {

    if (sgf->most_time * 1000 + sgf->sync_time_us / 1000 <
        cur_ms - sgf->start_time) {

      sgf->most_time_key = 2;
      sgf->stop_soon = 2;

    }

  }

  if (sgf->most_execs_key == 1 && sgf->queue_cycle) {

    if (sgf->most_execs <= sgf->fsrv.total_execs) {

      sgf->most_execs_key = 2;
      sgf->stop_soon = 2;

    }

  }

  /* If not enough time has passed since last UI update, bail out. */

  if (cur_ms - sgf->stats_last_ms < 1000 / UI_TARGET_HZ &&
      !sgf->force_ui_update) {

    return;

  }

  /* Check if we're past the 10 minute mark. */

  if (cur_ms - sgf->start_time > 10 * 60 * 1000) { sgf->run_over10m = 1; }

  /* Calculate smoothed exec speed stats. */

  if (unlikely(!sgf->stats_last_execs)) {

    if (likely(cur_ms != sgf->start_time)) {

      sgf->stats_avg_exec = ((double)sgf->fsrv.total_execs) * 1000 /
                            (sgf->prev_run_time + cur_ms - sgf->start_time);

    }

  } else {

    if (likely(cur_ms != sgf->stats_last_ms)) {

      double cur_avg =
          ((double)(sgf->fsrv.total_execs - sgf->stats_last_execs)) * 1000 /
          (cur_ms - sgf->stats_last_ms);

      /* If there is a dramatic (5x+) jump in speed, reset the indicator
         more quickly. */

      if (cur_avg * 5 < sgf->stats_avg_exec ||
          cur_avg / 5 > sgf->stats_avg_exec) {

        sgf->stats_avg_exec = cur_avg;

      }

      sgf->stats_avg_exec = sgf->stats_avg_exec * (1.0 - 1.0 / AVG_SMOOTHING) +
                            cur_avg * (1.0 / AVG_SMOOTHING);

    }

  }

  sgf->stats_last_ms = cur_ms;
  sgf->stats_last_execs = sgf->fsrv.total_execs;

  /* Tell the callers when to contact us (as measured in execs). */

  sgf->stats_update_freq = sgf->stats_avg_exec / (UI_TARGET_HZ * 10);
  if (!sgf->stats_update_freq) { sgf->stats_update_freq = 1; }

  /* Do some bitmap stats. */

  t_bytes = count_non_255_bytes(sgf, sgf->virgin_bits);
  t_byte_ratio = ((double)t_bytes * 100) / sgf->fsrv.real_map_size;

  if (unlikely(t_bytes > sgf->fsrv.real_map_size)) {

    if (unlikely(!sgf->sgf_env.sgf_ignore_problems)) {

      FATAL(
          "Incorrect fuzzing setup detected. Your target seems to have loaded "
          "incorrectly instrumented shared libraries (%u of %u/%u). If you use "
          "LTO mode "
          "please see instrumentation/README.lto.md. To ignore this problem "
          "and continue fuzzing just set 'SGF_IGNORE_PROBLEMS=1'.\n",
          t_bytes, sgf->fsrv.real_map_size, sgf->fsrv.map_size);

    }

  }

  if (likely(t_bytes) && unlikely(sgf->var_byte_count)) {

    stab_ratio = 100 - (((double)sgf->var_byte_count * 100) / t_bytes);

  } else {

    stab_ratio = 100;

  }

  /* Roughly every minute, update fuzzer stats and save auto tokens. */

  if (unlikely(
          !sgf->non_instrumented_mode &&
          (sgf->force_ui_update || cur_ms - sgf->stats_last_stats_ms >
                                       sgf->stats_file_update_freq_msecs))) {

    sgf->stats_last_stats_ms = cur_ms;
    write_stats_file(sgf, t_bytes, t_byte_ratio, stab_ratio,
                     sgf->stats_avg_exec);
    save_auto(sgf);
    write_bitmap(sgf);

  }

  if (unlikely(sgf->sgf_env.sgf_statsd)) {

    if (unlikely(sgf->force_ui_update || cur_ms - sgf->statsd_last_send_ms >
                                             STATSD_UPDATE_SEC * 1000)) {

      /* reset counter, even if send failed. */
      sgf->statsd_last_send_ms = cur_ms;
      if (statsd_send_metric(sgf)) { WARNF("could not send statsd metric."); }

    }

  }

  /* Every now and then, write plot data. */

  //Temporarily setting this to 1 to update plot file more frequently
  //TODO: remove the line below later
  sgf->force_ui_update = 1;
  if (unlikely(sgf->force_ui_update ||
               cur_ms - sgf->stats_last_plot_ms > PLOT_UPDATE_SEC * 1000)) {

    sgf->stats_last_plot_ms = cur_ms;
    maybe_update_plot_file(sgf, t_bytes, t_byte_ratio, sgf->stats_avg_exec);

  }

  /* Every now and then, write queue data. */

  if (unlikely(sgf->force_ui_update ||
               cur_ms - sgf->stats_last_queue_ms > QUEUE_UPDATE_SEC * 1000)) {

    sgf->stats_last_queue_ms = cur_ms;
#ifdef INTROSPECTION
    write_queue_stats(sgf);
#endif

  }

  /* SGF_EXIT_ON_TIME. */

  /* If no coverage was found yet, check whether run time is greater than
   * exit_on_time. */

  if (unlikely(!sgf->non_instrumented_mode && sgf->sgf_env.sgf_exit_on_time &&
               ((sgf->last_find_time &&
                 (cur_ms - sgf->last_find_time) > sgf->exit_on_time) ||
                (!sgf->last_find_time &&
                 (cur_ms - sgf->start_time) > sgf->exit_on_time)))) {

    sgf->stop_soon = 2;

  }

  if (unlikely(sgf->total_crashes && sgf->sgf_env.sgf_bench_until_crash)) {

    sgf->stop_soon = 2;

  }

  /* If we're not on TTY, bail out. */

  if (sgf->not_on_tty) { return; }

  /* If we haven't started doing things, bail out. */

  if (unlikely(!sgf->queue_cur)) { return; }

  /* Now, for the visuals... */

  if (sgf->clear_screen) {

    SAYF(TERM_CLEAR CURSOR_HIDE);
    sgf->clear_screen = 0;

    check_term_size(sgf);

  }

  SAYF(TERM_HOME);

  if (unlikely(sgf->term_too_small)) {

    SAYF(cBRI
         "Your terminal is too small to display the UI.\n"
         "Please resize terminal window to at least 79x24.\n" cRST);

    return;

  }

  /* Compute some mildly useful bitmap stats. */

  t_bits = (sgf->fsrv.map_size << 3) - count_bits(sgf, sgf->virgin_bits);

  /* Let's start by drawing a centered banner. */
  if (unlikely(!banner[0])) {

    char *si = "";
    char *fuzzer_name;

    if (sgf->sync_id) { si = sgf->sync_id; }
    memset(banner, 0, sizeof(banner));

    banner_len = strlen(VERSION) + strlen(si) + strlen(sgf->power_name) + 4 + 6;

    if (sgf->crash_mode) {

      fuzzer_name = "Skeleton Graph Fuzzer";

    } else {

      fuzzer_name = "Skeleton Graph Fuzzer";
      if (banner_len + strlen(fuzzer_name) + strlen(sgf->use_banner) > 75) {

        fuzzer_name = "SGF";

      }

    }

    banner_len += strlen(fuzzer_name);

    if (strlen(sgf->use_banner) + banner_len > 75) {

      sgf->use_banner += (strlen(sgf->use_banner) + banner_len) - 76;
      memset(sgf->use_banner, '.', 3);

    }

    banner_len += strlen(sgf->use_banner);
    banner_pad = (79 - banner_len) / 2;
    memset(banner, ' ', banner_pad);

#ifdef __linux__
    if (sgf->fsrv.nyx_mode) {

      snprintf(banner + banner_pad, sizeof(banner) - banner_pad,
               "%s%s " cLCY VERSION cLBL " {%s} " cLGN "(%s) " cPIN
               "[%s] - Nyx",
               sgf->crash_mode ? cPIN : cYEL, fuzzer_name, si, sgf->use_banner,
               sgf->power_name);

    } else {

#endif
      snprintf(banner + banner_pad, sizeof(banner) - banner_pad,
               "%s%s " cLCY VERSION cLBL " {%s} " cLGN "(%s) " cPIN "[%s]",
               sgf->crash_mode ? cPIN : cYEL, fuzzer_name, si, sgf->use_banner,
               sgf->power_name);

#ifdef __linux__

    }

#endif

    if (banner_pad)
      for (u32 i = 0; i < banner_pad; ++i)
        strcat(banner, " ");

  }

  SAYF("\n%s\n", banner);

  /* "Handy" shortcuts for drawing boxes... */

#define bSTG bSTART cGRA
#define bH2 bH bH
#define bH5 bH2 bH2 bH
#define bH10 bH5 bH5
#define bH20 bH10 bH10
#define bH30 bH20 bH10
#define SP5 "     "
#define SP10 SP5 SP5
#define SP20 SP10 SP10

  /* Since `total_crashes` does not get reloaded from disk on restart,
    it indicates if we found crashes this round already -> paint red.
    If it's 0, but `saved_crashes` is set from a past run, paint in yellow. */
  char *crash_color = sgf->total_crashes   ? cLRD
                      : sgf->saved_crashes ? cYEL
                                           : cRST;
  char *race_color = sgf->total_races   ? cLRD
                     : sgf->saved_races ? cYEL
                                        : cRST;

  /* Lord, forgive me this. */

  SAYF(SET_G1 bSTG bLT bH                         bSTOP cCYA
       " process timing " bSTG bH30 bH5 bH bHB bH bSTOP cCYA
       " overall results " bSTG bH2               bH2 bRT "\n");

  if (sgf->non_instrumented_mode) {

    strcpy(tmp, cRST);

  } else {

    u64 min_wo_finds = (cur_ms - sgf->last_find_time) / 1000 / 60;

    /* First queue cycle: don't stop now! */
    if (sgf->queue_cycle == 1 || min_wo_finds < 15) {

      strcpy(tmp, cMGN);

    } else

      /* Subsequent cycles, but we're still making finds. */
      if (sgf->cycles_wo_finds < 2 || min_wo_finds <= 30) {

        strcpy(tmp, cYEL);

      } else

        /* No finds for a long time and no test cases to try. */
        if (sgf->cycles_wo_finds > 1 && !sgf->pending_not_fuzzed &&
            min_wo_finds > 120) {

          strcpy(tmp, cLGN);

          /* Default: cautiously OK to stop? */

        } else {

          strcpy(tmp, cLBL);

        }

  }

  u_stringify_time_diff(time_tmp, sgf->prev_run_time + cur_ms, sgf->start_time);
  SAYF(bV bSTOP "        run time : " cRST "%-33s " bSTG bV bSTOP
                "  cycles done : %s%-5s " bSTG bV "\n",
       time_tmp, tmp, u_stringify_int(IB(0), sgf->queue_cycle - 1));

  /* We want to warn people about not seeing new paths after a full cycle,
     except when resuming fuzzing or running in non-instrumented mode. */

  if (!sgf->non_instrumented_mode &&
      (sgf->last_find_time || sgf->resuming_fuzz || sgf->queue_cycle == 1 ||
       sgf->in_bitmap || sgf->crash_mode)) {

    u_stringify_time_diff(time_tmp, cur_ms, sgf->last_find_time);
    SAYF(bV bSTOP "   last new find : " cRST "%-33s ", time_tmp);

  } else {

    if (sgf->non_instrumented_mode) {

      SAYF(bV bSTOP "   last new find : " cPIN "n/a" cRST
                    " (non-instrumented mode)       ");

    } else {

      SAYF(bV bSTOP "   last new find : " cRST "none yet " cLRD
                    "(odd, check syntax!)     ");

    }

  }

  SAYF(bSTG bV bSTOP " corpus count : " cRST "%-5s " bSTG bV "\n",
       u_stringify_int(IB(0), sgf->queued_items));

  /* Highlight crashes in red if found, denote going over the KEEP_UNIQUE_CRASH
     limit with a '+' appended to the count. */

  sprintf(tmp, "%s%s", u_stringify_int(IB(0), sgf->saved_crashes),
          (sgf->saved_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  u_stringify_time_diff(time_tmp, cur_ms, sgf->last_crash_time);
  SAYF(bV bSTOP "last saved crash : " cRST "%-33s " bSTG bV bSTOP
                "saved crashes : %s%-6s" bSTG bV "\n",
       time_tmp, crash_color, tmp);

  sprintf(tmp, "%s%s", u_stringify_int(IB(0), sgf->saved_hangs),
          (sgf->saved_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  u_stringify_time_diff(time_tmp, cur_ms, sgf->last_hang_time);
  SAYF(bV bSTOP " last saved hang : " cRST "%-33s " bSTG bV bSTOP
                "  saved hangs : " cRST "%-6s" bSTG bV "\n",
       time_tmp, tmp);

      if (sgf->check_data_race) {

        sprintf(tmp, "%s%s", u_stringify_int(IB(0), sgf->saved_races),
          (sgf->saved_races >= KEEP_UNIQUE_RACE) ? "+" : "");

        u_stringify_time_diff(time_tmp, cur_ms, sgf->last_race_time);
        SAYF(bV bSTOP " last saved race : " cRST "%-33s " bSTG bV bSTOP
          "  saved races : %s%-6s" bSTG bV "\n",
       time_tmp, race_color, tmp);

      }

  SAYF(bVR bH                                              bSTOP cCYA
       " cycle progress " bSTG bH10 bH5 bH2 bH2 bH2 bHB bH bSTOP cCYA
       " map coverage" bSTG bHT bH20                       bH2 bVL "\n");

  /* This gets funny because we want to print several variable-length variables
     together, but then cram them into a fixed-width field - so we need to
     put them in a temporary buffer first. */

  sprintf(tmp, "%s%s%u (%0.01f%%)", u_stringify_int(IB(0), sgf->current_entry),
          sgf->queue_cur->favored ? "." : "*", sgf->queue_cur->fuzz_level,
          ((double)sgf->current_entry * 100) / sgf->queued_items);

  SAYF(bV bSTOP "  now processing : " cRST "%-18s " bSTG bV bSTOP, tmp);

  sprintf(tmp, "%0.02f%% / %0.02f%%",
          ((double)sgf->queue_cur->bitmap_size) * 100 / sgf->fsrv.real_map_size,
          t_byte_ratio);

  SAYF("    map density : %s%-19s" bSTG bV "\n",
       t_byte_ratio > 70
           ? cLRD
           : ((t_bytes < 200 && !sgf->non_instrumented_mode) ? cPIN : cRST),
       tmp);

  sprintf(tmp, "%s (%0.02f%%)", u_stringify_int(IB(0), sgf->cur_skipped_items),
          ((double)sgf->cur_skipped_items * 100) / sgf->queued_items);

  SAYF(bV bSTOP "  runs timed out : " cRST "%-18s " bSTG bV, tmp);

  sprintf(tmp, "%0.02f bits/tuple", t_bytes ? (((double)t_bits) / t_bytes) : 0);

  SAYF(bSTOP " count coverage : " cRST "%-19s" bSTG bV "\n", tmp);

  SAYF(bVR bH                                             bSTOP cCYA
       " stage progress " bSTG bH10 bH5 bH2 bH2 bH2 bX bH bSTOP cCYA
       " findings in depth " bSTG bH10 bH5                bH2 bVL "\n");

  sprintf(tmp, "%s (%0.02f%%)", u_stringify_int(IB(0), sgf->queued_favored),
          ((double)sgf->queued_favored) * 100 / sgf->queued_items);

  /* Yeah... it's still going on... halp? */

  SAYF(bV bSTOP "  now trying : " cRST "%-22s " bSTG bV bSTOP
                " favored items : " cRST "%-20s" bSTG bV "\n",
       sgf->stage_name, tmp);

  if (!sgf->stage_max) {

    sprintf(tmp, "%s/-", u_stringify_int(IB(0), sgf->stage_cur));

  } else {

    sprintf(tmp, "%s/%s (%0.02f%%)", u_stringify_int(IB(0), sgf->stage_cur),
            u_stringify_int(IB(1), sgf->stage_max),
            ((double)sgf->stage_cur) * 100 / sgf->stage_max);

  }

  SAYF(bV bSTOP " stage execs : " cRST "%-23s" bSTG bV bSTOP, tmp);

  sprintf(tmp, "%s (%0.02f%%)", u_stringify_int(IB(0), sgf->queued_with_cov),
          ((double)sgf->queued_with_cov) * 100 / sgf->queued_items);

  SAYF("  new edges on : " cRST "%-20s" bSTG bV "\n", tmp);

  sprintf(tmp, "%s (%s%s saved)", u_stringify_int(IB(0), sgf->total_crashes),
          u_stringify_int(IB(1), sgf->saved_crashes),
          (sgf->saved_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  if (sgf->crash_mode) {

    SAYF(bV bSTOP " total execs : " cRST "%-22s " bSTG bV bSTOP
                  "   new crashes : %s%-20s" bSTG bV "\n",
         u_stringify_int(IB(0), sgf->fsrv.total_execs), crash_color, tmp);

  } else {

    SAYF(bV bSTOP " total execs : " cRST "%-22s " bSTG bV bSTOP
                  " total crashes : %s%-20s" bSTG bV "\n",
         u_stringify_int(IB(0), sgf->fsrv.total_execs), crash_color, tmp);

  }

  /* Show a warning about slow execution. */

  if (sgf->stats_avg_exec < 100) {

    sprintf(tmp, "%s/sec (%s)", u_stringify_float(IB(0), sgf->stats_avg_exec),
            sgf->stats_avg_exec < 20 ? "zzzz..." : "slow!");

    SAYF(bV bSTOP "  exec speed : " cLRD "%-22s ", tmp);

  } else {

    sprintf(tmp, "%s/sec", u_stringify_float(IB(0), sgf->stats_avg_exec));
    SAYF(bV bSTOP "  exec speed : " cRST "%-22s ", tmp);

  }

  sprintf(tmp, "%s (%s%s saved)", u_stringify_int(IB(0), sgf->total_tmouts),
          u_stringify_int(IB(1), sgf->saved_tmouts),
          (sgf->saved_tmouts >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF(bSTG bV bSTOP "  total tmouts : " cRST "%-20s" bSTG bV "\n", tmp);

  /* Aaaalmost there... hold on! */

  SAYF(bVR bH cCYA bSTOP " skeleton graph mutations " bSTG bH10 bH bHT bH10 bH2
           bH bHB bH bSTOP cCYA " item geometry " bSTG bH5 bH2 bVL "\n");

  if (unlikely(sgf->custom_only)) {

    strcpy(tmp, "disabled (custom-mutator-only mode)");

  } else if (likely(sgf->skip_deterministic)) {

    strcpy(tmp, "disabled (-z switch used)");

  } else {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), sgf->stage_finds[STAGE_FLIP1]),
            u_stringify_int(IB(1), sgf->stage_cycles[STAGE_FLIP1]),
            u_stringify_int(IB(2), sgf->stage_finds[STAGE_FLIP2]),
            u_stringify_int(IB(3), sgf->stage_cycles[STAGE_FLIP2]),
            u_stringify_int(IB(4), sgf->stage_finds[STAGE_FLIP4]),
            u_stringify_int(IB(5), sgf->stage_cycles[STAGE_FLIP4]));

  }

  sprintf(tmp, "%s",
          u_stringify_int(IB(0), sgf->mut_add_read_cnt + sgf->mut_add_write_cnt +
                                  sgf->mut_add_rmw_cnt + sgf->mut_add_cas_success_cnt +
                                  sgf->mut_add_cas_fail_cnt + sgf->mut_add_fence_cnt));

  SAYF(bV bSTOP "  add-a-node : " cRST "%-36s " bSTG bV bSTOP
                "    levels : " cRST "%-10s" bSTG bV "\n",
       tmp, u_stringify_int(IB(0), sgf->max_depth));

  if (unlikely(!sgf->skip_deterministic)) {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), sgf->stage_finds[STAGE_FLIP8]),
            u_stringify_int(IB(1), sgf->stage_cycles[STAGE_FLIP8]),
            u_stringify_int(IB(2), sgf->stage_finds[STAGE_FLIP16]),
            u_stringify_int(IB(3), sgf->stage_cycles[STAGE_FLIP16]),
            u_stringify_int(IB(4), sgf->stage_finds[STAGE_FLIP32]),
            u_stringify_int(IB(5), sgf->stage_cycles[STAGE_FLIP32]));

  }

  sprintf(tmp, "%s", u_stringify_int(IB(0), sgf->mut_rf_cnt));

  SAYF(bV bSTOP " rf mutation : " cRST "%-36s " bSTG bV bSTOP
                "   pending : " cRST "%-10s" bSTG bV "\n",
       tmp, u_stringify_int(IB(0), sgf->pending_not_fuzzed));

  if (unlikely(!sgf->skip_deterministic)) {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), sgf->stage_finds[STAGE_ARITH8]),
            u_stringify_int(IB(1), sgf->stage_cycles[STAGE_ARITH8]),
            u_stringify_int(IB(2), sgf->stage_finds[STAGE_ARITH16]),
            u_stringify_int(IB(3), sgf->stage_cycles[STAGE_ARITH16]),
            u_stringify_int(IB(4), sgf->stage_finds[STAGE_ARITH32]),
            u_stringify_int(IB(5), sgf->stage_cycles[STAGE_ARITH32]));

  }

  SAYF(bV bSTOP " arithmetics : " cRST "%-36s " bSTG bV bSTOP
                "  pend fav : " cRST "%-10s" bSTG bV "\n",
       tmp, u_stringify_int(IB(0), sgf->pending_favored));

  if (unlikely(!sgf->skip_deterministic)) {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), sgf->stage_finds[STAGE_INTEREST8]),
            u_stringify_int(IB(1), sgf->stage_cycles[STAGE_INTEREST8]),
            u_stringify_int(IB(2), sgf->stage_finds[STAGE_INTEREST16]),
            u_stringify_int(IB(3), sgf->stage_cycles[STAGE_INTEREST16]),
            u_stringify_int(IB(4), sgf->stage_finds[STAGE_INTEREST32]),
            u_stringify_int(IB(5), sgf->stage_cycles[STAGE_INTEREST32]));

  }

  SAYF(bV bSTOP "  known ints : " cRST "%-36s " bSTG bV bSTOP
                " own finds : " cRST "%-10s" bSTG bV "\n",
       tmp, u_stringify_int(IB(0), sgf->queued_discovered));

  if (unlikely(!sgf->skip_deterministic)) {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), sgf->stage_finds[STAGE_EXTRAS_UO]),
            u_stringify_int(IB(1), sgf->stage_cycles[STAGE_EXTRAS_UO]),
            u_stringify_int(IB(2), sgf->stage_finds[STAGE_EXTRAS_UI]),
            u_stringify_int(IB(3), sgf->stage_cycles[STAGE_EXTRAS_UI]),
            u_stringify_int(IB(4), sgf->stage_finds[STAGE_EXTRAS_AO]),
            u_stringify_int(IB(5), sgf->stage_cycles[STAGE_EXTRAS_AO]),
            u_stringify_int(IB(6), sgf->stage_finds[STAGE_EXTRAS_AI]),
            u_stringify_int(IB(7), sgf->stage_cycles[STAGE_EXTRAS_AI]));

  } else if (unlikely(!sgf->extras_cnt || sgf->custom_only)) {

    strcpy(tmp, "n/a");

  } else {

    strcpy(tmp, "havoc mode");

  }

  SAYF(bV bSTOP "  dictionary : " cRST "%-36s " bSTG bV bSTOP
                "  imported : " cRST "%-10s" bSTG bV "\n",
       tmp,
       sgf->sync_id ? u_stringify_int(IB(0), sgf->queued_imported)
                    : (u8 *)"n/a");

  sprintf(tmp, "%s/%s, %s/%s",
          u_stringify_int(IB(0), sgf->stage_finds[STAGE_HAVOC]),
          u_stringify_int(IB(2), sgf->stage_cycles[STAGE_HAVOC]),
          u_stringify_int(IB(3), sgf->stage_finds[STAGE_SPLICE]),
          u_stringify_int(IB(4), sgf->stage_cycles[STAGE_SPLICE]));

  SAYF(bV bSTOP "havoc/splice : " cRST "%-36s " bSTG bV bSTOP, tmp);

  if (t_bytes) {

    sprintf(tmp, "%0.02f%%", stab_ratio);

  } else {

    strcpy(tmp, "n/a");

  }

  SAYF(" stability : %s%-10s" bSTG bV "\n",
       (stab_ratio < 85 && sgf->var_byte_count > 40)
           ? cLRD
           : ((sgf->queued_variable &&
               (!sgf->persistent_mode || sgf->var_byte_count > 20))
                  ? cMGN
                  : cRST),
       tmp);

  if (unlikely(sgf->sgf_env.sgf_python_module)) {

    sprintf(tmp, "%s/%s,",
            u_stringify_int(IB(0), sgf->stage_finds[STAGE_PYTHON]),
            u_stringify_int(IB(1), sgf->stage_cycles[STAGE_PYTHON]));

  } else {

    strcpy(tmp, "unused,");

  }

  if (unlikely(sgf->sgf_env.sgf_custom_mutator_library)) {

    strcat(tmp, " ");
    strcat(tmp, u_stringify_int(IB(2), sgf->stage_finds[STAGE_CUSTOM_MUTATOR]));
    strcat(tmp, "/");
    strcat(tmp,
           u_stringify_int(IB(3), sgf->stage_cycles[STAGE_CUSTOM_MUTATOR]));
    strcat(tmp, ",");

  } else {

    strcat(tmp, " unused,");

  }

  if (unlikely(sgf->shm.cmplog_mode)) {

    strcat(tmp, " ");
    strcat(tmp, u_stringify_int(IB(4), sgf->stage_finds[STAGE_COLORIZATION]));
    strcat(tmp, "/");
    strcat(tmp, u_stringify_int(IB(5), sgf->stage_cycles[STAGE_COLORIZATION]));
    strcat(tmp, ", ");
    strcat(tmp, u_stringify_int(IB(6), sgf->stage_finds[STAGE_ITS]));
    strcat(tmp, "/");
    strcat(tmp, u_stringify_int(IB(7), sgf->stage_cycles[STAGE_ITS]));

  } else {

    strcat(tmp, " unused, unused");

  }

  SAYF(bV bSTOP "py/custom/rq : " cRST "%-36s " bSTG bVR bH20 bH2 bH bRB "\n",
       tmp);

  if (likely(sgf->disable_trim)) {

    sprintf(tmp, "disabled, ");

  } else if (unlikely(!sgf->bytes_trim_out ||

                      sgf->bytes_trim_in <= sgf->bytes_trim_out)) {

    sprintf(tmp, "n/a, ");

  } else {

    sprintf(tmp, "%0.02f%%/%s, ",
            ((double)(sgf->bytes_trim_in - sgf->bytes_trim_out)) * 100 /
                sgf->bytes_trim_in,
            u_stringify_int(IB(0), sgf->trim_execs));

  }

  if (likely(sgf->skip_deterministic)) {

    strcat(tmp, "disabled");

  } else if (unlikely(!sgf->blocks_eff_total ||

                      sgf->blocks_eff_select >= sgf->blocks_eff_total)) {

    strcat(tmp, "n/a");

  } else {

    u8 tmp2[128];

    sprintf(tmp2, "%0.02f%%",
            ((double)(sgf->blocks_eff_total - sgf->blocks_eff_select)) * 100 /
                sgf->blocks_eff_total);

    strcat(tmp, tmp2);

  }

  // if (sgf->custom_mutators_count) {

  //
  //  sprintf(tmp, "%s/%s",
  //          u_stringify_int(IB(0), sgf->stage_finds[STAGE_CUSTOM_MUTATOR]),
  //          u_stringify_int(IB(1), sgf->stage_cycles[STAGE_CUSTOM_MUTATOR]));
  //  SAYF(bV bSTOP " custom mut. : " cRST "%-36s " bSTG bV RESET_G1, tmp);
  //
  //} else {

  SAYF(bV bSTOP "    trim/eff : " cRST "%-36s " bSTG bV RESET_G1, tmp);

  //}

  /* Provide some CPU utilization stats. */

  if (sgf->cpu_core_count) {

    char *spacing = SP10, snap[24] = " " cLGN "snapshot" cRST " ";

    double cur_runnable = get_runnable_processes();
    u32    cur_utilization = cur_runnable * 100 / sgf->cpu_core_count;

    u8 *cpu_color = cCYA;

    /* If we could still run one or more processes, use green. */

    if (sgf->cpu_core_count > 1 && cur_runnable + 1 <= sgf->cpu_core_count) {

      cpu_color = cLGN;

    }

    /* If we're clearly oversubscribed, use red. */

    if (!sgf->no_cpu_meter_red && cur_utilization >= 150) { cpu_color = cLRD; }

    if (sgf->fsrv.snapshot) { spacing = snap; }

#ifdef HAVE_AFFINITY

    if (sgf->cpu_aff >= 0) {

      SAYF("%s" cGRA "[cpu%03u:%s%3u%%" cGRA "]\r" cRST, spacing,
           MIN(sgf->cpu_aff, 999), cpu_color, MIN(cur_utilization, (u32)999));

    } else {

      SAYF("%s" cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST, spacing, cpu_color,
           MIN(cur_utilization, (u32)999));

    }

#else

    SAYF("%s" cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST, spacing, cpu_color,
         MIN(cur_utilization, (u32)999));

#endif                                                    /* ^HAVE_AFFINITY */

  } else {

    SAYF("\r");

  }

  /* Last line */

  SAYF(SET_G1 "\n" bSTG bLB bH               cCYA bSTOP " strategy:" cPIN
              " %s " bSTG bH10               cCYA bSTOP " state:" cPIN
              " %s " bSTG bH2 bRB bSTOP cRST RESET_G1,
       sgf->fuzz_mode == 0 ? "explore" : "exploit", get_fuzzing_state(sgf));

  /* Additional lines for tracking the mo, rf and potential coverage */
  // TODO: include potential later
  SAYF(SET_G1 "\n" bSTG bLB bH            cCYA bSTOP " mo coverage:" cPIN
              " %s " bSTG bH10               cCYA bSTOP " rf coverage:" cPIN
              " %s " bSTG bH10               cCYA bSTOP " CURRENT PHASE:" cPIN
              " %-36s " bSTG bH2 bRB bSTOP cRST RESET_G1,
       u_stringify_int(IB(0), sgf->mo_coverage),
       u_stringify_int(IB(1), sgf->rf_coverage),
       sgf->current_phase == MO_FOOTPRINT_DRIVEN_PHASE
           ? "MO_FOOTPRINT_DRIVEN_PHASE"
           : (sgf->current_phase == RF_FOOTPRINT_DRIVEN_PHASE
                  ? "RF_FOOTPRINT_DRIVEN_PHASE"
                  : (sgf->current_phase == POTENTIAL_DRIVEN_PHASE
                         ? "POTENTIAL_DRIVEN_PHASE"
                         : (sgf->current_phase == PRUNING_PHASE ? "PRUNING_PHASE" : "UNKNOWN"))));
    if (sgf->enable_feedback){
      SAYF("\n**USING FEEDBACK FROM SCHEDULER FOR NEXT EVENT**");
    }
#undef IB

  /* Hallelujah! */

  fflush(0);

}

void show_stats_pizza(sgf_state_t *sgf) {

  double t_byte_ratio, stab_ratio;

  u64 cur_ms;
  u32 t_bytes, t_bits;

  static u8 banner[128];
  u32       banner_len, banner_pad;
  u8        tmp[256];
  u8        time_tmp[64];

  u8 val_buf[8][STRINGIFY_VAL_SIZE_MAX];
#define IB(i) (val_buf[(i)])

  cur_ms = get_cur_time();

  if (sgf->most_time_key && sgf->queue_cycle) {

    if (sgf->most_time * 1000 + sgf->sync_time_us / 1000 <
        cur_ms - sgf->start_time) {

      sgf->most_time_key = 2;
      sgf->stop_soon = 2;

    }

  }

  if (sgf->most_execs_key == 1 && sgf->queue_cycle) {

    if (sgf->most_execs <= sgf->fsrv.total_execs) {

      sgf->most_execs_key = 2;
      sgf->stop_soon = 2;

    }

  }

  /* If not enough time has passed since last UI update, bail out. */

  if (cur_ms - sgf->stats_last_ms < 1000 / UI_TARGET_HZ &&
      !sgf->force_ui_update) {

    return;

  }

  /* Check if we're past the 10 minute mark. */

  if (cur_ms - sgf->start_time > 10 * 60 * 1000) { sgf->run_over10m = 1; }

  /* Calculate smoothed exec speed stats. */

  if (unlikely(!sgf->stats_last_execs)) {

    if (likely(cur_ms != sgf->start_time)) {

      sgf->stats_avg_exec = ((double)sgf->fsrv.total_execs) * 1000 /
                            (sgf->prev_run_time + cur_ms - sgf->start_time);

    }

  } else {

    if (likely(cur_ms != sgf->stats_last_ms)) {

      double cur_avg =
          ((double)(sgf->fsrv.total_execs - sgf->stats_last_execs)) * 1000 /
          (cur_ms - sgf->stats_last_ms);

      /* If there is a dramatic (5x+) jump in speed, reset the indicator
         more quickly. */

      if (cur_avg * 5 < sgf->stats_avg_exec ||
          cur_avg / 5 > sgf->stats_avg_exec) {

        sgf->stats_avg_exec = cur_avg;

      }

      sgf->stats_avg_exec = sgf->stats_avg_exec * (1.0 - 1.0 / AVG_SMOOTHING) +
                            cur_avg * (1.0 / AVG_SMOOTHING);

    }

  }

  sgf->stats_last_ms = cur_ms;
  sgf->stats_last_execs = sgf->fsrv.total_execs;

  /* Tell the callers when to contact us (as measured in execs). */

  sgf->stats_update_freq = sgf->stats_avg_exec / (UI_TARGET_HZ * 10);
  if (!sgf->stats_update_freq) { sgf->stats_update_freq = 1; }

  /* Do some bitmap stats. */

  t_bytes = count_non_255_bytes(sgf, sgf->virgin_bits);
  t_byte_ratio = ((double)t_bytes * 100) / sgf->fsrv.real_map_size;

  if (unlikely(t_bytes > sgf->fsrv.real_map_size)) {

    if (unlikely(!sgf->sgf_env.sgf_ignore_problems)) {

      FATAL(
          "This is what happens when you speak italian to the rabbit "
          "Don't speak italian to the rabbit");

    }

  }

  if (likely(t_bytes) && unlikely(sgf->var_byte_count)) {

    stab_ratio = 100 - (((double)sgf->var_byte_count * 100) / t_bytes);

  } else {

    stab_ratio = 100;

  }

  /* Roughly every minute, update fuzzer stats and save auto tokens. */

  if (unlikely(!sgf->non_instrumented_mode &&
               (sgf->force_ui_update ||
                cur_ms - sgf->stats_last_stats_ms > STATS_UPDATE_SEC * 1000))) {

    sgf->stats_last_stats_ms = cur_ms;
    write_stats_file(sgf, t_bytes, t_byte_ratio, stab_ratio,
                     sgf->stats_avg_exec);
    save_auto(sgf);
    write_bitmap(sgf);

  }

  if (unlikely(sgf->sgf_env.sgf_statsd)) {

    if (unlikely(sgf->force_ui_update || cur_ms - sgf->statsd_last_send_ms >
                                             STATSD_UPDATE_SEC * 1000)) {

      /* reset counter, even if send failed. */
      sgf->statsd_last_send_ms = cur_ms;
      if (statsd_send_metric(sgf)) {

        WARNF("Could not order tomato sauce from statsd.");

      }

    }

  }

  /* Every now and then, write plot data. */
  if (unlikely(sgf->force_ui_update ||
               cur_ms - sgf->stats_last_plot_ms > PLOT_UPDATE_SEC * 1000)) {

    sgf->stats_last_plot_ms = cur_ms;
    maybe_update_plot_file(sgf, t_bytes, t_byte_ratio, sgf->stats_avg_exec);

  }

  /* Every now and then, write queue data. */

  if (unlikely(sgf->force_ui_update ||
               cur_ms - sgf->stats_last_queue_ms > QUEUE_UPDATE_SEC * 1000)) {

    sgf->stats_last_queue_ms = cur_ms;
#ifdef INTROSPECTION
    write_queue_stats(sgf);
#endif

  }

  /* SGF_EXIT_ON_TIME. */

  /* If no coverage was found yet, check whether run time is greater than
   * exit_on_time. */

  if (unlikely(!sgf->non_instrumented_mode && sgf->sgf_env.sgf_exit_on_time &&
               ((sgf->last_find_time &&
                 (cur_ms - sgf->last_find_time) > sgf->exit_on_time) ||
                (!sgf->last_find_time &&
                 (cur_ms - sgf->start_time) > sgf->exit_on_time)))) {

    sgf->stop_soon = 2;

  }

  if (unlikely(sgf->total_crashes && sgf->sgf_env.sgf_bench_until_crash)) {

    sgf->stop_soon = 2;

  }

  /* If we're not on TTY, bail out. */

  if (sgf->not_on_tty) { return; }

  /* If we haven't started doing things, bail out. */

  if (unlikely(!sgf->queue_cur)) { return; }

  /* Now, for the visuals... */

  if (sgf->clear_screen) {

    SAYF(TERM_CLEAR CURSOR_HIDE);
    sgf->clear_screen = 0;

    check_term_size(sgf);

  }

  SAYF(TERM_HOME);

  if (unlikely(sgf->term_too_small)) {

    SAYF(cBRI
         "Our pizzeria can't host this many guests.\n"
         "Please call Pizzeria Caravaggio. They have tables of at least "
         "79x24.\n" cRST);

    return;

  }

  /* Compute some mildly useful bitmap stats. */

  t_bits = (sgf->fsrv.map_size << 3) - count_bits(sgf, sgf->virgin_bits);

  /* Let's start by drawing a centered banner. */
  if (unlikely(!banner[0])) {

    char *si = "";
    if (sgf->sync_id) { si = sgf->sync_id; }
    memset(banner, 0, sizeof(banner));
    banner_len = (sgf->crash_mode ? 20 : 18) + strlen(VERSION) + strlen(si) +
                 strlen(sgf->power_name) + 4 + 6;

    if (strlen(sgf->use_banner) + banner_len > 75) {

      sgf->use_banner += (strlen(sgf->use_banner) + banner_len) - 76;
      memset(sgf->use_banner, '.', 3);

    }

    banner_len += strlen(sgf->use_banner);
    banner_pad = (79 - banner_len) / 2;
    memset(banner, ' ', banner_pad);

#ifdef __linux__
    if (sgf->fsrv.nyx_mode) {

      snprintf(banner + banner_pad, sizeof(banner) - banner_pad,
               "%s " cLCY VERSION cLBL " {%s} " cLGN "(%s) " cPIN "[%s] - Nyx",
               sgf->crash_mode ? cPIN
                   "Mozzarbella Pizzeria table booking system"
                               : cYEL "Mozzarbella Pizzeria management system",
               si, sgf->use_banner, sgf->power_name);

    } else {

#endif
      snprintf(banner + banner_pad, sizeof(banner) - banner_pad,
               "%s " cLCY VERSION cLBL " {%s} " cLGN "(%s) " cPIN "[%s]",
               sgf->crash_mode ? cPIN
                   "Mozzarbella Pizzeria table booking system"
                               : cYEL "Mozzarbella Pizzeria management system",
               si, sgf->use_banner, sgf->power_name);

#ifdef __linux__

    }

#endif

  }

  SAYF("\n%s\n", banner);

  /* "Handy" shortcuts for drawing boxes... */

#define bSTG bSTART cGRA
#define bH2 bH bH
#define bH5 bH2 bH2 bH
#define bH10 bH5 bH5
#define bH20 bH10 bH10
#define bH30 bH20 bH10
#define SP5 "     "
#define SP10 SP5 SP5
#define SP20 SP10 SP10

  /* Since `total_crashes` does not get reloaded from disk on restart,
    it indicates if we found crashes this round already -> paint red.
    If it's 0, but `saved_crashes` is set from a past run, paint in yellow. */
  char *crash_color = sgf->total_crashes   ? cLRD
                      : sgf->saved_crashes ? cYEL
                                           : cRST;

  /* Lord, forgive me this. */

  SAYF(SET_G1 bSTG bLT bH bSTOP cCYA
       " Mozzarbella has been proudly serving pizzas since " bSTG bH20 bH bH bH
           bHB bH bSTOP cCYA " In this time, we served " bSTG bH30 bRT "\n");

  if (sgf->non_instrumented_mode) {

    strcpy(tmp, cRST);

  } else {

    u64 min_wo_finds = (cur_ms - sgf->last_find_time) / 1000 / 60;

    /* First queue cycle: don't stop now! */
    if (sgf->queue_cycle == 1 || min_wo_finds < 15) {

      strcpy(tmp, cMGN);

    } else

      /* Subsequent cycles, but we're still making finds. */
      if (sgf->cycles_wo_finds < 2 || min_wo_finds <= 30) {

        strcpy(tmp, cYEL);

      } else

        /* No finds for a long time and no test cases to try. */
        if (sgf->cycles_wo_finds > 1 && !sgf->pending_not_fuzzed &&
            min_wo_finds > 120) {

          strcpy(tmp, cLGN);

          /* Default: cautiously OK to stop? */

        } else {

          strcpy(tmp, cLBL);

        }

  }

  u_stringify_time_diff(time_tmp, sgf->prev_run_time + cur_ms, sgf->start_time);
  SAYF(bV bSTOP
       "                         open time : " cRST "%-37s " bSTG bV bSTOP
       "                     seasons done : %s%-5s               " bSTG bV "\n",
       time_tmp, tmp, u_stringify_int(IB(0), sgf->queue_cycle - 1));

  /* We want to warn people about not seeing new paths after a full cycle,
     except when resuming fuzzing or running in non-instrumented mode. */

  if (!sgf->non_instrumented_mode &&
      (sgf->last_find_time || sgf->resuming_fuzz || sgf->queue_cycle == 1 ||
       sgf->in_bitmap || sgf->crash_mode)) {

    u_stringify_time_diff(time_tmp, cur_ms, sgf->last_find_time);
    SAYF(bV bSTOP "                  last pizza baked : " cRST "%-37s ",
         time_tmp);

  } else {

    if (sgf->non_instrumented_mode) {

      SAYF(bV bSTOP "                  last pizza baked : " cPIN "n/a" cRST
                    " (non-instrumented mode)           ");

    } else {

      SAYF(bV bSTOP "                  last pizza baked : " cRST
                    "none yet " cLRD
                    "(odd, check Gennarino, he might be slacking!)     ");

    }

  }

  SAYF(bSTG bV bSTOP "               pizzas on the menu : " cRST
                     "%-5s               " bSTG bV "\n",
       u_stringify_int(IB(0), sgf->queued_items));

  /* Highlight crashes in red if found, denote going over the KEEP_UNIQUE_CRASH
     limit with a '+' appended to the count. */

  sprintf(tmp, "%s%s", u_stringify_int(IB(0), sgf->saved_crashes),
          (sgf->saved_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  u_stringify_time_diff(time_tmp, cur_ms, sgf->last_crash_time);
  SAYF(bV bSTOP
       "                last ordered pizza : " cRST "%-33s     " bSTG bV bSTOP
       "                         at table : %s%-6s              " bSTG bV "\n",
       time_tmp, crash_color, tmp);

  sprintf(tmp, "%s%s", u_stringify_int(IB(0), sgf->saved_hangs),
          (sgf->saved_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  u_stringify_time_diff(time_tmp, cur_ms, sgf->last_hang_time);
  SAYF(bV bSTOP
       "  last conversation with customers : " cRST "%-33s     " bSTG bV bSTOP
       "                 number of Peroni : " cRST "%-6s              " bSTG bV
       "\n",
       time_tmp, tmp);

  SAYF(bVR bH                                           bSTOP cCYA
       " Baking progress  " bSTG bH30 bH20 bH5 bH bX bH bSTOP cCYA
       " Pizzeria busyness" bSTG bH30 bH5 bH            bH bVL "\n");

  /* This gets funny because we want to print several variable-length variables
     together, but then cram them into a fixed-width field - so we need to
     put them in a temporary buffer first. */

  sprintf(tmp, "%s%s%u (%0.01f%%)", u_stringify_int(IB(0), sgf->current_entry),
          sgf->queue_cur->favored ? "." : "*", sgf->queue_cur->fuzz_level,
          ((double)sgf->current_entry * 100) / sgf->queued_items);

  SAYF(bV bSTOP "                        now baking : " cRST
                "%-18s                    " bSTG bV bSTOP,
       tmp);

  sprintf(tmp, "%0.02f%% / %0.02f%%",
          ((double)sgf->queue_cur->bitmap_size) * 100 / sgf->fsrv.real_map_size,
          t_byte_ratio);

  SAYF("                       table full : %s%-19s " bSTG bV "\n",
       t_byte_ratio > 70
           ? cLRD
           : ((t_bytes < 200 && !sgf->non_instrumented_mode) ? cPIN : cRST),
       tmp);

  sprintf(tmp, "%s (%0.02f%%)", u_stringify_int(IB(0), sgf->cur_skipped_items),
          ((double)sgf->cur_skipped_items * 100) / sgf->queued_items);

  SAYF(bV bSTOP "                     burned pizzas : " cRST
                "%-18s                    " bSTG bV,
       tmp);

  sprintf(tmp, "%0.02f bits/tuple", t_bytes ? (((double)t_bits) / t_bytes) : 0);

  SAYF(bSTOP "                   count coverage : " cRST "%-19s " bSTG bV "\n",
       tmp);

  SAYF(bVR bH                                                 bSTOP cCYA
       " Pizzas almost ready " bSTG bH30 bH20 bH2 bH bX bH    bSTOP cCYA
       " Types of pizzas cooking " bSTG bH10 bH5 bH2 bH10 bH2 bH bVL "\n");

  sprintf(tmp, "%s (%0.02f%%)", u_stringify_int(IB(0), sgf->queued_favored),
          ((double)sgf->queued_favored) * 100 / sgf->queued_items);

  /* Yeah... it's still going on... halp? */

  SAYF(bV bSTOP "                     now preparing : " cRST
                "%-22s                " bSTG bV bSTOP
                "                favourite topping : " cRST "%-20s" bSTG bV
                "\n",
       sgf->stage_name, tmp);

  if (!sgf->stage_max) {

    sprintf(tmp, "%s/-", u_stringify_int(IB(0), sgf->stage_cur));

  } else {

    sprintf(tmp, "%s/%s (%0.02f%%)", u_stringify_int(IB(0), sgf->stage_cur),
            u_stringify_int(IB(1), sgf->stage_max),
            ((double)sgf->stage_cur) * 100 / sgf->stage_max);

  }

  SAYF(bV bSTOP "                  number of pizzas : " cRST
                "%-23s               " bSTG bV bSTOP,
       tmp);

  sprintf(tmp, "%s (%0.02f%%)", u_stringify_int(IB(0), sgf->queued_with_cov),
          ((double)sgf->queued_with_cov) * 100 / sgf->queued_items);

  SAYF(" new pizza type seen on Instagram : " cRST "%-20s" bSTG bV "\n", tmp);

  sprintf(tmp, "%s (%s%s saved)", u_stringify_int(IB(0), sgf->total_crashes),
          u_stringify_int(IB(1), sgf->saved_crashes),
          (sgf->saved_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  if (sgf->crash_mode) {

    SAYF(bV bSTOP "                      total pizzas : " cRST
                  "%-22s                " bSTG bV bSTOP
                  "      pizzas with pineapple : %s%-20s" bSTG bV "\n",
         u_stringify_int(IB(0), sgf->fsrv.total_execs), crash_color, tmp);

  } else {

    SAYF(bV bSTOP "                      total pizzas : " cRST
                  "%-22s                " bSTG bV bSTOP
                  "      total pizzas with pineapple : %s%-20s" bSTG bV "\n",
         u_stringify_int(IB(0), sgf->fsrv.total_execs), crash_color, tmp);

  }

  /* Show a warning about slow execution. */

  if (sgf->stats_avg_exec < 20) {

    sprintf(tmp, "%s/sec (%s)", u_stringify_float(IB(0), sgf->stats_avg_exec),
            "zzzz...");

    SAYF(bV bSTOP "                pizza making speed : " cLRD
                  "%-22s                ",
         tmp);

  } else {

    sprintf(tmp, "%s/sec", u_stringify_float(IB(0), sgf->stats_avg_exec));
    SAYF(bV bSTOP "                pizza making speed : " cRST
                  "%-22s                ",
         tmp);

  }

  sprintf(tmp, "%s (%s%s saved)", u_stringify_int(IB(0), sgf->total_tmouts),
          u_stringify_int(IB(1), sgf->saved_tmouts),
          (sgf->saved_tmouts >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF(bSTG bV bSTOP "                    burned pizzas : " cRST "%-20s" bSTG bV
                     "\n",
       tmp);

  /* Aaaalmost there... hold on! */

  SAYF(bVR bH cCYA bSTOP " Promotional campaign on TikTok yields " bSTG bH30 bH2
           bH bH2 bX bH                                          bSTOP cCYA
                         " Customer type " bSTG bH5 bH2 bH30 bH2 bH bVL "\n");

  if (unlikely(sgf->custom_only)) {

    strcpy(tmp, "oven off (custom-mutator-only mode)");

  } else if (likely(sgf->skip_deterministic)) {

    strcpy(tmp, "oven off (default, enable with -D)");

  } else {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), sgf->stage_finds[STAGE_FLIP1]),
            u_stringify_int(IB(1), sgf->stage_cycles[STAGE_FLIP1]),
            u_stringify_int(IB(2), sgf->stage_finds[STAGE_FLIP2]),
            u_stringify_int(IB(3), sgf->stage_cycles[STAGE_FLIP2]),
            u_stringify_int(IB(4), sgf->stage_finds[STAGE_FLIP4]),
            u_stringify_int(IB(5), sgf->stage_cycles[STAGE_FLIP4]));

  }

  SAYF(bV bSTOP
       "                pizzas for celiac  : " cRST "%-36s  " bSTG bV bSTOP
       "                           levels : " cRST "%-10s          " bSTG bV
       "\n",
       tmp, u_stringify_int(IB(0), sgf->max_depth));

  if (unlikely(!sgf->skip_deterministic)) {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), sgf->stage_finds[STAGE_FLIP8]),
            u_stringify_int(IB(1), sgf->stage_cycles[STAGE_FLIP8]),
            u_stringify_int(IB(2), sgf->stage_finds[STAGE_FLIP16]),
            u_stringify_int(IB(3), sgf->stage_cycles[STAGE_FLIP16]),
            u_stringify_int(IB(4), sgf->stage_finds[STAGE_FLIP32]),
            u_stringify_int(IB(5), sgf->stage_cycles[STAGE_FLIP32]));

  }

  SAYF(bV bSTOP
       "                   pizzas for kids : " cRST "%-36s  " bSTG bV bSTOP
       "                   pizzas to make : " cRST "%-10s          " bSTG bV
       "\n",
       tmp, u_stringify_int(IB(0), sgf->pending_not_fuzzed));

  if (unlikely(!sgf->skip_deterministic)) {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), sgf->stage_finds[STAGE_ARITH8]),
            u_stringify_int(IB(1), sgf->stage_cycles[STAGE_ARITH8]),
            u_stringify_int(IB(2), sgf->stage_finds[STAGE_ARITH16]),
            u_stringify_int(IB(3), sgf->stage_cycles[STAGE_ARITH16]),
            u_stringify_int(IB(4), sgf->stage_finds[STAGE_ARITH32]),
            u_stringify_int(IB(5), sgf->stage_cycles[STAGE_ARITH32]));

  }

  SAYF(bV bSTOP
       "                      pizza bianca : " cRST "%-36s  " bSTG bV bSTOP
       "                       nice table : " cRST "%-10s          " bSTG bV
       "\n",
       tmp, u_stringify_int(IB(0), sgf->pending_favored));

  if (unlikely(!sgf->skip_deterministic)) {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), sgf->stage_finds[STAGE_INTEREST8]),
            u_stringify_int(IB(1), sgf->stage_cycles[STAGE_INTEREST8]),
            u_stringify_int(IB(2), sgf->stage_finds[STAGE_INTEREST16]),
            u_stringify_int(IB(3), sgf->stage_cycles[STAGE_INTEREST16]),
            u_stringify_int(IB(4), sgf->stage_finds[STAGE_INTEREST32]),
            u_stringify_int(IB(5), sgf->stage_cycles[STAGE_INTEREST32]));

  }

  SAYF(bV bSTOP
       "               recurring customers : " cRST "%-36s  " bSTG bV bSTOP
       "                    new customers : " cRST "%-10s          " bSTG bV
       "\n",
       tmp, u_stringify_int(IB(0), sgf->queued_discovered));

  if (unlikely(!sgf->skip_deterministic)) {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s, %s/%s",
            u_stringify_int(IB(0), sgf->stage_finds[STAGE_EXTRAS_UO]),
            u_stringify_int(IB(1), sgf->stage_cycles[STAGE_EXTRAS_UO]),
            u_stringify_int(IB(2), sgf->stage_finds[STAGE_EXTRAS_UI]),
            u_stringify_int(IB(3), sgf->stage_cycles[STAGE_EXTRAS_UI]),
            u_stringify_int(IB(4), sgf->stage_finds[STAGE_EXTRAS_AO]),
            u_stringify_int(IB(5), sgf->stage_cycles[STAGE_EXTRAS_AO]),
            u_stringify_int(IB(6), sgf->stage_finds[STAGE_EXTRAS_AI]),
            u_stringify_int(IB(7), sgf->stage_cycles[STAGE_EXTRAS_AI]));

  } else if (unlikely(!sgf->extras_cnt || sgf->custom_only)) {

    strcpy(tmp, "n/a");

  } else {

    strcpy(tmp, "18 year anniversary mode");

  }

  SAYF(bV bSTOP
       "                        dictionary : " cRST "%-36s  " bSTG bV bSTOP
       "      patrons from old restaurant : " cRST "%-10s          " bSTG bV
       "\n",
       tmp,
       sgf->sync_id ? u_stringify_int(IB(0), sgf->queued_imported)
                    : (u8 *)"n/a");

  sprintf(tmp, "%s/%s, %s/%s",
          u_stringify_int(IB(0), sgf->stage_finds[STAGE_HAVOC]),
          u_stringify_int(IB(2), sgf->stage_cycles[STAGE_HAVOC]),
          u_stringify_int(IB(3), sgf->stage_finds[STAGE_SPLICE]),
          u_stringify_int(IB(4), sgf->stage_cycles[STAGE_SPLICE]));

  SAYF(bV bSTOP " 18 year anniversary mode/cleaning : " cRST
                "%-36s  " bSTG bV bSTOP,
       tmp);

  if (t_bytes) {

    sprintf(tmp, "%0.02f%%", stab_ratio);

  } else {

    strcpy(tmp, "n/a");

  }

  SAYF("                    oven flameout : %s%-10s          " bSTG bV "\n",
       (stab_ratio < 85 && sgf->var_byte_count > 40)
           ? cLRD
           : ((sgf->queued_variable &&
               (!sgf->persistent_mode || sgf->var_byte_count > 20))
                  ? cMGN
                  : cRST),
       tmp);

  if (unlikely(sgf->sgf_env.sgf_python_module)) {

    sprintf(tmp, "%s/%s,",
            u_stringify_int(IB(0), sgf->stage_finds[STAGE_PYTHON]),
            u_stringify_int(IB(1), sgf->stage_cycles[STAGE_PYTHON]));

  } else {

    strcpy(tmp, "unused,");

  }

  if (unlikely(sgf->sgf_env.sgf_custom_mutator_library)) {

    strcat(tmp, " ");
    strcat(tmp, u_stringify_int(IB(2), sgf->stage_finds[STAGE_CUSTOM_MUTATOR]));
    strcat(tmp, "/");
    strcat(tmp,
           u_stringify_int(IB(3), sgf->stage_cycles[STAGE_CUSTOM_MUTATOR]));
    strcat(tmp, ",");

  } else {

    strcat(tmp, " unused,");

  }

  if (unlikely(sgf->shm.cmplog_mode)) {

    strcat(tmp, " ");
    strcat(tmp, u_stringify_int(IB(4), sgf->stage_finds[STAGE_COLORIZATION]));
    strcat(tmp, "/");
    strcat(tmp, u_stringify_int(IB(5), sgf->stage_cycles[STAGE_COLORIZATION]));
    strcat(tmp, ", ");
    strcat(tmp, u_stringify_int(IB(6), sgf->stage_finds[STAGE_ITS]));
    strcat(tmp, "/");
    strcat(tmp, u_stringify_int(IB(7), sgf->stage_cycles[STAGE_ITS]));

  } else {

    strcat(tmp, " unused, unused");

  }

  SAYF(bV bSTOP "                      py/custom/rq : " cRST
                "%-36s  " bSTG bVR bH20 bH2 bH30 bH2 bH bH bRB "\n",
       tmp);

  if (likely(sgf->disable_trim)) {

    sprintf(tmp, "disabled, ");

  } else if (unlikely(!sgf->bytes_trim_out)) {

    sprintf(tmp, "n/a, ");

  } else {

    sprintf(tmp, "%0.02f%%/%s, ",
            ((double)(sgf->bytes_trim_in - sgf->bytes_trim_out)) * 100 /
                sgf->bytes_trim_in,
            u_stringify_int(IB(0), sgf->trim_execs));

  }

  if (likely(sgf->skip_deterministic)) {

    strcat(tmp, "disabled");

  } else if (unlikely(!sgf->blocks_eff_total)) {

    strcat(tmp, "n/a");

  } else {

    u8 tmp2[128];

    sprintf(tmp2, "%0.02f%%",
            ((double)(sgf->blocks_eff_total - sgf->blocks_eff_select)) * 100 /
                sgf->blocks_eff_total);

    strcat(tmp, tmp2);

  }

  // if (sgf->custom_mutators_count) {

  //
  //  sprintf(tmp, "%s/%s",
  //          u_stringify_int(IB(0), sgf->stage_finds[STAGE_CUSTOM_MUTATOR]),
  //          u_stringify_int(IB(1), sgf->stage_cycles[STAGE_CUSTOM_MUTATOR]));
  //  SAYF(bV bSTOP " custom mut. : " cRST "%-36s " bSTG bV RESET_G1, tmp);
  //
  //} else {

  SAYF(bV bSTOP "                   toilets clogged : " cRST
                "%-36s  " bSTG bV RESET_G1,
       tmp);

  //}

  /* Provide some CPU utilization stats. */

  if (sgf->cpu_core_count) {

    char *spacing = SP10, snap[80] = " " cLGN "Pizzaioli's busyness " cRST " ";

    double cur_runnable = get_runnable_processes();
    u32    cur_utilization = cur_runnable * 100 / sgf->cpu_core_count;

    u8 *cpu_color = cCYA;

    /* If we could still run one or more processes, use green. */

    if (sgf->cpu_core_count > 1 && cur_runnable + 1 <= sgf->cpu_core_count) {

      cpu_color = cLGN;

    }

    /* If we're clearly oversubscribed, use red. */

    if (!sgf->no_cpu_meter_red && cur_utilization >= 150) { cpu_color = cLRD; }

    if (sgf->fsrv.snapshot) { spacing = snap; }

#ifdef HAVE_AFFINITY

    if (sgf->cpu_aff >= 0) {

      SAYF("%s" cGRA "[cpu%03u:%s%3u%%" cGRA "]\r" cRST, spacing,
           MIN(sgf->cpu_aff, 999), cpu_color, MIN(cur_utilization, (u32)999));

    } else {

      SAYF("%s" cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST, spacing, cpu_color,
           MIN(cur_utilization, (u32)999));

    }

#else

    SAYF("%s" cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST, spacing, cpu_color,
         MIN(cur_utilization, (u32)999));

#endif                                                    /* ^HAVE_AFFINITY */

  } else {

    SAYF("\r");

  }

  /* Last line */
  SAYF(SET_G1 "\n" bSTG bLB bH30 bH20 bH2 bH20 bH2 bH bRB bSTOP cRST RESET_G1);

#undef IB

  /* Hallelujah! */

  fflush(0);

}

/* Display quick statistics at the end of processing the input directory,
   plus a bunch of warnings. Some calibration stuff also ended up here,
   along with several hardcoded constants. Maybe clean up eventually. */

void show_init_stats(sgf_state_t *sgf) {

  struct queue_entry *q;
  u32                 min_bits = 0, max_bits = 0, max_len = 0, count = 0, i;
  u64                 min_us = 0, max_us = 0;
  u64                 avg_us = 0;

  u8 val_bufs[4][STRINGIFY_VAL_SIZE_MAX];
#define IB(i) val_bufs[(i)], sizeof(val_bufs[(i)])

  if (sgf->total_cal_cycles) {

    avg_us = sgf->total_cal_us / sgf->total_cal_cycles;

  }

  for (i = 0; i < sgf->queued_items; i++) {

    q = sgf->queue_buf[i];
    if (unlikely(q->disabled)) { continue; }

    if (!min_us || q->exec_us < min_us) { min_us = q->exec_us; }
    if (q->exec_us > max_us) { max_us = q->exec_us; }

    if (!min_bits || q->bitmap_size < min_bits) { min_bits = q->bitmap_size; }
    if (q->bitmap_size > max_bits) { max_bits = q->bitmap_size; }

    if (q->len > max_len) { max_len = q->len; }

    ++count;

  }

  // SAYF("\n");

  if (avg_us > ((sgf->fsrv.cs_mode || sgf->fsrv.qemu_mode || sgf->unicorn_mode)
                    ? 50000
                    : 10000)) {

    WARNF(cLRD
          "The target binary is pretty slow! See "
          "%s/fuzzing_in_depth.md#i-improve-the-speed",
          doc_path);

  }

  /* Let's keep things moving with slow binaries. */

  if (unlikely(sgf->fixed_seed)) {

    sgf->havoc_div = 1;

  } else if (avg_us > 50000) {

    sgf->havoc_div = 10;                                /* 0-19 execs/sec   */

  } else if (avg_us > 20000) {

    sgf->havoc_div = 5;                                 /* 20-49 execs/sec  */

  } else if (avg_us > 10000) {

    sgf->havoc_div = 2;                                 /* 50-100 execs/sec */

  }

  if (!sgf->resuming_fuzz) {

    if (max_len > 50 * 1024) {

      WARNF(cLRD
            "Some test cases are huge (%s) - see "
            "%s/fuzzing_in_depth.md#i-improve-the-speed",
            stringify_mem_size(IB(0), max_len), doc_path);

    } else if (max_len > 10 * 1024) {

      WARNF(
          "Some test cases are big (%s) - see "
          "%s/fuzzing_in_depth.md#i-improve-the-speed",
          stringify_mem_size(IB(0), max_len), doc_path);

    }

    if (sgf->useless_at_start && !sgf->in_bitmap) {

      WARNF(cLRD "Some test cases look useless. Consider using a smaller set.");

    }

    if (sgf->queued_items > 100) {

      WARNF(cLRD
            "You probably have far too many input files! Consider trimming "
            "down.");

    } else if (sgf->queued_items > 20) {

      WARNF("You have lots of input files; try starting small.");

    }

  }

  OKF("Here are some useful stats:\n\n"

      cGRA "    Test case count : " cRST
      "%u favored, %u variable, %u ignored, %u total\n" cGRA
      "       Bitmap range : " cRST
      "%u to %u bits (average: %0.02f bits)\n" cGRA
      "        Exec timing : " cRST "%s to %s us (average: %s us)\n",
      sgf->queued_favored, sgf->queued_variable, sgf->queued_items - count,
      sgf->queued_items, min_bits, max_bits,
      ((double)sgf->total_bitmap_size) /
          (sgf->total_bitmap_entries ? sgf->total_bitmap_entries : 1),
      stringify_int(IB(0), min_us), stringify_int(IB(1), max_us),
      stringify_int(IB(2), avg_us));

  if (sgf->timeout_given == 3) {

    ACTF("Applying timeout settings from resumed session (%u ms).",
         sgf->fsrv.exec_tmout);

  } else if (sgf->timeout_given != 1) {

    /* Figure out the appropriate timeout. The basic idea is: 5x average or
       1x max, rounded up to EXEC_TM_ROUND ms and capped at 1 second.

       If the program is slow, the multiplier is lowered to 2x or 3x, because
       random scheduler jitter is less likely to have any impact, and because
       our patience is wearing thin =) */

    if (unlikely(sgf->fixed_seed)) {

      sgf->fsrv.exec_tmout = avg_us * 5 / 1000;

    } else if (avg_us > 50000) {

      sgf->fsrv.exec_tmout = avg_us * 2 / 1000;

    } else if (avg_us > 10000) {

      sgf->fsrv.exec_tmout = avg_us * 3 / 1000;

    } else {

      sgf->fsrv.exec_tmout = avg_us * 5 / 1000;

    }

    sgf->fsrv.exec_tmout = MAX(sgf->fsrv.exec_tmout, max_us / 1000);
    sgf->fsrv.exec_tmout =
        (sgf->fsrv.exec_tmout + EXEC_TM_ROUND) / EXEC_TM_ROUND * EXEC_TM_ROUND;

    if (sgf->fsrv.exec_tmout > EXEC_TIMEOUT) {

      sgf->fsrv.exec_tmout = EXEC_TIMEOUT;

    }

    ACTF("No -t option specified, so I'll use an exec timeout of %u ms.",
         sgf->fsrv.exec_tmout);

    sgf->timeout_given = 1;

  } else {

    ACTF("-t option specified. We'll use an exec timeout of %u ms.",
         sgf->fsrv.exec_tmout);

  }

  /* In non-instrumented mode, re-running every timing out test case with a
     generous time
     limit is very expensive, so let's select a more conservative default. */

  if (sgf->non_instrumented_mode && !(sgf->sgf_env.sgf_hang_tmout)) {

    sgf->hang_tmout = MIN((u32)EXEC_TIMEOUT, sgf->fsrv.exec_tmout * 2 + 100);

  }

  OKF("All set and ready to roll!");
#undef IB

}

inline void update_calibration_time(sgf_state_t *sgf, u64 *time) {

  u64 cur = get_cur_time_us();
  sgf->calibration_time_us += cur - *time;
  *time = cur;

}

inline void update_trim_time(sgf_state_t *sgf, u64 *time) {

  u64 cur = get_cur_time_us();
  sgf->trim_time_us += cur - *time;
  *time = cur;

}

inline void update_sync_time(sgf_state_t *sgf, u64 *time) {

  u64 cur = get_cur_time_us();
  sgf->sync_time_us += cur - *time;
  *time = cur;

}

inline void update_cmplog_time(sgf_state_t *sgf, u64 *time) {

  u64 cur = get_cur_time_us();
  sgf->cmplog_time_us += cur - *time;
  *time = cur;

}

