/*
   american fuzzy lop++ - globals declarations
   -------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eissfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

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

#include <signal.h>
#include <limits.h>
#include "sgf-fuzz.h"
#include "envs.h"

char *power_names[POWER_SCHEDULES_NUM] = {"explore", "mmopt", "exploit",
                                          "fast",    "coe",   "lin",
                                          "quad",    "rare",  "seek"};

/* Initialize MOpt "globals" for this sgf state */

static void init_mopt_globals(sgf_state_t *sgf) {

  MOpt_globals_t *core = &sgf->mopt_globals_core;
  core->finds = sgf->core_operator_finds_puppet;
  core->finds_v2 = sgf->core_operator_finds_puppet_v2;
  core->cycles = sgf->core_operator_cycles_puppet;
  core->cycles_v2 = sgf->core_operator_cycles_puppet_v2;
  core->cycles_v3 = sgf->core_operator_cycles_puppet_v3;
  core->is_pilot_mode = 0;
  core->pTime = &sgf->tmp_core_time;
  core->period = period_core;
  core->havoc_stagename = "MOpt-core-havoc";
  core->splice_stageformat = "MOpt-core-splice %u";
  core->havoc_stagenameshort = "MOpt_core_havoc";
  core->splice_stagenameshort = "MOpt_core_splice";

  MOpt_globals_t *pilot = &sgf->mopt_globals_pilot;
  pilot->finds = sgf->stage_finds_puppet[0];
  pilot->finds_v2 = sgf->stage_finds_puppet_v2[0];
  pilot->cycles = sgf->stage_cycles_puppet[0];
  pilot->cycles_v2 = sgf->stage_cycles_puppet_v2[0];
  pilot->cycles_v3 = sgf->stage_cycles_puppet_v3[0];
  pilot->is_pilot_mode = 1;
  pilot->pTime = &sgf->tmp_pilot_time;
  pilot->period = period_pilot;
  pilot->havoc_stagename = "MOpt-havoc";
  pilot->splice_stageformat = "MOpt-splice %u";
  pilot->havoc_stagenameshort = "MOpt_havoc";
  pilot->splice_stagenameshort = "MOpt_splice";

}

/* A global pointer to all instances is needed (for now) for signals to arrive
 */

static list_t sgf_states = {.element_prealloc_count = 0};

/* Initializes an sgf_state_t. */

void afl_state_init(sgf_state_t *sgf, uint32_t map_size) {

  /* thanks to this memset, growing vars like out_buf
  and out_size are NULL/0 by default. */
  memset(sgf, 0, sizeof(sgf_state_t));

  sgf->shm.map_size = map_size ? map_size : MAP_SIZE;

  sgf->smallest_favored = -1;
  sgf->sgf_ijon_history_limit = 20;
  sgf->w_init = 0.9;
  sgf->w_end = 0.3;
  sgf->g_max = 5000;
  sgf->cutoff_score = 0.0;
  sgf->queued_mu = 0.0;
  sgf->queued_mad = 0.0;
  sgf->period_pilot_tmp = 5000.0;
  sgf->schedule = EXPLORE;              /* Power schedule (default: EXPLORE)*/
  sgf->havoc_max_mult = HAVOC_MAX_MULT;
  sgf->clear_screen = 1;                /* Window resized?                  */
  sgf->havoc_div = 1;                   /* Cycle count divisor for havoc    */
  sgf->stage_name = "init";             /* Name of the current fuzz stage   */
  sgf->splicing_with = -1;              /* Splicing with which test case?   */
  sgf->cpu_to_bind = -1;
  sgf->havoc_stack_pow2 = HAVOC_STACK_POW2;
  sgf->hang_tmout = EXEC_TIMEOUT;
  sgf->exit_on_time = 0;
  sgf->stats_update_freq = 1;
  sgf->stats_file_update_freq_msecs = STATS_UPDATE_SEC * 1000;
  sgf->stats_avg_exec = 0;
  sgf->skip_deterministic = 0;
  sgf->sync_time = SYNC_TIME;
  sgf->cmplog_lvl = 2;
  sgf->min_length = 1;
  sgf->max_length = MAX_FILE;
  sgf->switch_fuzz_mode = STRATEGY_SWITCH_TIME * 1000;
  sgf->q_testcase_max_cache_size = TESTCASE_CACHE_SIZE * 1048576UL;
  sgf->q_testcase_max_cache_entries = 64 * 1024;
  sgf->last_scored_idx = -1;
  sgf->potential_nn_epoch = 0;
  sgf->potential_nn_recalc_interval = 64;  
  sgf->skeleton_graph_stage_max = 3;
  sgf->check_data_race = 0;
  sgf->enable_feedback = 0;
  sgf->cutoff_percentile = 1;

  sgf->sgf_env.skeleton_graph_stage_max = 3;
  sgf->sgf_env.check_data_race = 0;
  sgf->sgf_env.enable_feedback = 0;
  sgf->sgf_env.cutoff_percentile = 1;

#ifdef HAVE_AFFINITY
  sgf->cpu_aff = -1;                    /* Selected CPU core                */
#endif                                                     /* HAVE_AFFINITY */

  sgf->virgin_bits = ck_alloc(map_size + SKELETON_GRAPH_MAP_SIZE);
  sgf->virgin_tmout = ck_alloc(map_size + SKELETON_GRAPH_MAP_SIZE);
  sgf->virgin_crash = ck_alloc(map_size + SKELETON_GRAPH_MAP_SIZE);
  sgf->var_bytes = ck_alloc(map_size + SKELETON_GRAPH_MAP_SIZE);
  sgf->top_rated = ck_alloc(map_size * sizeof(void *));
  sgf->clean_trace = ck_alloc(map_size);
  sgf->clean_trace_custom = ck_alloc(map_size);
  sgf->first_trace = ck_alloc(map_size);
  sgf->map_tmp_buf = ck_alloc(map_size);

  /* Initialize IJON max tracking state */
  sgf->ijon_state = NULL;
  sgf->ijon_bits = NULL;
  sgf->last_ijon_log_time = 0;
  sgf->ijon_input_data = NULL;
  sgf->ijon_input_len = 0;
  sgf->is_doing_ijon = 0;

  sgf->perm = DEFAULT_PERMISSION;
  sgf->dir_perm = DEFAULT_DIRS_PERMISSION;

  sgf->fsrv.use_stdin = 1;
  sgf->fsrv.map_size = map_size;
  // sgf_state_t is not available in forkserver.c
  sgf->fsrv.sgf_ptr = (void *)sgf;
  sgf->fsrv.add_extra_func = (void (*)(void *, u8 *, u32)) & add_extra;
  sgf->fsrv.exec_tmout = EXEC_TIMEOUT;
  sgf->fsrv.mem_limit = MEM_LIMIT;
  sgf->fsrv.dev_urandom_fd = -1;
  sgf->fsrv.dev_null_fd = -1;
  sgf->fsrv.child_pid = -1;
  sgf->fsrv.out_dir_fd = -1;

  /* Init SkipDet */
  sgf->skipdet_g =
      (struct skipdet_global *)ck_alloc(sizeof(struct skipdet_global));
  sgf->skipdet_g->inf_prof =
      (struct inf_profile *)ck_alloc(sizeof(struct inf_profile));
  sgf->havoc_prof =
      (struct havoc_profile *)ck_alloc(sizeof(struct havoc_profile));

  init_mopt_globals(sgf);

  list_append(&sgf_states, sgf);

  /* Initialize bounded queue system */
  const char *impl_name = getenv("SGF_QUEUE_IMPL");
  if (!impl_name) { impl_name = "maxheap"; }  /* MaxHeap is the default */

  sgf->queue_impl_name = impl_name;
  sgf->bounded_queue = sgf_queue_create(impl_name, 500, 100, 100000);

  if (!sgf->bounded_queue) {
    FATAL("Failed to initialize queue implementation: %s", impl_name);
  }

}

void afl_resize_map_buffers(sgf_state_t *sgf, u32 old_size, u32 new_size) {

  sgf->virgin_bits = ck_realloc(sgf->virgin_bits, new_size + SKELETON_GRAPH_MAP_SIZE);
  sgf->virgin_tmout = ck_realloc(sgf->virgin_tmout, new_size + SKELETON_GRAPH_MAP_SIZE);
  sgf->virgin_crash = ck_realloc(sgf->virgin_crash, new_size + SKELETON_GRAPH_MAP_SIZE);
  sgf->var_bytes = ck_realloc(sgf->var_bytes, new_size + SKELETON_GRAPH_MAP_SIZE);
  sgf->top_rated = ck_realloc(sgf->top_rated, new_size * sizeof(void *));
  sgf->clean_trace = ck_realloc(sgf->clean_trace, new_size);
  sgf->clean_trace_custom = ck_realloc(sgf->clean_trace_custom, new_size);
  sgf->first_trace = ck_realloc(sgf->first_trace, new_size);
  sgf->map_tmp_buf = ck_realloc(sgf->map_tmp_buf, new_size);

  if (old_size < new_size) {

    u32 size_diff = new_size - old_size;

    memset(sgf->var_bytes + old_size, 0, size_diff);
    memset(sgf->top_rated + old_size, 0, size_diff * sizeof(void *));
    memset(sgf->clean_trace + old_size, 0, size_diff);
    memset(sgf->clean_trace_custom + old_size, 0, size_diff);
    memset(sgf->first_trace + old_size, 0, size_diff);
    memset(sgf->map_tmp_buf + old_size, 0, size_diff);

  }

}

/*This sets up the environment variables for sgf-fuzz into the sgf_state
 * struct*/

void read_afl_environment(sgf_state_t *sgf, char **envp) {

  int   index = 0, issue_detected = 0;
  char *env;
  while ((env = envp[index++]) != NULL) {

    if (strncmp(env, "ALF_", 4) == 0) {

      WARNF("Potentially mistyped AFL environment variable: %s", env);
      issue_detected = 1;

    } else if (strncmp(env, "USE_", 4) == 0) {

      WARNF(
          "Potentially mistyped AFL environment variable: %s, did you mean "
          "SGF_%s?",
          env, env);
      issue_detected = 1;

    } else if (strncmp(env, "SGF_", 4) == 0) {

      int i = 0, match = 0;
      while (match == 0 && sgf_environment_variables[i] != NULL) {

        size_t sgf_environment_variable_len =
            strlen(sgf_environment_variables[i]);
        if (strncmp(env, sgf_environment_variables[i],
                    sgf_environment_variable_len) == 0 &&
            env[sgf_environment_variable_len] == '=') {

          match = 1;
          if(!strncmp(env, "SGF_ENABLE_FEEDBACK", sgf_environment_variable_len)){
            // 1. Actually fetch the variable
            sgf->sgf_env.enable_feedback = 
                atoi((u8 *)get_afl_env(sgf_environment_variables[i]));

            // 2. Parse it if it exists
            if (sgf->sgf_env.enable_feedback) {
                sgf->enable_feedback = sgf->sgf_env.enable_feedback;
            }

            // 3. Fallback to default
            if (!sgf->enable_feedback) {
                sgf->enable_feedback = 0;
            }
          } else if(!strncmp(env, "SGF_CHECK_DATA_RACE", sgf_environment_variable_len)){
            // 1. Actually fetch the variable
            sgf->sgf_env.check_data_race = 
                atoi((u8 *)get_afl_env(sgf_environment_variables[i]));

            // 2. Parse it if it exists
            if (sgf->sgf_env.check_data_race) {
                sgf->check_data_race = sgf->sgf_env.check_data_race;
            }

            // 3. Fallback to default
            if (!sgf->check_data_race) {
                sgf->check_data_race = 0;
            }

          } else if (!strncmp(env, "SGF_SKELETON_GRAPH_HIGHEST_STEP", sgf_environment_variable_len)) {
            
            // 1. Actually fetch the variable
            sgf->sgf_env.skeleton_graph_stage_max = 
                atoi((u8 *)get_afl_env(sgf_environment_variables[i]));

            // 2. Parse it if it exists
            if (sgf->sgf_env.skeleton_graph_stage_max) {
                sgf->skeleton_graph_stage_max = sgf->sgf_env.skeleton_graph_stage_max;
            }

            // 3. Fallback to default
            if (!sgf->skeleton_graph_stage_max) {
                sgf->skeleton_graph_stage_max = 1;
            }

          } else if(!strncmp(env, "SGF_CUTOFF_PERCENTILE", sgf_environment_variable_len)){
            // 1. Actually fetch the variable
            sgf->sgf_env.cutoff_percentile = 
                atof((u8 *)get_afl_env(sgf_environment_variables[i]));

            // 2. Parse it if it exists
            if (sgf->sgf_env.cutoff_percentile) {
                sgf->cutoff_percentile = sgf->sgf_env.cutoff_percentile;
            }

            // 3. Fallback to default
            if (!sgf->cutoff_percentile) {
                sgf->cutoff_percentile = 1;
            }

          }
          else if (!strncmp(env, "SGF_SKIP_CPUFREQ", sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_skip_cpufreq =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_EXIT_WHEN_DONE",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_exit_when_done =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_EXIT_ON_TIME",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_exit_on_time =
                (u8 *)get_afl_env(sgf_environment_variables[i]);

          } else if (!strncmp(env, "SGF_CRASHING_SEEDS_AS_NEW_CRASH",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_crashing_seeds_as_new_crash =
                atoi((u8 *)get_afl_env(sgf_environment_variables[i]));

          } else if (!strncmp(env, "SGF_NO_AFFINITY",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_no_affinity =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_NO_WARN_INSTABILITY",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_no_warn_instability =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_TRY_AFFINITY",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_try_affinity =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_SKIP_CRASHES",

                              sgf_environment_variable_len)) {

            // we should mark this obsolete in a few versions

          } else if (!strncmp(env, "SGF_HANG_TMOUT",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_hang_tmout =
                (u8 *)get_afl_env(sgf_environment_variables[i]);

          } else if (!strncmp(env, "SGF_KEEP_TIMEOUTS",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_keep_timeouts =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_SKIP_BIN_CHECK",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_skip_bin_check =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_DUMB_FORKSRV",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_dumb_forksrv =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_IMPORT_FIRST",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_import_first =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_FINAL_SYNC",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_final_sync =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_NO_SYNC",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_no_sync =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_NO_FASTRESUME",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_no_fastresume =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_CUSTOM_MUTATOR_ONLY",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_custom_mutator_only =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_CUSTOM_MUTATOR_LATE_SEND",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_custom_mutator_late_send =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_CMPLOG_ONLY_NEW",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_cmplog_only_new =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_DISABLE_REDUNDANT",

                              sgf_environment_variable_len) ||
                     !strncmp(env, "SGF_NO_REDUNDANT",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_disable_redundant =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_NO_STARTUP_CALIBRATION",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_no_startup_calibration =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_NO_UI", sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_no_ui =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_FORCE_UI",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_force_ui =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_IGNORE_PROBLEMS",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_ignore_problems =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_IGNORE_SEED_PROBLEMS",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_ignore_seed_problems =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_IGNORE_TIMEOUTS",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_ignore_timeouts =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_I_DONT_CARE_ABOUT_MISSING_CRASHES",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_i_dont_care_about_missing_crashes =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_BENCH_JUST_ONE",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_bench_just_one =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_BENCH_UNTIL_CRASH",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_bench_until_crash =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_DEBUG_CHILD",

                              sgf_environment_variable_len) ||
                     !strncmp(env, "SGF_DEBUG_CHILD_OUTPUT",
                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_debug_child =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_AUTORESUME",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_autoresume =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_PERSISTENT_RECORD",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_persistent_record =
                get_afl_env(sgf_environment_variables[i]);

          } else if (!strncmp(env, "SGF_CYCLE_SCHEDULES",

                              sgf_environment_variable_len)) {

            sgf->cycle_schedules = sgf->sgf_env.sgf_cycle_schedules =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_EXIT_ON_SEED_ISSUES",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_exit_on_seed_issues =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_EXPAND_HAVOC_NOW",

                              sgf_environment_variable_len)) {

            sgf->expand_havoc = sgf->sgf_env.sgf_expand_havoc =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_CAL_FAST",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_cal_fast =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_FAST_CAL",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_cal_fast =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_STATSD",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_statsd =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_POST_PROCESS_KEEP_ORIGINAL",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_post_process_keep_original =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_TMPDIR",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_tmpdir =
                (u8 *)get_afl_env(sgf_environment_variables[i]);

          } else if (!strncmp(env, "SGF_CUSTOM_MUTATOR_LIBRARY",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_custom_mutator_library =
                (u8 *)get_afl_env(sgf_environment_variables[i]);

          } else if (!strncmp(env, "SGF_PYTHON_MODULE",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_python_module =
                (u8 *)get_afl_env(sgf_environment_variables[i]);

          } else if (!strncmp(env, "SGF_PATH", sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_path =
                (u8 *)get_afl_env(sgf_environment_variables[i]);

          } else if (!strncmp(env, "SGF_PRELOAD",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_preload =
                (u8 *)get_afl_env(sgf_environment_variables[i]);

          } else if (!strncmp(env, "SGF_MAX_DET_EXTRAS",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_max_det_extras =
                (u8 *)get_afl_env(sgf_environment_variables[i]);

          } else if (!strncmp(env, "SGF_FORKSRV_INIT_TMOUT",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_forksrv_init_tmout =
                (u8 *)get_afl_env(sgf_environment_variables[i]);

          } else if (!strncmp(env, "SGF_TESTCACHE_SIZE",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_testcache_size =
                (u8 *)get_afl_env(sgf_environment_variables[i]);

          } else if (!strncmp(env, "SGF_TESTCACHE_ENTRIES",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_testcache_entries =
                (u8 *)get_afl_env(sgf_environment_variables[i]);

          } else if (!strncmp(env, "SGF_STATSD_HOST",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_statsd_host =
                (u8 *)get_afl_env(sgf_environment_variables[i]);

          } else if (!strncmp(env, "SGF_STATSD_PORT",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_statsd_port =
                (u8 *)get_afl_env(sgf_environment_variables[i]);

          } else if (!strncmp(env, "SGF_STATSD_TAGS_FLAVOR",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_statsd_tags_flavor =
                (u8 *)get_afl_env(sgf_environment_variables[i]);

          } else if (!strncmp(env, "SGF_CRASH_EXITCODE",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_crash_exitcode =
                (u8 *)get_afl_env(sgf_environment_variables[i]);

#if defined USE_COLOR && !defined ALWAYS_COLORED

          } else if (!strncmp(env, "SGF_NO_COLOR",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_statsd_tags_flavor =
                (u8 *)get_afl_env(sgf_environment_variables[i]);

          } else if (!strncmp(env, "SGF_NO_COLOUR",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_statsd_tags_flavor =
                (u8 *)get_afl_env(sgf_environment_variables[i]);
#endif

          } else if (!strncmp(env, "SGF_KILL_SIGNAL",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_child_kill_signal =
                (u8 *)get_afl_env(sgf_environment_variables[i]);

          } else if (!strncmp(env, "SGF_FORK_SERVER_KILL_SIGNAL",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_fsrv_kill_signal =
                (u8 *)get_afl_env(sgf_environment_variables[i]);

          } else if (!strncmp(env, "SGF_TARGET_ENV",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_target_env =
                (u8 *)get_afl_env(sgf_environment_variables[i]);

          } else if (!strncmp(env, "SGF_INPUT_LEN_MIN",

                              sgf_environment_variable_len)) {

            sgf->min_length =
                atoi((u8 *)get_afl_env(sgf_environment_variables[i]));

          } else if (!strncmp(env, "SGF_INPUT_LEN_MAX",

                              sgf_environment_variable_len)) {

            sgf->max_length =
                atoi((u8 *)get_afl_env(sgf_environment_variables[i]));

          } else if (!strncmp(env, "SGF_IJON_HISTORY_LIMIT",

                              sgf_environment_variable_len)) {

            sgf->sgf_ijon_history_limit =
                atoi((u8 *)get_afl_env(sgf_environment_variables[i]));

            if (sgf->sgf_ijon_history_limit < 0) {

              sgf->sgf_ijon_history_limit = 0;

            }

          } else if (!strncmp(env, "SGF_PIZZA_MODE",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_pizza_mode =
                atoi((u8 *)get_afl_env(sgf_environment_variables[i]));

          } else if (!strncmp(env, "SGF_NO_CRASH_README",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_no_crash_readme =
                atoi((u8 *)get_afl_env(sgf_environment_variables[i]));

          } else if (!strncmp(env, "SGF_SYNC_TIME",

                              sgf_environment_variable_len)) {

            int time = atoi((u8 *)get_afl_env(sgf_environment_variables[i]));
            if (time > 0) {

              sgf->sync_time = time * (60 * 1000LL);

            } else {

              WARNF(
                  "incorrect value for SGF_SYNC_TIME environment variable, "
                  "used default value %lld instead.",
                  sgf->sync_time / 60 / 1000);

            }

          } else if (!strncmp(env, "SGF_FUZZER_STATS_UPDATE_INTERVAL",

                              sgf_environment_variable_len)) {

            u64 stats_update_freq_sec =
                strtoull(get_afl_env(sgf_environment_variables[i]), NULL, 0);
            if (stats_update_freq_sec >= UINT_MAX ||
                0 == stats_update_freq_sec) {

              WARNF(
                  "Incorrect value given to SGF_FUZZER_STATS_UPDATE_INTERVAL, "
                  "using default of %d seconds\n",
                  STATS_UPDATE_SEC);

            } else {

              sgf->stats_file_update_freq_msecs = stats_update_freq_sec * 1000;

            }

          } else if (!strncmp(env, "SGF_SHA1_FILENAMES",

                              sgf_environment_variable_len)) {

            sgf->sgf_env.sgf_sha1_filenames =
                get_afl_env(sgf_environment_variables[i]) ? 1 : 0;

          } else if (!strncmp(env, "SGF_FORKSRV_UID",

                              sgf_environment_variable_len)) {

            u8   *uid_str = (u8 *)get_afl_env(sgf_environment_variables[i]);
            char *ret;
            int   uid = strtol(uid_str, &ret, 10);
            if (*ret != '\0') {

              WARNF("Incorrect value given to SGF_FORKSRV_UID\n");

            } else {

              sgf->sgf_env.sgf_forksrv_uid_set = 1;
              sgf->sgf_env.sgf_forksrv_uid = uid;

            }

          } else if (!strncmp(env, "SGF_FORKSRV_GID",

                              sgf_environment_variable_len)) {

            u8 *gid_str = (u8 *)get_afl_env(sgf_environment_variables[i]);

            // Count the number of supplementary GIDs
            // and prepare the string for the next loop
            sgf->sgf_env.sgf_forksrv_nb_supl_gids = 0;
            for (u32 i = 0; gid_str[i] != '\0'; i++) {

              if (gid_str[i] == ',') {

                sgf->sgf_env.sgf_forksrv_nb_supl_gids++;
                gid_str[i] = '\0';

              }

            }

            if (sgf->sgf_env.sgf_forksrv_nb_supl_gids > 0) {

              sgf->sgf_env.sgf_forksrv_supl_gids = ck_alloc(
                  sizeof(gid_t) * sgf->sgf_env.sgf_forksrv_nb_supl_gids);

            }

            for (u16 i = 0; i < sgf->sgf_env.sgf_forksrv_nb_supl_gids + 1;
                 i++) {

              char *ret;
              int   gid = strtol(gid_str, &ret, 10);

              if (*ret != '\0') {

                WARNF("Incorrect value given to SGF_FORKSRV_GID\n");

                sgf->sgf_env.sgf_forksrv_gid_set = 0;
                sgf->sgf_env.sgf_forksrv_gid = 0;
                free(sgf->sgf_env.sgf_forksrv_supl_gids);

                break;

              } else {

                // First GID is the effective one, others are supplementary
                // ones.
                if (i == 0) {

                  sgf->sgf_env.sgf_forksrv_gid_set = 1;
                  sgf->sgf_env.sgf_forksrv_gid = gid;

                } else {

                  sgf->sgf_env.sgf_forksrv_supl_gids[i - 1] = gid;

                }

                // Jump to next GID
                gid_str = ret + 1;

              }

            }

          }

        } else {

          i++;

        }

      }

      i = 0;
      while (match == 0 && sgf_environment_variables[i] != NULL) {

        if (strncmp(env, sgf_environment_variables[i],
                    strlen(sgf_environment_variables[i])) == 0 &&
            env[strlen(sgf_environment_variables[i])] == '=') {

          match = 1;

        } else {

          i++;

        }

      }

      i = 0;
      while (match == 0 && sgf_environment_deprecated[i] != NULL) {

        if (strncmp(env, sgf_environment_deprecated[i],
                    strlen(sgf_environment_deprecated[i])) == 0 &&
            env[strlen(sgf_environment_deprecated[i])] == '=') {

          match = 1;

          WARNF("AFL environment variable %s is deprecated!",
                sgf_environment_deprecated[i]);
          issue_detected = 1;

        } else {

          i++;

        }

      }

      if (match == 0) {

        WARNF("Mistyped AFL environment variable: %s", env);
        issue_detected = 1;

        print_suggested_envs(env);

      }

    }

  }

  if (sgf->sgf_env.sgf_pizza_mode > 0) {

    sgf->pizza_is_served = 1;

  } else if (sgf->sgf_env.sgf_pizza_mode < 0) {

    OKF("Pizza easter egg mode is now disabled.");

  }

  if (issue_detected) { sleep(2); }

}

/* Removes this sgf_state instance and frees it. */

void afl_state_deinit(sgf_state_t *sgf) {

  if (sgf->in_place_resume) { ck_free(sgf->in_dir); }
  if (sgf->sync_id) { ck_free(sgf->out_dir); }
  if (sgf->pass_stats) { ck_free(sgf->pass_stats); }
  if (sgf->orig_cmp_map) { ck_free(sgf->orig_cmp_map); }
  if (sgf->cmplog_binary) { ck_free(sgf->cmplog_binary); }
  if (sgf->cycle_schedules) {

    for (u32 i = 0; i < sgf->fsrv.map_size; i++) {

      if (sgf->top_rated_candidates[i]) {

        ck_free(sgf->top_rated_candidates[i]);

      }

    }

    ck_free(sgf->top_rated_candidates);

  }

  afl_free(sgf->queue_buf);
  afl_free(sgf->out_buf);
  afl_free(sgf->out_scratch_buf);
  afl_free(sgf->eff_buf);
  afl_free(sgf->in_buf);
  afl_free(sgf->in_scratch_buf);
  afl_free(sgf->ex_buf);
  afl_free(sgf->alias_table);
  afl_free(sgf->alias_probability);

  ck_free(sgf->virgin_bits);
  ck_free(sgf->virgin_tmout);
  ck_free(sgf->virgin_crash);
  ck_free(sgf->var_bytes);
  ck_free(sgf->top_rated);
  ck_free(sgf->clean_trace);
  ck_free(sgf->clean_trace_custom);
  ck_free(sgf->first_trace);
  ck_free(sgf->map_tmp_buf);

  if (sgf->skel_hash_table) {
    ck_free(sgf->skel_hash_table);
    sgf->skel_hash_table = NULL;
    sgf->skel_hash_cap = 0;
    sgf->skel_hash_count = 0;
  }

  /* Free IJON max tracking state */
  if (sgf->ijon_state) {

    destroy_ijon_min_state((ijon_min_state *)sgf->ijon_state);
    sgf->ijon_state = NULL;
    sgf->ijon_bits = NULL;
    if (sgf->ijon_input_data) {

      ck_free(sgf->ijon_input_data);
      sgf->ijon_input_data = NULL;

    }

    if (sgf->ijon_shared_access) {

      cleanup_dynamic_shared_access(sgf->ijon_shared_access);
      sgf->ijon_shared_access = NULL;

    }

    sgf->ijon_input_len = 0;

  }

  ck_free(sgf->skipdet_g->inf_prof);
  ck_free(sgf->skipdet_g->virgin_det_bits);
  ck_free(sgf->skipdet_g);
  ck_free(sgf->havoc_prof);

  ck_free(sgf->sgf_env.sgf_forksrv_supl_gids);

  list_remove(&sgf_states, sgf);

}

void afl_states_stop(void) {

  /* We may be inside a signal handler.
   Set flags first, send kill signals to child processes later. */
  LIST_FOREACH(&sgf_states, sgf_state_t, {

    el->stop_soon = 1;

  });

  LIST_FOREACH(&sgf_states, sgf_state_t, {

    /* NOTE: We need to make sure that the parent (the forkserver) reap the
     * child (see below). */
    if (el->fsrv.child_pid > 0)
      kill(el->fsrv.child_pid, el->fsrv.child_kill_signal);
    if (el->fsrv.fsrv_pid > 0) {

      kill(el->fsrv.fsrv_pid, el->fsrv.fsrv_kill_signal);
      usleep(100);
      /* Make sure the forkserver does not end up as zombie. */
      waitpid(el->fsrv.fsrv_pid, NULL, WNOHANG);

    }

  });

}

void afl_states_clear_screen(void) {

  LIST_FOREACH(&sgf_states, sgf_state_t, { el->clear_screen = 1; });

}

void afl_states_request_skip(void) {

  LIST_FOREACH(&sgf_states, sgf_state_t, { el->skip_requested = 1; });

}
