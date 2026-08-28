/*
   american fuzzy lop++ - target execution related routines
   --------------------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eissfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com> and
                        Dominik Maier <mail@dmnk.co>

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
#include <sys/time.h>
#include <sys/stat.h>
#include <signal.h>
#include <limits.h>
#include <glob.h>
#if !defined NAME_MAX
  #define NAME_MAX _XOPEN_NAME_MAX
#endif

#include "cmplog.h"
#include "asanfuzz.h"
#include "skeleton_graph_mutator_wrapper.h"
#include "retgraph_shm.h"
#include "shm_next_events.h"

static void skel_hash_init(sgf_state_t *sgf, u32 cap) {
  if (!cap) { cap = 4096; }
  // force power-of-two
  u32 p = 1;
  while (p < cap) { p <<= 1; }
  sgf->skel_hash_cap = p;
  sgf->skel_hash_count = 0;
  sgf->skel_hash_table = ck_alloc(sizeof(u64) * sgf->skel_hash_cap);
  memset(sgf->skel_hash_table, 0, sizeof(u64) * sgf->skel_hash_cap);
}

static u64 saved_non_instantiable_graphs = 0;

void save_non_instantiable_skeleton_graph(sgf_state_t *sgf,
                                             const struct SkeletonGraph *graph,
                                             u8 exit_code,
                                             u32 graph_id) {

  if (unlikely(!sgf || !graph || !sgf->log_graph_run_details)) { return; }

  char *dir = alloc_printf("%s/non_instantiable", sgf->out_dir);
  if (mkdir(dir, 0700) && errno != EEXIST) {

    ck_free(dir);
    return;

  }

  uint8_t *buf = NULL;
  uint32_t len = 0;
  if (serialize_graph_c(graph, &buf, &len) != 0 || !buf || !len) {

    if (buf) { free(buf); }
    ck_free(dir);
    return;

  }

  u32 src_id = sgf->queue_cur ? sgf->queue_cur->id : 0;
  u8  fn[PATH_MAX];
  snprintf((char *)fn, PATH_MAX,
           "%s/non_instantiable/id:%06llu,src:%06u,gid:%06u,exit:%02u.json",
           sgf->out_dir, saved_non_instantiable_graphs, src_id, graph_id,
           exit_code);

  s32 fd = permissive_create(sgf, fn);
  if (fd >= 0) {

    ck_write(fd, buf, len, (char *)fn);
    close(fd);
    saved_non_instantiable_graphs++;

  }

  free(buf);
  ck_free(dir);

}

static void skel_hash_rehash(sgf_state_t *sgf, u32 new_cap) {
  u64 *old_table = sgf->skel_hash_table;
  u32 old_cap = sgf->skel_hash_cap;

  skel_hash_init(sgf, new_cap);
  if (!old_table) { return; }

  for (u32 i = 0; i < old_cap; i++) {
    u64 key = old_table[i];
    if (!key) { continue; }
    u32 mask = sgf->skel_hash_cap - 1;
    u32 idx = (u32)key & mask;
    while (sgf->skel_hash_table[idx]) {
      idx = (idx + 1) & mask;
    }
    sgf->skel_hash_table[idx] = key;
    sgf->skel_hash_count++;
  }

  ck_free(old_table);
}

bool skeleton_graph_seen(sgf_state_t *sgf, const struct SkeletonGraph *graph) {
  if (!sgf || !graph || !sgf->skel_hash_table || sgf->skel_hash_cap == 0) { return false; }

  u64 h = hash_skeleton_graph(graph);
  if (!h) { return false; }

  u64 key = h ^ 0x9e3779b97f4a7c15ULL;
  if (key == 0) { key = 1; }

  u32 mask = sgf->skel_hash_cap - 1;
  u32 idx = (u32)key & mask;
  while (1) {
    u64 slot = sgf->skel_hash_table[idx];
    if (!slot) {
      return false;
    }
    if (slot == key) {
      return true;
    }
    idx = (idx + 1) & mask;
  }
}

bool skeleton_graph_seen_or_add(sgf_state_t *sgf, const struct SkeletonGraph *graph) {
  if (!sgf || !graph) { return false; }

  u64 h = hash_skeleton_graph(graph);
  if (!h) { return false; }

  // Avoid zero sentinel values in table
  u64 key = h ^ 0x9e3779b97f4a7c15ULL;
  if (key == 0) { key = 1; }

  if (!sgf->skel_hash_table || sgf->skel_hash_cap == 0) {
    skel_hash_init(sgf, 4096);
  }

  if (sgf->skel_hash_count * 100 >= sgf->skel_hash_cap * 70) {
    skel_hash_rehash(sgf, sgf->skel_hash_cap << 1);
  }

  u32 mask = sgf->skel_hash_cap - 1;
  u32 idx = (u32)key & mask;
  while (1) {
    u64 slot = sgf->skel_hash_table[idx];
    if (!slot) {
      sgf->skel_hash_table[idx] = key;
      sgf->skel_hash_count++;
      return false;
    }
    if (slot == key) {
      return true;
    }
    idx = (idx + 1) & mask;
  }
}

static void crash_hash_init(sgf_state_t *sgf, u32 cap) {
  if (!cap) { cap = 4096; }
  u32 p = 1;
  while (p < cap) { p <<= 1; }
  sgf->crash_hash_cap = p;
  sgf->crash_hash_count = 0;
  sgf->crash_hash_table = ck_alloc(sizeof(u64) * sgf->crash_hash_cap);
  memset(sgf->crash_hash_table, 0, sizeof(u64) * sgf->crash_hash_cap);
}

static void crash_hash_rehash(sgf_state_t *sgf, u32 new_cap) {
  u64 *old_table = sgf->crash_hash_table;
  u32 old_cap = sgf->crash_hash_cap;
  crash_hash_init(sgf, new_cap);
  if (!old_table) { return; }
  for (u32 i = 0; i < old_cap; i++) {
    u64 key = old_table[i];
    if (!key) { continue; }
    u32 mask = sgf->crash_hash_cap - 1;
    u32 idx = (u32)key & mask;
    while (sgf->crash_hash_table[idx]) {
      idx = (idx + 1) & mask;
    }
    sgf->crash_hash_table[idx] = key;
    sgf->crash_hash_count++;
  }
  ck_free(old_table);
}

// Returns true if this exact crashing skeleton graph structure has been seen
// before (a duplicate crash), false and records it if it is genuinely new.
// Independent of non_instrumented_mode, since this project's instrumented
// binaries don't emit an AFL-style coverage bitmap -- the virgin_crash check
// in save_if_interesting_skeleton is a no-op for these targets, so this is
// the only real crash-uniqueness signal available.
bool crash_graph_seen_or_add(sgf_state_t *sgf, const struct SkeletonGraph *graph) {
  if (!sgf || !graph) { return false; }

  u64 h = hash_skeleton_graph(graph);
  if (!h) { return false; }

  u64 key = h ^ 0x9e3779b97f4a7c15ULL;
  if (key == 0) { key = 1; }

  if (!sgf->crash_hash_table || sgf->crash_hash_cap == 0) {
    crash_hash_init(sgf, 4096);
  }

  if (sgf->crash_hash_count * 100 >= sgf->crash_hash_cap * 70) {
    crash_hash_rehash(sgf, sgf->crash_hash_cap << 1);
  }

  u32 mask = sgf->crash_hash_cap - 1;
  u32 idx = (u32)key & mask;
  while (1) {
    u64 slot = sgf->crash_hash_table[idx];
    if (!slot) {
      sgf->crash_hash_table[idx] = key;
      sgf->crash_hash_count++;
      return false;
    }
    if (slot == key) {
      return true;
    }
    idx = (idx + 1) & mask;
  }
}


#ifdef PROFILING
u64 time_spent_working = 0;
#endif

/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update sgf->fsrv->trace_bits. */

fsrv_run_result_t __attribute__((hot)) fuzz_run_target(sgf_state_t      *sgf,
                                                       sgf_forkserver_t *fsrv,
                                                       u32 timeout) {

#ifdef PROFILING
  static u64      time_spent_start = 0;
  struct timespec spec;
  if (time_spent_start) {

    u64 current;
    clock_gettime(CLOCK_REALTIME, &spec);
    current = (spec.tv_sec * 1000000000) + spec.tv_nsec;
    time_spent_working += (current - time_spent_start);

  }

#endif

  fsrv_run_result_t res = afl_fsrv_run_target(fsrv, timeout, &sgf->stop_soon);

#ifdef __AFL_CODE_COVERAGE
  if (unlikely(!fsrv->persistent_trace_bits)) {

    // On the first run, we allocate the persistent map to collect coverage.
    fsrv->persistent_trace_bits = (u8 *)malloc(fsrv->map_size);
    memset(fsrv->persistent_trace_bits, 0, fsrv->map_size);

  }

  for (u32 i = 0; i < fsrv->map_size; ++i) {

    if (fsrv->persistent_trace_bits[i] != 255 && fsrv->trace_bits[i]) {

      fsrv->persistent_trace_bits[i]++;

    }

  }

#endif

  /* If post_run() function is defined in custom mutator, the function will be
     called each time after AFL++ executes the target program. */

  if (unlikely(sgf->custom_mutators_count)) {

    LIST_FOREACH(&sgf->custom_mutator_list, struct custom_mutator, {

      if (unlikely(el->afl_custom_post_run)) {

        el->afl_custom_post_run(el->data);

      }

    });

  }

  /* Check for new IJON max values after execution */
  if (unlikely(fsrv->use_ijon && sgf->ijon_state && sgf->ijon_bits)) {

    /* UNIFIED SHARED MEMORY ACCESS: Always use dynamic allocation */

    // Get current input data for IJON processing
    u8 *input_data = NULL;
    u32 input_len = 0;

    /* Read input data from testcase file that was just executed */
    if (sgf->fsrv.out_file) {

      struct stat st;
      if (stat(sgf->fsrv.out_file, &st) == 0) {

        if (st.st_size > 0) {

          input_len = st.st_size;
          input_data = ck_alloc(input_len);

          int fd = open(sgf->fsrv.out_file, O_RDONLY);
          if (fd >= 0) {

            ssize_t bytes_read = read(fd, input_data, input_len);
            close(fd);

            if (bytes_read != input_len) {

              ck_free(input_data);
              input_data = NULL;
              input_len = 0;

            }

          } else {

            ck_free(input_data);
            input_data = NULL;
            input_len = 0;

          }

        }

      }

    }

    if (input_data) {

      /* Use pre-initialized shared_access from sgf state */
      ijon_update_max_dynamic(sgf->ijon_state, sgf->ijon_shared_access,
                              input_data, input_len);

    }

    if (input_data) {

      ck_free(input_data);
      input_data = NULL;

    }

  }

#ifdef PROFILING
  clock_gettime(CLOCK_REALTIME, &spec);
  time_spent_start = (spec.tv_sec * 1000000000) + spec.tv_nsec;
#endif

  return res;

}

/* Write modified data to file for testing. If sgf->fsrv.out_file is set, the
   old file is unlinked and a new one is created. Otherwise, sgf->fsrv.out_fd is
   rewound and truncated. */

u32 __attribute__((hot)) write_to_testcase(sgf_state_t *sgf, void **mem,
                                           u32 len, u32 fix) {

  u8 sent = 0;

  if (unlikely(sgf->custom_mutators_count)) {

    ssize_t new_size = len;
    u8     *new_mem = *mem;
    u8     *new_buf = NULL;

    LIST_FOREACH(&sgf->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_post_process) {

        new_size =
            el->afl_custom_post_process(el->data, new_mem, new_size, &new_buf);

        if (unlikely(!new_buf || new_size <= 0)) {

          new_size = 0;
          new_buf = new_mem;
          // FATAL("Custom_post_process failed (ret: %lu)", (long
          // unsigned)new_size);

        } else {

          new_mem = new_buf;

        }

      }

    });

    if (unlikely(!new_size)) {

      // perform dummy runs (fix = 1), but skip all others
      if (fix) {

        new_size = len;

      } else {

        return 0;

      }

    }

    if (unlikely(new_size < sgf->min_length && !fix)) {

      new_size = sgf->min_length;

    } else if (unlikely(new_size > sgf->max_length)) {

      new_size = sgf->max_length;

    }

    if (new_mem != *mem && new_mem != NULL && new_size > 0) {

      new_buf = afl_realloc(SGF_BUF_PARAM(out_scratch), new_size);
      if (unlikely(!new_buf)) { PFATAL("alloc"); }
      memcpy(new_buf, new_mem, new_size);

      /* if SGF_POST_PROCESS_KEEP_ORIGINAL is set then save the original memory
         prior post-processing in new_mem to restore it later */
      if (unlikely(sgf->sgf_env.sgf_post_process_keep_original)) {

        new_mem = *mem;

      }

      *mem = new_buf;
      afl_swap_bufs(SGF_BUF_PARAM(out), SGF_BUF_PARAM(out_scratch));

    }

    LIST_FOREACH(&sgf->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_fuzz_send) {

        if (!sgf->sgf_env.sgf_custom_mutator_late_send) {

          el->afl_custom_fuzz_send(el->data, *mem, new_size);

        } else {

          sgf->fsrv.custom_input = *mem;
          sgf->fsrv.custom_input_len = new_size;

        }

        sent = 1;

      }

    });

    if (likely(!sent)) {

      /* everything as planned. use the potentially new data. */
      afl_fsrv_write_to_testcase(&sgf->fsrv, *mem, new_size);

    }

    if (likely(!sgf->sgf_env.sgf_post_process_keep_original)) {

      len = new_size;

    } else {

      /* restore the original memory which was saved in new_mem */
      *mem = new_mem;
      afl_swap_bufs(SGF_BUF_PARAM(out), SGF_BUF_PARAM(out_scratch));

    }

  } else {                                   /* !sgf->custom_mutators_count */

    if (unlikely(len < sgf->min_length && !fix)) {

      len = sgf->min_length;

    } else if (unlikely(len > sgf->max_length)) {

      len = sgf->max_length;

    }

    /* boring uncustom. */
    afl_fsrv_write_to_testcase(&sgf->fsrv, *mem, len);

  }

#ifdef _AFL_DOCUMENT_MUTATIONS
  s32  doc_fd;
  char fn[PATH_MAX];
  snprintf(fn, PATH_MAX, "%s/mutations/%09u:%s", sgf->out_dir,
           sgf->document_counter++,
           describe_op(sgf, 0, NAME_MAX - strlen("000000000:")));

  if ((doc_fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, sgf->perm)) >= 0) {

    if (write(doc_fd, *mem, len) != len)
      PFATAL("write to mutation file failed: %s", fn);

    if (sgf->chown_needed) {

      if (fchown(doc_fd, -1, sgf->fsrv.gid) == -1) {

        PFATAL("fchown() failed");

      }

    }

    close(doc_fd);

  }

#endif

  return len;

}

/* The same, but with an adjustable gap. Used for trimming. */

static void write_with_gap(sgf_state_t *sgf, u8 *mem, u32 len, u32 skip_at,
                           u32 skip_len) {

  s32 fd = sgf->fsrv.out_fd;
  u32 tail_len = len - skip_at - skip_len;

  /*
  This memory is used to carry out the post_processing(if present) after copying
  the testcase by removing the gaps. This can break though
  */
  u8 *mem_trimmed = afl_realloc(SGF_BUF_PARAM(out_scratch), len - skip_len + 1);
  if (unlikely(!mem_trimmed)) { PFATAL("alloc"); }

  ssize_t new_size = len - skip_len;
  u8     *new_mem = mem;

  bool post_process_skipped = true;

  if (unlikely(sgf->custom_mutators_count)) {

    u8 *new_buf = NULL;
    new_mem = mem_trimmed;

    LIST_FOREACH(&sgf->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_post_process) {

        // We copy into the mem_trimmed only if we actually have custom mutators
        // *with* post_processing installed

        if (post_process_skipped) {

          if (skip_at) { memcpy(mem_trimmed, (u8 *)mem, skip_at); }

          if (tail_len) {

            memcpy(mem_trimmed + skip_at, (u8 *)mem + skip_at + skip_len,
                   tail_len);

          }

          post_process_skipped = false;

        }

        new_size =
            el->afl_custom_post_process(el->data, new_mem, new_size, &new_buf);

        if (unlikely(!new_buf && new_size <= 0)) {

          new_size = 0;
          new_buf = new_mem;
          // FATAL("Custom_post_process failed (ret: %lu)", (long
          // unsigned)new_size);

        } else {

          new_mem = new_buf;

        }

      }

    });

  }

  if (likely(sgf->fsrv.use_shmem_fuzz)) {

    if (!post_process_skipped) {

      // If we did post_processing, copy directly from the new_mem buffer

      memcpy(sgf->fsrv.shmem_fuzz, new_mem, new_size);

    } else {

      memcpy(sgf->fsrv.shmem_fuzz, mem, skip_at);

      memcpy(sgf->fsrv.shmem_fuzz + skip_at, mem + skip_at + skip_len,
             tail_len);

    }

    *sgf->fsrv.shmem_fuzz_len = new_size;

#ifdef _DEBUG
    if (sgf->debug) {

      fprintf(
          stderr, "FS crc: %16llx len: %u\n",
          hash64(sgf->fsrv.shmem_fuzz, *sgf->fsrv.shmem_fuzz_len, HASH_CONST),
          *sgf->fsrv.shmem_fuzz_len);
      fprintf(stderr, "SHM :");
      for (u32 i = 0; i < *sgf->fsrv.shmem_fuzz_len; i++)
        fprintf(stderr, "%02x", sgf->fsrv.shmem_fuzz[i]);
      fprintf(stderr, "\nORIG:");
      for (u32 i = 0; i < *sgf->fsrv.shmem_fuzz_len; i++)
        fprintf(stderr, "%02x", (u8)((u8 *)mem)[i]);
      fprintf(stderr, "\n");

    }

#endif

    return;

  } else if (unlikely(!sgf->fsrv.use_stdin)) {

    if (unlikely(sgf->no_unlink)) {

      fd = open(sgf->fsrv.out_file, O_WRONLY | O_CREAT | O_TRUNC, sgf->perm);

    } else {

      unlink(sgf->fsrv.out_file);                         /* Ignore errors. */
      fd = open(sgf->fsrv.out_file, O_WRONLY | O_CREAT | O_EXCL, sgf->perm);

    }

    if (fd < 0) { PFATAL("Unable to create '%s'", sgf->fsrv.out_file); }

    if (sgf->chown_needed) {

      if (fchown(fd, -1, sgf->fsrv.gid) == -1) { PFATAL("fchown() failed"); }

    }

  } else {

    lseek(fd, 0, SEEK_SET);

  }

  if (!post_process_skipped) {

    ck_write(fd, new_mem, new_size, sgf->fsrv.out_file);

  } else {

    ck_write(fd, mem, skip_at, sgf->fsrv.out_file);

    ck_write(fd, mem + skip_at + skip_len, tail_len, sgf->fsrv.out_file);

  }

  if (sgf->fsrv.use_stdin) {

    if (ftruncate(fd, new_size)) { PFATAL("ftruncate() failed"); }
    lseek(fd, 0, SEEK_SET);

  } else {

    close(fd);

  }

}

/* Calibrate a new test case. This is done when processing the input directory
   to warn about flaky or otherwise problematic test cases early on; and when
   new paths are discovered to detect variable behavior and so on. */

u8 calibrate_case(sgf_state_t *sgf, struct queue_entry *q, u8 *use_mem,
                  u32 handicap, u8 from_queue) {

  u8 fault = 0, new_bits = 0, var_detected = 0, hnb = 0,
     first_run = (q->exec_cksum == 0);
  u64 start_us, stop_us, diff_us;
  s32 old_sc = sgf->stage_cur, old_sm = sgf->stage_max;
  u32 use_tmout = sgf->fsrv.exec_tmout;
  u8 *old_sn = sgf->stage_name;

  u64 calibration_start_us = get_cur_time_us();
  if (unlikely(sgf->shm.cmplog_mode)) { q->exec_cksum = 0; }

  /* Be a bit more generous about timeouts when resuming sessions, or when
     trying to calibrate already-added finds. This helps avoid trouble due
     to intermittent latency. */

  if (!from_queue || sgf->resuming_fuzz) {

    use_tmout = MAX(sgf->fsrv.exec_tmout + CAL_TMOUT_ADD,
                    sgf->fsrv.exec_tmout * CAL_TMOUT_PERC / 100);

  }

  ++q->cal_failed;

  sgf->stage_name = "calibration";
  sgf->stage_max = sgf->sgf_env.sgf_cal_fast ? CAL_CYCLES_FAST : CAL_CYCLES;

  /* Make sure the forkserver is up before we do anything, and let's not
     count its spin-up time toward binary calibration. */

  if (!sgf->fsrv.fsrv_pid) {

    afl_fsrv_start(&sgf->fsrv, sgf->argv, &sgf->stop_soon,
                   sgf->sgf_env.sgf_debug_child);

    if (sgf->fsrv.support_shmem_fuzz && !sgf->fsrv.use_shmem_fuzz) {

      afl_shm_deinit(sgf->shm_fuzz);
      ck_free(sgf->shm_fuzz);
      sgf->shm_fuzz = NULL;
      sgf->fsrv.support_shmem_fuzz = 0;
      sgf->fsrv.shmem_fuzz = NULL;

    }

  }

  u8 saved_afl_post_process_keep_original =
      sgf->sgf_env.sgf_post_process_keep_original;
  sgf->sgf_env.sgf_post_process_keep_original = 1;

  /* we need a dummy run if this is LTO + cmplog */
  /*
    if (unlikely(sgf->shm.cmplog_mode)) {

      (void)write_to_testcase(sgf, (void **)&use_mem, q->len, 1);

      fault = fuzz_run_target(sgf, &sgf->fsrv, use_tmout);

      // sgf->stop_soon is set by the handler for Ctrl+C. When it's pressed,
      // we want to bail out quickly.

      if (sgf->stop_soon || fault != sgf->crash_mode) { goto abort_calibration;

  }

      if (!sgf->non_instrumented_mode &&
          !count_bytes(sgf, sgf->fsrv.trace_bits)) {

        fault = FSRV_RUN_NOINST;
        goto abort_calibration;

      }

  #ifdef INTROSPECTION
      if (unlikely(!q->bitsmap_size)) { q->bitsmap_size = sgf->bitsmap_size; }
  #endif

    }

  */

  if (q->exec_cksum) {

    memcpy(sgf->first_trace, sgf->fsrv.trace_bits, sgf->fsrv.map_size);
    hnb = has_new_bits(sgf, sgf->virgin_bits);
    if (unlikely(hnb > new_bits)) { new_bits = hnb; }

  }

  start_us = get_cur_time_us();

  for (sgf->stage_cur = 0; sgf->stage_cur < sgf->stage_max; ++sgf->stage_cur) {

    if (unlikely(sgf->debug)) {

      DEBUGF("calibration stage %d/%d\n", sgf->stage_cur + 1, sgf->stage_max);

    }

    u64 cksum;

    (void)write_to_testcase(sgf, (void **)&use_mem, q->len, 1);

    fault = fuzz_run_target(sgf, &sgf->fsrv, use_tmout);

    // update the time spend in calibration after each execution, as those may
    // be slow
    update_calibration_time(sgf, &calibration_start_us);

    if (WIFEXITED(sgf->fsrv.child_status)) {
      int exit_code = WEXITSTATUS(sgf->fsrv.child_status);
      if (exit_code == EXIT_EVENT_MISMATCH ||
          exit_code == EXIT_RF_TYPE_MISMATCH ||
          exit_code == EXIT_NOT_INSTANTIABLE) {
        if (q->graph_data) {
          q->graph_data->sim_exit_code = (u8)exit_code;
          q->graph_data->non_instantiable = 1;
        }
        fault = FSRV_RUN_NOINST;
        goto abort_calibration;
      }
    }

    /* sgf->stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. */

    if (sgf->stop_soon || fault != sgf->crash_mode) { goto abort_calibration; }

    if (!sgf->non_instrumented_mode &&
        !count_bytes(sgf, sgf->fsrv.trace_bits)) {

      fault = FSRV_RUN_NOINST;
      goto abort_calibration;

    }

#ifdef INTROSPECTION
    if (unlikely(!q->bitsmap_size)) { q->bitsmap_size = sgf->bitsmap_size; }
#endif

    classify_counts(&sgf->fsrv);
    cksum = hash64(sgf->fsrv.trace_bits, sgf->fsrv.map_size, HASH_CONST);

    if (unlikely(q->exec_cksum != cksum)) {

      hnb = has_new_bits(sgf, sgf->virgin_bits);

      if (unlikely(hnb > new_bits)) { new_bits = hnb; }

      if (likely(q->exec_cksum)) {

        u32 i;

        for (i = 0; i < sgf->fsrv.map_size; ++i) {

          if (unlikely(!sgf->var_bytes[i]) &&
              unlikely(sgf->first_trace[i] != sgf->fsrv.trace_bits[i])) {

            sgf->var_bytes[i] = 1;
            // ignore the variable edge by setting it to fully discovered
            sgf->virgin_bits[i] = 0;

          }

        }

        if (unlikely(!var_detected && !sgf->sgf_env.sgf_no_warn_instability)) {

          // note: from_queue seems to only be set during initialization
          if (sgf->sgf_env.sgf_no_ui || from_queue) {

            WARNF("instability detected during calibration: %s", q->fname);

          } else if (sgf->debug) {

            DEBUGF("instability detected during calibration: %s\n", q->fname);

          }

        }

        var_detected = 1;
        sgf->stage_max =
            sgf->sgf_env.sgf_cal_fast ? CAL_CYCLES : CAL_CYCLES_LONG;

      } else {

        q->exec_cksum = cksum;
        memcpy(sgf->first_trace, sgf->fsrv.trace_bits, sgf->fsrv.map_size);

      }

    }

  }

  if (unlikely(sgf->fixed_seed)) {

    diff_us = (u64)(sgf->fsrv.exec_tmout - 1) * (u64)sgf->stage_max;

  } else {

    stop_us = get_cur_time_us();
    diff_us = stop_us - start_us;
    if (unlikely(!diff_us)) { ++diff_us; }

  }

  sgf->total_cal_us += diff_us;
  sgf->total_cal_cycles += sgf->stage_max;

  /* OK, let's collect some stats about the performance of this test case.
     This is used for fuzzing air time calculations in calculate_score(). */

  if (unlikely(!sgf->stage_max)) {

    // Pretty sure this cannot happen, yet scan-build complains.
    FATAL("BUG: stage_max should not be 0 here! Please report this condition.");

  }

  q->exec_us = diff_us / sgf->stage_max;
  if (unlikely(!q->exec_us)) { q->exec_us = 1; }

  q->bitmap_size = count_bytes(sgf, sgf->fsrv.trace_bits);
  q->handicap = handicap;
  q->cal_failed = 0;

  sgf->total_bitmap_size += q->bitmap_size;
  ++sgf->total_bitmap_entries;

  update_bitmap_score(sgf, q, true);

  /* If this case didn't result in new output from the instrumentation, tell
     parent. This is a non-critical problem, but something to warn the user
     about. */

  if (!sgf->non_instrumented_mode && first_run && !fault && !new_bits) {

    fault = FSRV_RUN_NOBITS;

  }

abort_calibration:

  sgf->sgf_env.sgf_post_process_keep_original =
      saved_afl_post_process_keep_original;

  if (new_bits == 2 && !q->has_new_cov) {

    q->has_new_cov = 1;
    ++sgf->queued_with_cov;

  }

  /* Mark variable paths. */

  if (var_detected) {

    sgf->var_byte_count = count_bytes(sgf, sgf->var_bytes);

    if (!q->var_behavior) { ++sgf->queued_variable; }

  }

  sgf->stage_name = old_sn;
  sgf->stage_cur = old_sc;
  sgf->stage_max = old_sm;

  if (!first_run) { show_stats(sgf); }

  update_calibration_time(sgf, &calibration_start_us);
  return fault;

}

/* Do not sync items that were synced from us */

static bool is_known_case(sgf_state_t *sgf, u8 *name) {

  static char coming_from_me_str[SYNC_ID_MAX_LEN + 2];
  static u32  coming_from_me_len = 0;
  static u32  min_len = 15 + 4 + 6;

  if (!coming_from_me_len) {

    snprintf(coming_from_me_str, sizeof(coming_from_me_str), "%s,",
             sgf->sync_id);
    min_len += coming_from_me_len = strlen(coming_from_me_str);

  }

  // file name length long enough so it can be ours
  if (unlikely(strlen(name) < min_len)) { return false; }
  // is it based on a sync? allow optimizer to make an integer comparison
  if (likely(memcmp(name + 10, "sync", 4) != 0)) { return false; }
  // we jump over the ':' after 'sync' and compare to our sync name
  if (unlikely(memcmp(name + 15, coming_from_me_str, coming_from_me_len) !=
               0)) {

    return false;

  }

  /* We do not need this as we now look on startup how many files are in sync
     targets.
  int src_id = atoi(name + 15 + coming_from_me_len + 4);
  if (unlikely(src_id >= sgf->queued_items)) return false;
  */

  // yes it is highly likely a current testcase we already know
  return true;

}

/* Write into .sync/INSTANCE.max how many queue files were there on startup */

void check_sync_fuzzers(sgf_state_t *sgf) {

  if (unlikely(sgf->sgf_env.sgf_no_sync)) { return; }

  DIR           *sd, *dir;
  struct dirent *sd_ent, *entry;
  u8  qd_path[PATH_MAX], qd_synced_maxid[PATH_MAX], qd_main_path[PATH_MAX];
  int have_main = sgf->is_main_node;

  sd = opendir(sgf->sync_dir);
  if (!sd) { PFATAL("Unable to open '%s'", sgf->sync_dir); }

  u64 sync_start_us = get_cur_time_us();
  // Look at the entries created for every other fuzzer in the sync directory.

  while ((sd_ent = readdir(sd))) {

    if (sd_ent->d_name[0] == '.' || !strcmp(sgf->sync_id, sd_ent->d_name)) {

      continue;

    }

    sprintf(qd_path, "%s/%s/queue", sgf->sync_dir, sd_ent->d_name);

    dir = opendir(qd_path);
    if (dir) {

      u32 max_start_id = 0;
      while ((entry = readdir(dir)) != NULL) {

        if (likely(entry->d_name[0] != '.')) { max_start_id++; }

      }

      if (max_start_id) {

        sprintf(qd_synced_maxid, "%s/.synced/%s.max", sgf->out_dir,
                sd_ent->d_name);
        s32 max_fd = open(qd_synced_maxid, O_WRONLY | O_CREAT | O_TRUNC,
                          DEFAULT_PERMISSION);

        if (max_fd >= 0) {

          --max_start_id;  // counting from 0
          if (unlikely(write(max_fd, &max_start_id, sizeof(u32)) !=
                       sizeof(u32))) {

            /* Ignore write failure - sync will continue */

          }

          close(max_fd);

        }

      }

      closedir(dir);

    }

    if (!have_main) {

      sprintf(qd_main_path, "%s/%s/is_main_node", sgf->sync_dir,
              sd_ent->d_name);
      if (access(qd_main_path, F_OK) == 0) { have_main = 1; }

    }

  }

  closedir(sd);

  if (!have_main) {

    sgf->is_main_node = 1;
    sprintf(qd_path, "%s/is_main_node", sgf->out_dir);
    int id_fd = open(qd_main_path, O_RDWR | O_CREAT, sgf->perm);
    if (id_fd >= 0) { close(id_fd); }

  }

  update_sync_time(sgf, &sync_start_us);

}

/* Grab interesting test cases from other fuzzers. */

void sync_fuzzers(sgf_state_t *sgf) {

  if (unlikely(sgf->sgf_env.sgf_no_sync)) { return; }

  DIR           *sd;
  struct dirent *sd_ent;
  u32            sync_cnt = 0, synced = 0, entries = 0;
  u8             path[PATH_MAX + 1 + NAME_MAX];

  sd = opendir(sgf->sync_dir);
  if (!sd) { PFATAL("Unable to open '%s'", sgf->sync_dir); }

  sgf->stage_max = sgf->stage_cur = 0;
  sgf->cur_depth = 0;

  u64 sync_start_us = get_cur_time_us();
  // Look at the entries created for every other fuzzer in the sync directory.

  while ((sd_ent = readdir(sd))) {

    // since sync can take substantial amounts of time, update time spend every
    // iteration
    update_sync_time(sgf, &sync_start_us);

    u8  qd_synced_path[PATH_MAX], qd_path[PATH_MAX], qd_synced_maxid[PATH_MAX];
    u32 min_accept = 0, next_min_accept = 0, max_start_id = 0;
    s32 id_fd;

    // Skip dot files and our own output directory.

    if (unlikely(sd_ent->d_name[0] == '.' ||
                 !strcmp(sgf->sync_id, sd_ent->d_name))) {

      continue;

    }

    entries++;

    // secondary nodes only syncs from main, the main node syncs from everyone
    if (likely(sgf->is_secondary_node)) {

      sprintf(qd_path, "%s/%s/is_main_node", sgf->sync_dir, sd_ent->d_name);
      int res = access(qd_path, F_OK);
      if (unlikely(sgf->is_main_node)) {  // an elected temporary main node

        if (likely(res == 0)) {  // there is another main node? downgrade.

          sgf->is_main_node = 0;
          sprintf(qd_path, "%s/is_main_node", sgf->out_dir);
          unlink(qd_path);

        }

      } else {

        if (likely(res != 0)) { continue; }

      }

    }

    synced++;

    // Skip anything that doesn't have a queue/ subdirectory.

    sprintf(qd_path, "%s/%s/queue", sgf->sync_dir, sd_ent->d_name);

    struct dirent **namelist = NULL;
    int             m = 0, n, o;

    n = scandir(qd_path, &namelist, NULL, alphasort);

    if (n < 1) {

      if (namelist) free(namelist);
      continue;

    }

    // Retrieve the ID of the last seen test case.

    sprintf(qd_synced_path, "%s/.synced/%s", sgf->out_dir, sd_ent->d_name);

    id_fd = open(qd_synced_path, O_RDWR | O_CREAT, sgf->perm);

    if (id_fd < 0) { PFATAL("Unable to create '%s'", qd_synced_path); }

    if (sgf->chown_needed) {

      if (fchown(id_fd, -1, sgf->fsrv.gid) == -1) { PFATAL("fchown() failed"); }

    }

    if (read(id_fd, &min_accept, sizeof(u32)) == sizeof(u32)) {

      next_min_accept = min_accept;
      lseek(id_fd, 0, SEEK_SET);

    }

    // now document the attempt to sync to this instance
    sprintf(qd_synced_path, "%s/.synced/%s.last", sgf->out_dir, sd_ent->d_name);
    int id_fd2 =
        open(qd_synced_path, O_RDWR | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);
    if (id_fd2 >= 0) close(id_fd2);

    // It could be that the target syncing instance was restarted, check!
    time_t      last_mtime = 0;
    char        id0[PATH_MAX];
    struct stat st;

    if (stat(qd_synced_path, &st) == 0) { last_mtime = st.st_mtime; }

    snprintf(id0, sizeof(id0), "%s/%s/cmdline", sgf->sync_dir, sd_ent->d_name);

    if (likely(stat(id0, &st) == 0)) {

      if (unlikely(last_mtime && last_mtime <= st.st_mtime)) {

        // the first entry is newer than when we synced last - instance was
        // restarted - we have to reset our counter and will skip this instance
        // this time. It could also be this was trimmed later, or restated with
        // resume-in-place though but better be safe.
        min_accept = 0;
        ck_write(id_fd, &min_accept, sizeof(u32), qd_synced_path);
        goto close_sync;

      }

    }  // else { This is likely a non-AFL++ but compliant instance, e.g. SymCC }

    // check if there is a file documented the maximum id seen on startup
    sprintf(qd_synced_maxid, "%s/.synced/%s.max", sgf->out_dir, sd_ent->d_name);
    s32 max_fd = open(qd_synced_maxid, O_RDONLY, DEFAULT_PERMISSION);

    if (likely(max_fd >= 0)) {

      if (unlikely(read(max_fd, &max_start_id, sizeof(u32)) != sizeof(u32))) {

        /* Use default value on read failure */
        max_start_id = 0;

      }

      close(max_fd);
      if (max_start_id < next_min_accept) { unlink(qd_synced_maxid); }

    }

    /* Show stats */

    snprintf(sgf->stage_name_buf, STAGE_BUF_SIZE, "sync %u", ++sync_cnt);

    sgf->stage_name = sgf->stage_name_buf;
    sgf->stage_cur = 0;
    sgf->stage_max = 0;

    show_stats(sgf);

    /* For every file queued by this fuzzer, parse ID and see if we have
       looked at it before; exec a test case if not. */

    u8 entry[12];
    sprintf(entry, "id:%06u", next_min_accept);

    while (m < n) {

      if (strncmp(namelist[m]->d_name, entry, 9)) {

        m++;

      } else {

        break;

      }

    }

    if (m >= n) { goto close_sync; }  // nothing new

    for (o = m; o < n; o++) {

      s32         fd;
      struct stat st;

      snprintf(path, sizeof(path), "%s/%s", qd_path, namelist[o]->d_name);
      sgf->syncing_case = next_min_accept;
      next_min_accept++;

      /* Allow this to fail in case the other fuzzer is resuming or so... */

      fd = open(path, O_RDONLY);

      if (fd < 0) { continue; }

      if (fstat(fd, &st)) { WARNF("fstat() failed"); }

      /* Ignore zero-sized or oversized files. */

      if (st.st_size && st.st_size <= MAX_FILE) {

        if (likely(next_min_accept < max_start_id ||
                   !is_known_case(sgf, namelist[o]->d_name))) {

          /* See what happens. We rely on save_if_interesting() to catch major
             errors and save the test case. */

          u8 *mem = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

          if (mem == MAP_FAILED) { PFATAL("Unable to mmap '%s'", path); }

          u32 new_len = write_to_testcase(sgf, (void **)&mem, st.st_size, 1);

          u8 fault = fuzz_run_target(sgf, &sgf->fsrv, sgf->fsrv.exec_tmout);

          if (sgf->stop_soon) {

            munmap(mem, st.st_size);
            close(fd);

            goto close_sync;

          }

          sgf->syncing_party = sd_ent->d_name;
          sgf->queued_imported += save_if_interesting(sgf, mem, new_len, fault, 0, MAP_SIZE);
          show_stats(sgf);
          sgf->syncing_party = 0;
          munmap(mem, st.st_size);

        }

      }

      close(fd);

    }

    ck_write(id_fd, &next_min_accept, sizeof(u32), qd_synced_path);

  close_sync:
    close(id_fd);
    if (n > 0)
      for (m = 0; m < n; m++)
        free(namelist[m]);
    free(namelist);

  }

  closedir(sd);

  // If we are a secondary and no main was found to sync then become the main
  if (unlikely(synced == 0) && likely(entries) &&
      likely(sgf->is_secondary_node)) {

    // there is a small race condition here that another secondary runs at the
    // same time. If so, the first temporary main node running again will demote
    // themselves so this is not an issue

    //    u8 path2[PATH_MAX];
    sgf->is_main_node = 1;
    sprintf(path, "%s/is_main_node", sgf->out_dir);
    int fd = open(path, O_CREAT | O_RDWR, 0644);
    if (fd >= 0) { close(fd); }

  }

  if (sgf->foreign_sync_cnt) read_foreign_testcases(sgf, 0);

  // add time in sync one last time
  update_sync_time(sgf, &sync_start_us);

  sgf->last_sync_time = get_cur_time();
  sgf->last_sync_cycle = sgf->queue_cycle;

}

/* Trim all new test cases to save cycles when doing deterministic checks. The
   trimmer uses power-of-two increments somewhere between 1/16 and 1/1024 of
   file size, to keep the stage short and sweet. */

u8 trim_case(sgf_state_t *sgf, struct queue_entry *q, u8 *in_buf) {

  u8  needs_write = 0, fault = 0;
  u32 orig_len = q->len;
  u64 trim_start_us = get_cur_time_us();
  sgf->bytes_trim_in += orig_len;

  /* Custom mutator trimmer */
  if (sgf->custom_mutators_count) {

    u8   trimmed_case = 0;
    bool custom_trimmed = false;

    LIST_FOREACH(&sgf->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_trim) {

        trimmed_case = trim_case_custom(sgf, q, in_buf, el);
        custom_trimmed = true;

      }

    });

    if (orig_len != q->len || custom_trimmed) {

      queue_testcase_retake(sgf, q, orig_len);

    }

    if (custom_trimmed) {

      fault = trimmed_case;
      goto abort_trimming;

    }

  }

  u32 trim_exec = 0;
  u32 remove_len;
  u32 len_p2;

  u8 val_bufs[2][STRINGIFY_VAL_SIZE_MAX];

  /* Although the trimmer will be less useful when variable behavior is
     detected, it will still work to some extent, so we don't check for
     this. */

  if (unlikely(q->len < 5)) {

    fault = 0;
    goto abort_trimming;

  }

  sgf->stage_name = sgf->stage_name_buf;

  /* Select initial chunk len, starting with large steps. */

  len_p2 = next_pow2(q->len);

  remove_len = MAX(len_p2 / TRIM_START_STEPS, (u32)TRIM_MIN_BYTES);

  /* Continue until the number of steps gets too high or the stepover
     gets too small. */

  while (remove_len >= MAX(len_p2 / TRIM_END_STEPS, (u32)TRIM_MIN_BYTES)) {

    u32 remove_pos = remove_len;

    sprintf(sgf->stage_name_buf, "trim %s/%s",
            u_stringify_int(val_bufs[0], remove_len),
            u_stringify_int(val_bufs[1], remove_len));

    sgf->stage_cur = 0;
    sgf->stage_max = q->len / remove_len;

    while (remove_pos < q->len) {

      u32 trim_avail = MIN(remove_len, q->len - remove_pos);
      u64 cksum;

      write_with_gap(sgf, in_buf, q->len, remove_pos, trim_avail);

      fault = fuzz_run_target(sgf, &sgf->fsrv, sgf->fsrv.exec_tmout);

      update_trim_time(sgf, &trim_start_us);

      if (sgf->stop_soon || fault == FSRV_RUN_ERROR) { goto abort_trimming; }

      /* Note that we don't keep track of crashes or hangs here; maybe TODO?
       */

      ++sgf->trim_execs;
      classify_counts(&sgf->fsrv);
      cksum = hash64(sgf->fsrv.trace_bits, sgf->fsrv.map_size, HASH_CONST);

      /* If the deletion had no impact on the trace, make it permanent. This
         isn't perfect for variable-path inputs, but we're just making a
         best-effort pass, so it's not a big deal if we end up with false
         negatives every now and then. */

      if (cksum == q->exec_cksum) {

        u32 move_tail = q->len - remove_pos - trim_avail;

        q->len -= trim_avail;
        len_p2 = next_pow2(q->len);

        memmove(in_buf + remove_pos, in_buf + remove_pos + trim_avail,
                move_tail);

        /* Let's save a clean trace, which will be needed by
           update_bitmap_score once we're done with the trimming stuff. */
        if (!needs_write) {

          needs_write = 1;
          memcpy(sgf->clean_trace, sgf->fsrv.trace_bits, sgf->fsrv.map_size);

        }

      } else {

        remove_pos += remove_len;

      }

      /* Since this can be slow, update the screen every now and then. */
      if (!(trim_exec++ % sgf->stats_update_freq)) { show_stats(sgf); }
      ++sgf->stage_cur;

    }

    remove_len >>= 1;

  }

  /* If we have made changes to in_buf, we also need to update the on-disk
     version of the test case. */

  if (needs_write) {

    // run afl_custom_post_process

    if (unlikely(sgf->custom_mutators_count) &&
        likely(!sgf->sgf_env.sgf_post_process_keep_original)) {

      ssize_t new_size = q->len;
      u8     *new_mem = in_buf;
      u8     *new_buf = NULL;

      LIST_FOREACH(&sgf->custom_mutator_list, struct custom_mutator, {

        if (el->afl_custom_post_process) {

          new_size = el->afl_custom_post_process(el->data, new_mem, new_size,
                                                 &new_buf);

          if (unlikely(!new_buf || new_size <= 0)) {

            new_size = 0;
            new_buf = new_mem;

          } else {

            new_mem = new_buf;

          }

        }

      });

      if (unlikely(!new_size)) {

        new_size = q->len;
        new_mem = in_buf;

      }

      if (unlikely(new_size < sgf->min_length)) {

        new_size = sgf->min_length;

      } else if (unlikely(new_size > sgf->max_length)) {

        new_size = sgf->max_length;

      }

      q->len = new_size;

      if (new_mem != in_buf && new_mem != NULL) {

        new_buf = afl_realloc(SGF_BUF_PARAM(out_scratch), new_size);
        if (unlikely(!new_buf)) { PFATAL("alloc"); }
        memcpy(new_buf, new_mem, new_size);

        in_buf = new_buf;

      }

    }

    s32 fd;

    if (unlikely(sgf->no_unlink)) {

      fd = open(q->fname, O_WRONLY | O_CREAT | O_TRUNC, sgf->perm);

      if (fd < 0) { PFATAL("Unable to create '%s'", q->fname); }

      u32 written = 0;
      while (written < q->len) {

        ssize_t result = write(fd, in_buf, q->len - written);
        if (result > 0) written += result;

      }

    } else {

      unlink(q->fname);                                    /* ignore errors */
      fd = open(q->fname, O_WRONLY | O_CREAT | O_EXCL, sgf->perm);

      if (fd < 0) { PFATAL("Unable to create '%s'", q->fname); }

      ck_write(fd, in_buf, q->len, q->fname);

    }

    if (sgf->chown_needed) {

      if (fchown(fd, -1, sgf->fsrv.gid) == -1) { PFATAL("fchown() failed"); }

    }

    close(fd);

    queue_testcase_retake_mem(sgf, q, in_buf, q->len, orig_len);

    memcpy(sgf->fsrv.trace_bits, sgf->clean_trace, sgf->fsrv.map_size);
    update_bitmap_score(sgf, q, true);

  }

abort_trimming:
  sgf->bytes_trim_out += q->len;
  update_trim_time(sgf, &trim_start_us);

  return fault;

}

size_t write_to_temp_json(sgf_state_t *sgf, struct SkeletonGraphData *sgi){

  char *filename = alloc_printf("%s/queue/id:%06u,src:%06u.json", sgf->out_dir, sgi->id, sgf->queue_cur->id);
  //checking if there is an existing file with same name
  if(access(filename, F_OK) != -1){
    //file exists
    // WARNF("File %s already exists.", filename);
  }
  size_t len = write_to_json(filename, sgi->skeleton_graph);
  // ACTF("wrote to %s", filename);
  ck_free(filename);
  return len;
}

// My understanding of the func: this seems to be populating the simulator_feedback attribute of the SkeletonGraphData struct when the ready flag is set
// Additionally, the earlier feedback is being destroyed
// But writing to this struct - is it necessary? - TODO: check! 
// I am assuming that it is just to store this as part of the meta data being stored in the queue about the skeletongraph
// writign my version of this with the new data structure
void update_simulator_feedback_cache(struct SkeletonGraphData *graph_data,
                                        struct SHM_next_events *next_events_from_shm) {

  if (!graph_data) { return; }

  // ACTF("Updating simulator feedback cache for graph_data id: %d", graph_data->id);
  
  if (graph_data->simulator_feedback) {
    destroy_simulator_feedback(graph_data->simulator_feedback);
    graph_data->simulator_feedback = NULL;
  }

  if(!next_events_from_shm){
    ACTF("next_events_from_shm is NULL");
  }else{
    // ACTF("next_events_from_shm: next nodes count = %d, ready = %d", next_events_from_shm->next_event_count, next_events_from_shm->ready);
    
    // Setting ready to 1here temporarily as I see the next event count but ready is still 0 
    //TODO: deal with ready appropriately later
    next_events_from_shm->ready = 1;
  }
  
  if (!next_events_from_shm || !next_events_from_shm->ready) {
    return;
  }
  
  // instead of directly passing pointer to the shared memory object, it would be better if I create another struct and pass that here
  struct SHM_next_events *clone_next_events_from_shm = ck_alloc(sizeof(struct SHM_next_events));
  
  memcpy(clone_next_events_from_shm, next_events_from_shm, sizeof(struct SHM_next_events));
  
  // clear the next events in the shared memory after cloning
  memset(next_events_from_shm, 0, sizeof(struct SHM_next_events));

  if(!clone_next_events_from_shm){
    ACTF("clone_next_events_from_shm is NULL");
  }else{
    // ACTF("clone_next_events_from_shm: next nodes count = %d, ready = %d", clone_next_events_from_shm->next_event_count, clone_next_events_from_shm->ready);
  }

  graph_data->simulator_feedback = clone_next_events_from_shm;
  
  if(!graph_data->simulator_feedback){
    ACTF("graph_data->simulator_feedback is NULL");
  }else{
    // ACTF("graph_data->simulator_feedback: next nodes count = %d, ready = %d", graph_data->simulator_feedback->next_event_count, graph_data->simulator_feedback->ready);
  } 
  
}

static inline int event_triple_cmp(EventTriple a, EventTriple b) {

  if (a.thread_id != b.thread_id) {
    return (a.thread_id < b.thread_id) ? -1 : 1;
  }
  if (a.instruction_id != b.instruction_id) {
    return (a.instruction_id < b.instruction_id) ? -1 : 1;
  }
  if (a.visit_id != b.visit_id) {
    return (a.visit_id < b.visit_id) ? -1 : 1;
  }
  return 0;

}

static u64 race_pair_hash(EventTriple first, EventTriple second) {

  if (event_triple_cmp(first, second) > 0) {
    EventTriple tmp = first;
    first = second;
    second = tmp;
  }

  struct {
    EventTriple a;
    EventTriple b;
  } pair;
  memset(&pair, 0, sizeof(pair));
  pair.a = first;
  pair.b = second;

  return hash64((u8 *)&pair, sizeof(pair), HASH_CONST);

}

static void race_set_init(sgf_state_t *sgf) {

  if (sgf->race_set_size) { return; }
  sgf->race_set_size = 1024;
  sgf->race_set_count = 0;
  sgf->race_set_hashes = ck_alloc(sgf->race_set_size * sizeof(u64));
  memset(sgf->race_set_hashes, 0, sgf->race_set_size * sizeof(u64));

}

static void race_set_grow(sgf_state_t *sgf) {

  u32 old_size = sgf->race_set_size;
  u64 *old = sgf->race_set_hashes;

  sgf->race_set_size = old_size ? old_size << 1 : 1024;
  sgf->race_set_hashes = ck_alloc(sgf->race_set_size * sizeof(u64));
  memset(sgf->race_set_hashes, 0, sgf->race_set_size * sizeof(u64));
  sgf->race_set_count = 0;

  if (!old) { return; }

  for (u32 i = 0; i < old_size; ++i) {

    if (!old[i]) { continue; }
    u64 key = old[i];
    u32 pos = (u32)(key & (sgf->race_set_size - 1));
    while (sgf->race_set_hashes[pos]) {
      pos = (pos + 1) & (sgf->race_set_size - 1);
    }
    sgf->race_set_hashes[pos] = key;
    ++sgf->race_set_count;

  }

  ck_free(old);

}

static bool race_set_add(sgf_state_t *sgf, u64 hash) {

  if (!sgf->race_set_size) { race_set_init(sgf); }

  if (sgf->race_set_count * 4 >= sgf->race_set_size * 3) {
    race_set_grow(sgf);
  }

  u64 key = hash + 1;
  if (unlikely(key == 0)) { key = 1; }
  u32 pos = (u32)(key & (sgf->race_set_size - 1));

  while (sgf->race_set_hashes[pos]) {

    if (sgf->race_set_hashes[pos] == key) { return false; }
    pos = (pos + 1) & (sgf->race_set_size - 1);

  }

  sgf->race_set_hashes[pos] = key;
  ++sgf->race_set_count;
  return true;

}

void save_race_if_interesting(sgf_state_t *sgf, const struct SkeletonGraphData *sgi) {

  if (!sgf->check_data_race || !sgi || !sgi->is_racy) { return; }
  size_t rp_count = race_pair_store_size(sgi->race_pairs);
  if (rp_count < 1) { return; }

  ++sgf->total_races;

  EventTriple r0, r1;
  if (!race_pair_store_get_pair(sgi->race_pairs, 0, &r0, &r1)) { return; }
  u64 hash = race_pair_hash(r0, r1);
  if (!race_set_add(sgf, hash)) { return; }

  if (sgf->saved_races >= KEEP_UNIQUE_RACE) { return; }

  u8 fn[PATH_MAX];
  snprintf(fn, PATH_MAX, "%s/races/id:%06llu,src:%06u", sgf->out_dir,
           sgf->saved_races, sgi->id);

  s32 fd = permissive_create(sgf, fn);
  if (fd >= 0) {

    char buf[256];
    int  len = snprintf(buf, sizeof(buf),
              "race_0: thread_id=%d instruction_id=%lld visit_id=%d\n"
              "race_1: thread_id=%d instruction_id=%lld visit_id=%d\n",
              r0.thread_id,
              (long long)r0.instruction_id,
              r0.visit_id,
              r1.thread_id,
              (long long)r1.instruction_id,
              r1.visit_id);
    if (len > 0) { ck_write(fd, buf, (u32)len, fn); }
    close(fd);

  }

  ++sgf->saved_races;
  sgf->last_race_time = get_cur_time();
  sgf->last_race_execs = sgf->fsrv.total_execs;

}

//Defining a function similar to common_fuzz_stuff that writes the modified testcase and runs the target program and processes the results
// TODO: Right now, I am only writing the modified testcase, I would have to write code to run the target program and process th results

u8 skeleton_graph_fuzz_stuff(sgf_state_t *sgf, struct SkeletonGraphData *sgi){
  
  // Very Important to make it null initially, otherwise it will have garbage values and we will end up reading garbage values from the shared memory
  // - Hardik
  struct SHM_next_events* next_events_from_shm = NULL;
  //return the fault code based on the program execution
  //this fault code would decide the result attribute of the skeletongraph instance - using that we decide if we need to save that graph or not
  u8 fault;
  int exit_code = -1;
  uint8_t *exec_buf = NULL;
  uint32_t exec_len = 0;

  if (unlikely(!sgi || !sgi->skeleton_graph)) {
    WARNF("Skipping skeleton execution: missing graph");
    return FSRV_RUN_ERROR;
  }

  if (serialize_graph_c(sgi->skeleton_graph, &exec_buf, &exec_len) != 0 ||
      !exec_buf || !exec_len) {

    if (exec_buf) { free(exec_buf); }
    WARNF("Skipping skeleton execution: failed to serialize graph");
    return FSRV_RUN_ERROR;

  }

  void *exec_mem = exec_buf;
  if (unlikely(write_to_testcase(sgf, &exec_mem, exec_len, 1) == 0)) {

    WARNF("Skipping skeleton execution: failed to write serialized graph to testcase");
    free(exec_buf);
    return FSRV_RUN_ERROR;

  }

  free(exec_buf);

  fault = fuzz_run_target(sgf, &sgf->fsrv, sgf->fsrv.exec_tmout);

  if (fault != FSRV_RUN_OK) {
    // for crashes and hangs
    save_if_interesting_skeleton(sgf, sgi->skeleton_graph, fault);
    return fault;
  }
  if (WIFEXITED(sgf->fsrv.child_status)) {
    sgi->already_simulated = 1;
    exit_code = WEXITSTATUS(sgf->fsrv.child_status);
    sgi->sim_exit_code = (u8)exit_code;
    // ACTF("Simulator exit code: %d", exit_code);
    if (exit_code == EXIT_EVENT_MISMATCH || exit_code == EXIT_RF_TYPE_MISMATCH || exit_code == EXIT_NOT_INSTANTIABLE) {
      // save_non_instantiable_skeleton_graph(sgf, sgi->skeleton_graph,(u8)exit_code, sgi->id);
      // Not required as we will not save this anyways. - Hardik
      // sgi->non_instantiable = 1;
      // ACTF("Flagged entry %u due to simulator exit %d", sgf->queue_cur->id,exit_code);
      // Incorrect to this as we haven't added the graph to the queue yet, 
      // so we don't want to reduce the score of the current queue entry as it not the one that ran.
      // - Hardik
      return (u8)exit_code;
    }
  }
  
  // Reading the feedback from shm
  if(sgf->enable_feedback && sgf->queue_cur && sgf->queue_cur->graph_data){
    if(!next_events_from_shm){
      // ACTF("Trying to get next events before calling update_simulator_feedback_cache");
      next_events_from_shm = get_shm_next_events_c();
    }

    if(!next_events_from_shm){
      ACTF("Failed at getting next events");
    }else{
      // ACTF("[SHM NEXT EVENTS FEEDBACK] updating the simulator feedback cache for queue_cur, graph_data id: %d", sgf->queue_cur->graph_data->id);
      update_simulator_feedback_cache(sgi, next_events_from_shm);
    }

  }
  return 0;
}

/* Write a modified test case, run program, process results. Handle
   error conditions, returning 1 if it's time to bail out. This is
   a helper function for fuzz_one(). */

u8 __attribute__((hot)) common_fuzz_stuff(sgf_state_t *sgf, u8 *out_buf,
                                          u32 len) {

  u8 fault;

  if (unlikely(len = write_to_testcase(sgf, (void **)&out_buf, len, 0)) == 0) {

    return 0;

  }

  fault = fuzz_run_target(sgf, &sgf->fsrv, sgf->fsrv.exec_tmout);

  if (sgf->stop_soon) { return 1; }

  if (fault == FSRV_RUN_TMOUT) {

    if (sgf->subseq_tmouts++ > TMOUT_LIMIT) {

      ++sgf->cur_skipped_items;
      return 1;

    }

  } else {

    sgf->subseq_tmouts = 0;

  }

  /* Users can hit us with SIGUSR1 to request the current input
     to be abandoned. */

  if (sgf->skip_requested) {

    sgf->skip_requested = 0;
    ++sgf->cur_skipped_items;
    return 1;

  }

  /* This handles FAULT_ERROR for us: */

  // REVISIT: temporarily commenting this out, to see how things work without
  // this ACTF("*Save if interesting, FAULT = %u           *", fault);
  sgf->queued_discovered += save_if_interesting(sgf, out_buf, len, fault, 0, MAP_SIZE);
  // ACTF("* queue_discovered = %u *", sgf->queued_discovered);

  if (!(sgf->stage_cur % sgf->stats_update_freq) ||
      sgf->stage_cur + 1 == sgf->stage_max) {

    show_stats(sgf);

  }

  return 0;

}

