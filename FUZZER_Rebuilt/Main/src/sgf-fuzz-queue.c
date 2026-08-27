/*
   american fuzzy lop++ - queue relates routines
   ---------------------------------------------

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

#include "sgf-fuzz.h"
#include <limits.h>
#include <ctype.h>
#include <math.h>

// for the read_from_json() func
#include "skeleton_graph_mutator_wrapper.h"
#include "potential_nn.h"

/* Mode 2 function declarations */
#ifdef __cplusplus
extern "C" {
#endif

extern void potential_nn_index_reset(void);
extern int potential_nn_index_contains(const void* entry);
extern void potential_nn_index_add(const void* entry, void* potential);
extern int potential_nn_find_diff(const void* entry, void* potential,
                                        int (*is_active_fn)(const void*, void*),
                                        void* user_data, double* out_diff,
                                        const void** out_neighbor);

#ifdef __cplusplus
}
#endif

#ifdef _STANDALONE_MODULE
void minimize_bits(sgf_state_t *sgf, u8 *dst, u8 *src) {

  return;

}

void run_afl_custom_queue_new_entry(sgf_state_t *sgf, struct queue_entry *q,
                                    u8 *a, u8 *b) {

  return;

}

#endif

static int nn_is_active_entry(const void* entry, void* user_data) {
  (void)user_data;
  const struct queue_entry* qe = (const struct queue_entry*)entry;
  if (!qe) return 0;
  return (!qe->disabled && !qe->fs_redundant);
}

/* select next queue entry based on alias algo - fast! */

inline u32 select_next_queue_entry(sgf_state_t *sgf) {

  u32    s = rand_below(sgf, sgf->queued_items);
  double p = rand_next_percent(sgf);

  /*
  fprintf(stderr, "select: p=%f s=%u ... p < prob[s]=%f ? s=%u : alias[%u]=%u"
  " ==> %u\n", p, s, sgf->alias_probability[s], s, s, sgf->alias_table[s], p <
  sgf->alias_probability[s] ? s : sgf->alias_table[s]);
  */

  return (p < sgf->alias_probability[s] ? s : sgf->alias_table[s]);

}

/* create the alias table that allows weighted random selection - expensive */

void create_alias_table(sgf_state_t *sgf) {

  u32    n = sgf->queued_items, i = 0, nSmall = 0, nLarge = n - 1;
  double sum = 0;

  double *P = (double *)afl_realloc(SGF_BUF_PARAM(out), n * sizeof(double));
  u32 *Small = (int *)afl_realloc(SGF_BUF_PARAM(out_scratch), n * sizeof(u32));
  u32 *Large = (int *)afl_realloc(SGF_BUF_PARAM(in_scratch), n * sizeof(u32));

  sgf->alias_table =
      (u32 *)afl_realloc((void **)&sgf->alias_table, n * sizeof(u32));
  sgf->alias_probability = (double *)afl_realloc(
      (void **)&sgf->alias_probability, n * sizeof(double));

  if (!P || !Small || !Large || !sgf->alias_table || !sgf->alias_probability) {

    FATAL("could not acquire memory for alias table");

  }

  memset((void *)sgf->alias_probability, 0, n * sizeof(double));
  memset((void *)sgf->alias_table, 0, n * sizeof(u32));
  memset((void *)Small, 0, n * sizeof(u32));
  memset((void *)Large, 0, n * sizeof(u32));

  if (likely(sgf->schedule < RARE)) {

    double avg_exec_us = 0.0;
    double avg_bitmap_size = 0.0;
    double avg_len = 0.0;
    u32    active = 0;

    for (i = 0; i < n; i++) {

      struct queue_entry *q = sgf->queue_buf[i];

      // disabled entries might have timings and bitmap values
      if (likely(!q->disabled)) {

        avg_exec_us += q->exec_us;
        avg_bitmap_size += log(q->bitmap_size);
        avg_len += q->len;
        ++active;

      }

    }

    avg_exec_us /= active;
    avg_bitmap_size /= active;
    avg_len /= active;

    for (i = 0; i < n; i++) {

      struct queue_entry *q = sgf->queue_buf[i];

      if (likely(!q->disabled)) {

        double weight = 1.0;
        {  // inline does result in a compile error with LTO, weird

          if (unlikely(sgf->schedule >= FAST && sgf->schedule <= RARE)) {

            u32 hits = sgf->n_fuzz[q->n_fuzz_entry];
            if (likely(hits)) { weight /= (log10(hits) + 1); }

          }

          if (likely(sgf->schedule < RARE)) {

            double t = q->exec_us / avg_exec_us;

            if (likely(t < 0.1)) {

              // nothing

            } else if (likely(t <= 0.25)) {

              weight *= 0.95;

            } else if (likely(t <= 0.5)) {

              // nothing

            } else if (likely(t <= 0.75)) {

              weight *= 1.05;

            } else if (likely(t <= 1.0)) {

              weight *= 1.1;

            } else if (likely(t < 1.25)) {

              weight *= 0.2;  // WTF ??? makes no sense

            } else if (likely(t <= 1.5)) {

              // nothing

            } else if (likely(t <= 2.0)) {

              weight *= 1.1;

            } else if (likely(t <= 2.5)) {

            } else if (likely(t <= 5.0)) {

              weight *= 1.15;

            } else if (likely(t <= 20.0)) {

              weight *= 1.1;
              // else nothing

            }

          }

          double l = q->len / avg_len;
          if (likely(l < 0.1)) {

            weight *= 0.5;

          } else if (likely(l <= 0.5)) {

            // nothing

          } else if (likely(l <= 1.25)) {

            weight *= 1.05;

          } else if (likely(l <= 1.75)) {

            // nothing

          } else if (likely(l <= 2.0)) {

            weight *= 0.95;

          } else if (likely(l <= 5.0)) {

            // nothing

          } else if (likely(l <= 10.0)) {

            weight *= 1.05;

          } else {

            weight *= 1.15;

          }

          double bms = q->bitmap_size / avg_bitmap_size;
          if (likely(bms < 0.1)) {

            weight *= 0.01;

          } else if (likely(bms <= 0.25)) {

            weight *= 0.55;

          } else if (likely(bms <= 0.5)) {

            // nothing

          } else if (likely(bms <= 0.75)) {

            weight *= 1.2;

          } else if (likely(bms <= 1.25)) {

            weight *= 1.3;

          } else if (likely(bms <= 1.75)) {

            weight *= 1.25;

          } else if (likely(bms <= 2.0)) {

            // nothing

          } else if (likely(bms <= 2.5)) {

            weight *= 1.3;

          } else {

            weight *= 0.75;

          }

          if (unlikely(!q->was_fuzzed)) { weight *= 2.5; }
          if (unlikely(q->fs_redundant)) { weight *= 0.75; }

        }

        q->weight = weight;
        if (q->perf_score <= 1.0) {
          q->perf_score = calculate_score(sgf, q->graph_data);
        }
        sum += q->weight;

      }

    }

    if (unlikely(sgf->schedule == MMOPT) && sgf->queued_discovered) {

      u32 cnt = sgf->queued_discovered >= 5 ? 5 : sgf->queued_discovered;

      for (i = n - cnt; i < n; i++) {

        struct queue_entry *q = sgf->queue_buf[i];

        if (likely(!q->disabled)) { q->weight *= 2.0; }

      }

    }

    for (i = 0; i < n; i++) {

      // weight is always 0 for disabled entries
      if (unlikely(sgf->queue_buf[i]->disabled)) {

        P[i] = 0;

      } else {

        P[i] = (sgf->queue_buf[i]->weight * n) / sum;

      }

    }

  } else {

    for (i = 0; i < n; i++) {

      struct queue_entry *q = sgf->queue_buf[i];

      if (likely(!q->disabled)) {

        if (q->perf_score <= 1.0) {
          q->perf_score = calculate_score(sgf, q->graph_data);
        }
        sum += q->perf_score;

      }

    }

    for (i = 0; i < n; i++) {

      // perf_score is always 0 for disabled entries
      if (unlikely(sgf->queue_buf[i]->disabled)) {

        P[i] = 0;

      } else {

        P[i] = (sgf->queue_buf[i]->perf_score * n) / sum;

      }

    }

  }

  // Done collecting weightings in P, now create the arrays.

  for (s32 j = (s32)(n - 1); j >= 0; j--) {

    if (P[j] < 1) {

      Small[nSmall++] = (u32)j;

    } else {

      Large[nLarge--] = (u32)j;

    }

  }

  while (nSmall && nLarge != n - 1) {

    u32 small = Small[--nSmall];
    u32 large = Large[++nLarge];

    sgf->alias_probability[small] = P[small];
    sgf->alias_table[small] = large;

    P[large] = P[large] - (1 - P[small]);

    if (P[large] < 1) {

      Small[nSmall++] = large;

    } else {

      Large[nLarge--] = large;

    }

  }

  while (nSmall) {

    sgf->alias_probability[Small[--nSmall]] = 1;

  }

  while (nLarge != n - 1) {

    sgf->alias_probability[Large[++nLarge]] = 1;

  }

  sgf->reinit_table = 0;

  /*
  #ifdef INTROSPECTION
    u8 fn[PATH_MAX];
    snprintf(fn, PATH_MAX, "%s/introspection_corpus.txt", sgf->out_dir);
    FILE *f = fopen(fn, "a");
    if (f) {

      for (i = 0; i < n; i++) {

        struct queue_entry *q = sgf->queue_buf[i];
        fprintf(
            f,
            "entry=%u name=%s favored=%s variable=%s disabled=%s len=%u "
            "exec_us=%u "
            "bitmap_size=%u bitsmap_size=%u tops=%u weight=%f perf_score=%f\n",
            i, q->fname, q->favored ? "true" : "false",
            q->var_behavior ? "true" : "false", q->disabled ? "true" : "false",
            q->len, (u32)q->exec_us, q->bitmap_size, q->bitsmap_size, q->tc_ref,
            q->weight, q->perf_score);

      }

      fprintf(f, "\n");
      fclose(f);

    }

  #endif
  */
  /*
  fprintf(stderr, "  entry  alias  probability  perf_score   weight
  filename\n"); for (i = 0; i < n; ++i) fprintf(stderr, "  %5u  %5u  %11u
  %0.9f  %0.9f  %s\n", i, sgf->alias_table[i], sgf->alias_probability[i],
  sgf->queue_buf[i]->perf_score, sgf->queue_buf[i]->weight,
            sgf->queue_buf[i]->fname);
  */

}

/* Mark deterministic checks as done for a particular queue entry. We use the
   .state file to avoid repeating deterministic fuzzing when resuming aborted
   scans. */

void mark_as_det_done(sgf_state_t *sgf, struct queue_entry *q) {

  char fn[PATH_MAX];
  s32  fd;

  snprintf(fn, PATH_MAX, "%s/queue/.state/deterministic_done/%s", sgf->out_dir,
           strrchr((char *)q->fname, '/') + 1);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, sgf->perm);
  if (fd < 0) { PFATAL("Unable to create '%s'", fn); }

  if (sgf->chown_needed) {

    if (fchown(fd, -1, sgf->fsrv.gid) == -1) { PFATAL("fchown() failed"); }

  }

  close(fd);

  q->passed_det = 1;

}

/* Mark / unmark as redundant (edge-only). This is not used for restoring state,
   but may be useful for post-processing datasets. */

void mark_as_redundant(sgf_state_t *sgf, struct queue_entry *q, u8 state) {

  if (likely(state == q->fs_redundant)) { return; }

  q->fs_redundant = state;

  if (likely(q->fs_redundant)) {

    if (unlikely(q->trace_mini)) {

      ck_free(q->trace_mini);
      q->trace_mini = NULL;

    }

  }

  if (state) {

    if (unlikely(sgf->sgf_env.sgf_disable_redundant)) { q->disabled = 1; }

  }

}

/* check if pointer is ascii or UTF-8 */

u8 check_if_text_buf(u8 *buf, u32 len) {

  u32 offset = 0, ascii = 0, utf8 = 0;

  while (offset < len) {

    // ASCII: <= 0x7F to allow ASCII control characters
    if ((buf[offset + 0] == 0x09 || buf[offset + 0] == 0x0A ||
         buf[offset + 0] == 0x0D ||
         (0x20 <= buf[offset + 0] && buf[offset + 0] <= 0x7E))) {

      offset++;
      utf8++;
      ascii++;
      continue;

    }

    if (isascii((int)buf[offset]) || isprint((int)buf[offset])) {

      ascii++;
      // we continue though as it can also be a valid utf8

    }

    // non-overlong 2-byte
    if (len - offset > 1 &&
        ((0xC2 <= buf[offset + 0] && buf[offset + 0] <= 0xDF) &&
         (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF))) {

      offset += 2;
      utf8++;
      continue;

    }

    // excluding overlongs
    if ((len - offset > 2) &&
        ((buf[offset + 0] == 0xE0 &&
          (0xA0 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] &&
           buf[offset + 2] <= 0xBF)) ||  // straight 3-byte
         (((0xE1 <= buf[offset + 0] && buf[offset + 0] <= 0xEC) ||
           buf[offset + 0] == 0xEE || buf[offset + 0] == 0xEF) &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] &&
           buf[offset + 2] <= 0xBF)) ||  // excluding surrogates
         (buf[offset + 0] == 0xED &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0x9F) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF)))) {

      offset += 3;
      utf8++;
      continue;

    }

    // planes 1-3
    if ((len - offset > 3) &&
        ((buf[offset + 0] == 0xF0 &&
          (0x90 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] &&
           buf[offset + 3] <= 0xBF)) ||  // planes 4-15
         ((0xF1 <= buf[offset + 0] && buf[offset + 0] <= 0xF3) &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] && buf[offset + 3] <= 0xBF)) ||  // plane 16
         (buf[offset + 0] == 0xF4 &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0x8F) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] && buf[offset + 3] <= 0xBF)))) {

      offset += 4;
      utf8++;
      continue;

    }

    offset++;

  }

  return (utf8 > ascii ? utf8 : ascii);

}

/* check if queue entry is ascii or UTF-8 */

static u8 check_if_text(sgf_state_t *sgf, struct queue_entry *q) {

  if (q->len < SGF_TXT_MIN_LEN || q->len > SGF_TXT_MAX_LEN) return 0;

  u8     *buf;
  int     fd;
  u32     len = q->len, offset = 0, ascii = 0, utf8 = 0;
  ssize_t comp;

  if (len >= MAX_FILE) len = MAX_FILE - 1;
  if ((fd = open((char *)q->fname, O_RDONLY)) < 0) return 0;
  buf = (u8 *)afl_realloc(SGF_BUF_PARAM(in_scratch), len + 1);
  comp = read(fd, buf, len);
  close(fd);
  if (comp != (ssize_t)len) return 0;
  buf[len] = 0;

  while (offset < len) {

    // ASCII: <= 0x7F to allow ASCII control characters
    if ((buf[offset + 0] == 0x09 || buf[offset + 0] == 0x0A ||
         buf[offset + 0] == 0x0D ||
         (0x20 <= buf[offset + 0] && buf[offset + 0] <= 0x7E))) {

      offset++;
      utf8++;
      ascii++;
      continue;

    }

    if (isascii((int)buf[offset]) || isprint((int)buf[offset])) {

      ascii++;
      // we continue though as it can also be a valid utf8

    }

    // non-overlong 2-byte
    if (len - offset > 1 &&
        ((0xC2 <= buf[offset + 0] && buf[offset + 0] <= 0xDF) &&
         (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF))) {

      offset += 2;
      utf8++;
      comp--;
      continue;

    }

    // excluding overlongs
    if ((len - offset > 2) &&
        ((buf[offset + 0] == 0xE0 &&
          (0xA0 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] &&
           buf[offset + 2] <= 0xBF)) ||  // straight 3-byte
         (((0xE1 <= buf[offset + 0] && buf[offset + 0] <= 0xEC) ||
           buf[offset + 0] == 0xEE || buf[offset + 0] == 0xEF) &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] &&
           buf[offset + 2] <= 0xBF)) ||  // excluding surrogates
         (buf[offset + 0] == 0xED &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0x9F) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF)))) {

      offset += 3;
      utf8++;
      comp -= 2;
      continue;

    }

    // planes 1-3
    if ((len - offset > 3) &&
        ((buf[offset + 0] == 0xF0 &&
          (0x90 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] &&
           buf[offset + 3] <= 0xBF)) ||  // planes 4-15
         ((0xF1 <= buf[offset + 0] && buf[offset + 0] <= 0xF3) &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] && buf[offset + 3] <= 0xBF)) ||  // plane 16
         (buf[offset + 0] == 0xF4 &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0x8F) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] && buf[offset + 3] <= 0xBF)))) {

      offset += 4;
      utf8++;
      comp -= 3;
      continue;

    }

    offset++;

  }

  u32 percent_utf8 = (utf8 * 100) / comp;
  u32 percent_ascii = (ascii * 100) / len;

  if (percent_utf8 >= percent_ascii && percent_utf8 >= SGF_TXT_MIN_PERCENT)
    return 2;
  if (percent_ascii >= SGF_TXT_MIN_PERCENT) return 1;
  return 0;

}

/* Append new test case to the queue. */

static inline void destroy_queue_graph_feedback(struct queue_entry *q) {

  if (!q || !q->graph_data) { return; }

  if (q->graph_data->simulator_feedback) {

    destroy_simulator_feedback(q->graph_data->simulator_feedback);
    q->graph_data->simulator_feedback = NULL;

  }

}

void add_to_queue(sgf_state_t *sgf, u8 *fname, u32 len, u8 passed_det) {
  // ACTF("Adding new test case to the queue: %s (%u bytes)", fname, len);
  struct queue_entry *q =
      (struct queue_entry *)ck_alloc(sizeof(struct queue_entry));

  q->fname = ck_strdup(fname);
  q->len = len ? len : 1;

  q->depth = sgf->cur_depth + 1;
  q->passed_det = passed_det;
  q->trace_mini = NULL;
  q->testcase_buf = NULL;
  q->mother = sgf->queue_cur;
  q->weight = 1.0;
  q->perf_score = 100; // TODO:Update if required.
  q->graph_data = (struct SkeletonGraphData*)ck_alloc(sizeof(struct SkeletonGraphData));
  memset(q->graph_data, 0, sizeof(struct SkeletonGraphData));
  q->graph_data->sim_exit_code = 0;
  q->graph_data->already_simulated = 0;
  q->graph_data->non_instantiable = 0;
  q->graph_data->simulator_feedback = NULL;
  q->graph_data->is_racy = 0;
  q->graph_data->racy_event_count = 0;
  q->graph_data->race_pairs = NULL;
  q->graph_data->forbidden_mutations = forbidden_mutations_create();
  
  // Initialize skeleton_potential to NULL (will be set later if needed)
  q->graph_data->skeleton_potential = NULL;
  q->graph_data->potential_indexed = 0;
  q->graph_data->potential_score_epoch = 0;

  q->graph_data->decay_ratio = 0.1; // Default decay ratio, can be adjusted later if needed

  // REVISIT: set this later if reqd
  // q->id = queued_paths;


  // setting has_pthread
  // REVISIT: I would have to add has_pthread to the args to dothis - I would have to modify all other files as well
  // q->has_pthread = has_pthread;

#ifdef INTROSPECTION
  q->bitsmap_size = sgf->bitsmap_size;
#endif

  if (q->depth > sgf->max_depth) { sgf->max_depth = q->depth; }

  if (sgf->queue_top) {

    sgf->queue_top = q;

  } else {

    sgf->queue = sgf->queue_top = q;

  }

  // initializing the graphs in the queue
  // This is how RFF deals with nscheds and sched in this function
  // q -> graph = NULL;

  // This is the right thing to do in my opinion
  // q -> graph = sgi;


  if (likely(q->len > 4)) { ++sgf->ready_for_splicing_count; }

  ++sgf->queued_items;
  ++sgf->active_items;
  ++sgf->pending_not_fuzzed;
  ++sgf->potential_nn_epoch;

  sgf->cycles_wo_finds = 0;

  struct queue_entry **queue_buf = (struct queue_entry **)afl_realloc(
      SGF_BUF_PARAM(queue), sgf->queued_items * sizeof(struct queue_entry *));
  if (unlikely(!queue_buf)) { PFATAL("alloc"); }
  queue_buf[sgf->queued_items - 1] = q;
  q->id = sgf->queued_items - 1;
  if (q->graph_data) {
    q->graph_data->id = q->id;
  }

  u64 cur_time = get_cur_time();

  if (likely(sgf->start_time) &&
      unlikely(sgf->longest_find_time < cur_time - sgf->last_find_time)) {

    if (unlikely(!sgf->last_find_time)) {

      sgf->longest_find_time = cur_time - sgf->start_time;

    } else {

      sgf->longest_find_time = cur_time - sgf->last_find_time;

    }

  }

  sgf->last_find_time = cur_time;

  if (sgf->custom_mutators_count) {

    /* At the initialization stage, queue_cur is NULL */
    if (sgf->queue_cur || sgf->syncing_party) {

      u8 *fname_orig = NULL;

      if (sgf->queue_cur) { fname_orig = sgf->queue_cur->fname; }

      run_afl_custom_queue_new_entry(sgf, q, fname, fname_orig);

    }

  }

  /* only redqueen currently uses is_ascii */
  if (unlikely(sgf->shm.cmplog_mode && !q->is_ascii)) {

    q->is_ascii = check_if_text(sgf, q);

  }

  q->skipdet_e = (struct skipdet_entry *)ck_alloc(sizeof(struct skipdet_entry));

}

/* Destroy the entire queue. */

void destroy_queue(sgf_state_t *sgf) {

  u32                 i;
  struct queue_entry *q;

  for (i = 0; i < sgf->queued_items; i++) {

    q = sgf->queue_buf[i];
    ck_free(q->testcase_buf);
    ck_free(q->fname);
    ck_free(q->trace_mini);
    if (q->skipdet_e) {

      if (q->skipdet_e->done_inf_map) ck_free(q->skipdet_e->done_inf_map);
      if (q->skipdet_e->skip_eff_map) ck_free(q->skipdet_e->skip_eff_map);

      ck_free(q->skipdet_e);

    }
    
    // Clean up skeleton graph resources and graph_data itself
    if (q->graph_data) {
      if (q->graph_data->skeleton_potential) {
        destroy_skeleton_potential(q->graph_data->skeleton_potential);
        q->graph_data->skeleton_potential = NULL;
      }
      if (q->graph_data->skeleton_graph) {
        destroy_SkeletonGraph(q->graph_data->skeleton_graph);
        q->graph_data->skeleton_graph = NULL;
      }
      if (q->graph_data->race_pairs) {
        race_pair_store_destroy(q->graph_data->race_pairs);
        q->graph_data->race_pairs = NULL;
      }
      if (q->graph_data->forbidden_mutations) {
        forbidden_mutations_destroy(q->graph_data->forbidden_mutations);
        q->graph_data->forbidden_mutations = NULL;
      }
      destroy_queue_graph_feedback(q);
      ck_free(q->graph_data);
      q->graph_data = NULL;
    }

    ck_free(q);

  }

}

/* When we bump into a new path, we call this to see if the path appears
   more "favorable" than any of the existing ones. The purpose of the
   "favorables" is to have a minimal set of paths that trigger all the bits
   seen in the bitmap so far, and focus on fuzzing them at the expense of
   the rest.

   The first step of the process is to maintain a list of sgf->top_rated[]
   entries for every byte in the bitmap. We win that slot if there is no
   previous contender, or if the contender has a more favorable speed x size
   factor. */

void update_bitmap_score(sgf_state_t *sgf, struct queue_entry *q,
                         bool have_trace) {

  u32 i;
  u64 fav_factor;
  u64 fuzz_p2;

  if (unlikely(q->disabled)) { return; }

  if (unlikely(sgf->schedule >= FAST && sgf->schedule < RARE)) {

    fuzz_p2 = 0;  // Skip the fuzz_p2 comparison

  } else if (unlikely(sgf->schedule == RARE)) {

    fuzz_p2 = next_pow2(sgf->n_fuzz[q->n_fuzz_entry]);

  } else {

    fuzz_p2 = q->fuzz_level;

  }

  if (unlikely(sgf->schedule >= RARE) || unlikely(sgf->fixed_seed)) {

    fav_factor = q->len << 2;

  } else {

    fav_factor = q->exec_us * q->len;

  }

  if (have_trace) {

    /* For every byte set in sgf->fsrv.trace_bits[], see if there is a previous
       winner, and how it compares to us. */
    for (i = 0; i < sgf->fsrv.map_size; ++i) {

      if (sgf->fsrv.trace_bits[i]) {

        if (sgf->top_rated[i]) {

          /* Faster-executing or smaller test cases are favored. */
          u64 top_rated_fav_factor;
          u64 top_rated_fuzz_p2;

          if (unlikely(sgf->schedule >= FAST && sgf->schedule < RARE)) {

            top_rated_fuzz_p2 = 0;  // Skip the fuzz_p2 comparison

          } else if (unlikely(sgf->schedule == RARE)) {

            top_rated_fuzz_p2 =
                next_pow2(sgf->n_fuzz[sgf->top_rated[i]->n_fuzz_entry]);

          } else {

            top_rated_fuzz_p2 = sgf->top_rated[i]->fuzz_level;

          }

          if (unlikely(sgf->schedule >= RARE) || unlikely(sgf->fixed_seed)) {

            top_rated_fav_factor = sgf->top_rated[i]->len << 2;

          } else {

            top_rated_fav_factor =
                sgf->top_rated[i]->exec_us * sgf->top_rated[i]->len;

          }

          if (likely(fuzz_p2 > top_rated_fuzz_p2)) { continue; }

          if (likely(fav_factor > top_rated_fav_factor)) { continue; }

          /* Looks like we're going to win. Decrease ref count for the
             previous winner, discard its sgf->fsrv.trace_bits[] if necessary.
           */

          if (!--sgf->top_rated[i]->tc_ref) {

            ck_free(sgf->top_rated[i]->trace_mini);
            sgf->top_rated[i]->trace_mini = NULL;

          }

        }

        /* Insert ourselves as the new winner. */

        sgf->top_rated[i] = q;
        ++q->tc_ref;

        if (!q->trace_mini) {

          u32 len = ((sgf->fsrv.map_size + 7) >> 3);
          q->trace_mini = (u8 *)ck_alloc(len);
          minimize_bits(sgf, q->trace_mini, sgf->fsrv.trace_bits);

        }

        sgf->score_changed = 1;

      }

    }

  }

}

/* The second part of the mechanism discussed above is a routine that
   goes over sgf->top_rated[] entries, and then sequentially grabs winners for
   previously-unseen bytes (temp_v) and marks them as favored, at least
   until the next run. The favored entries are given more air time during
   all fuzzing steps. */

void cull_queue(sgf_state_t *sgf) {

  if (likely(!sgf->score_changed || sgf->non_instrumented_mode)) { return; }

  u32 len = (sgf->fsrv.map_size >> 3);
  u32 i;
  u8 *temp_v = sgf->map_tmp_buf;

  sgf->score_changed = 0;

  memset(temp_v, 255, len);

  sgf->queued_favored = 0;
  sgf->pending_favored = 0;

  for (i = 0; i < sgf->queued_items; i++) {

    sgf->queue_buf[i]->favored = 0;

  }

  /* Let's see if anything in the bitmap isn't captured in temp_v.
     If yes, and if it has a sgf->top_rated[] contender, let's use it. */

  sgf->smallest_favored = -1;

  for (i = 0; i < sgf->fsrv.map_size; ++i) {

    if (sgf->top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7))) &&
        sgf->top_rated[i]->trace_mini) {

      u32 j = len;

      /* Remove all bits belonging to the current entry from temp_v. */

      while (j--) {

        if (sgf->top_rated[i]->trace_mini[j]) {

          temp_v[j] &= ~sgf->top_rated[i]->trace_mini[j];

        }

      }

      if (!sgf->top_rated[i]->favored && !sgf->top_rated[i]->disabled) {

        sgf->top_rated[i]->favored = 1;
        ++sgf->queued_favored;

        if (!sgf->top_rated[i]->was_fuzzed) {

          ++sgf->pending_favored;
          if (unlikely(sgf->smallest_favored < 0 ||
                       sgf->smallest_favored > (s64)sgf->top_rated[i]->id)) {

            sgf->smallest_favored = (s64)sgf->top_rated[i]->id;

          }

        }

      }

    }

  }

  for (i = 0; i < sgf->queued_items; i++) {

    if (likely(!sgf->queue_buf[i]->disabled)) {

      mark_as_redundant(sgf, sgf->queue_buf[i], !sgf->queue_buf[i]->favored);

    }

  }

  sgf->reinit_table = 1;

}

/* Re-selects top_rated[] entries based on the current fuzzing schedule.
   Each queued entry is executed once to collect trace_bits, and potential
   candidates for each bitmap index are stored.

   The candidate list format is [count][id1][id2]... as a u32 array,
   where 'count' indicates how many queue IDs hit that index. */

void recalculate_all_scores(sgf_state_t *sgf) {

  u8 *in_buf;
  u32 i;
  u32 j;

  for (i = sgf->last_scored_idx + 1; i < sgf->queued_items; i++) {

    if (likely(!sgf->queue_buf[i]->disabled)) {

      in_buf = queue_testcase_get(sgf, sgf->queue_buf[i]);
      (void)write_to_testcase(sgf, (void **)&in_buf, sgf->queue_buf[i]->len, 1);
      (void)fuzz_run_target(sgf, &sgf->fsrv, sgf->fsrv.exec_tmout);

      for (j = 0; j < sgf->fsrv.map_size; ++j) {

        if (sgf->fsrv.trace_bits[j]) {

          u32 *candidate_ids = sgf->top_rated_candidates[j];
          u32  id = sgf->queue_buf[i]->id;

          if (!candidate_ids) {

            // first candidate: [count][id]
            candidate_ids = ck_alloc(sizeof(u32) * 2);
            candidate_ids[0] = 1;   // count = 1
            candidate_ids[1] = id;  // first ID

          } else {

            u32 count = candidate_ids[0];

            candidate_ids =
                ck_realloc(candidate_ids, sizeof(u32) * (count + 2));
            candidate_ids[0] = count + 1;   // increment the count
            candidate_ids[count + 1] = id;  // append the new ID to the end

            // fprintf(stderr, "enroll candidate[%u][%u] %u\n", i, j, id);

          }

          sgf->top_rated_candidates[j] = candidate_ids;

        }

      }

    }

    sgf->last_scored_idx = i;

  }

  for (i = 0; i < sgf->fsrv.map_size; ++i) {

    u32 *candidate_ids = sgf->top_rated_candidates[i];
    if (candidate_ids) {

      u32 count = candidate_ids[0];

      for (u32 k = 0; k < count; k++) {

        u32                 id = candidate_ids[k + 1];
        struct queue_entry *entry = sgf->queue_buf[id];
        update_bitmap_rescore(sgf, entry, i);

      }

    }

  }

}

/* Re-evaluates top-rated entries without checking trace_bits.
   Unlike update_bitmap_score(), this function assumes the trace
   information is already known and only compares entries */

void update_bitmap_rescore(sgf_state_t *sgf, struct queue_entry *q, u32 index) {

  u32 i = index;
  u64 fav_factor;
  u64 fuzz_p2;

  if (unlikely(q->disabled)) { return; }

  if (unlikely(sgf->schedule >= FAST && sgf->schedule < RARE)) {

    fuzz_p2 = 0;  // Skip the fuzz_p2 comparison

  } else if (unlikely(sgf->schedule == RARE)) {

    fuzz_p2 = next_pow2(sgf->n_fuzz[q->n_fuzz_entry]);

  } else {

    fuzz_p2 = q->fuzz_level;

  }

  if (unlikely(sgf->schedule >= RARE) || unlikely(sgf->fixed_seed)) {

    fav_factor = q->len << 2;

  } else {

    fav_factor = q->exec_us * q->len;

  }

  if (sgf->top_rated[i]) {

    /* Faster-executing or smaller test cases are favored. */
    u64 top_rated_fav_factor;
    u64 top_rated_fuzz_p2;

    if (unlikely(sgf->schedule >= FAST && sgf->schedule < RARE)) {

      top_rated_fuzz_p2 = 0;  // Skip the fuzz_p2 comparison

    } else if (unlikely(sgf->schedule == RARE)) {

      top_rated_fuzz_p2 =
          next_pow2(sgf->n_fuzz[sgf->top_rated[i]->n_fuzz_entry]);

    } else {

      top_rated_fuzz_p2 = sgf->top_rated[i]->fuzz_level;

    }

    if (unlikely(sgf->schedule >= RARE) || unlikely(sgf->fixed_seed)) {

      top_rated_fav_factor = sgf->top_rated[i]->len << 2;

    } else {

      top_rated_fav_factor =
          sgf->top_rated[i]->exec_us * sgf->top_rated[i]->len;

    }

    if (likely(fuzz_p2 > top_rated_fuzz_p2)) { return; }

    if (likely(fav_factor > top_rated_fav_factor)) { return; }

    /* Looks like we're going to win. Decrease ref count for the
        previous winner, discard its sgf->fsrv.trace_bits[] if necessary. */

    if (!--sgf->top_rated[i]->tc_ref) {

      ck_free(sgf->top_rated[i]->trace_mini);
      sgf->top_rated[i]->trace_mini = NULL;

    }

  }

  /* Insert ourselves as the new winner. */

  sgf->top_rated[i] = q;
  ++q->tc_ref;

  if (!q->trace_mini) {

    u32 len = (sgf->fsrv.map_size >> 3);
    q->trace_mini = (u8 *)ck_alloc(len);
    minimize_bits(sgf, q->trace_mini, sgf->fsrv.trace_bits);

  }

  sgf->score_changed = 1;

}

/* Calculate case desirability score to adjust the length of havoc fuzzing.
   A helper function for fuzz_one(). Maybe some of these constants should
   go into config.h. */

double calculate_potential_score(sgf_state_t *sgf, struct SkeletonGraphData *sgi) {

  double score = 1.0;

  if (!sgi) { return 1.0; }

  if (sgi->skeleton_potential && sgi->potential_score_ready) {
    u64 epoch_gap = 0;
    if (sgf->potential_nn_epoch >= sgi->potential_score_epoch) {
      epoch_gap = sgf->potential_nn_epoch - sgi->potential_score_epoch;
    }
    if (sgf->potential_nn_recalc_interval == 0 ||
        epoch_gap < sgf->potential_nn_recalc_interval) {
      score = sgi->potential_score;
      if (score < 1.0) { score = 1.0; }
      if (score > 100.0) { score = 100.0; }
      return score;
    }
  }

  if (!sgi->skeleton_potential && sgi->skeleton_graph) {
    sgi->skeleton_potential =
        create_skeleton_potential(sgi->skeleton_graph);
  }

  size_t potential_count = 0;
  if (sgi->skeleton_potential) {
    potential_count = get_potential_count_from_ptr(sgi->skeleton_potential);
  }

  double nn_diff = 0;
  int nn_found = 0;

  if (sgi->skeleton_potential) {
    const void* neighbor = NULL;
    nn_found = potential_nn_find_diff(sgi, sgi->skeleton_potential,
                                      nn_is_active_entry, NULL, &nn_diff,
                                      &neighbor);
  }

  if (nn_found) {
    score = (double)nn_diff;
  } else if (potential_count > 0) {
    score = (double)potential_count;
  }

  if (score < 1.0) { score = 1.0; }
  if (score > 100.0) { score = 100.0; }

  if (sgi->skeleton_potential) {
    sgi->potential_score_ready = 1;
    sgi->potential_score_epoch = sgf->potential_nn_epoch;
    sgi->potential_score = score;
  }

  return score;
}

double calculate_mo_footprint_score(sgf_state_t *sgf, struct SkeletonGraphData *sgi){
  (void)sgf;
  double score = 1.0;
  if (sgi && sgi->skeleton_graph) {
    score = (double)skeleton_graph_mo_footprint_calc(sgi->skeleton_graph);
  }
  if (score < 1.0) { score = 1.0; }
  if (score > 100.0) { score = 100.0; }
  if (sgi) {
    sgi->mo_footprint_score = score;
  }
  return score;
}

double calculate_score(sgf_state_t *sgf, struct SkeletonGraphData *sgi) {
  if (!sgi) { return 1.0; }
  // potential_score should be between 1 and 100
  double potential_score = calculate_potential_score(sgf, sgi);
  // mo_footprint_score should be between 1 and 100
  double mo_footprint_score = calculate_mo_footprint_score(sgf, sgi);

  double alpha, beta;
  if (sgf->current_phase == MO_FOOTPRINT_DRIVEN_PHASE) {
    // MO FOOTPRINT DRIVEN PHASE
    alpha = 0.5;
    beta = 0.5;
  } else {
    // POTENTIAL DRIVEN PHASE
    alpha = 0.9;
    beta = 0.1;
  }
  double score = (alpha * potential_score) + (beta * mo_footprint_score);

  if (score < 1.0) { score = 1.0; }
  if (score > 100.0) { score = 100.0; }

  return score;
}

/* after a custom trim we need to reload the testcase from disk */

inline void queue_testcase_retake(sgf_state_t *sgf, struct queue_entry *q,
                                  u32 old_len) {

  if (likely(q->testcase_buf)) {

    u32 len = q->len;

    // only realloc if necessary or useful
    // (a custom trim can make the testcase larger)
    if (unlikely(len > old_len || len + 1024 < old_len)) {

      sgf->q_testcase_cache_size += len - old_len;
      q->testcase_buf = (u8 *)realloc(q->testcase_buf, len);

      if (unlikely(!q->testcase_buf)) {

        PFATAL("Unable to malloc '%s' with len %u", (char *)q->fname, len);

      }

    }

    int fd = open((char *)q->fname, O_RDONLY);

    if (unlikely(fd < 0)) { PFATAL("Unable to open '%s'", (char *)q->fname); }

    ck_read(fd, q->testcase_buf, len, q->fname);
    close(fd);

  }

}

/* after a normal trim we need to replace the testcase with the new data */

inline void queue_testcase_retake_mem(sgf_state_t *sgf, struct queue_entry *q,
                                      u8 *in, u32 len, u32 old_len) {

  if (likely(q->testcase_buf)) {

    if (likely(in != q->testcase_buf)) {

      // only realloc if we save memory
      if (unlikely(len + 1024 < old_len)) {

        u8 *ptr = (u8 *)realloc(q->testcase_buf, len);

        if (likely(ptr)) {

          q->testcase_buf = ptr;
          sgf->q_testcase_cache_size += len - old_len;

        }

      }

      memcpy(q->testcase_buf, in, len);

    }

  }

}

/* Returns the testcase buf from the file behind this queue entry.
   Increases the refcount. */

inline u8 *queue_testcase_get(sgf_state_t *sgf, struct queue_entry *q) {

  if (likely(q->testcase_buf)) { return q->testcase_buf; }

  // If the skeleton graph is in memory in q->graph_data, construct testcase_buf directly from memory
  if (q->graph_data && q->graph_data->skeleton_graph) {
    uint8_t *sbuf = NULL;
    uint32_t slen = 0;
    if (serialize_graph_c(q->graph_data->skeleton_graph, &sbuf, &slen) == 0 && sbuf) {
      q->len = slen;
      q->testcase_buf = sbuf;
      return q->testcase_buf;
    }
  }

  u32    len = q->len;
  double weight = q->weight;

  // first handle if no testcase cache is configured, or if the
  // weighting of the testcase is below average.

  if (unlikely(weight < 1.0 || !sgf->q_testcase_max_cache_size)) {

    u8 *buf;

    if (likely(q == sgf->queue_cur)) {

      buf = (u8 *)afl_realloc((void **)&sgf->testcase_buf, len ? len : 1);

    } else {

      buf = (u8 *)afl_realloc((void **)&sgf->splicecase_buf, len ? len : 1);

    }

    if (unlikely(!buf)) {

      PFATAL("Unable to malloc '%s' with len %u", (char *)q->fname, len);

    }

    int fd = open((char *)q->fname, O_RDONLY);

    if (unlikely(fd < 0)) {
      if (q->graph_data && q->graph_data->skeleton_graph) {
        uint8_t *sbuf = NULL;
        uint32_t slen = 0;
        if (serialize_graph_c(q->graph_data->skeleton_graph, &sbuf, &slen) == 0 && sbuf) {
          q->len = slen;
          q->testcase_buf = sbuf;
          return q->testcase_buf;
        }
      }
      PFATAL("Unable to open '%s'", (char *)q->fname);
    }

    ck_read(fd, buf, len, q->fname);
    close(fd);
    return buf;

  }

  /* now handle the testcase cache and we know it is an interesting one */

  /* Buf not cached, let's load it */
  u32        tid = sgf->q_testcase_max_cache_count;
  static u32 do_once = 0;  // because even threaded we would want this. WIP

  while (unlikely(
      (sgf->q_testcase_cache_size + len >= sgf->q_testcase_max_cache_size &&
       sgf->q_testcase_cache_count > 1) ||
      sgf->q_testcase_cache_count >= sgf->q_testcase_max_cache_entries - 1)) {

    /* We want a max number of entries to the cache that we learn.
       Very simple: once the cache is filled by size - that is the max. */

    if (unlikely(
            sgf->q_testcase_cache_size + len >=
                sgf->q_testcase_max_cache_size &&
            (sgf->q_testcase_cache_count < sgf->q_testcase_max_cache_entries &&
             sgf->q_testcase_max_cache_count <
                 sgf->q_testcase_max_cache_entries) &&
            !do_once)) {

      if (sgf->q_testcase_max_cache_count > sgf->q_testcase_cache_count) {

        sgf->q_testcase_max_cache_entries = sgf->q_testcase_max_cache_count + 1;

      } else {

        sgf->q_testcase_max_cache_entries = sgf->q_testcase_cache_count + 1;

      }

      do_once = 1;
      // release unneeded memory
      sgf->q_testcase_cache = (struct queue_entry **)ck_realloc(
          sgf->q_testcase_cache,
          (sgf->q_testcase_max_cache_entries + 1) * sizeof(size_t));

    }

    /* Cache full. We need to evict one or more to map one.
       Get a random one which is not in use */

    do {

      // if the cache (MB) is not enough for the queue then this gets
      // undesirable because q_testcase_max_cache_count grows sometimes
      // although the number of items in the cache will not change hence
      // more and more loops
      tid = rand_below(sgf, sgf->q_testcase_max_cache_count);

    } while (sgf->q_testcase_cache[tid] == NULL ||

             sgf->q_testcase_cache[tid] == sgf->queue_cur);

    struct queue_entry *old_cached = sgf->q_testcase_cache[tid];
    free(old_cached->testcase_buf);
    old_cached->testcase_buf = NULL;
    sgf->q_testcase_cache_size -= old_cached->len;
    sgf->q_testcase_cache[tid] = NULL;
    --sgf->q_testcase_cache_count;
    ++sgf->q_testcase_evictions;
    if (tid < sgf->q_testcase_smallest_free)
      sgf->q_testcase_smallest_free = tid;

  }

  if (unlikely(tid >= sgf->q_testcase_max_cache_entries)) {

    // uh we were full, so now we have to search from start
    tid = sgf->q_testcase_smallest_free;

  }

  // we need this while loop in case there were ever previous evictions but
  // not in this call.
  while (unlikely(sgf->q_testcase_cache[tid] != NULL))
    ++tid;

  /* Map the test case into memory. */

  int fd = open((char *)q->fname, O_RDONLY);

  if (unlikely(fd < 0)) {
    if (q->graph_data && q->graph_data->skeleton_graph) {
      uint8_t *sbuf = NULL;
      uint32_t slen = 0;
      if (serialize_graph_c(q->graph_data->skeleton_graph, &sbuf, &slen) == 0 && sbuf) {
        q->len = slen;
        q->testcase_buf = sbuf;
        sgf->q_testcase_cache[tid] = q;
        sgf->q_testcase_cache_size += slen;
        ++sgf->q_testcase_cache_count;
        return q->testcase_buf;
      }
    }
    PFATAL("Unable to open '%s'", (char *)q->fname);
  }

  q->testcase_buf = (u8 *)malloc(len ? len : 1);

  if (unlikely(!q->testcase_buf)) {

    PFATAL("Unable to malloc '%s' with len %u", (char *)q->fname, len);

  }

  ck_read(fd, q->testcase_buf, len, q->fname);
  close(fd);

  /* Register testcase as cached */
  sgf->q_testcase_cache[tid] = q;
  sgf->q_testcase_cache_size += len;
  ++sgf->q_testcase_cache_count;
  if (likely(tid >= sgf->q_testcase_max_cache_count)) {

    sgf->q_testcase_max_cache_count = tid + 1;

  } else if (unlikely(tid == sgf->q_testcase_smallest_free)) {

    sgf->q_testcase_smallest_free = tid + 1;

  }

  return q->testcase_buf;

}

/* Adds the new queue entry to the cache. */

inline void queue_testcase_store_mem(sgf_state_t *sgf, struct queue_entry *q,
                                     u8 *mem) {

  u32 len = q->len;

  if (unlikely(q->weight < 1.0 ||
               sgf->q_testcase_cache_size + len >=
                   sgf->q_testcase_max_cache_size ||
               sgf->q_testcase_cache_count >=
                   sgf->q_testcase_max_cache_entries - 1)) {

    // no space or uninteresting? will be loaded regularly later.
    return;

  }

  u32 tid;

  if (unlikely(sgf->q_testcase_max_cache_count >=
               sgf->q_testcase_max_cache_entries)) {

    // uh we were full, so now we have to search from start
    tid = sgf->q_testcase_smallest_free;

  } else {

    tid = sgf->q_testcase_max_cache_count;

  }

  while (unlikely(sgf->q_testcase_cache[tid] != NULL))
    ++tid;

  /* Map the test case into memory. */

  q->testcase_buf = (u8 *)malloc(len);

  if (unlikely(!q->testcase_buf)) {

    PFATAL("Unable to malloc '%s' with len %u", (char *)q->fname, len);

  }

  memcpy(q->testcase_buf, mem, len);

  /* Register testcase as cached */
  sgf->q_testcase_cache[tid] = q;
  sgf->q_testcase_cache_size += len;
  ++sgf->q_testcase_cache_count;

  if (likely(tid >= sgf->q_testcase_max_cache_count)) {

    sgf->q_testcase_max_cache_count = tid + 1;

  } else if (unlikely(tid == sgf->q_testcase_smallest_free)) {

    sgf->q_testcase_smallest_free = tid + 1;

  }

}

