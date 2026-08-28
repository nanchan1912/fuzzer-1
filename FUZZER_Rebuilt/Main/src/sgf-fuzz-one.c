/*
   american fuzzy lop++ - fuzze_one routines in different flavours
   ---------------------------------------------------------------
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

#include "diversity_checker.h"
#include "sgf-fuzz.h"
#include "sgf-ijon-min.h"
#include <string.h>
#include <limits.h>
#include "sgf-mutations.h"
#include <assert.h>
#include "skeleton_graph_mutator_wrapper.h" // for skeleton graph mutations
#include "potential_nn.h" // for potential score calculation

/* Mode-aware potential calculation wrappers */
#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

// Begin changes by us
static uint32_t graph_id = 0;
static uint32_t temp = 0;
static uint32_t temp_p = 0;

// Helper functions
static inline u32 skeleton_graph_total_instances(u32 highest_step) {
  if (highest_step < 1) { return 1; }
  if (highest_step >= 31) { return UINT32_MAX; }

  return (1U << highest_step) - 1U;
}

// TODO: can I get this as a cmd line arg instead of hardcoding? or make it dynamic in some sense?
const int k = 30; //number of mutations to track for coverage improvements

// array to keep track of mo coverage values and check for any improvements over the past k mutations
uint32_t track_mo_cov_k[30] = {0};
uint32_t track_rf_cov_k[30] = {0};

void update_cutoff(sgf_state_t *sgf, double current_cutoff, double new_score) {
  (void)current_cutoff;

  if (sgf->queued_mu == 0.0) {
    sgf->queued_mu = new_score;
    sgf->queued_mad = new_score * 0.1;
  } else {
    sgf->queued_mu = 0.95 * sgf->queued_mu + 0.05 * new_score;
    double diff = new_score - sgf->queued_mu;
    double abs_diff = diff < 0.0 ? -diff : diff;
    sgf->queued_mad = 0.95 * sgf->queued_mad + 0.05 * abs_diff;
  }

  double p = (double)sgf->cutoff_percentile / 100.0;
  if (p <= 0.0) p = 0.01;
  if (p >= 1.0) p = 0.99;

  double z_score = 0.0;
  if (p < 0.5) {
    z_score = -0.674 * (0.5 - p) / 0.25;
  } else {
    z_score = 0.674 * (p - 0.5) / 0.25;
  }

  double sigma = 1.25 * sgf->queued_mad;
  sgf->cutoff_score = sgf->queued_mu + z_score * sigma;

  if (sgf->cutoff_score < 0.0) {
    sgf->cutoff_score = 0.0;
  }
}

static inline void record_forbidden_mutation(struct queue_entry *parent, const MutationInfo *mut_info) {
  if (!parent || !parent->graph_data || !mut_info) return;
  if (!parent->graph_data->forbidden_mutations) {
    parent->graph_data->forbidden_mutations = forbidden_mutations_create();
  }
  if (mut_info->kind >= MUT_ADD_READ && mut_info->kind <= MUT_ADD_FENCE) {
    forbidden_mutations_add_event(parent->graph_data->forbidden_mutations, mut_info->dest_id);
  } else if (mut_info->kind == MUT_MUTATE_RF) {
    forbidden_mutations_add_rf(parent->graph_data->forbidden_mutations, mut_info->source_id, mut_info->dest_id);
  }
}

/*
 * Function to mutate the parent, run and enque the mutations created if they 
 * are not duplicates and are interesting.
 * 
 * @param sgf The SGF state.
 * @param parent The parent queue entry from which the mutation is derived.
 * @return The newly created queue entry after mutation and enqueueing, or NULL if the mutation was not successful or was a duplicate.
*/
struct queue_entry* mutate_run_enqueue_graph(sgf_state_t* sgf, struct queue_entry* parent) {
  if (!parent || !parent->graph_data || !parent->graph_data->skeleton_graph) {
    ACTF("Parent graph is NULL, cannot mutate and enqueue.");
    return NULL;
  }

  MutationInfo mut_info;
  memset(&mut_info, 0, sizeof(mut_info));
  mut_info.kind = MUT_NONE;

  void *potential_obj = NULL;

  /* Clone/create potential */
  if (parent->graph_data->skeleton_potential) {
    potential_obj = clone_skeleton_potential(parent->graph_data->skeleton_potential);
  } else {
    ACTF("Parents graph didn't had potential stored, so we create for it");
    potential_obj = create_skeleton_potential(parent->graph_data->skeleton_graph);
  }

  /* Perform mutation */
  if (parent->graph_data && !parent->graph_data->forbidden_mutations) {
    parent->graph_data->forbidden_mutations = forbidden_mutations_create();
  }
  SkeletonGraph *working_graph = mutate_skeleton_graph_with_info(parent->graph_data->skeleton_graph, (int)sgf->current_phase,
                                                            potential_obj,
                                                            (sgf->enable_feedback && parent->graph_data) ?
                                                               parent->graph_data->simulator_feedback : NULL,
                                                             &mut_info, sgf->enable_feedback,
                                                             parent->graph_data ? parent->graph_data->forbidden_mutations : NULL);

  if (!working_graph) {
    working_graph = empty_skeleton_graph();
  }

  switch (mut_info.kind) {
    case MUT_ADD_READ:         sgf->mut_add_read_cnt++;        break;
    case MUT_ADD_WRITE:        sgf->mut_add_write_cnt++;       break;
    case MUT_ADD_RMW:          sgf->mut_add_rmw_cnt++;         break;
    case MUT_ADD_CAS_SUCCESS:  sgf->mut_add_cas_success_cnt++; break;
    case MUT_ADD_CAS_FAILURE:  sgf->mut_add_cas_failure_cnt++; break;
    case MUT_ADD_FENCE:        sgf->mut_add_fence_cnt++;       break;
    case MUT_MUTATE_RF:        sgf->mut_rf_cnt++;              break;
    default: break;
  }

  /* Skip duplicates already in queue/seen set */
  if (skeleton_graph_seen(sgf, working_graph)) {
    destroy_SkeletonGraph(working_graph);
    destroy_skeleton_potential(potential_obj);
    return NULL;
  }

  // Allocate memory for mutated graph
  struct SkeletonGraphData *mutated_graph_metadata = ck_alloc(sizeof(struct SkeletonGraphData));
  memset(mutated_graph_metadata, 0, sizeof(struct SkeletonGraphData));

  // Assigning the working graph as the skeleton graph of the mutated graph instance
  mutated_graph_metadata->skeleton_graph = working_graph;

  /* Run graph on the simulator */
  u8 exit_code = skeleton_graph_fuzz_stuff(sgf, mutated_graph_metadata);

  // IMPORTANT: mutated_graph_metadata should now have the feedback from the simulator if enabled, 
  // which is stored in the simulator_feedback field. This feedback will be used in subsequent mutations.

  if(exit_code == EXIT_EVENT_MISMATCH || exit_code == EXIT_RF_TYPE_MISMATCH || exit_code == EXIT_NOT_INSTANTIABLE) {
    // ACTF("Mutated graph is not instantiable or has event mismatches, skipping enqueue and marking forbidden on parent.");
    record_forbidden_mutation(parent, &mut_info);
    if (mutated_graph_metadata->simulator_feedback) {
      destroy_simulator_feedback(mutated_graph_metadata->simulator_feedback);
      mutated_graph_metadata->simulator_feedback = NULL;
    }
    destroy_SkeletonGraph(working_graph);
    ck_free(mutated_graph_metadata);
    return NULL;
  }

  if (exit_code != FSRV_RUN_OK) {
    // Crash or hang, we can choose to save it or skip it based on the fuzzing strategy
    if (mutated_graph_metadata->simulator_feedback) {
      destroy_simulator_feedback(mutated_graph_metadata->simulator_feedback);
      mutated_graph_metadata->simulator_feedback = NULL;
    }
    destroy_SkeletonGraph(working_graph);
    ck_free(mutated_graph_metadata);
    return NULL;
  }
  
  // We reach here only when run was successful
  mutated_graph_metadata->id = graph_id++;  
  /* Update potential */
  potential_obj = update_potential(potential_obj, working_graph, &mut_info);

  if (!potential_obj) {
    ACTF("Potential update failed, creating new potential");
    potential_obj = create_skeleton_potential(working_graph);
  }
  
  void *race_pairs_obj = NULL;
  bool race_pairs_failed = false;

  /* Clone/create race pairs */
  if (sgf->check_data_race) {
    if (parent->graph_data->race_pairs) {
      race_pairs_obj = race_pair_store_clone(parent->graph_data->race_pairs);
    } else {
      ACTF("Parents graph didn't had potential stored, so we calculate for it");
      race_pairs_obj = race_pair_store_collect(parent->graph_data->skeleton_graph);
    }
    /* Update race pairs */
    if (race_pairs_obj != NULL) {
      race_pair_store_update_incremental(race_pairs_obj, working_graph, mut_info.dest_id);
    }
  }

  // Assiging the mutated graph, potential and race pairs
  mutated_graph_metadata->skeleton_potential = potential_obj;
  if (sgf->check_data_race) {
    if (race_pairs_failed) {
      if (race_pairs_obj){
        race_pair_store_destroy(race_pairs_obj);
      }
      race_pairs_obj = race_pair_store_create();
    }
    mutated_graph_metadata->race_pairs = race_pairs_obj;
    mutated_graph_metadata->racy_event_count = (u8)race_pair_store_size(race_pairs_obj);
    mutated_graph_metadata->is_racy = mutated_graph_metadata->racy_event_count > 0;
  }

  /* Update Coverage */
  sgf->mo_coverage = get_mo_coverage_count();
  sgf->rf_coverage = get_rf_coverage_count();

  /* Updating the mo frequency map before adding this new graph to the corpus */
  // Iterate over all memory locations and their MO orderings
  update_mo_coverage_for_graph(mutated_graph_metadata->skeleton_graph);

  // Dynamic cutoff check: only add to queue if calculate_score(mutated_graph_metadata) > sgf->cutoff_score
  double new_score = calculate_score(sgf, mutated_graph_metadata);

  bool has_no_children = (parent && parent->graph_data && parent->graph_data->children_enqueued == 0);

  if (new_score > sgf->cutoff_score || sgf->queued_items == 0 || (sgf->check_data_race && mutated_graph_metadata->is_racy) || has_no_children) {

    /* Mark graph as seen now that it passed cutoff and is being added to queue */
    skeleton_graph_seen_or_add(sgf, mutated_graph_metadata->skeleton_graph);

    /* Write graph */
    char *filename = alloc_printf("%s/queue/id:%06u,src:%06u.json", sgf->out_dir, sgf->queued_items, parent->id);
    size_t json_len = 0;
    if (sgf->log_graph_run_details) {
      json_len = write_to_json(filename, mutated_graph_metadata->skeleton_graph);
    }

    /* Enqueue */
    add_to_queue(sgf, (u8 *)filename, (u32)json_len, 0);
    ck_free(filename);

    if (parent && parent->graph_data) {
      parent->graph_data->children_enqueued++;
    }

    /* Populate queue entry */
    struct queue_entry *child = NULL;
    if (sgf->queue_top) {
      child = sgf->queue_top;
      mutated_graph_metadata->id = child->id;
      if (child->graph_data) {
        ck_free(child->graph_data);
      }
      child->graph_data = mutated_graph_metadata;
      child->graph_data->already_simulated = 1;
      child->perf_score = new_score;

      // Index in NN since we are keeping it
      if (child->graph_data->skeleton_potential && !child->graph_data->potential_indexed) {
        potential_nn_index_add(child, child->graph_data->skeleton_potential);
        child->graph_data->potential_indexed = 1;
      }
      
      /* Save race if interesting - done after ID is assigned to child, to prevent filename ID mismatch */
      if (sgf->check_data_race && mutated_graph_metadata->is_racy) {
        save_race_if_interesting(sgf, mutated_graph_metadata);
      }

      /* Index the fully-populated child in the bounded queue. This runs after
         add_to_queue() on purpose: add_to_queue() writes the file, allocates
         the queue_entry and sets sgf->queue_top, so `child` is only valid
         here. The bounded queue stores the queue_entry pointer itself and
         does not own it -- AFL's queue linked list retains ownership for the
         lifetime of the campaign, so eviction merely drops the pointer. */
      if (sgf->bounded_queue) {
        if (sgf_queue_enqueue(sgf->bounded_queue, child->id, child, new_score) != 0) {
          WARNF("bounded queue enqueue failed for entry %u", child->id);
        }
      }
    }

    // Update dynamic cutoff score based on current cutoff and new score
    update_cutoff(sgf, sgf->cutoff_score, new_score);

    return child;
  } else {
    // Discard mutated graph
    if (mutated_graph_metadata) {
      if (mutated_graph_metadata->skeleton_potential) {
        destroy_skeleton_potential(mutated_graph_metadata->skeleton_potential);
      }
      if (mutated_graph_metadata->race_pairs) {
        race_pair_store_destroy(mutated_graph_metadata->race_pairs);
      }
      if (mutated_graph_metadata->simulator_feedback) {
        destroy_simulator_feedback(mutated_graph_metadata->simulator_feedback);
      }
      if (mutated_graph_metadata->skeleton_graph) {
        destroy_SkeletonGraph(mutated_graph_metadata->skeleton_graph);
      }
      ck_free(mutated_graph_metadata);
    }
    return NULL;
  }
}
// End changes by us

/* MOpt */

static int select_algorithm(sgf_state_t *sgf, u32 max_algorithm) {

  int i_puppet, j_puppet = 0, operator_number = max_algorithm;

  double range_sele =
      (double)sgf->probability_now[sgf->swarm_now][operator_number - 1];
  double sele = ((double)(rand_below(sgf, 10000) * 0.0001 * range_sele));

  for (i_puppet = 0; i_puppet < operator_num; ++i_puppet) {

    if (unlikely(i_puppet == 0)) {

      if (sele < sgf->probability_now[sgf->swarm_now][i_puppet]) { break; }

    } else {

      if (sele < sgf->probability_now[sgf->swarm_now][i_puppet]) {

        j_puppet = 1;
        break;

      }

    }

  }

  if ((j_puppet == 1 &&
       sele < sgf->probability_now[sgf->swarm_now][i_puppet - 1]) ||
      (i_puppet + 1 < operator_num &&
       sele > sgf->probability_now[sgf->swarm_now][i_puppet + 1])) {

    FATAL("error select_algorithm");

  }

  return i_puppet;

}

/* Helper function to see if a particular change (xor_val = old ^ new) could
   be a product of deterministic bit flips with the lengths and stepovers
   attempted by sgf-fuzz. This is used to avoid dupes in some of the
   deterministic fuzzing operations that follow bit flips. We also
   return 1 if xor_val is zero, which implies that the old and attempted new
   values are identical and the exec would be a waste of time. */

static u8 could_be_bitflip(u32 xor_val) {

  u32 sh = 0;

  if (!xor_val) { return 1; }

  /* Shift left until first bit set. */

  while (!(xor_val & 1)) {

    ++sh;
    xor_val >>= 1;

  }

  /* 1-, 2-, and 4-bit patterns are OK anywhere. */

  if (xor_val == 1 || xor_val == 3 || xor_val == 15) { return 1; }

  /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
     divisible by 8, since that's the stepover for these ops. */

  if (sh & 7) { return 0; }

  if (xor_val == 0xff || xor_val == 0xffff || xor_val == 0xffffffff) {

    return 1;

  }

  return 0;

}

/* Helper function to see if a particular value is reachable through
   arithmetic operations. Used for similar purposes. */

static u8 could_be_arith(u32 old_val, u32 new_val, u8 blen) {

  u32 i, ov = 0, nv = 0, diffs = 0;

  if (old_val == new_val) { return 1; }

  /* See if one-byte adjustments to any byte could produce this result. */

  for (i = 0; (u8)i < blen; ++i) {

    u8 a = old_val >> (8 * i), b = new_val >> (8 * i);

    if (a != b) {

      ++diffs;
      ov = a;
      nv = b;

    }

  }

  /* If only one byte differs and the values are within range, return 1. */

  if (diffs == 1) {

    if ((u8)(ov - nv) <= ARITH_MAX || (u8)(nv - ov) <= ARITH_MAX) { return 1; }

  }

  if (blen == 1) { return 0; }

  /* See if two-byte adjustments to any byte would produce this result. */

  diffs = 0;

  for (i = 0; (u8)i < blen / 2; ++i) {

    u16 a = old_val >> (16 * i), b = new_val >> (16 * i);

    if (a != b) {

      ++diffs;
      ov = a;
      nv = b;

    }

  }

  /* If only one word differs and the values are within range, return 1. */

  if (diffs == 1) {

    if ((u16)(ov - nv) <= ARITH_MAX || (u16)(nv - ov) <= ARITH_MAX) {

      return 1;

    }

    ov = SWAP16(ov);
    nv = SWAP16(nv);

    if ((u16)(ov - nv) <= ARITH_MAX || (u16)(nv - ov) <= ARITH_MAX) {

      return 1;

    }

  }

  /* Finally, let's do the same thing for dwords. */

  if (blen == 4) {

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX) {

      return 1;

    }

    new_val = SWAP32(new_val);
    old_val = SWAP32(old_val);

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX) {

      return 1;

    }

  }

  return 0;

}

/* Last but not least, a similar helper to see if insertion of an
   interesting integer is redundant given the insertions done for
   shorter blen. The last param (check_le) is set if the caller
   already executed LE insertion for current blen and wants to see
   if BE variant passed in new_val is unique. */

static u8 could_be_interest(u32 old_val, u32 new_val, u8 blen, u8 check_le) {

  u32 i, j;

  if (old_val == new_val) { return 1; }

  /* See if one-byte insertions from interesting_8 over old_val could
     produce new_val. */

  for (i = 0; i < blen; ++i) {

    for (j = 0; j < sizeof(interesting_8); ++j) {

      u32 tval =
          (old_val & ~(0xff << (i * 8))) | (((u8)interesting_8[j]) << (i * 8));

      if (new_val == tval) { return 1; }

    }

  }

  /* Bail out unless we're also asked to examine two-byte LE insertions
     as a preparation for BE attempts. */

  if (blen == 2 && !check_le) { return 0; }

  /* See if two-byte insertions over old_val could give us new_val. */

  for (i = 0; (u8)i < blen - 1; ++i) {

    for (j = 0; j < sizeof(interesting_16) / 2; ++j) {

      u32 tval = (old_val & ~(0xffff << (i * 8))) |
                 (((u16)interesting_16[j]) << (i * 8));

      if (new_val == tval) { return 1; }

      /* Continue here only if blen > 2. */

      if (blen > 2) {

        tval = (old_val & ~(0xffff << (i * 8))) |
               (SWAP16(interesting_16[j]) << (i * 8));

        if (new_val == tval) { return 1; }

      }

    }

  }

  if (blen == 4 && check_le) {

    /* See if four-byte insertions could produce the same result
       (LE only). */

    for (j = 0; j < sizeof(interesting_32) / 4; ++j) {

      if (new_val == (u32)interesting_32[j]) { return 1; }

    }

  }

  return 0;

}

#ifndef IGNORE_FINDS

/* Helper function to compare buffers; returns first and last differing offset.
   We use this to find reasonable locations for splicing two files. */

static void locate_diffs(u8 *ptr1, u8 *ptr2, u32 len, s32 *first, s32 *last) {

  s32 f_loc = -1;
  s32 l_loc = -1;
  u32 pos;

  for (pos = 0; pos < len; ++pos) {

    if (*(ptr1++) != *(ptr2++)) {

      if (f_loc == -1) { f_loc = pos; }
      l_loc = pos;

    }

  }

  *first = f_loc;
  *last = l_loc;

  return;

}

#endif                                                     /* !IGNORE_FINDS */

/* Take the current entry from the queue, fuzz it for a while. This
   function is a tad too long... returns 0 if fuzzed successfully, 1 if
   skipped or bailed out. */

u8 fuzz_one_original(sgf_state_t *sgf) {

  u32 len, temp_len;
  u32 j;
  u32 i;
  u8 *in_buf, *out_buf, *orig_in, *ex_tmp;
  u64 havoc_queued = 0, orig_hit_cnt, new_hit_cnt = 0, prev_cksum, _prev_cksum;
  u32 splice_cycle = 0, perf_score = 100, orig_perf;

  u8 ret_val = 1, doing_det = 0;

  u8  a_collect[MAX_AUTO_EXTRA];
  u32 a_len = 0;

  /* IJON: If we're doing IJON, skip deterministic stages and go directly to
   * havoc */
  if (unlikely(sgf->is_doing_ijon)) {

    /* Use IJON input data that was set up in fuzz_one() */
    len = sgf->ijon_input_len;
    in_buf = orig_in = sgf->ijon_input_data;
    out_buf = ck_alloc_nozero(len);
    memcpy(out_buf, in_buf, len);

    /* Setup variables for havoc stage */
    temp_len = len;
    orig_hit_cnt = sgf->queued_items + sgf->saved_crashes;
    havoc_queued = sgf->queued_items;
    perf_score = 100;
    orig_perf = perf_score;

    /* Jump directly to havoc stage */
    goto havoc_stage;

  }

#ifdef IGNORE_FINDS

  /* In IGNORE_FINDS mode, skip any entries that weren't in the
     initial data set. */

  if (sgf->queue_cur->depth > 1) return 1;

#else

  if (unlikely(sgf->custom_mutators_count)) {

    /* The custom mutator will decide to skip this test case or not. */

    LIST_FOREACH(&sgf->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_queue_get &&
          !el->afl_custom_queue_get(el->data, sgf->queue_cur->fname)) {

        /* Abandon the entry and return that we skipped it.
           If we don't do this then when the entry is smallest_favored then
           we get caught in an infinite loop calling afl_custom_queue_get
           on smallest_favored */
        ret_val = 1;
        goto abandon_entry;

      }

    });

  }

  if (!sgf->queue_cur || !sgf->queue_cur->graph_data || !sgf->queue_cur->graph_data->skeleton_graph) {

    if (likely(sgf->pending_favored)) {

      /* If we have any favored, non-fuzzed new arrivals in the queue,
         possibly skip to them at the expense of already-fuzzed or non-favored
         cases. */

      if ((sgf->queue_cur->fuzz_level || !sgf->queue_cur->favored) &&
          likely(rand_below(sgf, 100) < SKIP_TO_NEW_PROB)) {

        return 1;

      }

    } else if (!sgf->non_instrumented_mode && !sgf->queue_cur->favored &&

               sgf->queued_items > 10) {

      /* Otherwise, still possibly skip non-favored cases, albeit less often.
         The odds of skipping stuff are higher for already-fuzzed inputs and
         lower for never-fuzzed entries. */

      if (sgf->queue_cycle > 1 && !sgf->queue_cur->fuzz_level) {

        if (likely(rand_below(sgf, 100) < SKIP_NFAV_NEW_PROB)) { return 1; }

      } else {

        if (likely(rand_below(sgf, 100) < SKIP_NFAV_OLD_PROB)) { return 1; }

      }

    }

  }

#endif                                                     /* ^IGNORE_FINDS */

  // Begin changes by us
  if (unlikely(sgf->queue_cur && sgf->queue_cur->graph_data && sgf->queue_cur->graph_data->non_instantiable)) {

    // ACTF("Skipping flagged entry %u (exit %u)", sgf->queue_cur->id,
        //  sgf->queue_cur->sim_exit_code);
    ++sgf->cur_skipped_items;
    return 1;

  }
  // End changes by us

  if (likely(sgf->not_on_tty)) {

    u8 time_tmp[64];

    u_simplestring_time_diff(time_tmp, sgf->prev_run_time + get_cur_time(),
                             sgf->start_time);
    ACTF(
        "Fuzzing test case #%u (%u total, %s%llu crashes saved%s, state: %s, "
        "mode=%s, "
        "perf_score=%0.0f, weight=%0.0f, favorite=%u, was_fuzzed=%u, "
        "exec_us=%llu, hits=%u, map=%u, ascii=%u, run_time=%s)...",
        sgf->current_entry, sgf->queued_items,
        sgf->saved_crashes != 0 ? cRED : "", sgf->saved_crashes, cRST,
        get_fuzzing_state(sgf), sgf->fuzz_mode ? "exploit" : "explore",
        sgf->queue_cur->perf_score, sgf->queue_cur->weight,
        sgf->queue_cur->favored, sgf->queue_cur->was_fuzzed,
        sgf->queue_cur->exec_us,
        likely(sgf->n_fuzz) ? sgf->n_fuzz[sgf->queue_cur->n_fuzz_entry] : 0,
        sgf->queue_cur->bitmap_size, sgf->queue_cur->is_ascii, time_tmp);
    fflush(stdout);

  }

  orig_in = in_buf = queue_testcase_get(sgf, sgf->queue_cur);
  len = sgf->queue_cur->len;

  out_buf = afl_realloc(SGF_BUF_PARAM(out), len);
  if (unlikely(!out_buf)) { PFATAL("alloc"); }

  sgf->subseq_tmouts = 0;

  sgf->cur_depth = sgf->queue_cur->depth;

  /*******************************************
   * CALIBRATION (only if failed earlier on) *
   *******************************************/

  if (unlikely(sgf->queue_cur->cal_failed)) {

    u8 res = FSRV_RUN_TMOUT;

    if (sgf->queue_cur->cal_failed < CAL_CHANCES) {

      sgf->queue_cur->exec_cksum = 0;

      res =
          calibrate_case(sgf, sgf->queue_cur, in_buf, sgf->queue_cycle - 1, 0);

      if (unlikely(res == FSRV_RUN_ERROR)) {

        FATAL("Unable to execute target application");

      }

    }

    if (unlikely(sgf->stop_soon) || res != sgf->crash_mode) {

      ++sgf->cur_skipped_items;
      goto abandon_entry;

    }

  }

  /************
   * TRIMMING *
   ************/

  if (unlikely(!sgf->non_instrumented_mode && !sgf->queue_cur->trim_done &&
               !sgf->disable_trim)) {
    u32 old_len = sgf->queue_cur->len;

    // u8 res = trim_case(sgf, sgf->queue_cur, in_buf);
    orig_in = in_buf = queue_testcase_get(sgf, sgf->queue_cur);

    // if (unlikely(res == FSRV_RUN_ERROR)) {

    //   FATAL("Unable to execute target application");

    // }

    if (unlikely(sgf->stop_soon)) {

      ++sgf->cur_skipped_items;
      goto abandon_entry;

    }

    /* Don't retry trimming, even if it failed. */

    sgf->queue_cur->trim_done = 1;

    len = sgf->queue_cur->len;

    /* maybe current entry is not ready for splicing anymore */
    if (unlikely(len <= 4 && old_len > 4)) --sgf->ready_for_splicing_count;

  }

  memcpy(out_buf, in_buf, len);

  /*********************
   * PERFORMANCE SCORE *
   *********************/

  // Begin changes by us
  ACTF("Current entry %u has perf_score %0.2f", sgf->queue_cur->id, sgf->queue_cur->perf_score);
  orig_perf = perf_score = sgf->queue_cur->perf_score;



  // Reduce perf_score after selection to avoid repeatedly favoring the same entry.
  if (sgf->queue_cur->perf_score > 1.0) {
    double decayed = sgf->queue_cur->perf_score * (1- sgf->queue_cur->graph_data->decay_ratio);
    if (decayed < 1.0) { decayed = 1.0; }
    sgf->queue_cur->perf_score = decayed;
  }

  /* For JSON skeleton graphs, skip standard byte-level mutations. */
havoc_stage:
  // Begin changes by us
  /****************************
   * FUZZING SKELETON GRAPHS  *
   ****************************/
    sgf->stage_name = "skeleton graph fuzzing";
    sgf->stage_short = "skeleton";
    const u32 highest_step = sgf->skeleton_graph_stage_max ?
                                 sgf->skeleton_graph_stage_max : 3;
    sgf->stage_max = skeleton_graph_total_instances(highest_step);
    sgf->stage_cur = 0;


    assert(sgf -> queue_cur != NULL);

    // Have to run the seed to get feedback
    if(sgf-> enable_feedback && sgf->queue_cur->graph_data->already_simulated == 0){
      u8 exit_code = skeleton_graph_fuzz_stuff(sgf, sgf->queue_cur->graph_data);
      if(exit_code == EXIT_NOT_INSTANTIABLE || exit_code == EXIT_EVENT_MISMATCH || exit_code == EXIT_RF_TYPE_MISMATCH){
        ACTF("Failed for the INIT entry");
        exit(1);
      }
    }

    if(sgf->enable_feedback){
      if(sgf->queue_cur && sgf->queue_cur->graph_data){
        if(!sgf->queue_cur->graph_data->simulator_feedback){
          ACTF("No Feedback found even after running");
          exit(1);
        }
      }
    }

    // Now, ensure the selected queue entry has skeleton_graph, potential, etc. populated
    if (sgf->queue_cur && sgf->queue_cur->graph_data) {
      // ACTF("The entry didn't have all the fields populated correctly.");
      // Will be required for seed
      // exit(1);
      if (!sgf->queue_cur->graph_data->skeleton_graph) {
        // No skeleton graph yet, read from JSON if file exists
        if (sgf->queue_cur->fname && access((char *)sgf->queue_cur->fname, R_OK) == 0) {
          sgf->queue_cur->graph_data->skeleton_graph = read_from_json(sgf->queue_cur->fname);
        }
        // If reading from JSON fails or file does not exist, create an empty skeleton graph
        if (!sgf->queue_cur->graph_data->skeleton_graph) {
          sgf->queue_cur->graph_data->skeleton_graph = empty_skeleton_graph();
        }
      }
      // If no potential object exists for the skeleton graph, create one
      if (!sgf->queue_cur->graph_data->skeleton_potential) {
        sgf->queue_cur->graph_data->skeleton_potential = create_skeleton_potential(sgf->queue_cur->graph_data->skeleton_graph);
      }
    }

    if (highest_step < 1 || highest_step >= 31) {
      assert(false && "highest_step must be between 1 and 30");
      goto end_skeleton_fuzzing;
    }

    u32 max_step_size = 1U << (highest_step - 1);
    struct queue_entry **prev_step_entries = ck_alloc(sizeof(struct queue_entry *) * max_step_size);
    u32 prev_step_count = 0;

    prev_step_entries[0] = sgf->queue_cur;
    prev_step_count = 1;

    for (u32 step = 1; step <= highest_step && sgf->stage_cur < sgf->stage_max; step++) {

      u32 target_count = 1U << (step - 1);
      struct queue_entry **curr_step_entries = ck_alloc(sizeof(struct queue_entry *) * target_count);
      u32 curr_step_count = 0;

      for (u32 instance = 0; instance < target_count && sgf->stage_cur < sgf->stage_max; ++instance) {

        struct queue_entry *parent = NULL;
        if (step == 1) {
          parent = prev_step_entries[0];
        } else {
          if (instance < prev_step_count) {
            parent = prev_step_entries[instance];
          } else {
            parent = prev_step_count > 0 ? prev_step_entries[instance % prev_step_count] : sgf->queue_cur;
          }
        }

        struct queue_entry *child = mutate_run_enqueue_graph(sgf, parent);
        if (!child) {
          // If mutation failed or was discarded by cutoff, skip to the next instance
          continue;
        }
        sgf->stage_cur++;

        curr_step_entries[curr_step_count++] = child;

      }

      ck_free(prev_step_entries);
      prev_step_entries = curr_step_entries;
      prev_step_count = curr_step_count;

    }

    ck_free(prev_step_entries);


end_skeleton_fuzzing:
// End changes by us

    /* Force UI update */
    show_stats(sgf);
    /* Skip other stages */
    ret_val = 0;
    goto abandon_entry;
abandon_entry:

  /* IJON queue protection only - memory cleanup handled normally */
  if (unlikely(sgf->is_doing_ijon)) {

    /* Reset IJON flag - memory cleanup handled by normal flow */
    sgf->is_doing_ijon = 0;

  }

  sgf->splicing_with = -1;

  /* Update sgf->pending_not_fuzzed count if we made it through the calibration
     cycle and have not seen this entry before. */

  if (unlikely(!sgf->is_doing_ijon && !sgf->stop_soon &&
               !sgf->queue_cur->cal_failed && !sgf->queue_cur->was_fuzzed &&
               !sgf->queue_cur->disabled)) {

    --sgf->pending_not_fuzzed;
    sgf->queue_cur->was_fuzzed = 1;
    sgf->reinit_table = 1;
    if (sgf->queue_cur->favored) {

      --sgf->pending_favored;
      sgf->smallest_favored = -1;

    }

  }

  if (unlikely(!sgf->is_doing_ijon)) { ++sgf->queue_cur->fuzz_level; }
  orig_in = NULL;
  return ret_val;

#undef FLIP_BIT

}

/* MOpt mode */
u8 fuzz_one(sgf_state_t *sgf) {

  int key_val_lv_1 = -1;

  /* IJON execution path - variables for file handling */
  u32 len = 0;
  u8 *in_buf = NULL, *out_buf = NULL, *orig_in = NULL;
  s32 fd = -1;

  /* IJON max tracking: Check if we should use IJON input (80% chance) */
  if (unlikely(sgf->ijon_state &&
               ijon_should_schedule((ijon_min_state *)sgf->ijon_state))) {

    ijon_input_info *ijon_input =
        ijon_get_input((ijon_min_state *)sgf->ijon_state);

    if (likely(ijon_input && ijon_input->len > 0)) {

      /* Open IJON input file directly */
      fd = open(ijon_input->filename, O_RDONLY);
      if (likely(fd >= 0)) {

        len = ijon_input->len;

        /* Map the IJON input file */
        orig_in = in_buf =
            mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        if (likely(orig_in != MAP_FAILED)) {

          close(fd);

          /* Allocate output buffer for mutations */
          out_buf = ck_alloc_nozero(len);
          memcpy(out_buf, in_buf, len);

          /* Store IJON input data for fuzz_one_original() */
          if (sgf->ijon_input_data) { ck_free(sgf->ijon_input_data); }
          sgf->ijon_input_data = ck_alloc(len);
          memcpy(sgf->ijon_input_data, in_buf, len);
          sgf->ijon_input_len = len;

          /* Set IJON execution flag */
          sgf->is_doing_ijon = 1;

          /* Clean up temporary buffers */
          ck_free(out_buf);
          munmap(orig_in, len);

          /* Call fuzz_one_original - it will handle IJON goto havoc_stage */
          u8 result = fuzz_one_original(sgf);

          /* Reset IJON flag and cleanup */
          sgf->is_doing_ijon = 0;
          if (sgf->ijon_input_data) {

            ck_free(sgf->ijon_input_data);
            sgf->ijon_input_data = NULL;
            sgf->ijon_input_len = 0;

          }

          return result;

        } else {

          WARNF("Unable to mmap IJON input '%s'", ijon_input->filename);
          close(fd);

        }

      } else {

        WARNF("Unable to open IJON input '%s'", ijon_input->filename);

      }

    }

  }

  /* Clear IJON input data for normal fuzzing */
  if (unlikely(sgf->ijon_input_data)) {

    ck_free(sgf->ijon_input_data);
    sgf->ijon_input_data = NULL;
    sgf->ijon_input_len = 0;

  }

  /* Reset IJON flag for normal fuzzing */
  sgf->is_doing_ijon = 0;

#ifdef _AFL_DOCUMENT_MUTATIONS

  u8 path_buf[PATH_MAX];
  if (sgf->do_document == 0) {

    snprintf(path_buf, PATH_MAX, "%s/mutations", sgf->out_dir);
    sgf->do_document =
        mkdir(path_buf, sgf->dir_perm);  // if it exists we do not care
    sgf->do_document = 1;

  } else {

    sgf->do_document = 2;
    sgf->stop_soon = 2;

  }

#endif

  // MOpt (-L flag) removed: graph-based fuzzing does not use it, and the
  // original -L flag parsing in sgf-fuzz.c should be removed alongside this
  // so -L is rejected outright rather than silently accepted and ignored.
  key_val_lv_1 = fuzz_one_original(sgf);

  if (unlikely(key_val_lv_1 == -1)) { key_val_lv_1 = 0; }

  return key_val_lv_1;

}