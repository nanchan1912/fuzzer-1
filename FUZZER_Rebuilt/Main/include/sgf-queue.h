/*
 * sgf-queue.h -- Public API for bounded queue implementations.
 *
 * Three implementations available at runtime:
 * - structure1: ThresholdBucketQueue (two-tier, periodic rebuild)
 * - structure2: RunnerUpQueue (three-tier, incremental, no rebuild)
 * - structure3: MaxHeapBucketQueue (three-tier, threshold-driven)
 *
 * All three implement the same interface; swap at runtime via SGF_QUEUE_IMPL env var.
 */

#ifndef SGF_QUEUE_H
#define SGF_QUEUE_H

#include <stdint.h>
#include <stddef.h>

/* Forward declare the opaque queue type */
typedef struct sgf_queue sgf_queue_t;

/* Entry returned by dequeue() */
typedef struct {
  uint32_t entry_id;           /* unique ID for this queue entry */
  void *graph_data;            /* pointer to SkeletonGraphData */
  double score;                /* perf_score at enqueue time */
} SgfQueueEntry;

/* =============================================================================
 * CORE API (same for all implementations)
 * ============================================================================= */

/**
 * Create a bounded queue of the specified implementation type.
 *
 * @param impl_name   "structure1", "structure2", or "structure3"
 * @param m           capacity of good_pile (top candidates)
 * @param r           capacity of runner_up buffer (if applicable)
 * @param initial_bad_cap  initial capacity of overflow buffer
 * @return            opaque handle, or NULL on error
 */
sgf_queue_t *sgf_queue_create(const char *impl_name, 
                               size_t m, size_t r, 
                               size_t initial_bad_cap);

/**
 * Destroy queue and free all resources.
 */
void sgf_queue_destroy(sgf_queue_t *q);

/**
 * Insert (enqueue) a new entry with score.
 *
 * @param q           queue handle
 * @param entry_id    unique ID for this entry
 * @param graph_data  pointer to the graph (opaque to queue)
 * @param score       perf_score (double)
 * @return            0 on success, -1 on error (e.g., alloc failure)
 *
 * Note: The queue does NOT take ownership of graph_data and never frees it.
 * Eviction simply drops the pointer. The caller owns the pointed-to object
 * and must keep it alive for as long as the entry may remain queued.
 * In sgf-fuzz this is a `struct queue_entry *` owned by AFL's queue linked
 * list, which lives for the whole campaign, so eviction is always safe.
 */
int sgf_queue_enqueue(sgf_queue_t *q, 
                      uint32_t entry_id,
                      void *graph_data, 
                      double score);

/**
 * Remove (dequeue) and return the next best entry.
 *
 * @param q           queue handle
 * @return            pointer to SgfQueueEntry (stack allocated, valid until next op),
 *                    or NULL if queue is empty
 *
 * Caller should use the returned entry immediately or copy its contents;
 * the pointer may be invalidated by the next queue operation.
 */
SgfQueueEntry *sgf_queue_dequeue(sgf_queue_t *q);

/**
 * Update score for an existing entry (lazy re-enqueue).
 *
 * @param q           queue handle
 * @param entry_id    the entry to update
 * @param new_score   new perf_score
 * @return            0 on success, -1 on error
 */
int sgf_queue_update_score(sgf_queue_t *q, uint32_t entry_id, double new_score);

/**
 * Get current total size (entries across all buckets).
 */
size_t sgf_queue_size(sgf_queue_t *q);

/**
 * Print internal statistics for benchmarking/debugging.
 */
void sgf_queue_stats(sgf_queue_t *q);

#endif /* SGF_QUEUE_H */
