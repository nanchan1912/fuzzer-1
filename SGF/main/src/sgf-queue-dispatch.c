/*
 * sgf-queue-dispatch.c -- Dispatch mechanism for runtime queue implementation selection.
 *
 * Implements the public API in sgf-queue.h by routing calls through function-pointer
 * tables to the appropriate implementation (threshold_bucket, runner_up, or maxheap_bucket).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sgf-queue.h"

/* ============================================================================
 * Forward declarations for the three implementations
 * ============================================================================ */

/* Structure 1: ThresholdBucketQueue */
sgf_queue_t *tbq_create(const char *impl_name, size_t m, size_t r, size_t bad_cap);
void tbq_destroy(sgf_queue_t *q);
int tbq_enqueue(sgf_queue_t *q, uint32_t entry_id, void *graph_data, double score);
SgfQueueEntry *tbq_dequeue(sgf_queue_t *q);
int tbq_update_score(sgf_queue_t *q, uint32_t entry_id, double new_score);
size_t tbq_size(sgf_queue_t *q);
void tbq_stats(sgf_queue_t *q);

/* Structure 2: RunnerUpQueue */
sgf_queue_t *rup_create(const char *impl_name, size_t m, size_t r, size_t bad_cap);
void rup_destroy(sgf_queue_t *q);
int rup_enqueue(sgf_queue_t *q, uint32_t entry_id, void *graph_data, double score);
SgfQueueEntry *rup_dequeue(sgf_queue_t *q);
int rup_update_score(sgf_queue_t *q, uint32_t entry_id, double new_score);
size_t rup_size(sgf_queue_t *q);
void rup_stats(sgf_queue_t *q);

/* Structure 3: MaxHeapBucketQueue */
sgf_queue_t *mhb_create(const char *impl_name, size_t m, size_t r, size_t bad_cap);
void mhb_destroy(sgf_queue_t *q);
int mhb_enqueue(sgf_queue_t *q, uint32_t entry_id, void *graph_data, double score);
SgfQueueEntry *mhb_dequeue(sgf_queue_t *q);
int mhb_update_score(sgf_queue_t *q, uint32_t entry_id, double new_score);
size_t mhb_size(sgf_queue_t *q);
void mhb_stats(sgf_queue_t *q);

/* MaxHeap: Baseline pure max-heap (ground-truth reference) */
sgf_queue_t *maxheap_create(const char *impl_name, size_t m, size_t r, size_t bad_cap);
void maxheap_destroy(sgf_queue_t *q);
int maxheap_enqueue(sgf_queue_t *q, uint32_t entry_id, void *graph_data, double score);
SgfQueueEntry *maxheap_dequeue(sgf_queue_t *q);
int maxheap_update_score(sgf_queue_t *q, uint32_t entry_id, double new_score);
size_t maxheap_size(sgf_queue_t *q);
void maxheap_stats(sgf_queue_t *q);

/* ============================================================================
 * Operation table (function pointers)
 * ============================================================================ */

typedef struct {
  sgf_queue_t *(*create)(const char *, size_t, size_t, size_t);
  void (*destroy)(sgf_queue_t *);
  int (*enqueue)(sgf_queue_t *, uint32_t, void *, double);
  SgfQueueEntry *(*dequeue)(sgf_queue_t *);
  int (*update_score)(sgf_queue_t *, uint32_t, double);
  size_t (*size)(sgf_queue_t *);
  void (*stats)(sgf_queue_t *);
} SgfQueueOps;

static const SgfQueueOps ops_threshold_bucket = {
  .create = tbq_create,
  .destroy = tbq_destroy,
  .enqueue = tbq_enqueue,
  .dequeue = tbq_dequeue,
  .update_score = tbq_update_score,
  .size = tbq_size,
  .stats = tbq_stats,
};

static const SgfQueueOps ops_runner_up = {
  .create = rup_create,
  .destroy = rup_destroy,
  .enqueue = rup_enqueue,
  .dequeue = rup_dequeue,
  .update_score = rup_update_score,
  .size = rup_size,
  .stats = rup_stats,
};

static const SgfQueueOps ops_maxheap_bucket = {
  .create = mhb_create,
  .destroy = mhb_destroy,
  .enqueue = mhb_enqueue,
  .dequeue = mhb_dequeue,
  .update_score = mhb_update_score,
  .size = mhb_size,
  .stats = mhb_stats,
};

static const SgfQueueOps ops_maxheap = {
  .create = maxheap_create,
  .destroy = maxheap_destroy,
  .enqueue = maxheap_enqueue,
  .dequeue = maxheap_dequeue,
  .update_score = maxheap_update_score,
  .size = maxheap_size,
  .stats = maxheap_stats,
};

/* ============================================================================
 * Opaque queue wrapper
 * ============================================================================ */

struct sgf_queue {
  const SgfQueueOps *ops;
  void *impl_state;  /* Pointer to tbq_queue_t, rup_queue_t, or mhb_queue_t */
};

/* ============================================================================
 * Public API (dispatch through ops table)
 * ============================================================================ */

sgf_queue_t *sgf_queue_create(const char *impl_name,
                               size_t m, size_t r,
                               size_t initial_bad_cap) {
  if (!impl_name) {
    impl_name = "maxheap";  /* Default: MaxHeap baseline */
  }
  
  sgf_queue_t *q = malloc(sizeof(*q));
  if (!q) return NULL;
  
  if (strcmp(impl_name, "threshold_bucket") == 0) {
    q->ops = &ops_threshold_bucket;
    q->impl_state = tbq_create(impl_name, m, r, initial_bad_cap);
    fprintf(stderr, "[SGF Queue] Using ThresholdBucketQueue\n");
  } else if (strcmp(impl_name, "runner_up") == 0) {
    q->ops = &ops_runner_up;
    q->impl_state = rup_create(impl_name, m, r, initial_bad_cap);
    fprintf(stderr, "[SGF Queue] Using RunnerUpQueue\n");
  } else if (strcmp(impl_name, "maxheap_bucket") == 0) {
    q->ops = &ops_maxheap_bucket;
    q->impl_state = mhb_create(impl_name, m, r, initial_bad_cap);
    fprintf(stderr, "[SGF Queue] Using MaxHeapBucketQueue\n");
  } else if (strcmp(impl_name, "maxheap") == 0) {
    q->ops = &ops_maxheap;
    q->impl_state = maxheap_create(impl_name, m, r, initial_bad_cap);
    fprintf(stderr, "[SGF Queue] Using MaxHeap (baseline, unbounded)\n");
  } else {
    fprintf(stderr, "[SGF Queue] ERROR: Unknown implementation '%s'\n", impl_name);
    fprintf(stderr, "           Available: threshold_bucket, runner_up, maxheap_bucket, maxheap\n");
    free(q);
    return NULL;
  }
  
  if (!q->impl_state) {
    free(q);
    return NULL;
  }
  
  return q;
}

void sgf_queue_destroy(sgf_queue_t *q) {
  if (!q) return;
  q->ops->destroy(q->impl_state);
  free(q);
}

int sgf_queue_enqueue(sgf_queue_t *q,
                      uint32_t entry_id,
                      void *graph_data,
                      double score) {
  if (!q) return -1;
  return q->ops->enqueue(q->impl_state, entry_id, graph_data, score);
}

SgfQueueEntry *sgf_queue_dequeue(sgf_queue_t *q) {
  if (!q) return NULL;
  return q->ops->dequeue(q->impl_state);
}

int sgf_queue_update_score(sgf_queue_t *q, uint32_t entry_id, double new_score) {
  if (!q) return -1;
  return q->ops->update_score(q->impl_state, entry_id, new_score);
}

size_t sgf_queue_size(sgf_queue_t *q) {
  if (!q) return 0;
  return q->ops->size(q->impl_state);
}

void sgf_queue_stats(sgf_queue_t *q) {
  if (!q) return;
  q->ops->stats(q->impl_state);
}
