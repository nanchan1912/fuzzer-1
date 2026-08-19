/*
 * afl-queue-dispatch.c -- Dispatch mechanism for runtime queue implementation selection.
 *
 * Implements the public API in afl-queue.h by routing calls through function-pointer
 * tables to the appropriate implementation (structure1, structure2, or structure3).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "afl-queue.h"

/* ============================================================================
 * Forward declarations for the three implementations
 * ============================================================================ */

/* Structure 1: ThresholdBucketQueue */
afl_queue_t *s1_create(const char *impl_name, size_t m, size_t r, size_t bad_cap);
void s1_destroy(afl_queue_t *q);
int s1_enqueue(afl_queue_t *q, uint32_t entry_id, void *graph_data, double score);
AflQueueEntry *s1_dequeue(afl_queue_t *q);
int s1_update_score(afl_queue_t *q, uint32_t entry_id, double new_score);
size_t s1_size(afl_queue_t *q);
void s1_stats(afl_queue_t *q);

/* Structure 2: RunnerUpQueue */
afl_queue_t *s2_create(const char *impl_name, size_t m, size_t r, size_t bad_cap);
void s2_destroy(afl_queue_t *q);
int s2_enqueue(afl_queue_t *q, uint32_t entry_id, void *graph_data, double score);
AflQueueEntry *s2_dequeue(afl_queue_t *q);
int s2_update_score(afl_queue_t *q, uint32_t entry_id, double new_score);
size_t s2_size(afl_queue_t *q);
void s2_stats(afl_queue_t *q);

/* Structure 3: MaxHeapBucketQueue */
afl_queue_t *s3_create(const char *impl_name, size_t m, size_t r, size_t bad_cap);
void s3_destroy(afl_queue_t *q);
int s3_enqueue(afl_queue_t *q, uint32_t entry_id, void *graph_data, double score);
AflQueueEntry *s3_dequeue(afl_queue_t *q);
int s3_update_score(afl_queue_t *q, uint32_t entry_id, double new_score);
size_t s3_size(afl_queue_t *q);
void s3_stats(afl_queue_t *q);

/* MaxHeap: Baseline pure max-heap (ground-truth reference) */
afl_queue_t *maxheap_create(const char *impl_name, size_t m, size_t r, size_t bad_cap);
void maxheap_destroy(afl_queue_t *q);
int maxheap_enqueue(afl_queue_t *q, uint32_t entry_id, void *graph_data, double score);
AflQueueEntry *maxheap_dequeue(afl_queue_t *q);
int maxheap_update_score(afl_queue_t *q, uint32_t entry_id, double new_score);
size_t maxheap_size(afl_queue_t *q);
void maxheap_stats(afl_queue_t *q);

/* ============================================================================
 * Operation table (function pointers)
 * ============================================================================ */

typedef struct {
  afl_queue_t *(*create)(const char *, size_t, size_t, size_t);
  void (*destroy)(afl_queue_t *);
  int (*enqueue)(afl_queue_t *, uint32_t, void *, double);
  AflQueueEntry *(*dequeue)(afl_queue_t *);
  int (*update_score)(afl_queue_t *, uint32_t, double);
  size_t (*size)(afl_queue_t *);
  void (*stats)(afl_queue_t *);
} AflQueueOps;

static const AflQueueOps ops_structure1 = {
  .create = s1_create,
  .destroy = s1_destroy,
  .enqueue = s1_enqueue,
  .dequeue = s1_dequeue,
  .update_score = s1_update_score,
  .size = s1_size,
  .stats = s1_stats,
};

static const AflQueueOps ops_structure2 = {
  .create = s2_create,
  .destroy = s2_destroy,
  .enqueue = s2_enqueue,
  .dequeue = s2_dequeue,
  .update_score = s2_update_score,
  .size = s2_size,
  .stats = s2_stats,
};

static const AflQueueOps ops_structure3 = {
  .create = s3_create,
  .destroy = s3_destroy,
  .enqueue = s3_enqueue,
  .dequeue = s3_dequeue,
  .update_score = s3_update_score,
  .size = s3_size,
  .stats = s3_stats,
};

static const AflQueueOps ops_maxheap = {
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

struct afl_queue {
  const AflQueueOps *ops;
  void *impl_state;  /* Pointer to s1_queue_t, s2_queue_t, or s3_queue_t */
};

/* ============================================================================
 * Public API (dispatch through ops table)
 * ============================================================================ */

afl_queue_t *afl_queue_create(const char *impl_name,
                               size_t m, size_t r,
                               size_t initial_bad_cap) {
  if (!impl_name) {
    impl_name = "maxheap";  /* Default: MaxHeap baseline */
  }
  
  afl_queue_t *q = malloc(sizeof(*q));
  if (!q) return NULL;
  
  if (strcmp(impl_name, "structure1") == 0) {
    q->ops = &ops_structure1;
    q->impl_state = s1_create(impl_name, m, r, initial_bad_cap);
    fprintf(stderr, "[AFL Queue] Using Structure 1 (ThresholdBucketQueue)\n");
  } else if (strcmp(impl_name, "structure2") == 0) {
    q->ops = &ops_structure2;
    q->impl_state = s2_create(impl_name, m, r, initial_bad_cap);
    fprintf(stderr, "[AFL Queue] Using Structure 2 (RunnerUpQueue)\n");
  } else if (strcmp(impl_name, "structure3") == 0) {
    q->ops = &ops_structure3;
    q->impl_state = s3_create(impl_name, m, r, initial_bad_cap);
    fprintf(stderr, "[AFL Queue] Using Structure 3 (MaxHeapBucketQueue)\n");
  } else if (strcmp(impl_name, "maxheap") == 0) {
    q->ops = &ops_maxheap;
    q->impl_state = maxheap_create(impl_name, m, r, initial_bad_cap);
    fprintf(stderr, "[AFL Queue] Using MaxHeap (baseline, unbounded)\n");
  } else {
    fprintf(stderr, "[AFL Queue] ERROR: Unknown implementation '%s'\n", impl_name);
    fprintf(stderr, "           Available: structure1, structure2, structure3, maxheap\n");
    free(q);
    return NULL;
  }
  
  if (!q->impl_state) {
    free(q);
    return NULL;
  }
  
  return q;
}

void afl_queue_destroy(afl_queue_t *q) {
  if (!q) return;
  q->ops->destroy(q->impl_state);
  free(q);
}

int afl_queue_enqueue(afl_queue_t *q,
                      uint32_t entry_id,
                      void *graph_data,
                      double score) {
  if (!q) return -1;
  return q->ops->enqueue(q->impl_state, entry_id, graph_data, score);
}

AflQueueEntry *afl_queue_dequeue(afl_queue_t *q) {
  if (!q) return NULL;
  return q->ops->dequeue(q->impl_state);
}

int afl_queue_update_score(afl_queue_t *q, uint32_t entry_id, double new_score) {
  if (!q) return -1;
  return q->ops->update_score(q->impl_state, entry_id, new_score);
}

size_t afl_queue_size(afl_queue_t *q) {
  if (!q) return 0;
  return q->ops->size(q->impl_state);
}

void afl_queue_stats(afl_queue_t *q) {
  if (!q) return;
  q->ops->stats(q->impl_state);
}
