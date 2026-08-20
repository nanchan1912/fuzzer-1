/*
 * sgf-queue-structure3.c -- MaxHeapBucketQueue implementation.
 *
 * Three-tier queue with sophisticated threshold-driven admission:
 * - good_pile:   MAX-heap of top m candidates (stored negated for min-heapq)
 * - runner_up:   small sorted list of next r best (ascending order)
 * - bad_pile:    unbounded overflow list
 * - threshold:   monotonic lower-bound on good_pile minimum (prevents bloat)
 *
 * select() pops MAX from good_pile (O(log m)), promotes runner_up max.
 * enqueue() only admits if score beats threshold.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sgf-queue.h"

/* ============================================================================
 * Internal structures
 * ============================================================================ */

typedef struct {
  uint32_t entry_id;
  void *graph_data;
  double score;
} QueueEntryNode;

typedef struct {
  QueueEntryNode **entries;
  size_t size;
  size_t capacity;
} MaxHeap;

typedef struct {
  QueueEntryNode **entries;
  size_t size;
  size_t capacity;
} SortedArray;

typedef struct {
  QueueEntryNode **entries;
  size_t size;
  size_t capacity;
} DynamicArray;

typedef struct {
  MaxHeap good_pile;
  SortedArray runner_up;
  DynamicArray bad_pile;
  size_t m;
  size_t r;
  double threshold;  /* admission threshold: candidates must beat this */
  int filling;       /* true while good_pile hasn't reached capacity m */
} S3Queue;

/* ============================================================================
 * Max-heap operations (using negated scores as min-heap proxy)
 * ============================================================================ */

static void s3_heappush(MaxHeap *heap, uint32_t id, void *gd, double score) {
  if (heap->size == heap->capacity) {
    heap->capacity = heap->capacity ? heap->capacity * 2 : 128;
    heap->entries = realloc(heap->entries, heap->capacity * sizeof(void *));
  }
  
  QueueEntryNode *node = malloc(sizeof(*node));
  node->entry_id = id;
  node->graph_data = gd;
  node->score = score;  /* store actual score, negate only for comparisons */
  
  size_t pos = heap->size;
  heap->entries[pos] = node;
  heap->size++;
  
  /* Sift-up: bubble node up while score > parent (max-heap) */
  while (pos > 0) {
    size_t parent_idx = (pos - 1) / 2;
    if (heap->entries[parent_idx]->score < score) {
      heap->entries[pos] = heap->entries[parent_idx];
      pos = parent_idx;
    } else {
      break;
    }
  }
  heap->entries[pos] = node;
}

static QueueEntryNode *s3_heappop(MaxHeap *heap) {
  if (heap->size == 0) return NULL;
  
  QueueEntryNode *max = heap->entries[0];
  heap->size--;
  
  if (heap->size == 0) return max;
  
  QueueEntryNode *last = heap->entries[heap->size];
  size_t pos = 0;
  double last_score = last->score;
  
  /* Sift-down: bubble last node down (max-heap) */
  while (2 * pos + 1 < heap->size) {
    size_t left = 2 * pos + 1;
    size_t right = 2 * pos + 2;
    size_t largest = left;
    
    if (right < heap->size && heap->entries[right]->score > heap->entries[left]->score) {
      largest = right;
    }
    
    if (heap->entries[largest]->score > last_score) {
      heap->entries[pos] = heap->entries[largest];
      pos = largest;
    } else {
      break;
    }
  }
  heap->entries[pos] = last;
  
  return max;
}

/* ============================================================================
 * Sorted array operations (for runner_up) -- ascending order
 * ============================================================================ */

static void s3_sorted_insert(SortedArray *arr, uint32_t id, void *gd, double score) {
  if (arr->size == arr->capacity) {
    arr->capacity = arr->capacity ? arr->capacity * 2 : 64;
    arr->entries = realloc(arr->entries, arr->capacity * sizeof(void *));
  }
  
  QueueEntryNode *node = malloc(sizeof(*node));
  node->entry_id = id;
  node->graph_data = gd;
  node->score = score;
  
  /* Binary search for insertion point */
  int left = 0, right = (int)arr->size;
  while (left < right) {
    int mid = (left + right) / 2;
    if (arr->entries[mid]->score < score) {
      left = mid + 1;
    } else {
      right = mid;
    }
  }
  
  /* Shift right and insert */
  for (int i = (int)arr->size; i > left; i--) {
    arr->entries[i] = arr->entries[i - 1];
  }
  arr->entries[left] = node;
  arr->size++;
}

static QueueEntryNode *s3_sorted_pop_max(SortedArray *arr) {
  if (arr->size == 0) return NULL;
  QueueEntryNode *max = arr->entries[arr->size - 1];
  arr->size--;
  return max;
}

/* ============================================================================
 * Dynamic array operations (for bad_pile)
 * ============================================================================ */

static void s3_dynamic_append(DynamicArray *arr, uint32_t id, void *gd, double score) {
  if (arr->size == arr->capacity) {
    arr->capacity = arr->capacity ? arr->capacity * 2 : 1024;
    arr->entries = realloc(arr->entries, arr->capacity * sizeof(void *));
  }
  
  QueueEntryNode *node = malloc(sizeof(*node));
  node->entry_id = id;
  node->graph_data = gd;
  node->score = score;
  
  arr->entries[arr->size++] = node;
}

/* ============================================================================
 * Core queue operations
 * ============================================================================ */

static void s3_admit_to_runner_up(S3Queue *q, uint32_t id, void *gd, double score) {
  SortedArray *ru = &q->runner_up;
  
  if (q->r == 0) {
    s3_dynamic_append(&q->bad_pile, id, gd, score);
    return;
  }
  
  if (ru->size < ru->capacity) {
    s3_sorted_insert(ru, id, gd, score);
  } else if (ru->size > 0 && score > ru->entries[0]->score) {
    /* Evict worst from runner_up, insert new */
    QueueEntryNode *evicted = ru->entries[0];
    s3_dynamic_append(&q->bad_pile, evicted->entry_id, evicted->graph_data, evicted->score);
    free(evicted);
    ru->size--;
    
    /* Shift left */
    for (size_t i = 0; i < ru->size; i++) {
      ru->entries[i] = ru->entries[i + 1];
    }
    
    s3_sorted_insert(ru, id, gd, score);
  } else {
    s3_dynamic_append(&q->bad_pile, id, gd, score);
  }
}

static void s3_rebuild_from_bad(S3Queue *q) {
  MaxHeap *gp = &q->good_pile;
  
  if (q->bad_pile.size == 0) return;
  
  /* Clear good_pile */
  for (size_t i = 0; i < gp->size; i++) {
    free(gp->entries[i]);
  }
  gp->size = 0;
  
  /* Take top m from bad_pile */
  for (size_t i = 0; i < q->bad_pile.size; i++) {
    QueueEntryNode *node = q->bad_pile.entries[i];
    s3_heappush(gp, node->entry_id, node->graph_data, node->score);
    
    if (gp->size > q->m) {
      QueueEntryNode *evicted = s3_heappop(gp);
      free(evicted);
    }
  }
  
  /* Update threshold to min of new good_pile */
  if (gp->size > 0) {
    q->threshold = gp->entries[gp->size - 1]->score;
    for (size_t i = 0; i < gp->size; i++) {
      if (gp->entries[i]->score < q->threshold) {
        q->threshold = gp->entries[i]->score;
      }
    }
  } else {
    q->threshold = 0.0;
  }
  
  /* Clear bad_pile and runner_up */
  for (size_t i = 0; i < q->bad_pile.size; i++) {
    free(q->bad_pile.entries[i]);
  }
  q->bad_pile.size = 0;
  
  for (size_t i = 0; i < q->runner_up.size; i++) {
    free(q->runner_up.entries[i]);
  }
  q->runner_up.size = 0;
}

/* ============================================================================
 * Public API
 * ============================================================================ */

sgf_queue_t *s3_create(const char *impl_name, size_t m, size_t r, size_t bad_cap) {
  (void)impl_name;
  
  S3Queue *impl = malloc(sizeof(*impl));
  impl->m = m;
  impl->r = r;
  impl->threshold = 0.0;
  impl->filling = 1;
  
  impl->good_pile.capacity = m;
  impl->good_pile.size = 0;
  impl->good_pile.entries = malloc(m * sizeof(void *));
  
  impl->runner_up.capacity = r;
  impl->runner_up.size = 0;
  impl->runner_up.entries = malloc(r * sizeof(void *));
  
  impl->bad_pile.capacity = bad_cap ? bad_cap : 100000;
  impl->bad_pile.size = 0;
  impl->bad_pile.entries = malloc(impl->bad_pile.capacity * sizeof(void *));
  
  return (sgf_queue_t *)impl;
}

void s3_destroy(sgf_queue_t *q) {
  S3Queue *impl = (S3Queue *)q;
  
  for (size_t i = 0; i < impl->good_pile.size; i++) {
    free(impl->good_pile.entries[i]);
  }
  free(impl->good_pile.entries);
  
  for (size_t i = 0; i < impl->runner_up.size; i++) {
    free(impl->runner_up.entries[i]);
  }
  free(impl->runner_up.entries);
  
  for (size_t i = 0; i < impl->bad_pile.size; i++) {
    free(impl->bad_pile.entries[i]);
  }
  free(impl->bad_pile.entries);
  
  free(impl);
}

int s3_enqueue(sgf_queue_t *q, uint32_t entry_id, void *graph_data, double score) {
  S3Queue *impl = (S3Queue *)q;
  MaxHeap *gp = &impl->good_pile;
  
  if (gp->size < impl->m) {
    s3_heappush(gp, entry_id, graph_data, score);
    if (impl->filling) {
      if (gp->size == 1) {
        impl->threshold = score;
      } else if (score < impl->threshold) {
        impl->threshold = score;
      }
    }
    if (gp->size == impl->m) {
      impl->filling = 0;
      /* Set threshold to minimum in good_pile */
      impl->threshold = gp->entries[gp->size - 1]->score;
      for (size_t i = 0; i < gp->size; i++) {
        if (gp->entries[i]->score < impl->threshold) {
          impl->threshold = gp->entries[i]->score;
        }
      }
    }
  } else if (score > impl->threshold) {
    /* Evict from good_pile, insert new */
    QueueEntryNode *evicted = s3_heappop(gp);
    s3_heappush(gp, entry_id, graph_data, score);
    s3_admit_to_runner_up(impl, evicted->entry_id, evicted->graph_data, evicted->score);
    free(evicted);
    
    /* Update threshold to new minimum */
    impl->threshold = gp->entries[gp->size - 1]->score;
    for (size_t i = 0; i < gp->size; i++) {
      if (gp->entries[i]->score < impl->threshold) {
        impl->threshold = gp->entries[i]->score;
      }
    }
  } else {
    s3_admit_to_runner_up(impl, entry_id, graph_data, score);
  }
  
  return 0;
}

SgfQueueEntry *s3_dequeue(sgf_queue_t *q) {
  static SgfQueueEntry result;
  
  S3Queue *impl = (S3Queue *)q;
  MaxHeap *gp = &impl->good_pile;
  SortedArray *ru = &impl->runner_up;
  
  if (gp->size == 0 && ru->size == 0) {
    s3_rebuild_from_bad(impl);
    if (gp->size == 0) {
      return NULL;
    }
  }
  
  if (gp->size == 0) {
    return NULL;
  }
  
  /* Pop max from good_pile (root, O(log m)) */
  QueueEntryNode *selected = s3_heappop(gp);
  
  /* Promote runner_up max if available */
  if (ru->size > 0) {
    QueueEntryNode *promoted = s3_sorted_pop_max(ru);
    s3_heappush(gp, promoted->entry_id, promoted->graph_data, promoted->score);
    free(promoted);
  }
  
  result.entry_id = selected->entry_id;
  result.graph_data = selected->graph_data;
  result.score = selected->score;
  
  free(selected);
  
  return &result;
}

int s3_update_score(sgf_queue_t *q, uint32_t entry_id, double new_score) {
  return s3_enqueue(q, entry_id, NULL, new_score);
}

size_t s3_size(sgf_queue_t *q) {
  S3Queue *impl = (S3Queue *)q;
  return impl->good_pile.size + impl->runner_up.size + impl->bad_pile.size;
}

void s3_stats(sgf_queue_t *q) {
  S3Queue *impl = (S3Queue *)q;
  fprintf(stderr,
    "[Queue S3] good=%zu (cap %zu), runner=%zu (cap %zu), bad=%zu (cap %zu), "
    "threshold=%.6f, total=%zu\n",
    impl->good_pile.size, impl->good_pile.capacity,
    impl->runner_up.size, impl->runner_up.capacity,
    impl->bad_pile.size, impl->bad_pile.capacity,
    impl->threshold,
    impl->good_pile.size + impl->runner_up.size + impl->bad_pile.size);
}
