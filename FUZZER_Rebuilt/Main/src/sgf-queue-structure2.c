/*
 * sgf-queue-structure2.c -- RunnerUpQueue implementation.
 *
 * Three-tier queue with no periodic rebuild:
 * - good_pile:   min-heap of top m candidates
 * - runner_up:   small sorted list of next r best (ascending order)
 * - bad_pile:    unbounded overflow list
 *
 * select() is O(1) leaf removal + O(log m) promotion from runner_up.
 * enqueue() is O(log m) or O(r) depending on which tier.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sgf-queue.h"

/* ============================================================================
 * Internal structures (opaque to caller)
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
} MinHeap;

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
  MinHeap good_pile;
  SortedArray runner_up;
  DynamicArray bad_pile;
  size_t m;
  size_t r;
} S2Queue;

/* ============================================================================
 * Min-heap operations (for good_pile)
 * ============================================================================ */

static void s2_heappush(MinHeap *heap, uint32_t id, void *gd, double score) {
  if (heap->size == heap->capacity) {
    heap->capacity = heap->capacity ? heap->capacity * 2 : 128;
    heap->entries = realloc(heap->entries, heap->capacity * sizeof(void *));
  }
  
  QueueEntryNode *node = malloc(sizeof(*node));
  node->entry_id = id;
  node->graph_data = gd;
  node->score = score;
  
  size_t pos = heap->size;
  heap->entries[pos] = node;
  heap->size++;
  
  /* Sift-up: bubble node up while score < parent */
  while (pos > 0) {
    size_t parent_idx = (pos - 1) / 2;
    if (heap->entries[parent_idx]->score > score) {
      heap->entries[pos] = heap->entries[parent_idx];
      pos = parent_idx;
    } else {
      break;
    }
  }
  heap->entries[pos] = node;
}

static QueueEntryNode *s2_heappop(MinHeap *heap) {
  if (heap->size == 0) return NULL;
  
  QueueEntryNode *min = heap->entries[0];
  heap->size--;
  
  if (heap->size == 0) return min;
  
  QueueEntryNode *last = heap->entries[heap->size];
  size_t pos = 0;
  double last_score = last->score;
  
  /* Sift-down: bubble last node down */
  while (2 * pos + 1 < heap->size) {
    size_t left = 2 * pos + 1;
    size_t right = 2 * pos + 2;
    size_t smallest = left;
    
    if (right < heap->size && heap->entries[right]->score < heap->entries[left]->score) {
      smallest = right;
    }
    
    if (heap->entries[smallest]->score < last_score) {
      heap->entries[pos] = heap->entries[smallest];
      pos = smallest;
    } else {
      break;
    }
  }
  heap->entries[pos] = last;
  
  return min;
}

/* ============================================================================
 * Sorted array operations (for runner_up) -- ascending order
 * ============================================================================ */

static void s2_sorted_insert(SortedArray *arr, uint32_t id, void *gd, double score) {
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

static QueueEntryNode *s2_sorted_pop_max(SortedArray *arr) {
  if (arr->size == 0) return NULL;
  QueueEntryNode *max = arr->entries[arr->size - 1];
  arr->size--;
  return max;
}

/* ============================================================================
 * Dynamic array operations (for bad_pile)
 * ============================================================================ */

static void s2_dynamic_append(DynamicArray *arr, uint32_t id, void *gd, double score) {
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

static void s2_admit_to_runner_up(S2Queue *q, uint32_t id, void *gd, double score) {
  SortedArray *ru = &q->runner_up;
  
  if (q->r == 0) {
    s2_dynamic_append(&q->bad_pile, id, gd, score);
    return;
  }
  
  if (ru->size < ru->capacity) {
    s2_sorted_insert(ru, id, gd, score);
  } else if (ru->size > 0 && score > ru->entries[0]->score) {
    /* Evict worst from runner_up, insert new */
    QueueEntryNode *evicted = ru->entries[0];
    s2_dynamic_append(&q->bad_pile, evicted->entry_id, evicted->graph_data, evicted->score);
    free(evicted);
    ru->size--;
    
    /* Shift left */
    for (size_t i = 0; i < ru->size; i++) {
      ru->entries[i] = ru->entries[i + 1];
    }
    
    s2_sorted_insert(ru, id, gd, score);
  } else {
    s2_dynamic_append(&q->bad_pile, id, gd, score);
  }
}

static void s2_rebuild_from_bad(S2Queue *q) {
  MinHeap *gp = &q->good_pile;
  
  if (q->bad_pile.size == 0) return;
  
  /* Clear good_pile */
  for (size_t i = 0; i < gp->size; i++) {
    free(gp->entries[i]);
  }
  gp->size = 0;
  
  /* Take top m from bad_pile by a simple O(n log m) approach:
   * scan bad_pile, maintain a min-heap of size m */
  for (size_t i = 0; i < q->bad_pile.size; i++) {
    QueueEntryNode *node = q->bad_pile.entries[i];
    s2_heappush(gp, node->entry_id, node->graph_data, node->score);
    
    if (gp->size > q->m) {
      QueueEntryNode *evicted = s2_heappop(gp);
      free(evicted);
    }
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
 * Public API implementation
 * ============================================================================ */

sgf_queue_t *s2_create(const char *impl_name, size_t m, size_t r, size_t bad_cap) {
  (void)impl_name;
  
  S2Queue *impl = malloc(sizeof(*impl));
  impl->m = m;
  impl->r = r;
  
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

void s2_destroy(sgf_queue_t *q) {
  S2Queue *impl = (S2Queue *)q;
  
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

int s2_enqueue(sgf_queue_t *q, uint32_t entry_id, void *graph_data, double score) {
  S2Queue *impl = (S2Queue *)q;
  MinHeap *gp = &impl->good_pile;
  
  if (gp->size < impl->m) {
    s2_heappush(gp, entry_id, graph_data, score);
  } else if (score > gp->entries[0]->score) {
    QueueEntryNode *evicted = s2_heappop(gp);
    s2_heappush(gp, entry_id, graph_data, score);
    s2_admit_to_runner_up(impl, evicted->entry_id, evicted->graph_data, evicted->score);
    free(evicted);
  } else {
    s2_admit_to_runner_up(impl, entry_id, graph_data, score);
  }
  
  return 0;
}

SgfQueueEntry *s2_dequeue(sgf_queue_t *q) {
  static SgfQueueEntry result;
  
  S2Queue *impl = (S2Queue *)q;
  MinHeap *gp = &impl->good_pile;
  SortedArray *ru = &impl->runner_up;
  
  if (gp->size == 0 && ru->size == 0) {
    s2_rebuild_from_bad(impl);
    if (gp->size == 0) {
      return NULL;  /* Truly empty */
    }
  }
  
  if (gp->size == 0) {
    return NULL;
  }
  
  /* O(1) leaf removal from good_pile */
  QueueEntryNode *selected = gp->entries[gp->size - 1];
  gp->size--;
  
  /* Restore heap property (sift-down from root if we removed the last) */
  if (gp->size > 0 && gp->size > 0) {
    QueueEntryNode *last = gp->entries[gp->size];
    size_t pos = 0;
    double last_score = last->score;
    
    while (2 * pos + 1 < gp->size) {
      size_t left = 2 * pos + 1;
      size_t right = 2 * pos + 2;
      size_t smallest = left;
      
      if (right < gp->size && gp->entries[right]->score < gp->entries[left]->score) {
        smallest = right;
      }
      
      if (gp->entries[smallest]->score < last_score) {
        gp->entries[pos] = gp->entries[smallest];
        pos = smallest;
      } else {
        break;
      }
    }
    gp->entries[pos] = last;
  }
  
  /* Promote runner_up max into good_pile */
  if (ru->size > 0) {
    QueueEntryNode *promoted = s2_sorted_pop_max(ru);
    s2_heappush(gp, promoted->entry_id, promoted->graph_data, promoted->score);
    free(promoted);
  }
  
  result.entry_id = selected->entry_id;
  result.graph_data = selected->graph_data;
  result.score = selected->score;
  
  free(selected);
  
  return &result;
}

int s2_update_score(sgf_queue_t *q, uint32_t entry_id, double new_score) {
  /* Lazy update: just re-enqueue */
  return s2_enqueue(q, entry_id, NULL, new_score);
}

size_t s2_size(sgf_queue_t *q) {
  S2Queue *impl = (S2Queue *)q;
  return impl->good_pile.size + impl->runner_up.size + impl->bad_pile.size;
}

void s2_stats(sgf_queue_t *q) {
  S2Queue *impl = (S2Queue *)q;
  fprintf(stderr, 
    "[Queue S2] good=%zu (cap %zu), runner=%zu (cap %zu), bad=%zu (cap %zu), total=%zu\n",
    impl->good_pile.size, impl->good_pile.capacity,
    impl->runner_up.size, impl->runner_up.capacity,
    impl->bad_pile.size, impl->bad_pile.capacity,
    impl->good_pile.size + impl->runner_up.size + impl->bad_pile.size);
}
