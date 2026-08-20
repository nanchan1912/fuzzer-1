/*
 * sgf-queue-structure1.c -- ThresholdBucketQueue implementation.
 *
 * Two-tier queue with periodic rebuild:
 * - good_pile:   min-heap of top m candidates
 * - bad_pile:    overflow list
 * - Rebuild every T operations: quickselect top m from both piles
 *
 * Simpler than Structure2, but has O(m log m) stalls every T ops.
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
} MinHeap;

typedef struct {
  QueueEntryNode **entries;
  size_t size;
  size_t capacity;
} DynamicArray;

typedef struct {
  MinHeap good_pile;
  DynamicArray bad_pile;
  size_t m;
  int T;  /* rebuild threshold (ops between rebuilds), -1 = never */
  size_t ops_since_rebuild;
} S1Queue;

/* ============================================================================
 * Min-heap operations (same as Structure2)
 * ============================================================================ */

static void s1_heappush(MinHeap *heap, uint32_t id, void *gd, double score) {
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

static QueueEntryNode *s1_heappop(MinHeap *heap) {
  if (heap->size == 0) return NULL;
  
  QueueEntryNode *min = heap->entries[0];
  heap->size--;
  
  if (heap->size == 0) return min;
  
  QueueEntryNode *last = heap->entries[heap->size];
  size_t pos = 0;
  double last_score = last->score;
  
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

static void s1_heapify(MinHeap *heap) {
  if (heap->size == 0) return;
  
  /* Build heap from array in-place: start from last non-leaf and sift down */
  for (int i = (int)(heap->size / 2) - 1; i >= 0; i--) {
    QueueEntryNode *node = heap->entries[i];
    double node_score = node->score;
    size_t pos = (size_t)i;
    
    while (2 * pos + 1 < heap->size) {
      size_t left = 2 * pos + 1;
      size_t right = 2 * pos + 2;
      size_t smallest = left;
      
      if (right < heap->size && heap->entries[right]->score < heap->entries[left]->score) {
        smallest = right;
      }
      
      if (heap->entries[smallest]->score < node_score) {
        heap->entries[pos] = heap->entries[smallest];
        pos = smallest;
      } else {
        break;
      }
    }
    heap->entries[pos] = node;
  }
}

/* ============================================================================
 * Quickselect-based rebuild: top-m split via heapq.nlargest style
 * ============================================================================ */

static int compare_nodes_desc(const void *a, const void *b) {
  QueueEntryNode *na = *(QueueEntryNode **)a;
  QueueEntryNode *nb = *(QueueEntryNode **)b;
  if (na->score > nb->score) return -1;
  if (na->score < nb->score) return 1;
  return 0;
}

static void s1_rebuild(S1Queue *q) {
  MinHeap *gp = &q->good_pile;
  DynamicArray *bp = &q->bad_pile;
  
  size_t total = gp->size + bp->size;
  if (total == 0) return;
  
  /* Merge good_pile and bad_pile into a single array */
  QueueEntryNode **all = malloc(total * sizeof(void *));
  size_t idx = 0;
  
  for (size_t i = 0; i < gp->size; i++) {
    all[idx++] = gp->entries[i];
  }
  for (size_t i = 0; i < bp->size; i++) {
    all[idx++] = bp->entries[i];
  }
  
  /* Sort by score descending */
  qsort(all, total, sizeof(void *), compare_nodes_desc);
  
  /* Take top m, put in good_pile */
  size_t take_m = q->m < total ? q->m : total;
  
  for (size_t i = 0; i < take_m; i++) {
    gp->entries[i] = all[i];
  }
  gp->size = take_m;
  s1_heapify(gp);
  
  /* Rest go to bad_pile */
  for (size_t i = take_m; i < total; i++) {
    bp->entries[i - take_m] = all[i];
  }
  bp->size = total - take_m;
  
  free(all);
  q->ops_since_rebuild = 0;
}

/* ============================================================================
 * Public API
 * ============================================================================ */

sgf_queue_t *s1_create(const char *impl_name, size_t m, size_t r, size_t bad_cap) {
  (void)impl_name;
  (void)r;  /* Structure1 doesn't use r */
  
  S1Queue *impl = malloc(sizeof(*impl));
  impl->m = m;
  impl->T = 2000;  /* Default: rebuild every 2000 ops */
  impl->ops_since_rebuild = 0;
  
  impl->good_pile.capacity = m;
  impl->good_pile.size = 0;
  impl->good_pile.entries = malloc(m * sizeof(void *));
  
  impl->bad_pile.capacity = bad_cap ? bad_cap : 100000;
  impl->bad_pile.size = 0;
  impl->bad_pile.entries = malloc(impl->bad_pile.capacity * sizeof(void *));
  
  return (sgf_queue_t *)impl;
}

void s1_destroy(sgf_queue_t *q) {
  S1Queue *impl = (S1Queue *)q;
  
  for (size_t i = 0; i < impl->good_pile.size; i++) {
    free(impl->good_pile.entries[i]);
  }
  free(impl->good_pile.entries);
  
  for (size_t i = 0; i < impl->bad_pile.size; i++) {
    free(impl->bad_pile.entries[i]);
  }
  free(impl->bad_pile.entries);
  
  free(impl);
}

int s1_enqueue(sgf_queue_t *q, uint32_t entry_id, void *graph_data, double score) {
  S1Queue *impl = (S1Queue *)q;
  MinHeap *gp = &impl->good_pile;
  DynamicArray *bp = &impl->bad_pile;
  
  if (gp->size < impl->m) {
    s1_heappush(gp, entry_id, graph_data, score);
  } else if (score > gp->entries[0]->score) {
    QueueEntryNode *evicted = s1_heappop(gp);
    s1_heappush(gp, entry_id, graph_data, score);
    
    /* Add evicted to bad_pile */
    if (bp->size == bp->capacity) {
      bp->capacity = bp->capacity ? bp->capacity * 2 : 1024;
      bp->entries = realloc(bp->entries, bp->capacity * sizeof(void *));
    }
    bp->entries[bp->size++] = evicted;
  } else {
    /* Add directly to bad_pile */
    QueueEntryNode *node = malloc(sizeof(*node));
    node->entry_id = entry_id;
    node->graph_data = graph_data;
    node->score = score;
    
    if (bp->size == bp->capacity) {
      bp->capacity = bp->capacity ? bp->capacity * 2 : 1024;
      bp->entries = realloc(bp->entries, bp->capacity * sizeof(void *));
    }
    bp->entries[bp->size++] = node;
  }
  
  impl->ops_since_rebuild++;
  if (impl->T > 0 && impl->ops_since_rebuild >= (size_t)impl->T) {
    s1_rebuild(impl);
  }
  
  return 0;
}

SgfQueueEntry *s1_dequeue(sgf_queue_t *q) {
  static SgfQueueEntry result;
  
  S1Queue *impl = (S1Queue *)q;
  MinHeap *gp = &impl->good_pile;
  
  if (gp->size == 0) {
    s1_rebuild(impl);
    if (gp->size == 0) {
      return NULL;
    }
  }
  
  /* O(1) leaf removal */
  QueueEntryNode *selected = gp->entries[gp->size - 1];
  gp->size--;
  
  /* Restore heap property */
  if (gp->size > 0) {
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
  
  impl->ops_since_rebuild++;
  if (impl->T > 0 && impl->ops_since_rebuild >= (size_t)impl->T) {
    s1_rebuild(impl);
  }
  
  result.entry_id = selected->entry_id;
  result.graph_data = selected->graph_data;
  result.score = selected->score;
  
  free(selected);
  
  return &result;
}

int s1_update_score(sgf_queue_t *q, uint32_t entry_id, double new_score) {
  return s1_enqueue(q, entry_id, NULL, new_score);
}

size_t s1_size(sgf_queue_t *q) {
  S1Queue *impl = (S1Queue *)q;
  return impl->good_pile.size + impl->bad_pile.size;
}

void s1_stats(sgf_queue_t *q) {
  S1Queue *impl = (S1Queue *)q;
  fprintf(stderr,
    "[Queue S1] good=%zu (cap %zu), bad=%zu (cap %zu), ops_since_rebuild=%zu, total=%zu\n",
    impl->good_pile.size, impl->good_pile.capacity,
    impl->bad_pile.size, impl->bad_pile.capacity,
    impl->ops_since_rebuild,
    impl->good_pile.size + impl->bad_pile.size);
}
