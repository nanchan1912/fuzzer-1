/*
 * afl-queue-maxheap.c -- MaxHeapDS implementation (baseline).
 *
 * Pure single-tier max-heap baseline for ground-truth comparison.
 * Always selects the candidate with the absolute maximum score in the population.
 *
 * No tiers, no buckets, no rebuild logic. Just a plain max-heap that grows
 * unbounded and always pops the highest-scoring entry.
 *
 * This is the simplest possible queue implementation, useful as a reference
 * to see how much the tiered structures (1, 2, 3) actually buy you.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "afl-queue.h"

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
  MaxHeap heap;
} MaxHeapQueue;

/* ============================================================================
 * Max-heap operations (stores actual scores, compares directly)
 * ============================================================================ */

static void maxheap_push(MaxHeap *heap, uint32_t id, void *gd, double score) {
  if (heap->size == heap->capacity) {
    heap->capacity = heap->capacity ? heap->capacity * 2 : 256;
    heap->entries = realloc(heap->entries, heap->capacity * sizeof(void *));
  }
  
  QueueEntryNode *node = malloc(sizeof(*node));
  node->entry_id = id;
  node->graph_data = gd;
  node->score = score;
  
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

static QueueEntryNode *maxheap_pop(MaxHeap *heap) {
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
 * Public API
 * ============================================================================ */

afl_queue_t *maxheap_create(const char *impl_name, size_t m, size_t r, size_t bad_cap) {
  (void)impl_name;
  (void)m;  /* MaxHeap doesn't use m, r, or bad_cap parameters */
  (void)r;
  (void)bad_cap;
  
  MaxHeapQueue *impl = malloc(sizeof(*impl));
  impl->heap.capacity = 256;
  impl->heap.size = 0;
  impl->heap.entries = malloc(impl->heap.capacity * sizeof(void *));
  
  return (afl_queue_t *)impl;
}

void maxheap_destroy(afl_queue_t *q) {
  MaxHeapQueue *impl = (MaxHeapQueue *)q;
  
  for (size_t i = 0; i < impl->heap.size; i++) {
    free(impl->heap.entries[i]);
  }
  free(impl->heap.entries);
  free(impl);
}

int maxheap_enqueue(afl_queue_t *q, uint32_t entry_id, void *graph_data, double score) {
  MaxHeapQueue *impl = (MaxHeapQueue *)q;
  maxheap_push(&impl->heap, entry_id, graph_data, score);
  return 0;
}

AflQueueEntry *maxheap_dequeue(afl_queue_t *q) {
  static AflQueueEntry result;
  
  MaxHeapQueue *impl = (MaxHeapQueue *)q;
  
  if (impl->heap.size == 0) {
    return NULL;
  }
  
  QueueEntryNode *selected = maxheap_pop(&impl->heap);
  
  result.entry_id = selected->entry_id;
  result.graph_data = selected->graph_data;
  result.score = selected->score;
  
  free(selected);
  
  return &result;
}

int maxheap_update_score(afl_queue_t *q, uint32_t entry_id, double new_score) {
  /* Lazy update: just re-enqueue */
  return maxheap_enqueue(q, entry_id, NULL, new_score);
}

size_t maxheap_size(afl_queue_t *q) {
  MaxHeapQueue *impl = (MaxHeapQueue *)q;
  return impl->heap.size;
}

void maxheap_stats(afl_queue_t *q) {
  MaxHeapQueue *impl = (MaxHeapQueue *)q;
  fprintf(stderr,
    "[Queue MaxHeap] size=%zu (cap %zu), total=%zu\n",
    impl->heap.size, impl->heap.capacity,
    impl->heap.size);
}
