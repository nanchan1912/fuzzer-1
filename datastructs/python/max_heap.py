"""
max_heap.py -- Baseline exact Max-Heap for ground-truth comparison.

Self-contained single file implementation.
"""

import heapq
from typing import Tuple, Dict


class MaxHeapDS:
    """Standard Binary Max-Heap Baseline.

    Always selects the candidate with the absolute maximum score in the population.
    """

    def __init__(self):
        # Stores (-score, cid)
        self.heap = []
        self.scores: Dict[int, float] = {}
        self.last_selected_cid = None

    def __len__(self) -> int:
        return len(self.scores)

    def insert(self, cid: int, score: float) -> None:
        self.scores[cid] = float(score)
        heapq.heappush(self.heap, (-float(score), cid))

    def select(self) -> Tuple[int, float]:
        """Pops and returns the candidate with the highest score in the queue."""
        while self.heap:
            neg_score, cid = heapq.heappop(self.heap)
            score = -neg_score
            # Check if entry is valid (not stale)
            if cid in self.scores and self.scores[cid] == score:
                del self.scores[cid]
                self.last_selected_cid = cid
                return cid, score
        raise RuntimeError("select() called on empty MaxHeapDS")

    def update_score(self, cid: int, new_score: float) -> None:
        """Re-inserts updated candidate with new_score."""
        self.insert(cid, new_score)


# Convenient Alias
MaxHeap = MaxHeapDS
