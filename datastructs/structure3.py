"""
structure3.py -- Structure 3: Max-Heap Bucket Queue.

Self-contained single file implementation.
"""

import heapq
from bisect import insort
from typing import Tuple, List, Union


def quickselect_top_m_split(
    scores: List[float],
    cids: List[int],
    m: int
) -> Tuple[List[Tuple[float, int]], List[Tuple[float, int]]]:
    """Split (scores, cids) into top_m tuples and bad_pile tuples using heapq.nlargest."""
    n = len(scores)
    if n <= m:
        return list(zip(scores, cids)), []

    all_items = list(zip(scores, cids))
    top_m = heapq.nlargest(m, all_items, key=lambda x: x[0])
    top_set = set(id(x) for x in top_m)
    bad = [x for x in all_items if id(x) not in top_set]
    return top_m, bad


class MaxHeapBucketQueueDS:
    """Structure 3: Max-Heap Bucket Queue (three-tier, max-heap selection, threshold admission).

    good_pile: max-heap of capacity m (stored as negated scores for Python heapq)
    runner_up: sorted list of capacity r, ascending by score
    bad_pile:  unbounded plain list
    threshold: running minimum score ever admitted to good_pile (monotonic lower bound)
    """

    def __init__(self, m: int = 500, r: int = 100):
        self.m = m
        self.r = r
        # Store (-score, cid) so Python's min-heapq gives us max-heap behaviour
        self.good_pile: List[Tuple[float, int]] = []
        # Sorted ascending (score, cid) — [0] = min, [-1] = max
        self.runner_up: List[Tuple[float, int]] = []
        self.bad_pile: List[Tuple[float, int]] = []
        # Admission threshold: lower-bound on good_pile minimum.
        # Starts at 0.0 (admit everything during fill-up).
        self.threshold: float = 0.0
        self._filling = True  # True while good_pile has not yet reached capacity m

    def __len__(self) -> int:
        return len(self.good_pile) + len(self.runner_up) + len(self.bad_pile)

    def insert(self, cid: int, score: float) -> None:
        s = float(score)
        gp = self.good_pile

        if len(gp) < self.m:
            # Fill-up phase: admit everything, track running minimum
            heapq.heappush(gp, (-s, cid))              # O(log m), C code
            if self._filling:
                if len(gp) == 1:                        # very first item
                    self.threshold = s
                else:
                    self.threshold = min(self.threshold, s)
            if len(gp) == self.m:
                self._filling = False
        elif s > self.threshold:
            # New candidate beats our tracked minimum -> evict a leaf, insert new
            neg_evict, cid_evict = gp.pop()             # O(1) leaf removal
            evicted_score = -neg_evict
            heapq.heappush(gp, (-s, cid))               # O(log m), C code
            self._admit_runner_up((evicted_score, cid_evict))
        else:
            self._admit_runner_up((s, cid))

    def _admit_runner_up(self, item: Tuple[float, int]) -> None:
        """Try to place item into runner_up; overflow goes to bad_pile."""
        if self.r == 0:
            self.bad_pile.append(item)
            return

        ru = self.runner_up
        if len(ru) < self.r:
            insort(ru, item)                             # O(r) array shift, r <= 100
        elif item[0] > ru[0][0]:                         # beats runner_up minimum?
            self.bad_pile.append(ru[0])                  # evict worst from runner_up
            ru.pop(0)
            insort(ru, item)
        else:
            self.bad_pile.append(item)

    def select(self) -> Tuple[int, float]:
        """Pop the maximum from good_pile in O(log m), then promote best runner_up."""
        ru = self.runner_up

        if not self.good_pile and not ru:
            # Emergency rebuild from bad_pile via quickselect
            bp_scores = [x[0] for x in self.bad_pile]
            bp_cids   = [x[1] for x in self.bad_pile]
            top_m, bad = quickselect_top_m_split(bp_scores, bp_cids, self.m)
            # Build max-heap (negate scores)
            max_heap = [(-s, c) for s, c in top_m]
            heapq.heapify(max_heap)
            self.good_pile = max_heap
            self.bad_pile = bad
            # Reset threshold to min of new good_pile (scan once — O(m) but only on emergency)
            if self.good_pile:
                self.threshold = min(-item[0] for item in self.good_pile)
            else:
                self.threshold = 0.0

        if not self.good_pile:
            raise RuntimeError("select() on completely empty MaxHeapBucketQueueDS")

        # Pop the maximum (root of max-heap) -> O(log m)
        neg_score, cid = heapq.heappop(self.good_pile)
        score = -neg_score

        # Promote the highest-scoring runner_up into good_pile -> O(1) + O(log m)
        if self.r > 0 and ru:
            promoted = ru.pop(-1)                        # O(1): pop max from sorted list
            heapq.heappush(self.good_pile, (-promoted[0], promoted[1]))  # O(log m)

        return cid, score

    def update_score(self, cid: int, new_score: float) -> None:
        """Lazy update: re-insert with new score."""
        self.insert(cid, new_score)


# Convenient Alias
Structure3 = MaxHeapBucketQueueDS
