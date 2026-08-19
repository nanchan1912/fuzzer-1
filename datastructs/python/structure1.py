"""
structure1.py -- Structure 1: Threshold Bucket Queue.

Self-contained single file implementation.
"""

import heapq
from typing import Tuple, List, Union


def quickselect_top_m_split(
    scores: List[float],
    cids: List[int],
    m: int
) -> Tuple[List[Tuple[float, int]], List[Tuple[float, int]]]:
    """Split (scores, cids) into top_m tuples and bad_pile tuples.

    Uses heapq.nlargest — O(n log m), much cheaper than a full sort.
    Returns two lists of (score, cid) tuples: top_m and bad.
    """
    n = len(scores)
    if n <= m:
        return list(zip(scores, cids)), []

    all_items = list(zip(scores, cids))
    top_m = heapq.nlargest(m, all_items, key=lambda x: x[0])
    top_set = set(id(x) for x in top_m)
    bad = [x for x in all_items if id(x) not in top_set]
    return top_m, bad


class ThresholdBucketQueueDS:
    """Structure 1: Threshold Bucket Queue (two-pile, heapq-backed, periodic rebuild).

    Uses Python's built-in heapq (C code) for the min-heap operations on good_pile,
    storing plain (score, cid) tuples — avoids custom-Python-class overhead on the
    hot insert/select paths.

    select() uses list.pop() directly on the backing array (the last element is always
    a leaf, so no sift is needed — this is the O(1) leaf trick).
    """

    def __init__(self, m: int = 50, T: Union[int, str] = 2000):
        self.m = m
        self.T = T
        self.good_pile: List[Tuple[float, int]] = []   # min-heap: (score, cid)
        self.bad_pile: List[Tuple[float, int]] = []    # plain list: (score, cid)
        self.ops_since_rebuild: int = 0

    def __len__(self) -> int:
        return len(self.good_pile) + len(self.bad_pile)

    def insert(self, cid: int, score: float) -> None:
        s = float(score)
        gp = self.good_pile

        if len(gp) < self.m:
            heapq.heappush(gp, (s, cid))          # O(log m) via C
        elif s > gp[0][0]:                         # better than current min?
            evicted = heapq.heapreplace(gp, (s, cid))  # O(log m), atomic pop+push via C
            self.bad_pile.append(evicted)           # O(1)
        else:
            self.bad_pile.append((s, cid))          # O(1)

        self.ops_since_rebuild += 1
        if self.T != "never" and self.ops_since_rebuild >= self.T:
            self.rebuild()

    def select(self) -> Tuple[int, float]:
        if self.good_pile:
            score, cid = self.good_pile.pop()      # O(1) leaf removal — list.pop() from end
        else:
            self.rebuild()                          # emergency rebuild
            if not self.good_pile:
                raise RuntimeError("select() on empty ThresholdBucketQueueDS")
            score, cid = self.good_pile.pop()

        self.ops_since_rebuild += 1
        if self.T != "never" and self.ops_since_rebuild >= self.T:
            self.rebuild()

        return cid, score

    def update_score(self, cid: int, new_score: float) -> None:
        """Re-inserts candidate with updated score (lazy update)."""
        self.insert(cid, new_score)

    def rebuild(self) -> None:
        """Quickselect the top m from good_pile + bad_pile, heapify in O(m)."""
        everyone_scores = [x[0] for x in self.good_pile] + [x[0] for x in self.bad_pile]
        everyone_cids   = [x[1] for x in self.good_pile] + [x[1] for x in self.bad_pile]
        top_m, bad = quickselect_top_m_split(everyone_scores, everyone_cids, self.m)
        heapq.heapify(top_m)
        self.good_pile = top_m
        self.bad_pile = bad
        self.ops_since_rebuild = 0


# Convenient Alias
Structure1 = ThresholdBucketQueueDS
