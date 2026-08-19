"""
structure2.py -- Structure 2: Runner-Up Bucket Queue.

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


class RunnerUpQueueDS:
    """Structure 2: Runner-Up Bucket Queue (three-tier, no periodic rebuild).

    Uses heapq (C code) for good_pile and a small sorted list for runner_up.
    Flat (score, cid) tuples throughout — no custom Python object overhead on the
    hot insert/select paths.
    """

    def __init__(self, m: int = 500, r: int = 100):
        self.m = m
        self.r = r
        self.good_pile: List[Tuple[float, int]] = []   # min-heap: (score, cid)
        self.runner_up: List[Tuple[float, int]] = []   # sorted list: [(score, cid), ...]
        self.bad_pile: List[Tuple[float, int]] = []    # unsorted list: (score, cid)

    def __len__(self) -> int:
        return len(self.good_pile) + len(self.runner_up) + len(self.bad_pile)

    def insert(self, cid: int, score: float) -> None:
        s = float(score)
        gp = self.good_pile

        if len(gp) < self.m:
            heapq.heappush(gp, (s, cid))              # O(log m), C code
        elif s > gp[0][0]:
            evicted = heapq.heapreplace(gp, (s, cid)) # O(log m), atomic pop+push, C
            self._admit_runner_up(evicted)
        else:
            self._admit_runner_up((s, cid))

    def _admit_runner_up(self, item: Tuple[float, int]) -> None:
        """Attempt to add item into the runner_up buffer."""
        if self.r == 0:
            self.bad_pile.append(item)
            return

        ru = self.runner_up
        if len(ru) < self.r:
            insort(ru, item)                           # O(r) but r is tiny (<=100)
        elif item[0] > ru[0][0]:                       # better than runner_up minimum?
            self.bad_pile.append(ru[0])                # evict worst from runner_up
            ru.pop(0)
            insort(ru, item)
        else:
            self.bad_pile.append(item)

    def select(self) -> Tuple[int, float]:
        """O(1) leaf pop from good_pile, then O(log r) promotion from runner_up."""
        ru = self.runner_up
        if not self.good_pile and not ru:
            # Emergency refill from bad_pile
            bp_scores = [x[0] for x in self.bad_pile]
            bp_cids   = [x[1] for x in self.bad_pile]
            top_m, bad = quickselect_top_m_split(bp_scores, bp_cids, self.m)
            heapq.heapify(top_m)
            self.good_pile = top_m
            self.bad_pile = bad

        if not self.good_pile:
            raise RuntimeError("select() on completely empty RunnerUpQueueDS")

        score, cid = self.good_pile.pop()              # O(1) leaf removal

        if self.r > 0 and ru:
            promoted = ru.pop(-1)                      # O(1): pop max from sorted list
            heapq.heappush(self.good_pile, promoted)   # O(log m), C

        return cid, score

    def update_score(self, cid: int, new_score: float) -> None:
        """Re-inserts candidate with updated score (lazy update)."""
        self.insert(cid, new_score)


# Convenient Alias
Structure2 = RunnerUpQueueDS
