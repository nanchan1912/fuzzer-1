"""
datastructs package -- Standalone Data Structures.

Contains:
  - Structure 1 (ThresholdBucketQueueDS)
  - Structure 2 (RunnerUpQueueDS)
  - Structure 3 (MaxHeapBucketQueueDS)
  - Max Heap    (MaxHeapDS)
"""

from datastructs.structure1 import ThresholdBucketQueueDS, Structure1
from datastructs.structure2 import RunnerUpQueueDS, Structure2
from datastructs.structure3 import MaxHeapBucketQueueDS, Structure3
from datastructs.max_heap import MaxHeapDS, MaxHeap

__all__ = [
    "ThresholdBucketQueueDS",
    "Structure1",
    "RunnerUpQueueDS",
    "Structure2",
    "MaxHeapBucketQueueDS",
    "Structure3",
    "MaxHeapDS",
    "MaxHeap",
]
