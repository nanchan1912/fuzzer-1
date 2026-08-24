#ifndef CONSISTENCY_H
#define CONSISTENCY_H

#include "skeleton_graph.hpp"

/*
  Finds all writes consistent according to the memory model if a read to a location is to be added to the graph.

  This function implements the logic to find the set of writes that can be observed by a read event
  according to the RC20 memory model. It traverses the graph backwards from the last event through RF
  (reads-from) only on same location, SW (synchronizes-with), and PO (program order) edges to find all writes that
  the read is aware of, after that it chooses the cutoff write as the last among them in the MO order.
  All the writes from and including the cutoff in the MO order are returned as the consistent writes for the read.

  @param graph The skeleton graph containing all events and their relationships.
  @param last_event The event just after which read event is to be added for which to find consistent writes.
  @param target_location The location being read; limits search to writes to this location.
  @param is_rmw_or_cas_success A boolean indicating whether the read is part of a Read-Modify-Write (RMW) or Compare-And-Swap (CAS) operation. If true, the function will ensure that no other RMW/CAS reads from any of the consistent writes.
  @return A set of EventIDs representing all writes consistent with the read event.
*/
set<EventID> find_consistent_writes(const SkeletonGraph& graph,
									const Event& last_event,
									const std::string& target_location,
                  bool is_rmw_or_cas_success);

/*
  Checks if the skeleton graph is SC-consistent.
  This function checks whether the skeleton graph satisfies Sequential Consistency (SC) by verifying that the union of
  program order (PO), reads-from (RF), modification order (MO), and from-read (FR) relations is acyclic. It constructs
  the combined relation and performs a cycle detection algorithm to determine if the graph is SC-consistent.

  @param graph The skeleton graph containing all events and their relationships.
  @return True if the graph is SC-consistent; false otherwise.
*/
bool is_sc_consistent(const SkeletonGraph& graph);

extern "C" bool is_sc_consistent_c(const struct SkeletonGraph* graph);

#endif // CONSISTENCY_H
