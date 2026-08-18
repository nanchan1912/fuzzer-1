#include "consistency.hpp"

set<EventID> find_consistent_writes(const SkeletonGraph& graph,
                                    const Event& last_event,
                                    const std::string& target_location,
                                    bool is_rmw_or_cas_success) {

    set<EventID> consistent_writes; // will contain the answer

    EventID last_event_id = last_event.get_event_id();
    const auto& threadwise_po = graph.get_threadwise_po();
    const auto& rf = graph.get_rf();
    const auto& rf_reverse = graph.get_rf_reverse();
    const auto& sw_reverse = graph.get_sw_reverse();
    const auto& mo_by_location = graph.get_mo_by_location();
    const auto& mo_position_map = graph.get_mo_position_map();
    const auto& tcj_reverse = graph.get_tcj_reverse();

    // Check if there is mo_by_location entry for the target location
    // if not, then there are no writes to that location and we can return empty set immediately
    auto it_mo = mo_by_location.find(target_location);
    if (it_mo == mo_by_location.end()) {
        // No writes to this location at all, so no consistent writes
        return consistent_writes;
    }
    const vector<EventID>& mo_ordered_writes = it_mo->second;
    // No map for this location, should not happen but guard against it
    if(mo_ordered_writes.empty() || mo_position_map.find(mo_ordered_writes[0]) == mo_position_map.end()){
        return consistent_writes;
    }


    // Collect aware_of_write IDs
    set<EventID> aware_of_writes;

    // Unified traversal of (PO ? SW ? RF)+ edges in reverse
    // This explores all paths that can affect which writes are visible to the read
    set<EventID> visited;
    queue<EventID> to_explore;

    // Start with the last event
    to_explore.push(last_event_id);
    // BFS traversal
    while (!to_explore.empty()) {
        // Get the event to explore
        EventID curr_id = to_explore.front();
        to_explore.pop();

        // Mark as visited
        visited.insert(curr_id);

        const Event* curr_event = graph.get_event_by_id(curr_id);
        if(!curr_event) continue; // Should not happen, but guard against invalid event IDs

        // Condition 1: Found a WRITE or RMW or CAS_SUCCESS on the same location - this is a aware_of point
        // RMW and CAS_SUCCESS events are both reads and writes, so they can be cutoff points
        if (curr_event->get_location() == target_location &&
            (curr_event->get_event_type() == Event_Type::WRITE ||
             curr_event->get_event_type() == Event_Type::RMW ||
             curr_event->get_event_type() == Event_Type::CAS_SUCCESS)) {
            aware_of_writes.insert(curr_id);
            // Continue exploring from this write through PO edges
            // (don't stop here - there may be other writes reachable through different paths)
        }

        // Condition 2: Found a READ or CAS_FAILURE or RMW or CAS_SUCCESS on the same location - follow RF edges to find writes
        // RMW and CAS_SUCCESS events are both reads and writes, so their read part can follow RF edges
        if (curr_event->get_location() == target_location &&
            (curr_event->get_event_type() == Event_Type::READ ||
             curr_event->get_event_type() == Event_Type::RMW ||
             curr_event->get_event_type() == Event_Type::CAS_SUCCESS||
             curr_event->get_event_type() == Event_Type::CAS_FAILURE)) {
            // Find what this read reads from via RF reverse edge
            auto rf_it = rf_reverse.find(curr_id);
            if (rf_it != rf_reverse.end()) {
                for (const auto& write_id : rf_it->second) {
                    if (visited.find(write_id) == visited.end()) {
                        to_explore.push(write_id);
                        visited.insert(write_id); // Mark as visited to avoid duplicates in queue
                    }
                }
            }
        }

        // If this is an acquire read/fence/RMW, follow SW edges (synchronizes-with backwards)
        // RMW with acquire or acq_rel semantics can participate in synchronization chains
        // This allows us to chain synchronization across threads

        // The mode checking is not required as sw edges are not only created for acquire reads/fences/RMWs.
        // So we should follow SW edges regardless of the access mode of the current event.
        // Important caviat is that the sw edge addition by mutator should be correct.

        // if (is_acquire_mode(curr_event->get_access_mode()) &&
        //     (curr_event->get_event_type() == Event_Type::READ ||
        //      curr_event->get_event_type() == Event_Type::FENCE ||
        //      curr_event->get_event_type() == Event_Type::RMW)) {
            auto sw_it = sw_reverse.find(curr_id);
            if (sw_it != sw_reverse.end()) {
                for (const auto& sw_pred : sw_it->second) {
                    if (visited.find(sw_pred) == visited.end()) {
                        to_explore.push(sw_pred);
                        visited.insert(sw_pred); // Mark as visited to avoid duplicates in queue
                    }
                }
            }
        // }

        // traverse through TCJ edges (thread-create-join backwards)
        auto tcj_it = tcj_reverse.find(curr_id);
        if (tcj_it != tcj_reverse.end()) {
            for (const auto& tcj_pred : tcj_it->second) {
                if (visited.find(tcj_pred) == visited.end()) {
                    to_explore.push(tcj_pred);
                    visited.insert(tcj_pred); // Mark as visited to avoid duplicates in queue
                }
            }
        }

        // Continue traversal through PO edges (program order backwards)
        // Get PO predecessors from threadwise_po
        ThreadID curr_thread = std::get<0>(curr_id); // First element of EventID tuple is thread_id
        auto curr_thread_po_it = threadwise_po.find(curr_thread); // Find PO chain for this thread
        // Find the position of curr_id in threadwise_po
        auto po_index_it = graph.get_threadwise_po_index().find(curr_id);
        if (po_index_it != graph.get_threadwise_po_index().end()) {
            size_t index_in_threadwise_po = po_index_it->second; // Get index of current event in threadwise_po for O(1) access
            if (curr_thread_po_it != threadwise_po.end()) {
                const auto& curr_thread_po = curr_thread_po_it->second;
                if (index_in_threadwise_po > 0) { // If there are predecessors in PO
                    // Add the immediate predecessor in PO to explore
                    EventID po_pred = curr_thread_po[index_in_threadwise_po - 1];
                    if (visited.find(po_pred) == visited.end()) {
                        to_explore.push(po_pred);
                        visited.insert(po_pred); // Mark as visited to avoid duplicates in queue
                    }
                }
            }
        }
    }

    // Find the latest cutoff in MO order using O(1) position map
    size_t cutoff_position = 0;
    for (const auto& write_event_id : aware_of_writes) {
        auto pos_it_find = mo_position_map.find(write_event_id);
        if (pos_it_find != mo_position_map.end()) {
            size_t pos_it = pos_it_find->second; // Get position of this write in MO order
            cutoff_position = max(cutoff_position, pos_it) ;
        }
    }

    // All writes in MO order after and including the cutoff position are consistent writes
    size_t start_index = cutoff_position;
    for (size_t i = start_index; i < mo_ordered_writes.size(); i++) {
        const auto& write_id = mo_ordered_writes[i];
        // There should be no 2 rmw's reading from the same write, so remove the writes where rmw is reading from
        if(is_rmw_or_cas_success){
            // check all the outgoiong rf's from the write_id and if that none of them is to a rmw
            auto rf_it = rf.find(write_id);
            if(rf_it != rf.end() && rf_it->second.size() > 0){
                bool rmw_cas_found = false;
                for(const auto& read_id : rf_it->second){
                    const Event* read_event = graph.get_event_by_id(read_id);
                    if(read_event && (read_event->get_event_type() == Event_Type::RMW || read_event->get_event_type() == Event_Type::CAS_SUCCESS)){
                        rmw_cas_found = true;
                        break;
                    }
                }
                if(rmw_cas_found){
                    continue; // skip this write_id as it has an RMW or CAS_SUCCESS reading from it
                }
            }
        }
        consistent_writes.insert(write_id);
    }

    return consistent_writes;
}
