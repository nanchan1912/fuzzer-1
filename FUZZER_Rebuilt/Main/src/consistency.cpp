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
bool is_sc_consistent(const SkeletonGraph& graph) {

    const auto& events          = graph.get_events();
    const auto& threadwise_po   = graph.get_threadwise_po();
    const auto& rf              = graph.get_rf();
    const auto& rf_reverse      = graph.get_rf_reverse();
    const auto& mo_by_location  = graph.get_mo_by_location();
    const auto& mo_position_map = graph.get_mo_position_map();

    const size_t N = events.size();

    if (N <= 1) {
        return true;
    }

    /*
     * indegree[e] =
     *     number of incoming PO edges
     *   + number of incoming RF edges
     *   + number of incoming MO edges
     *   + number of incoming FR edges
     *
     * We use Kahn's algorithm.
     */
    unordered_map<EventID, size_t, TripleHash> indegree;
    indegree.reserve(N * 2);

    for (const auto& [eid, event] : events) {
        indegree.emplace(eid, 0);
    }

    /*
     * ------------------------------------------------------------
     * 1. PO
     *
     * threadwise_po stores each thread as a chain:
     *
     *     e0 ->po e1 ->po e2 ->po ...
     *
     * We only need immediate PO edges because their transitive
     * closure is equivalent for cycle detection.
     * ------------------------------------------------------------
     */
    for (const auto& [tid, po] : threadwise_po) {
        if (po.size() < 2) {
            continue;
        }

        for (size_t i = 1; i < po.size(); ++i) {
            auto it = indegree.find(po[i]);
            if (it != indegree.end()) {
                ++it->second;
            }
        }
    }

    /*
    * ------------------------------------------------------------
    * 1b. TCJ
    *
    * TCJ represents thread-create/join ordering and is treated
    * like a PO edge for the SC-consistency relation.
    *
    *     from ->tcj to
    *
    * Therefore every TCJ edge contributes one incoming edge to `to`.
    * ------------------------------------------------------------
    */
    const auto& tcj = graph.get_tcj();

    for (const auto& [from, tos] : tcj) {
        for (const EventID& to : tos) {
            auto it = indegree.find(to);
            if (it != indegree.end()) {
                ++it->second;
            }
        }
    }

    /*
     * ------------------------------------------------------------
     * 2. RF
     *
     * rf is stored:
     *
     *     write -> reads
     *
     * Therefore every RF edge contributes one incoming edge to
     * the read.
     *
     * We use the forward map directly.
     * ------------------------------------------------------------
     */
    for (const auto& [write_id, reads] : rf) {
        for (const EventID& read_id : reads) {
            auto it = indegree.find(read_id);
            if (it != indegree.end()) {
                ++it->second;
            }
        }
    }

    /*
     * ------------------------------------------------------------
     * 3. MO
     *
     * mo_by_location contains each location's writes in MO order:
     *
     *     w0 ->mo w1 ->mo w2 ->mo ...
     *
     * Again, immediate MO edges are sufficient for cycle detection.
     * ------------------------------------------------------------
     */
    for (const auto& [location, writes] : mo_by_location) {
        if (writes.size() < 2) {
            continue;
        }

        for (size_t i = 1; i < writes.size(); ++i) {
            auto it = indegree.find(writes[i]);
            if (it != indegree.end()) {
                ++it->second;
            }
        }
    }

    /*
     * ------------------------------------------------------------
     * 4. FR
     *
     *     fr = rf^{-1} ; mo
     *
     * If:
     *
     *     w ->rf r
     *
     * and:
     *
     *     w ->mo w1 ->mo w2 ->mo ...
     *
     * then:
     *
     *     r ->fr w1
     *     r ->fr w2
     *     ...
     *
     * We don't store FR explicitly.
     *
     * First calculate the number of incoming FR edges for every
     * write.
     *
     * For a write w at MO position p, every read whose source is
     * before p contributes one incoming FR edge.
     *
     * ------------------------------------------------------------
     */

    /*
     * Number of reads originating from each write.
     *
     * rf_reverse[read] -> {source_write}
     *
     * We first construct:
     *
     *     reads_from_write[write] = number of reads reading it
     *
     * This avoids repeatedly scanning rf_reverse.
     */
    unordered_map<EventID, size_t, TripleHash> reads_from_write;
    reads_from_write.reserve(rf.size() * 2 + 1);

    for (const auto& [write_id, reads] : rf) {
        reads_from_write[write_id] += reads.size();
    }

    /*
     * For each location, walk MO from oldest to newest.
     *
     * prefix_reads =
     *     number of reads whose source write is strictly before
     *     the current write in MO.
     *
     * Those reads all have an FR edge into the current write.
     */
    for (const auto& [location, writes] : mo_by_location) {

        size_t prefix_reads = 0;

        for (const EventID& write_id : writes) {

            /*
             * Every read whose RF source occurs before this write
             * contributes:
             *
             *     read ->fr write_id
             */
            auto it = indegree.find(write_id);
            if (it != indegree.end()) {
                it->second += prefix_reads;
            }

            /*
             * Now make this write's RF reads available as FR
             * predecessors of subsequent writes.
             */
            auto rf_it = reads_from_write.find(write_id);
            if (rf_it != reads_from_write.end()) {
                prefix_reads += rf_it->second;
            }
        }
    }

    /*
     * ------------------------------------------------------------
     * 5. Kahn's topological sort
     *
     * If we can process all events, the relation is acyclic.
     * ------------------------------------------------------------
     */

    queue<EventID> ready;

    for (const auto& [eid, degree] : indegree) {
        if (degree == 0) {
            ready.push(eid);
        }
    }

    size_t processed = 0;

    /*
     * Helper to decrement indegree and enqueue when it reaches zero.
     */
    auto consume_edge = [&](const EventID& to) {
        auto it = indegree.find(to);

        if (it == indegree.end()) {
            return;
        }

        if (--it->second == 0) {
            ready.push(to);
        }
    };

    /*
     * We need to know the RF source of a read when processing
     * the read, because that lets us generate its FR successors.
     *
     * For a well-formed execution there should normally be one
     * RF source per read/RMW/CAS-success.
     */
    while (!ready.empty()) {

        EventID current = ready.front();
        ready.pop();

        ++processed;

        /*
         * --------------------------------------------------------
         * PO successors
         * --------------------------------------------------------
         *
         * Since threadwise_po is a chain, use the O(1) index.
         */
        auto event_it = events.find(current);

        if (event_it != events.end()) {

            ThreadID tid = event_it->second.get_thread_id();

            auto po_it = threadwise_po.find(tid);

            if (po_it != threadwise_po.end()) {

                /*
                 * Find current's position.
                 *
                 * We use the graph's existing index map.
                 */
                const auto& po_index = graph.get_threadwise_po_index();

                auto idx_it = po_index.find(current);

                if (idx_it != po_index.end()) {

                    size_t idx = idx_it->second;

                    if (idx + 1 < po_it->second.size()) {
                        const EventID& po_succ = po_it->second[idx + 1];

                        consume_edge(po_succ);
                    }
                }
            }
        }

        /*
        * --------------------------------------------------------
        * TCJ successors
        *
        * TCJ is treated as an ordering edge just like PO.
        *
        *     current ->tcj successor
        * --------------------------------------------------------
        */
        auto tcj_it = graph.get_tcj().find(current);

        if (tcj_it != graph.get_tcj().end()) {
            for (const EventID& tcj_succ : tcj_it->second) {
                consume_edge(tcj_succ);
            }
        }

        /*
         * --------------------------------------------------------
         * RF successors
         *
         * write ->rf read
         * --------------------------------------------------------
         */
        auto rf_it = rf.find(current);

        if (rf_it != rf.end()) {
            for (const EventID& read_id : rf_it->second) {
                consume_edge(read_id);
            }
        }

        /*
         * --------------------------------------------------------
         * MO successor
         *
         * The current event can only have an MO successor if it
         * is a write/RMW/CAS-success appearing in mo_by_location.
         *
         * Since mo_position_map gives O(1) position lookup, this
         * is O(1).
         * --------------------------------------------------------
         */
        auto mo_pos_it = mo_position_map.find(current);

        if (mo_pos_it != mo_position_map.end()) {

            const Event* current_event =
                graph.get_event_by_id(current);

            if (current_event != nullptr) {

                auto loc_it =
                    mo_by_location.find(current_event->get_location());

                if (loc_it != mo_by_location.end()) {

                    const auto& writes = loc_it->second;
                    size_t pos = mo_pos_it->second;

                    if (pos + 1 < writes.size()) {
                        consume_edge(writes[pos + 1]);
                    }
                }
            }
        }

        /*
         * --------------------------------------------------------
         * FR successors
         *
         * This is the important part.
         *
         * If:
         *
         *     current ->rf w
         *
         * then:
         *
         *     current ->fr every write MO-after w.
         *
         * We generate these edges lazily.
         *
         * NOTE:
         * We deliberately enumerate them here rather than storing
         * an explicit FR graph.
         * --------------------------------------------------------
         */

        auto source_it = rf_reverse.find(current);

        if (source_it != rf_reverse.end()) {

            /*
             * In a well-formed execution a read has exactly one
             * RF source. We nevertheless support multiple sources
             * defensively.
             */
            for (const EventID& source_write : source_it->second) {

                auto source_pos_it =
                    mo_position_map.find(source_write);

                if (source_pos_it == mo_position_map.end()) {
                    continue;
                }

                const Event* source_event =
                    graph.get_event_by_id(source_write);

                if (source_event == nullptr) {
                    continue;
                }

                auto loc_it =
                    mo_by_location.find(source_event->get_location());

                if (loc_it == mo_by_location.end()) {
                    continue;
                }

                const auto& writes = loc_it->second;

                size_t source_pos = source_pos_it->second;

                /*
                 * Every write after source_write in MO is an FR
                 * successor of current.
                 *
                 * source_pos itself is NOT included because:
                 *
                 *     fr = rf^{-1};mo
                 *
                 * requires a strict MO successor.
                 */
                for (size_t i = source_pos + 1;
                     i < writes.size();
                     ++i) {

                    consume_edge(writes[i]);
                }
            }
        }
    }

    /*
     * If every event was removed by Kahn's algorithm, then:
     *
     *     po U rf U mo U fr
     *
     * is acyclic, hence:
     *
     *     (po U rf U mo U fr)+
     *
     * is irreflexive.
     */
    return processed == N;
}

extern "C" bool is_sc_consistent_c(const struct SkeletonGraph* graph) {
    if (!graph) return true;
    return is_sc_consistent(*graph);
}
