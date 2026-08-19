#ifndef GRAPHS_H
#define GRAPHS_H

#include "skeleton_graph_events.hpp"

// Hash function for EventID tuple to be used in unordered_map/set
struct TripleHash {
    std::size_t operator()(const EventID& t) const noexcept {
        std::size_t h1 = std::hash<ThreadID>{}(std::get<0>(t));
        std::size_t h2 = std::hash<InstructionID>{}(std::get<1>(t));
        std::size_t h3 = std::hash<VisitID>{}(std::get<2>(t));
        return h1 ^ (h2 << 4) ^ (h3 << 8);
    }
};

// EdgeMap maps from an EventID to vector of EventIDs (for RF and SW edges)
using EdgeMap = std::unordered_map<EventID, std::vector<EventID>, TripleHash>;

// Used for mapping ThreadID and InstructionID to VisitID
struct PairHash {
    std::size_t operator()(const std::pair<ThreadID, InstructionID>& p) const noexcept {
        std::size_t h1 = std::hash<ThreadID>{}(p.first);
        std::size_t h2 = std::hash<InstructionID>{}(p.second);
        return h1 ^ (h2 << 1);
    }
};
using pair_hash = PairHash;

// Skeleton Graph
typedef struct SkeletonGraph {
protected:
    // We maintain a map EventID -> Event as the primary storage for events to allow O(1) lookups by id
    std::unordered_map<EventID, Event, TripleHash> events;

    // We maintain a map Location -> Event_Type -> Access_Mode -> set of EventIDs
    // Used for O(1) membership checks when looking for events of a certain type/mode at a location (Used: data_race checks)
    std::unordered_map<Location, std::unordered_map<Event_Type, std::unordered_map<Access_Mode, std::unordered_set<EventID, TripleHash>>>> event_type_sets; 

    // We maintain a map from pair of (ThreadID, InstructionID) -> VisitID
    // Used to get the current VisitID for them in graph (Used: loops etc) 
    std::unordered_map<std::pair<ThreadID, InstructionID>, VisitID, PairHash> last_visit;

    // We maintain a map from ThreadID to vector of EventIDs in program order for that thread
    std::map<ThreadID, std::vector<EventID>> threadwise_po;

    // We maintain a map from EventID to its index in the threadwise_po vector 
    // Used for O(1) lookup of predecessors/successors in PO (Used: consistency checks etc)
    std::unordered_map<EventID, std::size_t, TripleHash> threadwise_po_index;

    EdgeMap rf;         // read-from
    EdgeMap rf_reverse; // reverse read-from

    EdgeMap sw;         // synchronizes-with
    EdgeMap sw_reverse; // reverse synchronizes-with

    // We maintain a map from Location to vector of EventIDs in MO order for that location
    std::map<Location, std::vector<EventID>> mo_by_location;
    // We maintain a map from EventID to its position in the mo_by_location vector 
    // Used for O(1) lookup of predecessor/successor events in MO order for a given EventID
    std::unordered_map<EventID, std::size_t, TripleHash> mo_position_map;

    EdgeMap tcj;           // thread-create-join
    EdgeMap tcj_reverse;   // reverse thread-create-join

public:
    // Constructor
    SkeletonGraph() {
        events = std::unordered_map<EventID, Event, TripleHash>{};
        event_type_sets = std::unordered_map<Location, std::unordered_map<Event_Type, std::unordered_map<Access_Mode, std::unordered_set<EventID, TripleHash>>>>{};
        last_visit = std::unordered_map<std::pair<ThreadID, InstructionID>, VisitID, PairHash>{};
        threadwise_po = std::map<ThreadID, std::vector<EventID>>{};
        threadwise_po_index = std::unordered_map<EventID, std::size_t, TripleHash>{};
        rf = EdgeMap{};
        rf_reverse = EdgeMap{};
        sw = EdgeMap{};
        sw_reverse = EdgeMap{};
        mo_by_location = std::map<Location, std::vector<EventID>>{};
        mo_position_map = std::unordered_map<EventID, std::size_t, TripleHash>{};
        tcj = EdgeMap{};
        tcj_reverse = EdgeMap{};
    }

    // Destructor
    virtual ~SkeletonGraph() = default;

    // Getters
    // std::vector<Event>& get_events() { return events; }
    // const std::unordered_map<EventID, Event, TripleHash>& get_events() const { return events; }

    // const std::unordered_map<Location, std::unordered_map<Event_Type, std::unordered_map<Access_Mode, std::unordered_set<EventID, TripleHash>>>>& get_event_type_sets() const {
    //     return event_type_sets;
    // }

    // std::map<ThreadID, std::vector<EventID>>& get_threadwise_po() { return threadwise_po; }
    std::map<ThreadID, std::vector<EventID>>& get_threadwise_po() { return threadwise_po; }
    const std::map<ThreadID, std::vector<EventID>>& get_threadwise_po() const { return threadwise_po; }


    // std::unordered_map<EventID, std::size_t, TripleHash>& get_threadwise_po_index() { return threadwise_po_index; }
    const std::unordered_map<EventID, std::size_t, TripleHash>& get_threadwise_po_index() const { return threadwise_po_index; }

    // EdgeMap& get_rf(){ return rf; }
    const EdgeMap& get_rf() const { return rf; }
    EdgeMap& get_rf() { return rf; }

    // EdgeMap& get_sw() { return sw; }
    const EdgeMap& get_sw() const { return sw; }
    EdgeMap& get_sw() { return sw; }

    // EdgeMap& get_rf_reverse() { return rf_reverse; }
    const EdgeMap& get_rf_reverse() const { return rf_reverse; }
    EdgeMap& get_rf_reverse() { return rf_reverse; }

    // EdgeMap& get_sw_reverse() { return sw_reverse; }
    const EdgeMap& get_sw_reverse() const { return sw_reverse; }
    EdgeMap& get_sw_reverse() { return sw_reverse; }

    // std::map<Location, std::vector<EventID>>& get_mo_by_location() { return mo_by_location; }
    const std::map<Location, std::vector<EventID>>& get_mo_by_location() const { return mo_by_location; }
    std::map<Location, std::vector<EventID>>& get_mo_by_location() { return mo_by_location; }

    // std::unordered_map<EventID, std::size_t, TripleHash>& get_mo_position_map() { return mo_position_map; }
    const std::unordered_map<EventID, std::size_t, TripleHash>& get_mo_position_map() const { return mo_position_map; }
    std::unordered_map<EventID, std::size_t, TripleHash>& get_mo_position_map() { return mo_position_map; }

    const EdgeMap& get_tcj() const { return tcj; }
    EdgeMap& get_tcj() { return tcj; }

    const EdgeMap& get_tcj_reverse() const { return tcj_reverse; }
    EdgeMap& get_tcj_reverse() { return tcj_reverse; }

    Event* get_event_by_id(const EventID& id) {
        auto it = events.find(id);
        return it != events.end() ? &it->second : nullptr;
    }

    std::unordered_map<EventID, Event, TripleHash>& get_events() { return events; }
    const std::unordered_map<EventID, Event, TripleHash>& get_events() const { return events; }

    // Get the next visit_id for a given thread_id and instruction_id (Used: loops)
    VisitID get_next_visit_id(ThreadID thread_id, InstructionID instruction_id) const {
        const auto key = std::make_pair(thread_id, instruction_id);
        auto it = last_visit.find(key);
        if (it == last_visit.end()) return 1;
        return it->second + 1;
    }

    // Return pointer to event with given id, or nullptr if not found
    const Event* get_event_by_id(const EventID& id) const {
        return events.find(id) != events.end() ? &events.at(id) : nullptr;
    }
    
    // For given location, type, and mode, return the set of EventIDs that match those criteria (or empty set if none)
    const std::unordered_set<EventID, TripleHash>& get_event_ids_by_loc_type_and_mode(const Location& location, Event_Type type, Access_Mode mode) const {
        static const std::unordered_set<EventID, TripleHash> empty_set;
        auto loc_it = event_type_sets.find(location);
        if (loc_it == event_type_sets.end()) return empty_set;
        auto type_it = loc_it->second.find(type);
        if (type_it == loc_it->second.end()) return empty_set;
        auto mode_it = type_it->second.find(mode);
        if (mode_it == type_it->second.end()) return empty_set;
        return mode_it->second;
    }

    // Get the last MO event for a given location (returns nullptr if no writes to that location)
    const Event* get_mo_last_event(const Location& location) const {
        auto it = mo_by_location.find(location);
        if (it != mo_by_location.end() && !it->second.empty()) {
            const auto& last_id = it->second.back();
            return get_event_by_id(last_id);
        }
        return nullptr;
    }

    // Add a event to the graph (also updates indices and type sets)
    // Assumes that the event has all the fields correctly set 
    // including event_id and visit_id before being added to the graph
    // Doesn't update the edges (rf, sw, mo) - those should be updated separately after adding the event
    void add_event(const Event& event) {
        const EventID& eid = event.get_event_id();
        events.insert_or_assign(eid, event);

        // Update event_type_sets
        const Location& location = event.get_location();
        Event_Type type = event.get_event_type();
        Access_Mode mode = event.get_access_mode();
        event_type_sets[location][type][mode].insert(eid);

        // Update last_visit
        if (event.get_instruction_id() != -1 && event.get_thread_id() != -1) {
            const auto key = std::make_pair(event.get_thread_id(), event.get_instruction_id());
            auto it = last_visit.find(key);
            if (it == last_visit.end() || event.get_visit_id() > it->second) {
                last_visit[key] = event.get_visit_id();
            }
        }
    }

    void add_po_threadwise(ThreadID thread_id, EventID new_event) {
        threadwise_po[thread_id].push_back(new_event);
        threadwise_po_index[new_event] = threadwise_po[thread_id].size() - 1;
    }

    void add_rf(EventID from, EventID to) {
        rf[from].push_back(to);
        rf_reverse[to].push_back(from);
    }

    void add_sw(EventID from, EventID to) {
        sw[from].push_back(to);
        sw_reverse[to].push_back(from);
    }

    void add_mo(const EventID& new_event, const Location& location) {
        mo_by_location[location].push_back(new_event);
        mo_position_map[new_event] = mo_by_location[location].size() - 1;
    }

    void add_tcj(EventID from, EventID to) {
        tcj[from].push_back(to);
        tcj_reverse[to].push_back(from);
    }
    
    // carefully remove the finalize() and rebuild_mo() functions as they are making the code
    // less optimal if they are called after every mutation. 
    // If they are called after every mutation, we can optimize them by doing 
    // incremental updates instead of full rebuilds. 
    // For now, we can keep them as is and optimize later if needed.

    // Rebuild MO internals:
    // 1) Remove stale EventIDs (no longer present in event_index)
    // 2) Preserve relative order of valid writes
    // 3) Rebuild mo_position_map to match filtered vectors
    void rebuild_mo() {
        mo_position_map.clear();
        for (auto& kv : mo_by_location) {
            const Location& location = kv.first;
            std::vector<EventID>& event_ids = kv.second;

            // Filter out invalid EventIDs
            std::vector<EventID> valid_event_ids;
            for (const auto& eid : event_ids) {
                if (events.find(eid) != events.end()) {
                    valid_event_ids.push_back(eid);
                }
            }

            // Update the vector with only valid EventIDs
            event_ids = std::move(valid_event_ids);

            // Rebuild position map for this location
            for (std::size_t i = 0; i < event_ids.size(); ++i) {
                mo_position_map[event_ids[i]] = i;
            }
        }
    }

    void rebuild_event_type_sets() {
        event_type_sets.clear();
        for (const auto& kv : events) {
            const EventID& eid = kv.first;
            const Event& event = kv.second;
            if (std::get<0>(eid) == -1 || std::get<1>(eid) == -1 || std::get<2>(eid) == -1) {
                continue;
            }
            const Location& location = event.get_location();
            Event_Type type = event.get_event_type();
            Access_Mode mode = event.get_access_mode();

            event_type_sets[location][type][mode].insert(eid);
        }
    }

    void rebuild_po_index() {
        threadwise_po_index.clear();
        for (auto& kv : threadwise_po) {
            auto& po_list = kv.second;
            std::vector<EventID> valid_po_list;
            valid_po_list.reserve(po_list.size());

            for (const auto& eid : po_list) {
                if (events.find(eid) == events.end()) {
                    continue;
                }
                threadwise_po_index[eid] = valid_po_list.size();
                valid_po_list.push_back(eid);
            }

            po_list = std::move(valid_po_list);
        }
    }

    void rebuild_edge_reverse_maps() {
        rf_reverse.clear();
        sw_reverse.clear();
        tcj_reverse.clear();

        auto rebuild_reverse = [&](const EdgeMap& forward, EdgeMap& reverse) {
            for (const auto& [from, tos] : forward) {
                if (events.find(from) == events.end()) {
                    continue;
                }
                for (const auto& to : tos) {
                    if (events.find(to) == events.end()) {
                        continue;
                    }
                    reverse[to].push_back(from);
                }
            }
        };

        rebuild_reverse(rf, rf_reverse);
        rebuild_reverse(sw, sw_reverse);
        rebuild_reverse(tcj, tcj_reverse);
    }

    void rebuild_edge_maps() {
        auto filter_forward = [&](EdgeMap& edges) {
            for (auto it = edges.begin(); it != edges.end(); ) {
                if (events.find(it->first) == events.end()) {
                    it = edges.erase(it);
                    continue;
                }

                auto& tos = it->second;
                std::vector<EventID> valid_tos;
                valid_tos.reserve(tos.size());
                for (const auto& to : tos) {
                    if (events.find(to) != events.end()) {
                        valid_tos.push_back(to);
                    }
                }
                tos = std::move(valid_tos);

                if (tos.empty()) {
                    it = edges.erase(it);
                } else {
                    ++it;
                }
            }
        };

        filter_forward(rf);
        filter_forward(sw);
        filter_forward(tcj);
    }

    void rebuild_last_visit() {
        last_visit.clear();
        for (const auto& kv : events) {
            const Event& event = kv.second;
            if (event.get_instruction_id() != -1 && event.get_thread_id() != -1) {
                const auto key = std::make_pair(event.get_thread_id(), event.get_instruction_id());
                auto it = last_visit.find(key);
                if (it == last_visit.end() || event.get_visit_id() > it->second) {
                    last_visit[key] = event.get_visit_id();
                }
            }
        }
    }

    /*
     * Important for rf-mutation, where we remove successors of the event being mutated. 
     * After removing the successors, we need to rebuild the edge maps and reverse maps to ensure consistency.
    */
    void finalize() {
        rebuild_edge_maps();
        rebuild_edge_reverse_maps();

        rebuild_po_index();
        rebuild_mo();

        rebuild_event_type_sets();
        rebuild_last_visit();
    }

    // Pretty printer
    // TODO: TCJ Edge addition left
    void pretty_print(ostream& os = cout) const {
        auto access_mode_to_str = [](Access_Mode m) -> string {
            switch (m) {
                case Access_Mode::NON_ATOMIC: return "NON_ATOMIC";
                case Access_Mode::RELAXED:    return "RELAXED";
                case Access_Mode::ACQUIRE:    return "ACQUIRE";
                case Access_Mode::RELEASE:    return "RELEASE";
                case Access_Mode::ACQ_REL:    return "ACQ_REL";
                case Access_Mode::SC:         return "SC";
            }
            return "UNKNOWN";
        };

        auto type_to_str = [](Event_Type t) -> string {
            switch (t) {
                case Event_Type::READ:  return "R";
                case Event_Type::WRITE: return "W";
                case Event_Type::RMW:   return "RMW";
                case Event_Type::CAS_SUCCESS: return "CAS_SUCCESS";
                case Event_Type::CAS_FAILURE: return "CAS_FAILURE";
                case Event_Type::FENCE: return "FENCE";
            }
            return "UNKNOWN";
        };

        // Helper to compare tuples for sorting
        auto tuple_less = [](const EventID& a, const EventID& b) {
            if (std::get<0>(a) != std::get<0>(b)) return std::get<0>(a) < std::get<0>(b);
            if (std::get<1>(a) != std::get<1>(b)) return std::get<1>(a) < std::get<1>(b);
            return std::get<2>(a) < std::get<2>(b);
        };

        os << "\n===== Skeleton Graph =====\n";

        // 1) Events (sorted by id)
        os << "\nEvents (by id):\n";
        std::vector<const Event*> evs; evs.reserve(events.size());
        for (const auto& kv : events) evs.push_back(&kv.second);
        sort(evs.begin(), evs.end(), [&tuple_less](const Event* a, const Event* b){
            return tuple_less(a->get_event_id(), b->get_event_id());
        });
        for (const Event* e : evs) {
            os << "  i" << e->get_instruction_id()
               << "(v" << e->get_visit_id() << ")"
               << ": T" << e->get_thread_id()
               << " " << type_to_str(e->get_event_type())
               << "(" << e->get_location() << ")"
               << " mem=" << access_mode_to_str(e->get_access_mode())
               << "\n";
        }

        // 2) MO per location (as chains)
        os << "\nMO (per location):\n";
        std::vector<std::pair<Location, std::vector<EventID>>> mo_pairs(mo_by_location.begin(), mo_by_location.end());
        sort(mo_pairs.begin(), mo_pairs.end(), [](const auto& a, const auto& b){ return a.first < b.first; });
        for (const auto& kv : mo_pairs) {
            os << "  " << kv.first << ": ";
            for (std::size_t i = 0; i < kv.second.size(); ++i) {
                os << "i" << std::get<1>(kv.second[i]) << "(T" << std::get<0>(kv.second[i]) << ",v" << std::get<2>(kv.second[i]) << ")";
                if (i + 1 < kv.second.size()) os << " -mo-> ";
            }
            os << "\n";
        }

        // 3) RF edges
        os << "\nRF edges:\n";
        std::vector<EventID> rf_from_keys; rf_from_keys.reserve(rf.size());
        for (const auto& kv : rf) rf_from_keys.push_back(kv.first);
        sort(rf_from_keys.begin(), rf_from_keys.end(), tuple_less);
        for (const auto& from : rf_from_keys) {
            std::vector<EventID> tos = rf.at(from);
            sort(tos.begin(), tos.end(), tuple_less);
            for (const auto& to : tos) {
                os << "  e" << std::get<1>(from) << "(v" << std::get<2>(from) << ") -rf-> e" << std::get<1>(to) << "(v" << std::get<2>(to) << ")\n";
            }
        }

        // 3b) SW edges
        os << "\nSW edges:\n";
        std::vector<EventID> sw_from_keys; sw_from_keys.reserve(sw.size());
        for (const auto& kv : sw) sw_from_keys.push_back(kv.first);
        sort(sw_from_keys.begin(), sw_from_keys.end(), tuple_less);
        for (const auto& from : sw_from_keys) {
            std::vector<EventID> tos = sw.at(from);
            sort(tos.begin(), tos.end(), tuple_less);
            for (const auto& to : tos) {
                os << "  e" << std::get<1>(from) << "(v" << std::get<2>(from) << ") -sw-> e" << std::get<1>(to) << "(v" << std::get<2>(to) << ")\n";
            }
        }

        // 4) PO per thread as sequences
        os << "\nPO (per thread):\n";
        // Collect events per thread
        std::unordered_map<int, std::vector<EventID>> thread_events;
        for (const auto& kv : events) thread_events[kv.second.get_thread_id()].push_back(kv.first);
        std::vector<int> tids; tids.reserve(thread_events.size());
        for (auto& kv : thread_events) tids.push_back(kv.first);
        sort(tids.begin(), tids.end());
        for (int tid : tids) {
            // Build predecessors and successors restricted to this thread using threadwise_po
            std::unordered_map<EventID, int, TripleHash> indeg;
            std::unordered_map<EventID, std::vector<EventID>, TripleHash> succ;
            for (const auto& id : thread_events[tid]) indeg[id] = 0;
            // Use threadwise_po to build the PO chain for this thread
            auto it = threadwise_po.find(tid);
            if (it != threadwise_po.end()) {
                const auto& thread_po = it->second;
                for (std::size_t i = 0; i + 1 < thread_po.size(); ++i) {
                    succ[thread_po[i]].push_back(thread_po[i + 1]);
                    indeg[thread_po[i + 1]]++;
                }
            }
            // Find sources (indegree 0)
            std::vector<EventID> sources;
            for (const auto& kv : indeg) if (kv.second == 0) sources.push_back(kv.first);
            sort(sources.begin(), sources.end(), tuple_less);
            os << "  T" << tid << ": ";
            // Print each chain from a source
            bool first_chain = true;
            for (const auto& s : sources) {
                if (!first_chain) os << " | ";
                first_chain = false;
                // Follow linear chain greedily
                auto cur = s; bool first = true;
                while (true) {
                    if (!first) os << " -> ";
                    first = false;
                    os << "i" << std::get<1>(cur) << "(v" << std::get<2>(cur) << ")";
                    if (!succ.count(cur) || succ[cur].empty()) break;
                    // Choose smallest successor for stability
                    sort(succ[cur].begin(), succ[cur].end(), tuple_less);
                    cur = succ[cur][0];
                }
            }
            os << "\n";
        }

        // 4b) Diagram-like summary (columns per location)
        // Collect locations in sorted order
        std::vector<Location> locs; locs.reserve(mo_pairs.size());
        for (auto& p : mo_pairs) locs.push_back(p.first);
        sort(locs.begin(), locs.end());
        // Determine column width
        auto label_for = [&](const EventID& id){
            const Event* ev = get_event_by_id(id);
            if (!ev) return string("?");
            string kind = type_to_str(ev->get_event_type());
            Location loc = ev->get_location();
            return kind + string("(") + loc + string(")") + string(" e") + to_string(std::get<1>(id)) + string("v") + to_string(std::get<2>(id));
        };
        std::size_t colw = 20;
        // Print MO stacks row by row (max height)
        std::size_t maxh = 0; for (auto& loc : locs) maxh = max(maxh, mo_by_location.at(loc).size());
        // Header
        for (auto& loc : locs) {
            string hdr = string(" ") + loc + string(" ");
            if (hdr.size() < colw) hdr += string(colw - hdr.size(), ' ');
            os << hdr;
        }
        os << "\n";
        for (std::size_t r = 0; r < maxh; ++r) {
            for (auto& loc : locs) {
                const auto& order = mo_by_location.at(loc);
                string cell;
                if (r < order.size()) cell = label_for(order[r]);
                if (cell.size() < colw) cell += string(colw - cell.size(), ' ');
                os << cell;
            }
            os << "\n";
        }

        // RF summary lines under diagram
        os << "\nrf: ";
        bool first = true;
        for (const auto& from : rf_from_keys) {
            std::vector<EventID> tos(rf.at(from).begin(), rf.at(from).end());
            sort(tos.begin(), tos.end(), tuple_less);
            for (const auto& to : tos) {
                if (!first) os << ", ";
                first = false;
                os << "e" << std::get<1>(from) << "(v" << std::get<2>(from) << ")->e" << std::get<1>(to) << "(v" << std::get<2>(to) << ")";
            }
        }
        os << "\n";
    }

    // Canonicalize the graph by sorting events and edges for stable ordering (useful for testing and debugging)
    void canonicalize() {
        // 1. Sort events by (thread_id, instruction_id, visit_id) and reinsert into the map
        std::vector<Event> evlist; evlist.reserve(events.size());
        for (const auto& kv : events) evlist.push_back(kv.second);
        std::sort(evlist.begin(), evlist.end(), [](const Event& a, const Event& b) {
            if (a.get_thread_id() != b.get_thread_id()) return a.get_thread_id() < b.get_thread_id();
            if (a.get_instruction_id() != b.get_instruction_id()) return a.get_instruction_id() < b.get_instruction_id();
            return a.get_visit_id() < b.get_visit_id();
        });
        // Rebuild events map from sorted list (keys are derived from each event)
        events.clear();
        for (const auto& e : evlist) events.insert_or_assign(e.get_event_id(), e);
        // 2. Sort edges in rf and sw by from and to event_ids for stable ordering
        auto sort_edges = [&](EdgeMap& edges) {
            for (auto& kv : edges) {
                std::sort(kv.second.begin(), kv.second.end(), [](const EventID& a, const EventID& b) {
                    if (std::get<0>(a) != std::get<0>(b)) return std::get<0>(a) < std::get<0>(b);
                    if (std::get<1>(a) != std::get<1>(b)) return std::get<1>(a) < std::get<1>(b);
                    return std::get<2>(a) < std::get<2>(b);
                });
            }
        };
        sort_edges(rf);
        sort_edges(sw);
        sort_edges(tcj);
        finalize();
    }

} SkeletonGraph;

#endif // GRAPHS_H
