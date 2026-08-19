#ifndef STATIC_PROGRAM_ABSTRACTION_HPP
#define STATIC_PROGRAM_ABSTRACTION_HPP

#include <bits/stdc++.h>
#include <filesystem>
#include <iostream>
#include <sstream>
#include "skeleton_graph_events.hpp"
using namespace std;

/* ============================================================
 *  CFG Representation
 * ============================================================ */

struct CFGNode {
    Event event;
    vector<int> succ;
    vector<int> pred;

    CFGNode() : event(0, Access_Mode::NON_ATOMIC, Event_Type::EOP, "", -1, 1) {}
};


typedef struct ProgramCFG {
public:
    // nodes is a map from static event_id to CFGNode.
    // Event::instruction_id remains the original instruction id from the source.
    unordered_map<int, struct CFGNode> nodes;

    // Per-thread ordered static event ids.
    unordered_map<int, vector<int>>thread_index;

    // Lookup from (thread_id, instruction_id) -> static event id.
    unordered_map<string, int> tid_instruction_to_event;

    static string make_tid_instruction_key(int tid, long long instruction_id) {
        return std::to_string(tid) + ":" + std::to_string(instruction_id);
    }

    void add_event(int event_id, const Event& e) {
        nodes[event_id].event = e;
        thread_index[e.get_thread_id()].push_back(event_id);
        tid_instruction_to_event[make_tid_instruction_key(e.get_thread_id(), e.get_instruction_id())] = event_id;
    }

    void add_event(const Event& e) {
        // Backward compatibility path: use instruction_id as node id.
        add_event(static_cast<int>(e.get_instruction_id()), e);
    }

    void add_cf_edge(int from, int to) {
        nodes[from].succ.push_back(to);
        nodes[to].pred.push_back(from);
    }

    const Event& get_event(int eid) const {
        return nodes.at(eid).event;
    }

    int resolve_event_id(int tid, long long instruction_id) const {
        auto it = tid_instruction_to_event.find(make_tid_instruction_key(tid, instruction_id));
        if (it != tid_instruction_to_event.end()) {
            return it->second;
        }
        return -1;
    }

    vector<int> get_next_event_ids(int eid) const {
        auto it = nodes.find(eid);
        if (it == nodes.end()) return {};
        return it->second.succ;
    }

    vector<const Event*> get_next_events(int eid) const {
        vector<const Event*> out;
        for (int s : get_next_event_ids(eid)){
            out.push_back(&nodes.at(s).event);
        }
        return out;
    }

    vector<int> get_thread_entries(int tid) const {
        // ACTF("Getting entries for thread %d", tid);
        vector<int> entries;
        for (int eid : thread_index.at(tid)){

            // ACTF("Pushing event %d as entry for thread %d", eid, tid);
            entries.push_back(eid);

            // if (nodes.at(eid).pred.empty()){
            //         entries.push_back(eid);
            //     }
        }
        return entries;
    }

    const Event* get_parent_event(int eid) const {
        const auto& preds = nodes.at(eid).pred;
        if (preds.empty())
            return nullptr;
        return &nodes.at(preds[0]).event;
    }

    const Event* get_parent_event_for_visit(int eid, int visit_id) const {
        const auto& preds = nodes.at(eid).pred;
        if (preds.empty()) return nullptr;
        
        const Event* curr_event = &nodes.at(eid).event;
        
        // For visit_id > 1, find the loop-back predecessor (same thread)
        if (visit_id > 1) {
            for (int pred_id : preds) {
                const Event* pred_event = &nodes.at(pred_id).event;
                if (pred_event->get_thread_id() == curr_event->get_thread_id()) {
                    return pred_event;
                }
            }
            // No same-thread loop-back found, return nullptr
            return nullptr;
        }
        
        // For visit_id == 1, prefer a predecessor from a different thread.
        // Loop heads often have both a back-edge predecessor and an entry predecessor;
        // predecessor ordering in the CFG file is not guaranteed to reflect semantics.
        for (int pred_id : preds) {
            const Event* pred_event = &nodes.at(pred_id).event;
            if (pred_event->get_thread_id() != curr_event->get_thread_id()) {
                return pred_event;
            }
        }

        // Fallback: if all predecessors are same-thread, keep the first one.
        return &nodes.at(preds[0]).event;
    }
}ProgramCFG;

/* ============================================================
 *  Parser Helpers
 * ============================================================ */

inline Event_Type parse_event_type(const string& s) {
    if (s == "R") return Event_Type::READ;
    if (s == "W") return Event_Type::WRITE;
    if (s == "F") return Event_Type::FENCE;
    if (s == "RMW") return Event_Type::RMW;
    if (s == "EOP") return Event_Type::EOP;
    throw runtime_error("Bad event type");
}

inline Access_Mode parse_access_mode(const string& s) {
    if (s == "Rlx") return Access_Mode::RELAXED;
    if (s == "Rel") return Access_Mode::RELEASE;
    if (s == "Acq") return Access_Mode::ACQUIRE;
    if (s == "AcqRel") return Access_Mode::ACQ_REL;
    if (s == "SC") return Access_Mode::SC;

    return Access_Mode::NON_ATOMIC;
}

inline int parse_event_id(const string& s) {
    if (s.empty()) throw runtime_error("Bad event id");
    if (s[0] == 'e' || s[0] == 'E') {
        return stoi(s.substr(1)); // e0 -> 0
    }
    return stoi(s);
}


inline std::string to_string(Event_Type t) {
    switch (t) {
        case Event_Type::READ:  return "R";
        case Event_Type::WRITE: return "W";
        case Event_Type::RMW:   return "RMW";
        case Event_Type::FENCE: return "F";
        case Event_Type::EOP:   return "EOP";
    }
    return "?";
}

inline std::string to_string(Access_Mode m) {
    switch (m) {
        case Access_Mode::RELAXED:    return "Rlx";
        case Access_Mode::RELEASE:    return "Rel";
        case Access_Mode::ACQUIRE:    return "Acq";
        case Access_Mode::ACQ_REL:    return "AcqRel";
        case Access_Mode::SC:         return "SC";
        case Access_Mode::NON_ATOMIC: return "NA";
    }
    return "?";
}

inline void print_cfg(const ProgramCFG& cfg, std::ostream& os = std::cout) {
    os << "CFG Dump\n";
    os << "========\n";

    for (const auto& [eid, node] : cfg.nodes) {
        const Event& e = node.event;

        os << "Event e" << eid
              << " [iid=" << e.get_instruction_id() << "]"
              << " (T" << e.get_thread_id()
              << ", " << to_string(e.get_event_type())
              << ", " << e.get_location()
              << ", " << to_string(e.get_access_mode())
           << ")\n";

        // Predecessors
        os << "  Pred: ";
        if (node.pred.empty()) {
            os << "-";
        } else {
            for (int p : node.pred)
                os << "e" << p << " ";
        }
        os << "\n";

        // Successors
        os << "  Succ: ";
        if (node.succ.empty()) {
            os << "-";
        } else {
            for (int s : node.succ)
                os << "e" << s << " ";
        }
        os << "\n\n";
    }
}

// Shared static-program abstraction state and parser implementation.
extern ProgramCFG cfg_new;
extern std::filesystem::path eg_file;
void parse_program_abstraction(const std::string& file, ProgramCFG& cfg);

#endif // STATIC_PROGRAM_ABSTRACTION_HPP
