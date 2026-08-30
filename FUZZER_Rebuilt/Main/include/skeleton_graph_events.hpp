#ifndef EVENTS_H
#define EVENTS_H

#include <bits/stdc++.h>
using namespace std;

enum class Event_Type {
    READ,
    WRITE,
    RMW,
    FENCE,
    CAS, // Will be only in static program abstraction, not in skeleton graph
    CAS_SUCCESS,
    CAS_FAIL
};

enum class Access_Mode {
    NON_ATOMIC,
    RELAXED,
    ACQUIRE,
    RELEASE,
    ACQ_REL,
    SC  //REVISIT: Is SC needed?
};

using ThreadID = int;                                    // Unique identifier for a thread
using InstructionID = long long;                         // Unique identifier for an instruction
using VisitID = int;                                     // Unique identifier for a visit (used for loops)
using EventID = tuple<ThreadID, InstructionID, VisitID>; // Unique identifier for an event
using Location = string;                                 // e.g. "x", "y", "z"

// Event Classes
class Event {
protected:
    ThreadID thread_id; 
    InstructionID instruction_id;
    VisitID visit_id;
    Access_Mode access_mode; // NON_ATOMIC, RELAXED, ACQUIRE, RELEASE, ACQ_REL, SC
    Event_Type event_type;   // R, W, RMW, FENCE, CAS_SUCCESS, CAS_FAIL
    Location location;       // x, y

public:
    // Constructor
    Event(ThreadID tid, Access_Mode mode, Event_Type type, Location loc, InstructionID id = -1, VisitID vid = 1)
        : thread_id(tid), instruction_id(id), access_mode(mode), event_type(type), location(loc), visit_id(vid) {}
    // Destructor
    virtual ~Event() = default;

    // Getters
    ThreadID get_thread_id() const { return thread_id; }
    InstructionID get_instruction_id() const { return instruction_id; }
    VisitID get_visit_id() const { return visit_id; }
    Access_Mode get_access_mode() const { return access_mode; }
    Event_Type get_event_type() const { return event_type; }
    Location get_location() const { return location; }

    // Unique identifier - now using tuple of (thread_id, instruction_id, visit_id)
    EventID get_event_id() const {
        return make_tuple(thread_id, instruction_id, visit_id); 
    }

    // String representation of unique event ID
    string get_unique_id_string() const {
        return "T" + to_string(thread_id) + "_I" + to_string(instruction_id) + "_V" + to_string(visit_id);
    }

    // Setters
    void set_tid(ThreadID tid) { thread_id = tid; }
    void set_instruction_id(InstructionID id) { instruction_id = id; }
    void set_visit_id(VisitID vid) { visit_id = vid; }
    void set_access_mode(Access_Mode mode) { access_mode = mode; }
    void set_event_type(Event_Type type) { event_type = type; }
    void set_location(const Location& loc) { location = loc; }

    // Comparison operators for set operations
    bool operator<(const Event& other) const {
        if (thread_id != other.thread_id) return thread_id < other.thread_id;
        if (instruction_id != other.instruction_id) return instruction_id < other.instruction_id;
        if (visit_id != other.visit_id) return visit_id < other.visit_id;
        return location < other.location; // Arbitrary tie-breaker
    }

    // Equality operator based on unique event ID
    bool operator==(const Event& other) const {
        return (
            instruction_id == other.instruction_id
            && thread_id == other.thread_id
            && visit_id == other.visit_id
            && location == other.location
        );
    }

    // Pretty print
    void pretty_print(ostream& os = cout) const {
        os << ", Thread ID: " << thread_id
            << "Instruction ID: " << instruction_id
           << ", Visit ID: " << visit_id
           << ", Type: " << (event_type == Event_Type::READ ? "READ" :
                            event_type == Event_Type::WRITE ? "WRITE" :
                            event_type == Event_Type::RMW ? "RMW" :
                            event_type == Event_Type::CAS_SUCCESS ? "CAS_SUCCESS" :
                            event_type == Event_Type::CAS_FAIL ? "CAS_FAIL" : "FENCE"
                        )
           << ", Location: " << location
           << ", Access Mode: " << (access_mode == Access_Mode::NON_ATOMIC ? "NON_ATOMIC" :
                                   access_mode == Access_Mode::RELAXED ? "RELAXED" :
                                   access_mode == Access_Mode::ACQUIRE ? "ACQUIRE" :
                                   access_mode == Access_Mode::RELEASE ? "RELEASE" :
                                   access_mode == Access_Mode::ACQ_REL ? "ACQ_REL" : "SC")
           << "\n";
    }

};

#endif // EVENTS_H
