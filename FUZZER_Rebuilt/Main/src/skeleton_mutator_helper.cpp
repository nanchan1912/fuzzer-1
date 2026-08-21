#include "diversity_checker.h"
#include <algorithm>  // including this for std::copy
#include <fstream>
#include <mutex>
#include <map>
#include <set>
#include "json.hpp"  // for JSON parsing (downloaded from nlohmann/json)
#include "skeleton_graph_mutator.hpp"
#include "skeleton_graph_events.hpp"
#include "skeleton_mutator_helper.hpp"
#include "static_program_abstraction.hpp"
#include "skeleton_graph.hpp"
#include "consistency.hpp"
#include "skeleton_mutator_helper.hpp"
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <climits>
#include <memory>

using json = nlohmann::json;

Event_Type event_type_from_string(const std::string& s) {
    if (s == "R")     return Event_Type::READ;
    if (s == "CAS_FAILURE")     return Event_Type::CAS_FAILURE;
    if (s == "W")     return Event_Type::WRITE;
    if (s == "RMW")   return Event_Type::RMW;
    if (s == "CAS_SUCCESS") return Event_Type::CAS_SUCCESS;
    if (s == "F")     return Event_Type::FENCE;

    throw std::runtime_error("Unknown Event_Type: " + s);
}

Access_Mode access_mode_from_string(const std::string& s) {
    if (s == "NA")      return Access_Mode::NON_ATOMIC;
    if (s == "RLX")     return Access_Mode::RELAXED;
    if (s == "ACQ")     return Access_Mode::ACQUIRE;
    if (s == "REL")     return Access_Mode::RELEASE;
    if (s == "ACQ_REL") return Access_Mode::ACQ_REL;
    if (s == "SC")      return Access_Mode::SC;

    throw std::runtime_error("Unknown Access_Mode: " + s);
}

std::string event_type_to_string(Event_Type t) {
    switch (t) {
        case Event_Type::READ:  return "R";
        case Event_Type::CAS_FAILURE:  return "CAS_FAILURE";
        case Event_Type::WRITE: return "W";
        case Event_Type::RMW:   return "RMW";
        case Event_Type::CAS_SUCCESS: return "CAS_SUCCESS";
        case Event_Type::FENCE: return "F";
    }
    throw std::runtime_error("Unknown Event_Type enum value");
}

std::string access_mode_to_string(Access_Mode m) {
    switch (m) {
        case Access_Mode::NON_ATOMIC: return "NA";
        case Access_Mode::RELAXED:    return "RLX";
        case Access_Mode::ACQUIRE:    return "ACQ";
        case Access_Mode::RELEASE:    return "REL";
        case Access_Mode::ACQ_REL:    return "ACQ_REL";
        case Access_Mode::SC:         return "SC";
    }
    throw std::runtime_error("Unknown Access_Mode enum value");
}

/* ============================================================
 *  Program Abstraction Parser
 * ============================================================ */


namespace fs = std::filesystem;
fs::path eg_file;

// this function is called from sgf-fuzz-init.c to set the .eg file path
extern "C" void parse_program_abstraction_file(const char *file_name){
    eg_file = fs::path(file_name);
    //check if the file exists
    if(!fs::exists(eg_file)){
        ACTF("The specified .eg file does not exist: %s", eg_file.string().c_str());
        exit(1);
    }
    ACTF("Set .eg file path to: %s", eg_file.string().c_str());
}

void parse_program_abstraction(const string& file, ProgramCFG& cfg) {
    ifstream in(file);
    if (!in) throw runtime_error("Cannot open file");

    string line;
    while (getline(in, line)) {
        size_t comment_pos = line.find('#');
        if (comment_pos != string::npos) {
            line = line.substr(0, comment_pos);
        }
        if (line.empty() || line.find_first_not_of(" \t\r\n") == string::npos) continue;

        istringstream iss(line);
        string tag;
        iss >> tag;

        if (tag == "E") {
            vector<string> toks;
            string tok;
            while (iss >> tok) {
                toks.push_back(tok);
            }

            if (toks.size() < 5) {
                continue;
            }

            // New format: E <event_id> <tid> <instruction_id> <kind> <loc> <mode>
            // Legacy format: E <event_id> <tid> <kind> <loc> <mode>
            const int event_id = parse_event_id(toks[0]);
            const int tid = stoi(toks[1]);

            long long instruction_id = event_id;
            size_t kind_idx = 2;
            if (toks.size() >= 6) {
                instruction_id = parse_long_long_compatible(toks[2], "program_abstraction.instruction_id");
                kind_idx = 3;
            }

            const string& kind = toks[kind_idx];
            const string& loc = toks[kind_idx + 1];
            const string& mode = toks[kind_idx + 2];

            cfg.add_event(event_id, Event(
                tid,
                parse_access_mode(mode),
                parse_event_type(kind),
                loc,
                instruction_id
            ));
        }

        else if (tag == "CF") {
            string a, b;
            iss >> a >> b;
            cfg.add_cf_edge(parse_event_id(a), parse_event_id(b));
        }
    }

}

long long parse_long_long_compatible(const std::string& s, const char* context) {
    try {
        size_t pos = 0;
        long long v = static_cast<long long>(std::stoull(s, &pos, 0));
        if (pos != s.size()) {
            throw std::runtime_error(std::string("Expected long-long-like value for ") + context);
        }
        return v;
    } catch (const std::out_of_range&) {
        throw std::runtime_error(std::string("Out-of-range long long for ") + context);
    } catch (const std::invalid_argument&) {
        throw std::runtime_error(std::string("Expected long-long-like value for ") + context);
    }
}

int json_to_int(const json& value, const char* context) {
    if (value.is_number_integer()) return value.get<int>();
    if (value.is_number_unsigned()) return static_cast<int>(value.get<unsigned long long>());
    if (value.is_number_float()) return static_cast<int>(value.get<double>());
    if (value.is_string()) {
        const auto& s = value.get_ref<const std::string&>();
        long long v = parse_long_long_compatible(s, context);
        if (v < static_cast<long long>(std::numeric_limits<int>::min()) ||
            v > static_cast<long long>(std::numeric_limits<int>::max())) {
            throw std::runtime_error(std::string("Out-of-range int for ") + context);
        }
        return static_cast<int>(v);
    }
    throw std::runtime_error(std::string("Expected integer-like value for ") + context);
}

long long json_to_ll(const json& value, const char* context) {
    if (value.is_number_integer()) return value.get<long long>();
    if (value.is_number_unsigned()) {
        const auto v = value.get<unsigned long long>();
        if (v > static_cast<unsigned long long>(std::numeric_limits<long long>::max())) {
            throw std::runtime_error(std::string("Out-of-range long long for ") + context);
        }
        return static_cast<long long>(v);
    }
    if (value.is_number_float()) return static_cast<long long>(value.get<double>());
    if (value.is_string()) {
        const auto& s = value.get_ref<const std::string&>();
        return parse_long_long_compatible(s, context);
    }
    throw std::runtime_error(std::string("Expected long-long-like value for ") + context);
}

std::string json_to_string(const json& value, const char* context) {
    if (value.is_string()) return value.get<std::string>();
    if (value.is_number_integer()) return std::to_string(value.get<long long>());
    if (value.is_number_unsigned()) return std::to_string(value.get<unsigned long long>());
    if (value.is_number_float()) return std::to_string(value.get<double>());
    throw std::runtime_error(std::string("Expected string-like value for ") + context);
}

EventID parse_event_id_array(const json& arr, const char* context) {
    if (!arr.is_array()) {
        throw std::runtime_error(std::string("Invalid ") + context + ": expected JSON array");
    }
    if (arr.size() == 2) {
        return std::make_tuple(json_to_int(arr.at(0), context), json_to_ll(arr.at(1), context), 1);
    }
    if (arr.size() == 3) {
        return std::make_tuple(json_to_int(arr.at(0), context), json_to_ll(arr.at(1), context), json_to_int(arr.at(2), context));
    }
    throw std::runtime_error(std::string("Invalid ") + context + ": expected 2 or 3 elements");
}

bool event_id_less(const EventID& a, const EventID& b) {
    if (std::get<0>(a) != std::get<0>(b)) return std::get<0>(a) < std::get<0>(b);
    if (std::get<1>(a) != std::get<1>(b)) return std::get<1>(a) < std::get<1>(b);
    return std::get<2>(a) < std::get<2>(b);
}

json event_id_to_json_string_array(const EventID& id) {
    return json::array({
        std::to_string(std::get<0>(id)),
        std::to_string(std::get<1>(id)),
        std::to_string(std::get<2>(id))
    });
}

EventID parse_event_id_value(const json& value, const char* context) {
    if (value.is_array()) {
        return parse_event_id_array(value, context);
    }
    if (value.is_number() || value.is_string()) {
        return std::make_tuple(0, json_to_ll(value, context), 1);
    }
    throw std::runtime_error(std::string("Invalid ") + context + ": expected array or scalar id");
}

bool is_event_id_tuple(const json& value) {
    if (!value.is_array()) return false;
    if (value.size() != 2 && value.size() != 3) return false;
    return !value.empty() && !value.at(0).is_array() && !value.at(0).is_object();
}

void for_each_event_id_value(const json& value, const char* context, const std::function<void(const EventID&)>& fn) {
    if (is_event_id_tuple(value) || value.is_number() || value.is_string()) {
        fn(parse_event_id_value(value, context));
        return;
    }

    if (value.is_array()) {
        for (const auto& item : value) {
            fn(parse_event_id_value(item, context));
        }
        return;
    }

    throw std::runtime_error(std::string("Invalid ") + context + ": expected event id or list of event ids");
}

void parse_adj_list(const nlohmann::json& json_file, const std::string& field, const std::function<void(EventID, EventID)>& add_edge)
{
    if (!json_file.contains(field) || !json_file[field].is_array()) return;

    for (const auto& entry : json_file[field]) {
        EventID from = parse_event_id_value(entry.at("from"), field.c_str());

        for_each_event_id_value(entry.at("to"), field.c_str(), [&](const EventID& to) {
            add_edge(from, to);
        });
    }
}


extern "C" void update_mo_freq_from_seed(const char* filename) {
    std::ifstream f(filename);
      if (!f) {
          ACTF("There was a problem while opening the json file");
          return;
      }
      json json_file;
      f >> json_file;

      if (!json_file.contains("mo_per_location")) {
        ACTF("mo_per_location was not found in the json file");
      }
      if (json_file.contains("mo_per_location") && json_file["mo_per_location"].is_array()) {
        for (const auto& entry : json_file["mo_per_location"]) {
            std::string location = json_to_string(entry.at("location"), "mo_per_location[].location");
            EventID prev_event_id;

            for_each_event_id_value(entry.at("list"), "mo_per_location[].list[]", [&](const EventID& mo_id) {
                if(mo_id != prev_event_id){
                    // where there are multiple writes to the same location, I have mo edges in the seed - update their freq in the mo footprint map
                    // update freq for prev_event_id and mo_id
                    EventTriple prev_event_triple = {std::get<0>(prev_event_id), std::get<1>(prev_event_id), std::get<2>(prev_event_id)};
                    EventTriple new_event_triple = {std::get<0>(mo_id), std::get<1>(mo_id), std::get<2>(mo_id)};
                    // ACTF("Updating MO coverage for edge: (%d, %lld, %d) -> (%d, %lld, %d)", std::get<0>(prev_event_id), std::get<1>(prev_event_id), std::get<2>(prev_event_id),
                    //     mo_id->get_thread_id(), mo_id->get_instruction_id(), mo_id->get_visit_id());
                    
                    update_mo_coverage(prev_event_triple, new_event_triple);
                }
                prev_event_id = mo_id;
            });
        }
    }
}


extern "C" SkeletonGraph* read_from_json(const char *filename) {
    std::ifstream f(filename);
    if (!f) {
        ACTF("There was a problem while opening the json file");
        return nullptr;
    }
    json json_file;
    f >> json_file;

    SkeletonGraph* graph = new SkeletonGraph{};

    if (json_file.contains("nodes") && json_file["nodes"].is_array()) {
        const auto& nodes = json_file["nodes"];

        // No-op: `reallocate_events_vector` removed. unordered_map will grow as needed.

        for (const auto& node : nodes) {
            
            auto instr_id = json_to_ll(node.at("instruction_id"), "nodes[].instruction_id");
            auto thread_id = json_to_int(node.at("thread_id"), "nodes[].thread_id");
            
            auto visit_id = 1; // default visit_id
            if (node.contains("visit_id")) {
                visit_id = json_to_int(node.at("visit_id"), "nodes[].visit_id");
            }
            
            auto event_type = event_type_from_string(json_to_string(node.at("kind"), "nodes[].kind"));

            string loc = "";
            if (node.contains("loc")) {
                loc = json_to_string(node.at("loc"), "nodes[].loc");
            } else if (node.contains("loc_id")) {
                loc = json_to_string(node.at("loc_id"), "nodes[].loc_id");
            }

            Access_Mode access_mode = Access_Mode::RELAXED; // default access mode
            if (node.contains("access_mode")) {
                access_mode = access_mode_from_string(json_to_string(node.at("access_mode"), "nodes[].access_mode"));
            }
            
            Event* e = new Event{int(thread_id), access_mode, event_type, loc, instr_id, visit_id};
            graph->add_event(*e);
        }
    }

    if (!json_file.contains("po_per_thread")) {
        ACTF("po_per_thread was not found in the json file");
    }else{
        for (const auto& entry : json_file["po_per_thread"]) {
            int thread_id = json_to_int(entry.at("thread_id"), "po_per_thread[].thread_id");
            for_each_event_id_value(entry.at("list"), "po_per_thread[].list[]", [&](const EventID& po_id) {
                graph -> add_po_threadwise(thread_id, po_id);
            });
        }
    }

    parse_adj_list(json_file, "rf_edges", [&](EventID from, EventID to) {graph->add_rf(from, to);});

    parse_adj_list(json_file, "sw_edges", [&](EventID from, EventID to) {graph->add_sw(from, to);});

    parse_adj_list(json_file, "tcj_edges", [&](EventID from, EventID to) {graph->add_tcj(from, to);});

    if (!json_file.contains("mo_per_location")) {
        ACTF("mo_per_location was not found in the json file");
    }

    if (json_file.contains("mo_per_location") && json_file["mo_per_location"].is_array()) {
        for (const auto& entry : json_file["mo_per_location"]) {
            std::string location = json_to_string(entry.at("location"), "mo_per_location[].location");

            for_each_event_id_value(entry.at("list"), "mo_per_location[].list[]", [&](const EventID& mo_id) {
                graph -> add_mo(mo_id, location);
            });
        }
    }

    graph->finalize();
    return graph;
}

std::string serialize_graph_cpp(const SkeletonGraph& graph) {
    SkeletonGraph tmp = graph;
    // tmp.canonicalize();

    json j;

    // Collect events and sort by EventID for stable output
    std::vector<const Event*> evs; evs.reserve(tmp.get_events().size());
    for (const auto& kv : tmp.get_events()) evs.push_back(&kv.second);
    std::sort(evs.begin(), evs.end(), [](const Event* a, const Event* b){
        if (a->get_thread_id() != b->get_thread_id()) return a->get_thread_id() < b->get_thread_id();
        if (a->get_instruction_id() != b->get_instruction_id()) return a->get_instruction_id() < b->get_instruction_id();
        return a->get_visit_id() < b->get_visit_id();
    });
    for (size_t i = 0; i < evs.size(); ++i) {
        const Event& e = *evs[i];
        json node;

        node["event_id"] = std::to_string(i + 1);
        node["thread_id"] = std::to_string(e.get_thread_id());
        node["instruction_id"] = std::to_string(e.get_instruction_id());
        node["visit_id"] = std::to_string(e.get_visit_id());
        node["kind"]        = event_type_to_string(e.get_event_type());
        node["loc_id"] = e.get_location();
        node["access_mode"] = access_mode_to_string(e.get_access_mode());

        j["nodes"].push_back(node);
    }

    write_adj_list(j, "rf_edges", tmp.get_rf());
    write_adj_list(j, "sw_edges", tmp.get_sw());
    write_adj_list(j, "tcj_edges", tmp.get_tcj());
    for (const auto& [tid, lst] : tmp.get_threadwise_po()) {
        json entry;
        entry["thread_id"] = tid;
        json list_array = json::array();
        for (const auto& event_id : lst) {
            list_array.push_back(event_id_to_json_string_array(event_id));
        }
        entry["list"] = list_array;
        j["po_per_thread"].push_back(entry);
    }

    for (const auto& [loc, lst] : tmp.get_mo_by_location()) {
        json entry;
        entry["location"] = loc;
        json list_array = json::array();
        for (const auto& event_id : lst) {
            list_array.push_back(event_id_to_json_string_array(event_id));
        }
        entry["list"] = list_array;
        j["mo_per_location"].push_back(entry);
    }

    return j.dump();
}

extern "C" int serialize_graph_c(const SkeletonGraph *graph,
                      uint8_t **out_buf,
                      uint32_t *out_len) {
    if (!graph || !out_buf || !out_len) return -1;

    try {
        SkeletonGraph tmp = *graph;
        // tmp.canonicalize();

        std::string s = serialize_graph_cpp(tmp);

        if (s.empty()) return -1;

        uint8_t *buf = (uint8_t*)malloc(s.size());
        if (!buf) return -1;

        memcpy(buf, s.data(), s.size());

        *out_buf = buf;
        *out_len = (uint32_t)s.size();
        return 0;
    } catch (...) {
        return -1;
    }
}

extern "C" size_t write_to_json(const char* filename, const SkeletonGraph* graph){
    assert(graph != nullptr);

    std::string serialized = serialize_graph_cpp(*graph);
    std::filesystem::path filepath(filename);
    std::filesystem::create_directories(filepath.parent_path());
    std::ofstream f(filename);
    assert(f && "Failed to open output JSON file");
    f << serialized << "\n";
    return f.tellp();
}

template <typename AdjMap>
void write_adj_list(json& json_file, const std::string& field, const AdjMap& adj) {
    json edges = json::array();

    std::vector<EventID> from_ids;
    from_ids.reserve(adj.size());
    for (const auto& kv : adj) {
        from_ids.push_back(kv.first);
    }
    std::sort(from_ids.begin(), from_ids.end(), event_id_less);

    for (const auto& from : from_ids) {
        json entry;
        entry["from"] = event_id_to_json_string_array(from);
        json to_array = json::array();
        std::vector<EventID> to_vec = adj.at(from);
        std::sort(to_vec.begin(), to_vec.end(), event_id_less);
        for (const auto& to : to_vec) {
            to_array.push_back(event_id_to_json_string_array(to));
        }
        entry["to"] = to_array;
        edges.push_back(entry);
    }

    json_file[field] = std::move(edges);
}

bool load_thread_event_counts(std::unordered_map<ThreadID, int> &expected_thread_counts) {
    expected_thread_counts.clear();

    const char* filepath = getenv("THREAD_EVENT_COUNTS");
    if (!filepath || filepath[0] == '\0') {
        return false;
    }

    std::ifstream infile(filepath);
    if (!infile.is_open()) {
        return false;
    }

    std::string line;
    bool has_entries = false;
    bool has_error = false;

    while (std::getline(infile, line)) {
        size_t start = 0;
        while (start < line.size() && std::isspace((unsigned char)line[start])) {
            start++;
        }
        if (start >= line.size() || line[start] == '#') {
            continue;
        }

        std::stringstream ss(line.substr(start));
        int thread_id = 0;
        if (!(ss >> thread_id)) {
            has_error = true;
            break;
        }

        char sep = '\0';
        while (ss.peek() != EOF && (std::isspace((unsigned char)ss.peek()) || ss.peek() == ':' || ss.peek() == ',' || ss.peek() == '=')) {
            ss.get(sep);
        }

        int count = 0;
        if (!(ss >> count)) {
            has_error = true;
            break;
        }

        std::string extra;
        if (ss >> extra) {
            if (extra[0] != '#') {
                has_error = true;
                break;
            }
        }

        expected_thread_counts[thread_id] = count;
        has_entries = true;
    }

    if (!has_error && has_entries) {
        printf("Loaded expected thread event counts from %s\n", filepath);
    } else {
        expected_thread_counts.clear();
        return false;
    }
    return true;
}

static std::map<int, std::set<std::string>> global_explored_locations;
static std::mutex explored_locations_mutex;

extern "C" void dump_explored_locations() {
    const char *out_env = getenv("SGF_CUSTOM_INFO_OUT");
    if (!out_env) out_env = getenv("__SGF_OUT_DIR");
    if (!out_env) out_env = getenv("__AFL_OUT_DIR");
    std::string out_dir = out_env ? out_env : "";
    std::string filename = "locations.loc";
    filename = std::string(out_dir) + "/locations.loc";
    std::ofstream outfile(filename);
    if (!outfile.is_open()) {
        outfile.open("locations.loc");
    }
    if (outfile.is_open()) {
        std::lock_guard<std::mutex> lock(explored_locations_mutex);
        for (const auto& pair : global_explored_locations) {
            outfile << pair.first << ":";
            for (const auto& loc : pair.second) {
                outfile << " " << loc;
            }
            outfile << "\n";
        }
        outfile.close();
    }
}

void log_explored_location(int thread_id, const std::string& location) {
    if (thread_id < 0 || location.empty()) return;
    
    std::lock_guard<std::mutex> lock(explored_locations_mutex);
    global_explored_locations[thread_id].insert(location);
}