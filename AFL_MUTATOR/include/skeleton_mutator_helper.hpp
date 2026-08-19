#pragma once

#include "json.hpp"
#include "skeleton_graph.hpp"
#include "skeleton_graph_events.hpp"
#include <functional>
#include <string>

using json = nlohmann::json;

Event_Type event_type_from_string(const std::string& s);
Access_Mode access_mode_from_string(const std::string& s);
std::string event_type_to_string(Event_Type t);
std::string access_mode_to_string(Access_Mode m);

long long parse_long_long_compatible(const std::string& s, const char* context);
int json_to_int(const json& value, const char* context);
long long json_to_ll(const json& value, const char* context);
std::string json_to_string(const json& value, const char* context);

EventID parse_event_id_array(const json& arr, const char* context);
bool event_id_less(const EventID& a, const EventID& b);
json event_id_to_json_string_array(const EventID& id);
EventID parse_event_id_value(const json& value, const char* context);
bool is_event_id_tuple(const json& value);

// Generic iterator for event id values. Uses std::function for callbacks.
void for_each_event_id_value(const json& value, const char* context, const std::function<void(const EventID&)>& fn);

// Parse adjacency list field from JSON into add_edge(from,to)
void parse_adj_list(const nlohmann::json& json_file, const std::string& field, const std::function<void(EventID, EventID)>& add_edge);

//func to update the MO coverage map from a seed file
extern "C" void update_mo_freq_from_seed(const char* filename);

extern "C" SkeletonGraph* read_from_json(const char *filename);

template <typename AdjMap>
void write_adj_list(json& json_file, const std::string& field, const AdjMap& adj);

std::string serialize_graph_cpp(const SkeletonGraph& graph);
extern "C" int serialize_graph_c(const SkeletonGraph *graph, uint8_t **out_buf, uint32_t *out_len);
extern "C" size_t write_to_json(const char* filename, const SkeletonGraph* graph);

bool load_thread_event_counts(std::unordered_map<ThreadID, int> &expected_thread_counts);

void log_explored_location(int thread_id, const std::string& location);