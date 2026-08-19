#include "include/static_program_abstraction.hpp"

#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

static long long parse_long_long_compatible(const std::string& s,
                                            const char* context) {
  try {
    size_t pos = 0;
    long long v = static_cast<long long>(std::stoull(s, &pos, 0));
    if (pos != s.size()) {
      throw std::runtime_error("trailing characters");
    }
    return v;
  } catch (...) {
    try {
      size_t pos = 0;
      double d = std::stod(s, &pos);
      if (pos != s.size()) {
        throw std::runtime_error("trailing characters");
      }
      return static_cast<long long>(d);
    } catch (...) {
      std::ostringstream oss;
      oss << "Invalid integer for " << context << ": '" << s << "'";
      throw std::runtime_error(oss.str());
    }
  }
}

static void parse_program_abstraction_local(const std::string& file,
                                            ProgramCFG& cfg) {
  std::ifstream in(file);
  if (!in) {
    throw std::runtime_error("Cannot open file: " + file);
  }

  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') {
      continue;
    }

    std::istringstream iss(line);
    std::string tag;
    iss >> tag;

    if (tag == "E") {
      std::vector<std::string> toks;
      std::string tok;
      while (iss >> tok) {
        toks.push_back(tok);
      }

      if (toks.size() < 5) {
        continue;
      }

      const int event_id = parse_event_id(toks[0]);
      const int tid = std::stoi(toks[1]);

      long long instruction_id = event_id;
      size_t kind_idx = 2;
      if (toks.size() >= 6) {
        instruction_id = parse_long_long_compatible(
            toks[2], "program_abstraction.instruction_id");
        kind_idx = 3;
      }

      const std::string& kind = toks[kind_idx];
      const std::string& loc = toks[kind_idx + 1];
      const std::string& mode = toks[kind_idx + 2];

      cfg.add_event(event_id, Event(event_id, tid, parse_access_mode(mode),
                                    parse_event_type(kind), loc,
                                    instruction_id));
    } else if (tag == "CF") {
      std::string from, to;
      iss >> from >> to;
      cfg.add_cf_edge(parse_event_id(from), parse_event_id(to));
    }
  }
}

static void print_usage(const char* argv0) {
  std::cerr << "Usage: " << argv0 << " <static_program.eg>\n";
}

int main(int argc, char** argv) {
  if (argc < 2) {
    print_usage(argv[0]);
    return 1;
  }

  const std::string static_file = argv[1];
  ProgramCFG cfg;
  parse_program_abstraction_local(static_file, cfg);
  print_cfg(cfg);

  std::vector<int> event_ids;
  event_ids.reserve(cfg.nodes.size());
  for (const auto& kv : cfg.nodes) {
    event_ids.push_back(kv.first);
  }
  std::sort(event_ids.begin(), event_ids.end());

  for (int eid : event_ids) {
    const auto next_ids = cfg.get_next_event_ids(eid);
    if (next_ids.empty()) {
      std::cout << eid << "->-\n";
    } else {
      for (int sid : next_ids) {
        std::cout << eid << "->" << sid << "\n";
      }
    }
  }
  return 0;
}
