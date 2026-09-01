#include "potential_nn.h"
#include "skeleton_potential.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {

struct Entry {
  const void* owner;
  SkeletonPotential* potential;
  std::vector<WriteKey> keys;
};

std::unordered_map<const void*, Entry*> g_entries;
std::unordered_map<WriteKey, std::vector<Entry*>, WriteKeyHash> g_postings;

constexpr size_t kRarestKeyCount = 6;

static std::vector<WriteKey> collect_keys(const SkeletonPotential& pot) {
  std::vector<WriteKey> keys;
  bool use_interesting = is_interesting_locations_valid();
  const auto& interesting_locs = get_interesting_locations();

  for (const auto& kv : pot.get_all_threads()) {
    for (const auto& loc_kv : kv.second) {
      if (use_interesting && !interesting_locs.count(loc_kv.first)) {
        continue;
      }
      const WriteSet& ws = loc_kv.second;
      keys.insert(keys.end(), ws.begin(), ws.end());
    }
  }
  return keys;
}

static bool is_active_entry(const Entry* entry,
                            potential_nn_is_active_fn is_active,
                            void* user_data) {
  if (!entry || !entry->potential) {
    return false;
  }
  if (!is_active) {
    return true;
  }
  return is_active(entry->owner, user_data) != 0;
}

}  // namespace

extern "C" void potential_nn_index_reset(void) {
  for (auto& kv : g_entries) {
    delete kv.second;
  }
  g_entries.clear();
  g_postings.clear();
}

extern "C" int potential_nn_index_contains(const void* entry) {
  return g_entries.find(entry) != g_entries.end();
}

extern "C" void potential_nn_index_add(const void* entry, void* potential) {
  if (!entry || !potential) {
    return;
  }

  if (g_entries.find(entry) != g_entries.end()) {
    return;
  }

  Entry* e = new Entry();
  e->owner = entry;
  e->potential = static_cast<SkeletonPotential*>(potential);
  e->keys = collect_keys(*e->potential);

  for (const WriteKey& key : e->keys) {
    g_postings[key].push_back(e);
  }

  g_entries[entry] = e;
}

extern "C" int potential_nn_find_diff(const void* entry,
                                      void* potential,
                                      potential_nn_is_active_fn is_active,
                                      void* user_data,
                                      double* out_diff,
                                      const void** out_neighbor) {
  if (!potential || !out_diff) {
    return 0;
  }

  const SkeletonPotential* target =
      static_cast<const SkeletonPotential*>(potential);

  std::vector<WriteKey> keys = collect_keys(*target);

  std::vector<std::pair<size_t, WriteKey>> ranked;
  ranked.reserve(keys.size());

  for (const WriteKey& key : keys) {
    auto it = g_postings.find(key);
    if (it == g_postings.end() || it->second.empty()) {
      continue;
    }
    ranked.emplace_back(it->second.size(), key);
  }

  std::sort(ranked.begin(), ranked.end(),
            [](const auto& a, const auto& b) { return a.first < b.first; });

  std::unordered_set<Entry*> candidates;
  size_t key_limit = std::min(kRarestKeyCount, ranked.size());
  for (size_t i = 0; i < key_limit; ++i) {
    const WriteKey& key = ranked[i].second;
    auto it = g_postings.find(key);
    if (it == g_postings.end()) {
      continue;
    }
    for (Entry* cand : it->second) {
      if (!cand || cand->owner == entry) {
        continue;
      }
      candidates.insert(cand);
    }
  }

  double best_diff = 0;
  const Entry* best_entry = nullptr;

  auto consider_entry = [&](Entry* cand) {
    if (!cand || cand->owner == entry) {
      return;
    }
    if (!is_active_entry(cand, is_active, user_data)) {
      return;
    }

    double diff = compare_skeletons(*target, *cand->potential);
    if (!best_entry || diff < best_diff) {
      best_entry = cand;
      best_diff = diff;
    }
  };

  if (!candidates.empty()) {
    for (Entry* cand : candidates) {
      consider_entry(cand);
    }
  } else {
    // If no candidate was found via rarest keys postings, sample a bounded number of entries
    // (up to 32) instead of linear scanning tens of thousands of corpus entries.
    size_t scanned = 0;
    for (auto& kv : g_entries) {
      consider_entry(kv.second);
      if (++scanned >= 32) {
        break;
      }
    }
  }

  if (!best_entry) {
    return 0;
  }

  *out_diff = best_diff;
  if (out_neighbor) {
    *out_neighbor = best_entry->owner;
  }
  return 1;
}
