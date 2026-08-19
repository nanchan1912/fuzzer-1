#ifndef DATASTRUCTS_MAX_HEAP_HPP
#define DATASTRUCTS_MAX_HEAP_HPP

#include <vector>
#include <unordered_map>
#include <queue>
#include <stdexcept>
#include <utility>
#include <algorithm>
#include <optional>

/**
 * @brief Standard Binary Max-Heap Baseline.
 * 
 * Always selects the candidate with the absolute maximum score in the population.
 * Lazy update / invalidation pattern matching Python implementation.
 */
class MaxHeapDS {
public:
    std::vector<std::pair<double, int>> heap; // stores (score, cid)
    std::unordered_map<int, double> scores;    // cid -> score
    std::optional<int> last_selected_cid;

    MaxHeapDS() : last_selected_cid(std::nullopt) {}

    size_t size() const {
        return scores.size();
    }

    bool empty() const {
        return scores.empty();
    }

    void insert(int cid, double score) {
        double s = static_cast<double>(score);
        scores[cid] = s;
        heap.push_back({s, cid});
        std::push_heap(heap.begin(), heap.end(), [](const std::pair<double, int>& a, const std::pair<double, int>& b) {
            return a.first < b.first || (a.first == b.first && a.second < b.second);
        });
    }

    std::pair<int, double> select() {
        auto comp_max = [](const std::pair<double, int>& a, const std::pair<double, int>& b) {
            return a.first < b.first || (a.first == b.first && a.second < b.second);
        };

        while (!heap.empty()) {
            std::pop_heap(heap.begin(), heap.end(), comp_max);
            auto top = heap.back();
            heap.pop_back();

            double score = top.first;
            int cid = top.second;

            auto it = scores.find(cid);
            if (it != scores.end() && it->second == score) {
                scores.erase(it);
                last_selected_cid = cid;
                return {cid, score};
            }
        }
        throw std::runtime_error("select() called on empty MaxHeapDS");
    }

    void update_score(int cid, double new_score) {
        insert(cid, new_score);
    }
};

using MaxHeap = MaxHeapDS;

#endif // DATASTRUCTS_MAX_HEAP_HPP
