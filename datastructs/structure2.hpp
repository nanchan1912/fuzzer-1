#ifndef DATASTRUCTS_STRUCTURE2_HPP
#define DATASTRUCTS_STRUCTURE2_HPP

#include <vector>
#include <utility>
#include <algorithm>
#include <stdexcept>
#include "structure1.hpp"

/**
 * @brief Structure 2: Runner-Up Bucket Queue (three-tier, no periodic rebuild).
 */
class RunnerUpQueueDS {
public:
    size_t m;
    size_t r;
    std::vector<std::pair<double, int>> good_pile; // min-heap: (score, cid)
    std::vector<std::pair<double, int>> runner_up; // sorted list: [(score, cid), ...]
    std::vector<std::pair<double, int>> bad_pile;  // unsorted list: (score, cid)

    RunnerUpQueueDS(size_t m = 500, size_t r = 100)
        : m(m), r(r) {}

    size_t size() const {
        return good_pile.size() + runner_up.size() + bad_pile.size();
    }

    bool empty() const {
        return good_pile.empty() && runner_up.empty() && bad_pile.empty();
    }

    void insert(int cid, double score) {
        double s = static_cast<double>(score);
        std::pair<double, int> item = {s, cid};
        auto comp_min = [](const std::pair<double, int>& a, const std::pair<double, int>& b) {
            return a.first > b.first || (a.first == b.first && a.second > b.second);
        };

        if (good_pile.size() < m) {
            good_pile.push_back(item);
            std::push_heap(good_pile.begin(), good_pile.end(), comp_min);
        } else if (s > good_pile.front().first) {
            std::pop_heap(good_pile.begin(), good_pile.end(), comp_min);
            std::pair<double, int> evicted = good_pile.back();
            good_pile.back() = item;
            std::push_heap(good_pile.begin(), good_pile.end(), comp_min);
            _admit_runner_up(evicted);
        } else {
            _admit_runner_up(item);
        }
    }

    void _admit_runner_up(const std::pair<double, int>& item) {
        if (r == 0) {
            bad_pile.push_back(item);
            return;
        }

        if (runner_up.size() < r) {
            auto it = std::lower_bound(runner_up.begin(), runner_up.end(), item);
            runner_up.insert(it, item);
        } else if (item.first > runner_up.front().first) {
            bad_pile.push_back(runner_up.front());
            runner_up.erase(runner_up.begin());
            auto it = std::lower_bound(runner_up.begin(), runner_up.end(), item);
            runner_up.insert(it, item);
        } else {
            bad_pile.push_back(item);
        }
    }

    std::pair<int, double> select() {
        auto comp_min = [](const std::pair<double, int>& a, const std::pair<double, int>& b) {
            return a.first > b.first || (a.first == b.first && a.second > b.second);
        };

        if (good_pile.empty() && runner_up.empty()) {
            if (!bad_pile.empty()) {
                std::vector<double> bp_scores;
                std::vector<int> bp_cids;
                bp_scores.reserve(bad_pile.size());
                bp_cids.reserve(bad_pile.size());
                for (const auto& item : bad_pile) {
                    bp_scores.push_back(item.first);
                    bp_cids.push_back(item.second);
                }

                auto [top_m, bad] = quickselect_top_m_split(bp_scores, bp_cids, m);
                good_pile = top_m;
                std::make_heap(good_pile.begin(), good_pile.end(), comp_min);
                bad_pile = bad;
            }
        }

        if (good_pile.empty()) {
            throw std::runtime_error("select() on completely empty RunnerUpQueueDS");
        }

        std::pair<double, int> item = good_pile.back();
        good_pile.pop_back();

        if (r > 0 && !runner_up.empty()) {
            std::pair<double, int> promoted = runner_up.back();
            runner_up.pop_back();
            good_pile.push_back(promoted);
            std::push_heap(good_pile.begin(), good_pile.end(), comp_min);
        }

        return {item.second, item.first}; // (cid, score)
    }

    void update_score(int cid, double new_score) {
        insert(cid, new_score);
    }
};

using Structure2 = RunnerUpQueueDS;

#endif // DATASTRUCTS_STRUCTURE2_HPP
