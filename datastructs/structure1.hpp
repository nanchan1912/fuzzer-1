#ifndef DATASTRUCTS_STRUCTURE1_HPP
#define DATASTRUCTS_STRUCTURE1_HPP

#include <vector>
#include <utility>
#include <algorithm>
#include <stdexcept>
#include <string>
#include <iostream>

/**
 * @brief Splits items (score, cid) into top_m and bad_pile vectors.
 */
inline std::pair<std::vector<std::pair<double, int>>, std::vector<std::pair<double, int>>>
quickselect_top_m_split(const std::vector<double>& scores, const std::vector<int>& cids, size_t m) {
    size_t n = scores.size();
    std::vector<std::pair<double, int>> all_items(n);
    for (size_t i = 0; i < n; ++i) {
        all_items[i] = {scores[i], cids[i]};
    }

    if (n <= m) {
        return {all_items, {}};
    }

    std::nth_element(all_items.begin(), all_items.begin() + m, all_items.end(),
        [](const std::pair<double, int>& a, const std::pair<double, int>& b) {
            return a.first > b.first || (a.first == b.first && a.second > b.second);
        });

    std::vector<std::pair<double, int>> top_m(all_items.begin(), all_items.begin() + m);
    std::vector<std::pair<double, int>> bad(all_items.begin() + m, all_items.end());
    return {top_m, bad};
}

/**
 * @brief Structure 1: Threshold Bucket Queue (two-pile, min-heap backed, periodic rebuild).
 */
class ThresholdBucketQueueDS {
public:
    size_t m;
    long long T; // threshold for periodic rebuild (-1 means "never")
    std::vector<std::pair<double, int>> good_pile; // min-heap: (score, cid)
    std::vector<std::pair<double, int>> bad_pile;  // plain list: (score, cid)
    long long ops_since_rebuild;

    ThresholdBucketQueueDS(size_t m = 50, long long T = 2000)
        : m(m), T(T), ops_since_rebuild(0) {}

    ThresholdBucketQueueDS(size_t m, const std::string& T_str)
        : m(m), ops_since_rebuild(0) {
        if (T_str == "never") {
            T = -1;
        } else {
            T = std::stoll(T_str);
        }
    }

    size_t size() const {
        return good_pile.size() + bad_pile.size();
    }

    bool empty() const {
        return good_pile.empty() && bad_pile.empty();
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
            bad_pile.push_back(evicted);
        } else {
            bad_pile.push_back(item);
        }

        ops_since_rebuild++;
        if (T >= 0 && ops_since_rebuild >= T) {
            rebuild();
        }
    }

    std::pair<int, double> select() {
        std::pair<double, int> item;
        if (!good_pile.empty()) {
            item = good_pile.back();
            good_pile.pop_back();
        } else {
            rebuild();
            if (good_pile.empty()) {
                throw std::runtime_error("select() on empty ThresholdBucketQueueDS");
            }
            item = good_pile.back();
            good_pile.pop_back();
        }

        ops_since_rebuild++;
        if (T >= 0 && ops_since_rebuild >= T) {
            rebuild();
        }

        return {item.second, item.first}; // (cid, score)
    }

    void update_score(int cid, double new_score) {
        insert(cid, new_score);
    }

    void rebuild() {
        std::vector<double> everyone_scores;
        std::vector<int> everyone_cids;
        everyone_scores.reserve(good_pile.size() + bad_pile.size());
        everyone_cids.reserve(good_pile.size() + bad_pile.size());

        for (const auto& item : good_pile) {
            everyone_scores.push_back(item.first);
            everyone_cids.push_back(item.second);
        }
        for (const auto& item : bad_pile) {
            everyone_scores.push_back(item.first);
            everyone_cids.push_back(item.second);
        }

        auto [top_m, bad] = quickselect_top_m_split(everyone_scores, everyone_cids, m);
        
        auto comp_min = [](const std::pair<double, int>& a, const std::pair<double, int>& b) {
            return a.first > b.first || (a.first == b.first && a.second > b.second);
        };
        good_pile = top_m;
        std::make_heap(good_pile.begin(), good_pile.end(), comp_min);
        bad_pile = bad;
        ops_since_rebuild = 0;
    }
};

using Structure1 = ThresholdBucketQueueDS;

#endif // DATASTRUCTS_STRUCTURE1_HPP
