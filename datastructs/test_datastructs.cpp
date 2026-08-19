#include <iostream>
#include <cassert>
#include <cmath>
#include <vector>
#include "datastructs.hpp"

void test_max_heap() {
    std::cout << "[Testing MaxHeapDS / MaxHeap...]" << std::endl;
    MaxHeap ds;
    assert(ds.size() == 0);
    assert(ds.empty());

    ds.insert(1, 10.5);
    ds.insert(2, 50.2);
    ds.insert(3, 25.0);
    assert(ds.size() == 3);

    // Highest score is cid=2 (50.2)
    auto [cid1, score1] = ds.select();
    assert(cid1 == 2);
    assert(std::abs(score1 - 50.2) < 1e-6);
    assert(ds.size() == 2);

    // Update cid 1 score to 100.0
    ds.update_score(1, 100.0);
    assert(ds.size() == 2); // size shouldn't double count valid items

    auto [cid2, score2] = ds.select();
    assert(cid2 == 1);
    assert(std::abs(score2 - 100.0) < 1e-6);

    auto [cid3, score3] = ds.select();
    assert(cid3 == 3);
    assert(std::abs(score3 - 25.0) < 1e-6);

    assert(ds.empty());
    bool threw = false;
    try {
        ds.select();
    } catch (const std::runtime_error& e) {
        threw = true;
    }
    assert(threw);
    std::cout << "  MaxHeapDS PASSED!\n";
}

void test_structure1() {
    std::cout << "[Testing ThresholdBucketQueueDS / Structure1...]" << std::endl;
    // m = 3, T = 10 ops
    Structure1 ds(3, 10);
    for (int i = 1; i <= 10; ++i) {
        ds.insert(i, static_cast<double>(i * 10));
    }
    assert(ds.size() == 10);

    // Select items
    auto [cid, score] = ds.select();
    assert(cid > 0 && score > 0);
    std::cout << "  Structure1 selected cid=" << cid << ", score=" << score << "\n";
    std::cout << "  Structure1 PASSED!\n";
}

void test_structure2() {
    std::cout << "[Testing RunnerUpQueueDS / Structure2...]" << std::endl;
    // m = 3, r = 2
    Structure2 ds(3, 2);
    for (int i = 1; i <= 10; ++i) {
        ds.insert(i, static_cast<double>(i * 5));
    }
    assert(ds.size() == 10);

    auto [cid, score] = ds.select();
    assert(cid > 0 && score > 0);
    std::cout << "  Structure2 selected cid=" << cid << ", score=" << score << "\n";
    std::cout << "  Structure2 PASSED!\n";
}

void test_structure3() {
    std::cout << "[Testing MaxHeapBucketQueueDS / Structure3...]" << std::endl;
    // m = 3, r = 2
    Structure3 ds(3, 2);
    for (int i = 1; i <= 10; ++i) {
        ds.insert(i, static_cast<double>(i * 15));
    }
    assert(ds.size() == 10);

    auto [cid, score] = ds.select();
    assert(cid > 0 && score > 0);
    std::cout << "  Structure3 selected cid=" << cid << ", score=" << score << "\n";
    std::cout << "  Structure3 PASSED!\n";
}

int main() {
    std::cout << "Running Data Structures C++ Unit Tests...\n";
    test_max_heap();
    test_structure1();
    test_structure2();
    test_structure3();
    std::cout << "ALL DATASTRUCTURES C++ TESTS PASSED SUCCESSFULLY!\n";
    return 0;
}
