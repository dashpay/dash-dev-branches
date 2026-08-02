// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <limitedmap.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(limitedmap_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(limitedmap_test)
{
    // create a limitedmap capped at 10 items
    unordered_limitedmap<int, int> map(10);

    // check that the max size is 10
    BOOST_CHECK(map.max_size() == 10);

    // check that it's empty
    BOOST_CHECK(map.size() == 0);

    // insert (-1, -1)
    map.insert(std::pair<int, int>(-1, -1));

    // make sure that the size is updated
    BOOST_CHECK(map.size() == 1);

    // make sure that the new item is in the map
    BOOST_CHECK(map.count(-1) == 1);

    // insert 10 new items
    for (int i = 0; i < 10; i++) {
        map.insert(std::pair<int, int>(i, i + 1));
    }

    // make sure that the map now contains 10 items...
    BOOST_CHECK(map.size() == 10);

    // ...and that the first item has been discarded
    BOOST_CHECK(map.count(-1) == 0);

    // iterate over the map, both with an index and an iterator
    unordered_limitedmap<int, int>::const_iterator it = map.begin();
    for (int i = 0; i < 10; i++) {
        // make sure the item is present
        BOOST_CHECK(map.count(i) == 1);

        // use the iterator to check for the expected key and value
        //BOOST_CHECK(it->first == i);
        //BOOST_CHECK(it->second == i + 1);

        // use find to check for the value
        BOOST_CHECK(map.find(i)->second == i + 1);

        // update and recheck
        auto jt = map.find(i);
        map.update(jt, i + 2);
        BOOST_CHECK(map.find(i)->second == i + 2);

        it++;
    }

    // check that we've exhausted the iterator
    BOOST_CHECK(it == map.end());

    // resize the map to 5 items
    map.max_size(5);

    // check that the max size and size are now 5
    BOOST_CHECK(map.max_size() == 5);
    BOOST_CHECK(map.size() == 5);

    // check that items less than 5 have been discarded
    // and items greater than 5 are retained
    for (int i = 0; i < 10; i++) {
        if (i < 5) {
            BOOST_CHECK(map.count(i) == 0);
        } else {
            BOOST_CHECK(map.count(i) == 1);
        }
    }

    // erase some items not in the map
    for (int i = 100; i < 1000; i += 100) {
        map.erase(i);
    }

    // check that the size is unaffected
    BOOST_CHECK(map.size() == 5);

    // erase the remaining elements
    for (int i = 5; i < 10; i++) {
        map.erase(i);
    }

    // check that the map is now empty
    BOOST_CHECK(map.empty());
}

// A map constructed with a prune-after size larger than its retained size must not prune on
// every insertion past the retained size. Instead it is allowed to grow up to the prune-after
// size and is then pruned back down to the retained size in a single batch. This amortises the
// cost of prune() -- which partitions every element -- over many insertions.
BOOST_AUTO_TEST_CASE(limitedmap_prune_after_size_test)
{
    constexpr int RETAINED_SIZE{10};
    constexpr int PRUNE_AFTER_SIZE{2 * RETAINED_SIZE};

    unordered_limitedmap<int, int> map(RETAINED_SIZE, PRUNE_AFTER_SIZE);

    // max_size() reports the retained size, not the temporary prune threshold
    BOOST_CHECK_EQUAL(map.max_size(), static_cast<size_t>(RETAINED_SIZE));

    // fill the map up to (and including) the prune-after size. No prune may happen along the
    // way, so every insertion is retained -- in particular size() exceeds the retained size
    // without anything being evicted.
    for (int i = 0; i < PRUNE_AFTER_SIZE; i++) {
        map.insert(std::pair<int, int>(i, i));
        BOOST_CHECK_EQUAL(map.size(), static_cast<size_t>(i) + 1U);
    }

    // nothing has been evicted yet, even though we are well past the retained size
    BOOST_CHECK_EQUAL(map.size(), static_cast<size_t>(PRUNE_AFTER_SIZE));
    for (int i = 0; i < PRUNE_AFTER_SIZE; i++) {
        BOOST_CHECK(map.count(i) == 1);
    }

    // crossing the prune-after size prunes back down to the retained size in one batch
    map.insert(std::pair<int, int>(PRUNE_AFTER_SIZE, PRUNE_AFTER_SIZE));
    BOOST_CHECK_EQUAL(map.size(), static_cast<size_t>(RETAINED_SIZE));

    // the retained entries are the ones with the highest values
    for (int i = 0; i <= PRUNE_AFTER_SIZE; i++) {
        if (i <= PRUNE_AFTER_SIZE - RETAINED_SIZE) {
            BOOST_CHECK(map.count(i) == 0);
        } else {
            BOOST_CHECK(map.count(i) == 1);
        }
    }

    // the cycle repeats: after a prune the map grows again without evicting anything until it
    // once more exceeds the prune-after size, at which point it drops back to the retained size
    int next_key{PRUNE_AFTER_SIZE + 1};
    for (int i = 0; i < PRUNE_AFTER_SIZE - RETAINED_SIZE; i++, next_key++) {
        map.insert(std::pair<int, int>(next_key, next_key));
        BOOST_CHECK_EQUAL(map.size(), static_cast<size_t>(RETAINED_SIZE + i) + 1U);
    }
    BOOST_CHECK_EQUAL(map.size(), static_cast<size_t>(PRUNE_AFTER_SIZE));

    map.insert(std::pair<int, int>(next_key, next_key));
    BOOST_CHECK_EQUAL(map.size(), static_cast<size_t>(RETAINED_SIZE));
}

// Without an explicit prune-after size the map prunes as soon as it exceeds the retained size,
// so it never holds more than that many elements.
BOOST_AUTO_TEST_CASE(limitedmap_default_prune_after_size_test)
{
    constexpr int RETAINED_SIZE{10};

    unordered_limitedmap<int, int> map(RETAINED_SIZE);
    BOOST_CHECK_EQUAL(map.max_size(), static_cast<size_t>(RETAINED_SIZE));

    for (int i = 0; i < 4 * RETAINED_SIZE; i++) {
        map.insert(std::pair<int, int>(i, i));
        BOOST_CHECK_LE(map.size(), static_cast<size_t>(RETAINED_SIZE));
    }
    BOOST_CHECK_EQUAL(map.size(), static_cast<size_t>(RETAINED_SIZE));
}

BOOST_AUTO_TEST_SUITE_END()
