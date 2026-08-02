// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <unordered_lru_cache.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

using IntCache = unordered_lru_cache<int, int, std::hash<int>>;

BOOST_FIXTURE_TEST_SUITE(unordered_lru_cache_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(no_truncation_below_threshold)
{
    // the default truncate threshold is twice the max size
    IntCache cache(10);
    BOOST_CHECK_EQUAL(cache.max_size(), 10U);

    for (int i = 0; i < 20; i++) {
        cache.insert(i, i);
    }

    // reaching the threshold is not enough to trigger truncation
    for (int i = 0; i < 20; i++) {
        BOOST_CHECK(cache.exists(i));
    }
}

BOOST_AUTO_TEST_CASE(truncation_keeps_most_recent)
{
    IntCache cache(10);

    // exceeding the threshold truncates down to the max size
    for (int i = 0; i < 21; i++) {
        cache.insert(i, i);
    }

    for (int i = 0; i < 21; i++) {
        BOOST_CHECK_EQUAL(cache.exists(i), i >= 11);
    }

    // the retained values are intact
    for (int i = 11; i < 21; i++) {
        int value{0};
        BOOST_CHECK(cache.get(i, value));
        BOOST_CHECK_EQUAL(value, i);
    }
}

BOOST_AUTO_TEST_CASE(truncation_honors_explicit_threshold)
{
    IntCache cache(5, 6);
    BOOST_CHECK_EQUAL(cache.max_size(), 5U);

    for (int i = 0; i < 6; i++) {
        cache.insert(i, i);
    }
    for (int i = 0; i < 6; i++) {
        BOOST_CHECK(cache.exists(i));
    }

    cache.insert(6, 6);
    for (int i = 0; i < 7; i++) {
        BOOST_CHECK_EQUAL(cache.exists(i), i >= 2);
    }
}

BOOST_AUTO_TEST_CASE(get_refreshes_recency)
{
    IntCache cache(4);

    // fill up to the threshold without triggering truncation
    for (int i = 0; i < 8; i++) {
        cache.insert(i, i);
    }

    // make the oldest entry the most recently used one
    int value{0};
    BOOST_CHECK(cache.get(0, value));
    BOOST_CHECK_EQUAL(value, 0);

    // this insert exceeds the threshold and truncates
    cache.insert(8, 8);

    // the refreshed entry survives, the entries it outranks do not
    for (int i = 0; i < 9; i++) {
        const bool expected = i == 0 || i >= 6;
        BOOST_CHECK_EQUAL(cache.exists(i), expected);
    }
}

BOOST_AUTO_TEST_CASE(exists_refreshes_recency)
{
    IntCache cache(4);

    for (int i = 0; i < 8; i++) {
        cache.insert(i, i);
    }

    BOOST_CHECK(cache.exists(1));

    cache.insert(8, 8);

    for (int i = 0; i < 9; i++) {
        const bool expected = i == 1 || i >= 6;
        BOOST_CHECK_EQUAL(cache.exists(i), expected);
    }
}

BOOST_AUTO_TEST_CASE(erase_and_clear)
{
    IntCache cache(10);

    for (int i = 0; i < 5; i++) {
        cache.insert(i, i);
    }

    cache.erase(2);
    BOOST_CHECK(!cache.exists(2));
    BOOST_CHECK(cache.exists(1));

    // erasing an absent key is a no-op
    cache.erase(2);
    cache.erase(100);
    BOOST_CHECK(cache.exists(1));

    cache.clear();
    for (int i = 0; i < 5; i++) {
        BOOST_CHECK(!cache.exists(i));
    }

    // the cache is still usable afterwards
    cache.insert(7, 7);
    int value{0};
    BOOST_CHECK(cache.get(7, value));
    BOOST_CHECK_EQUAL(value, 7);
}

BOOST_AUTO_TEST_CASE(emplace_inserts_and_overwrites)
{
    IntCache cache(10);
    int value{0};

    cache.emplace(1, 10);
    BOOST_CHECK(cache.get(1, value));
    BOOST_CHECK_EQUAL(value, 10);

    // emplacing a key that is already present replaces its value
    cache.emplace(1, 20);
    BOOST_CHECK(cache.get(1, value));
    BOOST_CHECK_EQUAL(value, 20);

    cache.insert(1, 30);
    BOOST_CHECK(cache.get(1, value));
    BOOST_CHECK_EQUAL(value, 30);
}

BOOST_AUTO_TEST_CASE(overwrite_does_not_grow_map)
{
    IntCache cache(4);

    // fill up to the threshold without triggering truncation
    for (int i = 0; i < 8; i++) {
        cache.insert(i, i);
    }

    // overwriting an existing key must not grow the map, so this stays at the threshold rather than exceeding it
    cache.insert(0, 100);
    for (int i = 0; i < 8; i++) {
        BOOST_CHECK(cache.exists(i));
    }

    int value{0};
    BOOST_CHECK(cache.get(0, value));
    BOOST_CHECK_EQUAL(value, 100);
}

BOOST_AUTO_TEST_SUITE_END()
