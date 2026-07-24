// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <key_io.h>
#include <script/standard.h>
#include <spork.h>
#include <timedata.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>

BOOST_FIXTURE_TEST_SUITE(spork_tests, RegTestingSetup)

BOOST_AUTO_TEST_CASE(extreme_timestamps_are_handled_without_overflow)
{
    CSporkManager sporkman;
    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);
    BOOST_REQUIRE(sporkman.SetSporkAddress(EncodeDestination(PKHash{key.GetPubKey()})));
    BOOST_REQUIRE(sporkman.SetMinSporkKeys(1));

    CSporkMessage future_spork;
    future_spork.nTimeSigned = std::numeric_limits<int64_t>::max();
    BOOST_CHECK(!sporkman.GetValidSporkSigner(future_spork).has_value());

    CSporkMessage inactive_spork{SPORK_2_INSTANTSEND_ENABLED, std::numeric_limits<int64_t>::max(),
                                 GetAdjustedTime()};
    BOOST_REQUIRE(inactive_spork.Sign(key));
    const auto signer{sporkman.GetValidSporkSigner(inactive_spork)};
    BOOST_REQUIRE(signer.has_value());
    BOOST_REQUIRE(sporkman.ProcessSpork(inactive_spork, *signer));
    BOOST_CHECK(!sporkman.IsSporkActive(SPORK_2_INSTANTSEND_ENABLED));
}

BOOST_AUTO_TEST_SUITE_END()
