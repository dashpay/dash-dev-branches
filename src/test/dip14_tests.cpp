// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/common.h>
#include <key.h>
#include <pubkey.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(dip14_tests, BasicTestingSetup)

namespace {
//! One step of a DIP-14 derivation path: a 256-bit child index (big-endian)
//! plus hardened flag.
struct PathElement {
    std::array<unsigned char, 32> index{};
    bool hardened{false};
};

PathElement Elem256(const std::string& hex, bool hardened)
{
    const std::vector<unsigned char> v{ParseHex(hex)};
    BOOST_REQUIRE_EQUAL(v.size(), 32U);
    PathElement e;
    std::copy(v.begin(), v.end(), e.index.begin());
    e.hardened = hardened;
    return e;
}

PathElement Elem32(uint32_t index, bool hardened)
{
    PathElement e;
    WriteBE32(e.index.data() + 28, index);
    e.hardened = hardened;
    return e;
}

//! Master key from the seed shared by all DIP-14 test vectors (dashpay/dips
//! dip-0014.md), from mnemonic "birth kingdom trash renew flavor utility
//! donkey gasp regular alert pave layer".
CExtKey MasterKey()
{
    const std::vector<unsigned char> seed{ParseHex(
        "b16d3782e714da7c55a397d5f19104cfed7ffa8036ac514509bbb50807f8ac59"
        "8eeb26f0797bd8cc221a6cbff2168d90a5e9ee025a5bd977977b9eccd97894bb")};
    CExtKey master;
    master.SetSeed(MakeByteSpan(seed));
    return master;
}

void DerivePath(const std::vector<PathElement>& path, CKey& key_out, ChainCode& cc_out)
{
    const CExtKey master{MasterKey()};
    key_out = master.key;
    cc_out = master.chaincode;
    for (const PathElement& e : path) {
        CKey child;
        ChainCode cc_child;
        BOOST_REQUIRE(key_out.Derive256(child, cc_child, e.index, e.hardened, cc_out));
        key_out = child;
        cc_out = cc_child;
    }
}

std::string DerivedKeyHex(const std::vector<PathElement>& path)
{
    CKey key;
    ChainCode cc;
    DerivePath(path, key, cc);
    return HexStr(Span{key.begin(), key.size()});
}
} // namespace

// DIP-14 test vector 1: m/<id1>/<id2>'/<id3>/0
BOOST_AUTO_TEST_CASE(dip14_vector_1)
{
    const std::vector<PathElement> path{
        Elem256("775d3854c910b7dee436869c4724bed2fe0784e198b8a39f02bbb49d8ebcfc3b", false),
        Elem256("f537439f36d04a15474ff7423e4b904a14373fafb37a41db74c84f1dbb5c89a6", true),
        Elem256("4c4592ca670c983fc43397dfd21a6f427fac9b4ac53cb4dcdc6522ec51e81e79", false),
        Elem32(0, false),
    };
    BOOST_CHECK_EQUAL(DerivedKeyHex(path), "e8781fdef72862968cd9a4d2df34edaf9dcc5b17629ec505f0d2d1a8ed6f9f09");
}

// DIP-14 test vector 2: m/9'/5'/15'/0'/<idA>'/<idB>'/0 (DIP-15 shape)
BOOST_AUTO_TEST_CASE(dip14_vector_2)
{
    const std::vector<PathElement> path{
        Elem32(9, true),
        Elem32(5, true),
        Elem32(15, true),
        Elem32(0, true),
        Elem256("555d3854c910b7dee436869c4724bed2fe0784e198b8a39f02bbb49d8ebcfc3a", true),
        Elem256("a137439f36d04a15474ff7423e4b904a14373fafb37a41db74c84f1dbb5c89b5", true),
        Elem32(0, false),
    };
    BOOST_CHECK_EQUAL(DerivedKeyHex(path), "fac40790776d171ee1db90899b5eb2df2f7d2aaf35ad56f07ffb8ed2c57f8e60");
}

// DIP-14 test vector 3: m/<id> (single 256-bit non-hardened step)
BOOST_AUTO_TEST_CASE(dip14_vector_3)
{
    const std::vector<PathElement> path{
        Elem256("775d3854c910b7dee436869c4724bed2fe0784e198b8a39f02bbb49d8ebcfc3b", false),
    };
    BOOST_CHECK_EQUAL(DerivedKeyHex(path), "f6a95ae75ea8362d9478932f71b262b3d981918fe030316686a475dea4889938");
}

// DIP-14 test vector 4: m/<id1>/<id2>'
BOOST_AUTO_TEST_CASE(dip14_vector_4)
{
    const std::vector<PathElement> path{
        Elem256("775d3854c910b7dee436869c4724bed2fe0784e198b8a39f02bbb49d8ebcfc3b", false),
        Elem256("f537439f36d04a15474ff7423e4b904a14373fafb37a41db74c84f1dbb5c89a6", true),
    };
    BOOST_CHECK_EQUAL(DerivedKeyHex(path), "b898ad92d3a0698bc3117d3777d82676673816ce52f4fc2f1263a2f676825f90");
}

//! Indexes below 2^32 must derive exactly as BIP32, so a DIP-14 path mixing
//! 32-bit and 256-bit steps stays compatible with existing BIP32 code.
BOOST_AUTO_TEST_CASE(dip14_bip32_compatibility)
{
    const CExtKey master{MasterKey()};

    CKey child_bip32, child_dip14;
    ChainCode cc_bip32, cc_dip14;
    BOOST_REQUIRE(master.key.Derive(child_bip32, cc_bip32, 5, master.chaincode));
    BOOST_REQUIRE(master.key.Derive256(child_dip14, cc_dip14, Elem32(5, false).index, false, master.chaincode));
    BOOST_CHECK(child_bip32.GetPrivKey() == child_dip14.GetPrivKey());
    BOOST_CHECK(cc_bip32 == cc_dip14);

    BOOST_REQUIRE(master.key.Derive(child_bip32, cc_bip32, 5 | 0x80000000u, master.chaincode));
    BOOST_REQUIRE(master.key.Derive256(child_dip14, cc_dip14, Elem32(5, false).index, true, master.chaincode));
    BOOST_CHECK(child_bip32.GetPrivKey() == child_dip14.GetPrivKey());
    BOOST_CHECK(cc_bip32 == cc_dip14);

    const CPubKey parent_pub{master.key.GetPubKey()};
    CPubKey pub_bip32, pub_dip14;
    BOOST_REQUIRE(parent_pub.Derive(pub_bip32, cc_bip32, 5, master.chaincode));
    BOOST_REQUIRE(parent_pub.Derive256(pub_dip14, cc_dip14, Elem32(5, false).index, master.chaincode));
    BOOST_CHECK(pub_bip32 == pub_dip14);
    BOOST_CHECK(cc_bip32 == cc_dip14);
}

//! Non-hardened 256-bit public derivation must match private derivation
//! (this is what lets a contact derive our friendship addresses from an
//! exported xpub), and hardened derivation must be rejected on the public
//! side.
BOOST_AUTO_TEST_CASE(dip14_public_derivation_matches)
{
    CKey parent_key;
    ChainCode parent_cc;
    DerivePath({Elem32(9, true), Elem32(1, true), Elem32(15, true), Elem32(0, true)}, parent_key, parent_cc);

    const PathElement id_a{Elem256("555d3854c910b7dee436869c4724bed2fe0784e198b8a39f02bbb49d8ebcfc3a", false)};
    const PathElement id_b{Elem256("a137439f36d04a15474ff7423e4b904a14373fafb37a41db74c84f1dbb5c89b5", false)};

    // Private side: parent/idA/idB
    CKey mid_key, leaf_key;
    ChainCode mid_cc, leaf_cc;
    BOOST_REQUIRE(parent_key.Derive256(mid_key, mid_cc, id_a.index, false, parent_cc));
    BOOST_REQUIRE(mid_key.Derive256(leaf_key, leaf_cc, id_b.index, false, mid_cc));

    // Public side: neuter parent, then derive idA/idB
    const CPubKey parent_pub{parent_key.GetPubKey()};
    CPubKey mid_pub, leaf_pub;
    ChainCode mid_pub_cc, leaf_pub_cc;
    BOOST_REQUIRE(parent_pub.Derive256(mid_pub, mid_pub_cc, id_a.index, parent_cc));
    BOOST_REQUIRE(mid_pub.Derive256(leaf_pub, leaf_pub_cc, id_b.index, mid_pub_cc));

    BOOST_CHECK(leaf_pub == leaf_key.GetPubKey());
    BOOST_CHECK(leaf_pub_cc == leaf_cc);

    // A hardened 32-bit index (high bit set) cannot be derived from a pubkey.
    CPubKey unused;
    ChainCode unused_cc;
    BOOST_CHECK(!parent_pub.Derive256(unused, unused_cc, Elem32(0x80000000u, false).index, parent_cc));
}

BOOST_AUTO_TEST_CASE(dip14_rejects_invalid_index_sizes)
{
    const CExtKey master{MasterKey()};
    const CPubKey parent_pub{master.key.GetPubKey()};
    const std::array<unsigned char, 31> short_index{};
    const std::array<unsigned char, 33> long_index{};
    CKey child_key;
    CPubKey child_pubkey;
    ChainCode child_cc;

    BOOST_CHECK(!master.key.Derive256(child_key, child_cc, short_index, false, master.chaincode));
    BOOST_CHECK(!master.key.Derive256(child_key, child_cc, long_index, false, master.chaincode));
    BOOST_CHECK(!parent_pub.Derive256(child_pubkey, child_cc, short_index, master.chaincode));
    BOOST_CHECK(!parent_pub.Derive256(child_pubkey, child_cc, long_index, master.chaincode));
}

BOOST_AUTO_TEST_SUITE_END()
