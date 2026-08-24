// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <coinjoin/coinjoin.h>
#include <txmempool.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/coinjoin.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(availablecoins_tests, WalletTestingSetup)
class AvailableCoinsTestingSetup : public TestChain100Setup
{
public:
    AvailableCoinsTestingSetup()
    {
        CreateAndProcessBlock({}, {});
        wallet = CreateSyncedWallet(*m_node.chain, *m_node.coinjoin_loader, *m_node.chainman, m_args, coinbaseKey);
    }

    ~AvailableCoinsTestingSetup()
    {
        wallet.reset();
    }
    CWalletTx& AddTx(CRecipient recipient)
    {
        CTransactionRef tx;
        CCoinControl dummy;
        {
            auto res = CreateTransaction(*wallet, {recipient}, RANDOM_CHANGE_POSITION, dummy);
            BOOST_CHECK(res);
            tx = res->tx;
        }
        wallet->CommitTransaction(tx, {}, {});
        CMutableTransaction blocktx;
        {
            LOCK(wallet->cs_wallet);
            blocktx = CMutableTransaction(*wallet->mapWallet.at(tx->GetHash()).tx);
        }
        CreateAndProcessBlock({CMutableTransaction(blocktx)}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));

        const CBlockIndex* tip{WITH_LOCK(m_node.chainman->GetMutex(), return m_node.chainman->ActiveChain().Tip())};
        LOCK(wallet->cs_wallet);
        wallet->SetLastBlockProcessed(tip->nHeight, tip->GetBlockHash());
        auto it = wallet->mapWallet.find(tx->GetHash());
        BOOST_CHECK(it != wallet->mapWallet.end());
        it->second.m_state = TxStateConfirmed{tip->GetBlockHash(), tip->nHeight, /*index=*/1};
        return it->second;
    }

    std::unique_ptr<CWallet> wallet;
};

BOOST_FIXTURE_TEST_CASE(BasicOutputTypesTest, AvailableCoinsTestingSetup)
{
    CoinsResult available_coins;
    util::Result<CTxDestination> dest{util::Error{}};

    // Verify our wallet has one usable coinbase UTXO before starting
    // This UTXO is a P2PK, so it should show up in the Other bucket
    {
        LOCK(wallet->cs_wallet);
        available_coins = AvailableCoins(*wallet);
    }
    BOOST_CHECK_EQUAL(available_coins.size(), 1U);
    BOOST_CHECK_EQUAL(available_coins.other.size(), 1U);

    // We will create a self transfer for each of the OutputTypes and
    // verify it is put in the correct bucket after running GetAvailablecoins
    //
    // For each OutputType, We expect 2 UTXOs in our wallet following the self transfer:
    //   1. One UTXO as the recipient
    //   2. One UTXO from the change, due to payment address matching logic

    // Legacy (P2PKH)
    {
        LOCK(wallet->cs_wallet);
        dest = wallet->GetNewDestination("");
    }
    BOOST_ASSERT(dest);
    AddTx(CRecipient{{GetScriptForDestination(*dest)}, 4 * COIN, /*fSubtractFeeFromAmount=*/true});
    {
        LOCK(wallet->cs_wallet);
        available_coins = AvailableCoins(*wallet);
    }
    BOOST_CHECK_EQUAL(available_coins.legacy.size(), 2U);
}

BOOST_FIXTURE_TEST_CASE(UnconfirmableOutputsAreNotWalletFunds, AvailableCoinsTestingSetup)
{
    LOCK(wallet->cs_wallet);

    const auto dest{wallet->GetNewDestination("")};
    BOOST_ASSERT(dest);

    // Use a real CoinJoin denomination so the denominated-credit paths apply.
    const CAmount denom{CoinJoin::GetSmallestDenomination()};
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint{uint256::ONE, 0});
    mtx.vout.emplace_back(denom, GetScriptForDestination(*dest));
    const CTransactionRef tx{MakeTransactionRef(mtx)};

    // A transaction the wallet knows about but that never reached the mempool cannot
    // confirm as it stands, so its outputs are not funds the wallet can spend or mix.
    BOOST_CHECK(wallet->AddToWallet(tx, TxStateInactive{}));
    BOOST_CHECK_EQUAL(wallet->CountInputsWithAmount(denom), 0);

    // The aggregate CoinJoin balances have to agree: an output that is not wallet funds
    // is not denominated or anonymized funds either.
    const CWalletTx& wtx{wallet->mapWallet.at(tx->GetHash())};
    BOOST_CHECK_EQUAL(CachedTxGetAvailableCoinJoinCredits(*wallet, wtx).m_denominated, 0);

    // Once it is in the mempool they count.
    BOOST_CHECK(wallet->AddToWallet(tx, TxStateInMempool{}));
    BOOST_CHECK_EQUAL(wallet->CountInputsWithAmount(denom), 1);
    BOOST_CHECK_EQUAL(CachedTxGetAvailableCoinJoinCredits(*wallet, wtx).m_denominated, denom);
}

BOOST_FIXTURE_TEST_CASE(MempoolRemovalInvalidatesAnonymizableTally, AvailableCoinsTestingSetup)
{
    LOCK(wallet->cs_wallet);

    const auto dest{wallet->GetNewDestination("")};
    BOOST_ASSERT(dest);

    // A wallet transaction in the mempool is trusted at depth zero, so its outputs count
    // towards the anonymizable tally and that tally is cacheable.
    auto created{CreateTransaction(*wallet, {CRecipient{GetScriptForDestination(*dest), 1 * COIN,
                                                        /*fSubtractFeeFromAmount=*/false}},
                                   RANDOM_CHANGE_POSITION, CCoinControl{})};
    BOOST_REQUIRE(created);
    const CTransactionRef tx{created->tx};
    BOOST_CHECK(wallet->AddToWallet(tx, TxStateInMempool{}));

    const auto tallied = [&](const CTxDestination& target) {
        for (const auto& item : wallet->SelectCoinsGroupedByAddresses()) {
            if (item.txdest == target) return true;
        }
        return false;
    };

    // Prime the cache, so that the check below cannot pass by recomputing the tally.
    BOOST_REQUIRE(tallied(*dest));

    // Leaving the mempool makes the transaction unconfirmable as it stands; the cached
    // tally must not keep handing out its outputs.
    wallet->transactionRemovedFromMempool(tx, MemPoolRemovalReason::EXPIRY);
    BOOST_CHECK(!tallied(*dest));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
