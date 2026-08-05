// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_MASTERNODE_H
#define BITCOIN_TEST_UTIL_MASTERNODE_H

#include <coins.h>
#include <primitives/transaction.h>

#include <map>
#include <vector>

class CBLSSecretKey;
class ChainstateManager;
class CKey;

using SimpleUTXOMap = std::map<COutPoint, Coin>;

SimpleUTXOMap BuildSimpleUtxoMap(const std::vector<CTransactionRef>& txs);
SimpleUTXOMap FundTransaction(const ChainstateManager& chainman, CMutableTransaction& tx, SimpleUTXOMap& utxos,
                              const CScript& script_payout, CAmount amount);
void SignTransaction(CMutableTransaction& tx, const SimpleUTXOMap& coins, const CKey& coinbase_key);
CMutableTransaction CreateProRegTx(const ChainstateManager& chainman, SimpleUTXOMap& utxos, int port,
                                   const CScript& script_payout, const CKey& coinbase_key, CKey& owner_key_ret,
                                   CBLSSecretKey& operator_key_ret);
CScript GenerateRandomAddress();

#endif // BITCOIN_TEST_UTIL_MASTERNODE_H
