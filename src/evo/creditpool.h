// Copyright (c) 2023 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_EVO_CREDITPOOL_H
#define BITCOIN_EVO_CREDITPOOL_H

#include <coins.h>

#include <evo/assetlocktx.h>

#include <sync.h>
#include <threadsafety.h>

#include <map>

class CBlockIndex;
class TxValidationState;

namespace Consensus
{
    struct Params;
}

class CCreditPoolManager
{
private:
    CBlockIndex* pindexPrev;

    CAmount prevLocked{0};
    CAmount sessionLimit{0};
    CAmount sessionLocked{0};
    CAmount sessionUnlocked{0};

    bool lock(const CTransaction& tx, TxValidationState& state);

    bool unlock(const CTransaction& tx, TxValidationState& state);

    static constexpr int LimitBlocksToTrace = 576;
    static constexpr CAmount LimitAmountLow = 100 * COIN;
    static constexpr CAmount LimitAmountHigh = 1000 * COIN;
public:
    CCreditPoolManager(CBlockIndex* pindexPrev, const Consensus::Params& consensusParams);

    ~CCreditPoolManager() = default;

    // This function should be called for each Asset Lock/Unlock tx
    // to change amount of credit pool
    bool processTransaction(const CTransaction& tx, TxValidationState& state);

    CAmount getTotalLocked() const;
};

#endif
