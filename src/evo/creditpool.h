// Copyright (c) 2022 The Dash Core developers
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

class CCreditPoolManager
{
private:
    CBlockIndex* pindexPrev;

    CAmount totalLocked;

    bool lock(const CTransaction& tx, CValidationState& state);

    bool unlock(const CTransaction& tx, CValidationState& state);

public:
    CCreditPoolManager(CBlockIndex* pindexPrev, CAmount totalLocked = 0)
    : pindexPrev(pindexPrev)
    , totalLocked(totalLocked)
    {}

    ~CCreditPoolManager() = default;

    // This function should be called for each Asset Lock/Unlock tx
    // to change amount of credit pool
    bool processTransaction(const CTransaction& tx, CValidationState& state);

    CAmount getTotalLocked() const;
};

#endif
