// Copyright (c) 2023 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/creditpool.h>

#include <evo/assetlocktx.h>
#include <evo/cbtx.h>

#include <saltedhasher.h>
#include <unordered_lru_cache.h>
#include <chain.h>
#include <logging.h>
#include <util/validation.h>
#include <validation.h>

#include <exception>
#include <memory>

static bool getAmountToUnlock(const CTransaction& tx, CAmount& toUnlock, TxValidationState& state) {
    CAssetUnlockPayload assetUnlockTx;
    if (!GetTxPayload(tx, assetUnlockTx)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "failed-creditpool-unlock-payload");
    }

    toUnlock = assetUnlockTx.getFee();
    for (const CTxOut& txout : tx.vout) {
        if (txout.nValue < 0) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "failed-creditpool-unlock-negative-amount");
        }
        toUnlock += txout.nValue;
    }
    return true;
}

namespace {
CCriticalSection cs_cache;

struct CCreditPool {
    CAmount locked;
    CAmount latelyUnlocked;
};
} // anonymous namespace

static CCreditPool GetCbForBlock(const CBlockIndex* block_index, const Consensus::Params& consensusParams, size_t tailLength) {
    if (block_index == nullptr || tailLength == 0) return {0, 0};

    // recursively collect tail of blocks
    CCreditPool prev = GetCbForBlock(block_index->pprev, consensusParams, tailLength - 1);

    uint256 block_hash = block_index->GetBlockHash();

    constexpr size_t CreditPoolCacheSize = 1000;
    static unordered_lru_cache<uint256, CCreditPool, StaticSaltedHasher> creditPoolCache(CreditPoolCacheSize) GUARDED_BY(cs_cache);

    CCreditPool pool;
    bool cached = false;
    {
        LOCK(cs_cache);
        cached = creditPoolCache.get(block_hash, pool);
    }
    if (!cached) {
        CBlock block;
        if (!ReadBlockFromDisk(block, block_index, consensusParams)) {
            throw std::runtime_error("failed-getcbforblock-read");
        }
        if (block.vtx.size() < 1 || block.vtx[0]->vExtraPayload.empty())  {
            return prev;
        }
        CCbTx cbTx;
        if (!GetTxPayload(block.vtx[0]->vExtraPayload, cbTx)) {
            throw std::runtime_error("failed-getcbforblock-cbtx-payload");
        }

        CAmount blockUnlocked{0};
        for (CTransactionRef tx : block.vtx) {
            if (tx->nVersion != 3 || tx->nType != TRANSACTION_ASSET_UNLOCK) continue;

            CAmount unlocked{0};
            TxValidationState tx_state;
            if (!getAmountToUnlock(*tx, unlocked, tx_state)) {
                throw std::runtime_error(strprintf("%s: GetCbForBlock failed: %s", __func__, FormatStateMessage(tx_state)));
            }
            blockUnlocked += unlocked;
        }

        pool = CCreditPool{cbTx.assetLockedAmount, blockUnlocked};

        LOCK(cs_cache);
        creditPoolCache.insert(block_hash, pool);
    }

    return {pool.locked, pool.latelyUnlocked + prev.latelyUnlocked};
}

CCreditPoolManager::CCreditPoolManager(CBlockIndex* pindexPrev, const Consensus::Params& consensusParams)
: pindexPrev(pindexPrev)
{
    CCreditPool creditPoolCb = GetCbForBlock(pindexPrev, consensusParams, LimitBlocksToTrace);

    this->prevLocked = creditPoolCb.locked;
    this->sessionLimit = this->prevLocked;
    CAmount latelyUnlocked = creditPoolCb.latelyUnlocked;

    // # max(100, min(.10 * assetlockpool, 1000))
    if ((sessionLimit + latelyUnlocked > (prevLocked + latelyUnlocked) / 10) && (sessionLimit + latelyUnlocked > LimitAmountLow)) {
        sessionLimit = std::max<CAmount>(0, (latelyUnlocked + prevLocked) / 10 - latelyUnlocked);
        if (sessionLimit > prevLocked) sessionLimit = prevLocked;
    }
    if (sessionLimit + latelyUnlocked > LimitAmountHigh) {
        sessionLimit = LimitAmountHigh - latelyUnlocked;
    }

    if (prevLocked || latelyUnlocked || sessionLimit) {
        LogPrintf("CreditPoolManager init on height %d: %d.%08d %d.%08d limited by %d.%08d\n", pindexPrev->nHeight, prevLocked / COIN, prevLocked % COIN,
               latelyUnlocked / COIN, latelyUnlocked % COIN,
               sessionLimit / COIN, sessionLimit % COIN);
    }
}

bool CCreditPoolManager::lock(const CTransaction& tx, TxValidationState& state)
{
    CAssetLockPayload assetLockTx;
    if (!GetTxPayload(tx, assetLockTx)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "failed-creditpool-lock-payload");
    }

    for (const CTxOut& txout : tx.vout) {
        const CScript& script = txout.scriptPubKey;
        if (script.empty() || script[0] != OP_RETURN) continue;

        sessionLocked += txout.nValue;
        return true;
    }

    return state.Invalid(TxValidationResult::TX_CONSENSUS, "failed-creditpool-lock-invalid");
}

bool CCreditPoolManager::unlock(const CTransaction& tx, TxValidationState& state)
{
    CAmount toUnlock{0};
    if (!getAmountToUnlock(tx, toUnlock, state)) {
        // state is set up inside getAmountToUnlock
        return false;
    }

    if (sessionUnlocked + toUnlock > sessionLimit ) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "failed-creditpool-unlock-too-much");
    }

    sessionUnlocked += toUnlock;
    return true;
}

bool CCreditPoolManager::processTransaction(const CTransaction& tx, TxValidationState& state) {
    if (tx.nVersion != 3) return true;
    if (tx.nType != TRANSACTION_ASSET_LOCK && tx.nType != TRANSACTION_ASSET_UNLOCK) return true;

    if (!CheckAssetLockUnlockTx(tx, pindexPrev, state)) {
        // pass the state returned by the function above
        return false;
    }

    try {
        switch (tx.nType) {
        case TRANSACTION_ASSET_LOCK:
            return lock(tx, state);
        case TRANSACTION_ASSET_UNLOCK:
            return unlock(tx, state);
        default:
            return true;
        }
    } catch (const std::exception& e) {
        LogPrintf("%s -- failed: %s\n", __func__, e.what());
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "failed-procassetlocksinblock");
    }
}


CAmount CCreditPoolManager::getTotalLocked() const
{
    return prevLocked + sessionLocked - sessionUnlocked;
}
