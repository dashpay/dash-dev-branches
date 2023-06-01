// Copyright (c) 2023 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_EVO_CREDITPOOL_H
#define BITCOIN_EVO_CREDITPOOL_H

#include <coins.h>

#include <evo/assetlocktx.h>
#include <evo/evodb.h>

#include <sync.h>
#include <threadsafety.h>

#include <optional>
#include <unordered_set>

#include <saltedhasher.h>
#include <unordered_lru_cache.h>

class CBlockIndex;
class TxValidationState;

namespace Consensus
{
    struct Params;
}

// This datastructure keeps efficiently all indexes and have a strict limit for used memory
// So far as CCreditPool is built only in direction from parent block to child
// there's no need to remove elements from CSkipSet ever, only add them
class CSkipSet {
private:
    std::unordered_set<uint64_t> skipped;
    uint64_t current_max{0};
    size_t capacity_limit;
public:
    explicit CSkipSet(size_t capacity_limit = 10'000) :
        capacity_limit(capacity_limit)
    {}

    /**
     * adding value that already exist in CKipSet will cause `assert`.
     *
     */
    [[nodiscard]] bool add(uint64_t value);

    bool canBeAdded(uint64_t value) const;

    bool contains(uint64_t value) const;

    size_t size() const {
        return current_max - skipped.size();
    }
    size_t capacity() const {
        return skipped.size();
    }

    SERIALIZE_METHODS(CSkipSet, obj)
    {
        READWRITE(obj.current_max);
        READWRITE(obj.skipped);
    }
};

struct CCreditPool {
    CAmount locked{0};

    // needs for logic of limits of unlocks
    CAmount currentLimit{0};
    CAmount latelyUnlocked{0};
    CSkipSet indexes{};

    std::string ToString() const;

    SERIALIZE_METHODS(CCreditPool, obj)
    {
        READWRITE(
            obj.locked,
            obj.currentLimit,
            obj.latelyUnlocked,
            obj.indexes
        );
    }
};

/**
 * The class CCreditPoolDiff has 2 purposes:
 *  - it helps to determine which transaction can be included in new mined block
 *  within current limits for Asset Unlock transactions and filter duplicated indexes
 *  - to validate Asset Unlock transaction in mined block. The standalone checks of tx
 *  such as CheckSpecialTx is not able to do so because at that moment there is no full
 *  information about Credit Pool limits.
 *
 * CCreditPoolDiff temporary stores new values `lockedAmount` and `indexes` while
 * limits should stay same and depends only on the previous block.
 */
class CCreditPoolDiff {
private:
    const CCreditPool pool;
    std::unordered_set<uint64_t> newIndexes;

    CAmount sessionLocked{0};
    CAmount sessionUnlocked{0};

    // target value is used to validate CbTx. If values mismatched, block is invalid
    std::optional<CAmount> targetLocked;

    const CBlockIndex *pindex{nullptr};
public:
    explicit CCreditPoolDiff(CCreditPool starter, const CBlockIndex *pindex, const Consensus::Params& consensusParams);

    /**
     * This function should be called for each Asset Lock/Unlock tx
     * to change amount of credit pool
     * @return true if transaction can be included in this block
     */
    bool processTransaction(const CTransaction& tx, TxValidationState& state);

    CAmount getTotalLocked() const {
        return pool.locked + sessionLocked - sessionUnlocked;
    }

    const std::optional<CAmount>& getTargetLocked() const {
        return targetLocked;
    }

    std::string ToString() const {
        return strprintf("CCreditPoolDiff(target=%lld,sessionLocked=%lld,sessionUnlocked=%lld,newIndexes=%lld,pool=%s", getTargetLocked() ? *getTargetLocked() : -1, sessionLocked, sessionUnlocked, newIndexes.size(), pool.ToString());
    }

private:
    bool setTarget(const CTransaction& tx, TxValidationState& state);
    bool lock(const CTransaction& tx, TxValidationState& state);
    bool unlock(const CTransaction& tx, TxValidationState& state);
};

class CCreditPoolManager
{
private:
    static constexpr size_t CreditPoolCacheSize = 1000;
    RecursiveMutex cache_mutex;
    unordered_lru_cache<uint256, CCreditPool, StaticSaltedHasher> creditPoolCache GUARDED_BY(cache_mutex) {CreditPoolCacheSize};

    CEvoDB& evoDb;

    static constexpr int DISK_SNAPSHOT_PERIOD = 576; // once per day

public:
    static constexpr int LimitBlocksToTrace = 576;
    static constexpr CAmount LimitAmountLow = 100 * COIN;
    static constexpr CAmount LimitAmountHigh = 1000 * COIN;

    explicit CCreditPoolManager(CEvoDB& _evoDb);

    ~CCreditPoolManager() = default;

    /**
      * @return CCreditPool with data or with empty depends on activation V19 at that block
      * In case if block is invalid the function getCreditPool throws an exception
      * it can happen if there limits of withdrawal (unlock) exceed
      */
    CCreditPool getCreditPool(const CBlockIndex* block, const Consensus::Params& consensusParams);

private:
    std::optional<CCreditPool> getFromCache(const CBlockIndex* const block_index);
    void addToCache(const uint256& block_hash, int height, const CCreditPool& pool);

    CCreditPool constructCreditPool(const CBlockIndex* block_index, CCreditPool prev, const Consensus::Params& consensusParams);
};

extern std::unique_ptr<CCreditPoolManager> creditPoolManager;

#endif
