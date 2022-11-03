// Copyright (c) 2023 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/creditpool.h>

#include <evo/assetlocktx.h>
#include <evo/cbtx.h>

#include <llmq/utils.h>

#include <chain.h>
#include <logging.h>
#include <util/validation.h>
#include <validation.h>

#include <algorithm>
#include <exception>
#include <memory>
#include <stack>

static const std::string DB_CREDITPOOL_SNAPSHOT = "cpm_S";

std::unique_ptr<CCreditPoolManager> creditPoolManager;

static bool getDataFromUnlockTx(const CTransaction& tx, CAmount& toUnlock, uint64_t& index, TxValidationState& state) {
    CAssetUnlockPayload assetUnlockTx;
    if (!GetTxPayload(tx, assetUnlockTx)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "failed-creditpool-unlock-payload");
    }

    index = assetUnlockTx.getIndex();
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
    struct UnlockDataPerBlock  {
        CAmount unlocked{0};
        std::unordered_set<uint64_t> indexes;
    };
} // anonymous namespace

// it throws exception if anything went wrong
static UnlockDataPerBlock getDataFromUnlockTxes(const std::vector<CTransactionRef>& vtx) {
    UnlockDataPerBlock blockData;

    for (CTransactionRef tx : vtx) {
        if (tx->nVersion != 3 || tx->nType != TRANSACTION_ASSET_UNLOCK) continue;

        CAmount unlocked{0};
        TxValidationState tx_state;
        uint64_t index{0};
        if (!getDataFromUnlockTx(*tx, unlocked, index, tx_state)) {
            throw std::runtime_error(strprintf("%s: CCreditPoolManager::getCreditPool failed: %s", __func__, FormatStateMessage(tx_state)));
        }
        blockData.unlocked += unlocked;
        blockData.indexes.insert(index);
    }
    return blockData;
}

bool CSkipSet::add(uint64_t value) {
    assert(!contains(value));

    if (auto it = skipped.find(value); it != skipped.end()) {
        skipped.erase(it);
        return true;
    }

    assert(current_max <= value);
    if (capacity() + value - current_max > capacity_limit) {
        LogPrintf("CSkipSet::add failed due to capacity exceeded: requested %lld to %lld while limit is %lld\n",
                value - current_max, capacity(), capacity_limit);
        return false;
    }
    for (uint64_t index = current_max; index < value; ++index) {
        bool insert_ret = skipped.insert(index).second;
        assert(insert_ret);
    }
    current_max = value + 1;
    return true;
}

bool CSkipSet::canBeAdded(uint64_t value) const {
    if (contains(value)) return false;

    if (skipped.find(value) != skipped.end()) return true;

    if (capacity() + value - current_max > capacity_limit) {
        return false;
    }

    return true;
}

bool CSkipSet::contains(uint64_t value) const {
    if (current_max <= value) return false;
    return skipped.find(value) == skipped.end();
}

std::string CCreditPool::ToString() const {
    return strprintf("CCreditPool(locked=%lld,currentLimit=%lld,nIndexes=%lld)",
            locked, currentLimit, indexes.size());
}

std::optional<CCreditPool> CCreditPoolManager::getFromCache(const CBlockIndex* const block_index) {
    if (!llmq::utils::IsV20Active(block_index)) return CCreditPool{};

    uint256 block_hash = block_index->GetBlockHash();
    CCreditPool pool;
    {
        LOCK(cs_cache);
        if (creditPoolCache.get(block_hash, pool)) {
            return pool;
        }
    }
    if (block_index->nHeight % DISK_SNAPSHOT_PERIOD == 0) {
        if (evoDb.Read(std::make_pair(DB_CREDITPOOL_SNAPSHOT, block_hash), pool)) {
            LOCK(cs_cache);
            creditPoolCache.insert(block_hash, pool);
            return pool;
        }
    }
    return std::nullopt;
}

void CCreditPoolManager::addToCache(const uint256& block_hash, int height, const CCreditPool &pool) {
    {
        LOCK(cs_cache);
        creditPoolCache.insert(block_hash, pool);
    }
    if (height % DISK_SNAPSHOT_PERIOD == 0) {
        evoDb.Write(std::make_pair(DB_CREDITPOOL_SNAPSHOT, block_hash), pool);
    }
}

static std::optional<CBlock> getBlockForCreditPool(const CBlockIndex *block_index, const Consensus::Params& consensusParams) {
    CBlock block;
    if (!ReadBlockFromDisk(block, block_index, consensusParams)) {
        throw std::runtime_error("failed-getcbforblock-read");
    }
    // Should not fail if V20 (DIP0027) are active but it happens for Unit Tests
    if (block.vtx[0]->nVersion != 3) return std::nullopt;

    assert(!block.vtx.empty());
    assert(block.vtx[0]->nVersion == 3);
    assert(!block.vtx[0]->vExtraPayload.empty());

    return block;
}

CCreditPool CCreditPoolManager::constructCreditPool(const CBlockIndex* block_index, CCreditPool prev, const Consensus::Params& consensusParams)
{
    std::optional<CBlock> block = getBlockForCreditPool(block_index, consensusParams);
    if (!block) {
        // If reading of previous block is not read successfully, but
        // prev contains credit pool related data, something strange happened
        assert(prev.locked == 0);
        assert(prev.indexes.size() == 0);

        CCreditPool emptyPool;
        addToCache(block_index->GetBlockHash(), block_index->nHeight, emptyPool);
        return emptyPool;
    }
    CAmount locked{0};
    {
        CCbTx cbTx;
        if (!GetTxPayload(block->vtx[0]->vExtraPayload, cbTx)) {
            throw std::runtime_error(strprintf("%s: failed-getcreditpool-cbtx-payload", __func__));
        }
        locked = cbTx.assetLockedAmount;
    }

    // We use here sliding window with LimitBlocksToTrace to determine
    // current limits for asset unlock transactions.
    // Indexes should not be duplicated since genesis block, but the Unlock Amount
    // of withdrawal transaction is limited only by this window
    UnlockDataPerBlock blockData = getDataFromUnlockTxes(block->vtx);
    CSkipSet indexes{std::move(prev.indexes)};
    if (std::any_of(blockData.indexes.begin(), blockData.indexes.end(), [&](const uint64_t index) { return !indexes.add(index); })) {
        throw std::runtime_error(strprintf("%s: failed-getcreditpool-index-exceed", __func__));
    }

    const CBlockIndex* distant_block_index = block_index;
    for (size_t i = 0; i < CCreditPoolManager::LimitBlocksToTrace; ++i) {
        distant_block_index = distant_block_index->pprev;
        if (distant_block_index == nullptr) break;
    }
    CAmount distantUnlocked{0};
    if (distant_block_index) {
        if (std::optional<CBlock> distant_block = getBlockForCreditPool(distant_block_index, consensusParams); distant_block) {
            distantUnlocked = getDataFromUnlockTxes(distant_block->vtx).unlocked;
        }
    }

    // Unlock limits are # max(100, min(.10 * assetlockpool, 1000)) inside window
    CAmount currentLimit = locked;
    CAmount latelyUnlocked = prev.latelyUnlocked + blockData.unlocked - distantUnlocked;
    if (currentLimit + latelyUnlocked > LimitAmountLow) {
        currentLimit = std::max(LimitAmountLow, locked / 10) - latelyUnlocked;
        if (currentLimit < 0) currentLimit = 0;
    }
    currentLimit = std::min(currentLimit, LimitAmountHigh - latelyUnlocked);

    assert(currentLimit >= 0);

    if (currentLimit || latelyUnlocked || locked) {
        LogPrintf("CCreditPoolManager: asset unlock limits on height: %d locked: %d.%08d limit: %d.%08d previous: %d.%08d\n", block_index->nHeight, locked / COIN, locked % COIN,
               currentLimit / COIN, currentLimit % COIN,
               latelyUnlocked / COIN, latelyUnlocked % COIN);
    }

    CCreditPool pool{locked, currentLimit, latelyUnlocked, indexes};
    addToCache(block_index->GetBlockHash(), block_index->nHeight, pool);
    return pool;

}

CCreditPool CCreditPoolManager::getCreditPool(const CBlockIndex* block_index, const Consensus::Params& consensusParams)
{
    std::stack<const CBlockIndex *> to_calculate;

    std::optional<CCreditPool> poolTmp;
    while (!(poolTmp = getFromCache(block_index)).has_value()) {
        to_calculate.push(block_index);
        block_index = block_index->pprev;
    }
    while (!to_calculate.empty()) {
        poolTmp = constructCreditPool(to_calculate.top(), *poolTmp, consensusParams);
        to_calculate.pop();
    }
    return *poolTmp;
}

CCreditPoolManager::CCreditPoolManager(CEvoDB& _evoDb)
: evoDb(_evoDb)
{
}

CCreditPoolDiff::CCreditPoolDiff(CCreditPool starter, const CBlockIndex *pindex, const Consensus::Params& consensusParams) :
    pool(std::move(starter)),
    pindex(pindex)
{
    assert(pindex);
}


bool CCreditPoolDiff::lock(const CTransaction& tx, TxValidationState& state)
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

bool CCreditPoolDiff::unlock(const CTransaction& tx, TxValidationState& state)
{
    uint64_t index{0};
    CAmount toUnlock{0};
    if (!getDataFromUnlockTx(tx, toUnlock, index, state)) {
        // state is set up inside getDataFromUnlockTx
        return false;
    }

    if (sessionUnlocked + toUnlock > pool.currentLimit) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "failed-creditpool-unlock-too-much");
    }

    if (pool.indexes.contains(index) || newIndexes.count(index)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "failed-creditpool-duplicated-index");
    }

    if (!pool.indexes.canBeAdded(index)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "failed-getcbforblock-index-exceed");
    }

    newIndexes.insert(index);
    sessionUnlocked += toUnlock;
    return true;
}

bool CCreditPoolDiff::processTransaction(const CTransaction& tx, TxValidationState& state) {
    if (tx.nVersion != 3) return true;
    if (tx.nType != TRANSACTION_ASSET_LOCK && tx.nType != TRANSACTION_ASSET_UNLOCK) return true;

    if (!CheckAssetLockUnlockTx(tx, pindex, this->pool, state)) {
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
