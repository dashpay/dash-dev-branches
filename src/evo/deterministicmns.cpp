// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "deterministicmns.h"
#include "specialtx.h"

#include "validation.h"
#include "validationinterface.h"
#include "chainparams.h"

static const char DB_MN = 'M';
static const char DB_MANAGER_STATE = 's';
static const char DB_LIST_SNAPSHOT = 'S';
static const char DB_LIST_DIFF = 'D';

CDeterministicMNManager* deterministicMNManager;

bool CDeterministicMNList::IsMNValid(const uint256& proTxHash) const {
    auto it = mnMap->find(proTxHash);
    if (it == mnMap->end()) {
        return false;
    }
    return IsMNValid(it->second);
}

bool CDeterministicMNList::IsMNMature(const uint256& proTxHash) const {
    auto it = mnMap->find(proTxHash);
    if (it == mnMap->end()) {
        return false;
    }
    return IsMNMature(it->second);
}

bool CDeterministicMNList::IsMNPoSeBanned(const uint256& proTxHash) const {
    auto it = mnMap->find(proTxHash);
    if (it == mnMap->end()) {
        return false;
    }
    return IsMNPoSeBanned(it->second);
}

bool CDeterministicMNList::IsMNValid(const CDeterministicMNCPtr& dmn) const {
    return IsMNMature(dmn) && !IsMNPoSeBanned(dmn);
}

bool CDeterministicMNList::IsMNMature(const CDeterministicMNCPtr& dmn) const {
    assert(dmn);
    const CDeterministicMNState& state = *dmn->state;
    return height >= state.maturityHeight;
}

bool CDeterministicMNList::IsMNPoSeBanned(const CDeterministicMNCPtr& dmn) const {
    assert(dmn);
    const CDeterministicMNState& state = *dmn->state;
    return state.PoSeBanHeight != -1;
}

CDeterministicMNCPtr CDeterministicMNList::GetMN(const uint256& proTxHash) const {
    auto it = mnMap->find(proTxHash);
    if (it == mnMap->end()) {
        return nullptr;
    }
    return it->second;
}

CDeterministicMNCPtr CDeterministicMNList::GetValidMN(const uint256& proTxHash) const {
    auto dmn = GetMN(proTxHash);
    if (dmn && !IsMNValid(dmn)) {
        return nullptr;
    }
    return dmn;
}

CDeterministicMNCPtr CDeterministicMNList::GetMNByMasternodeKey(const CKeyID& keyIDMasternode) {
    for (const auto& p : *mnMap) {
        if (p.second->proTx->keyIDMasternode == keyIDMasternode) {
            return p.second;
        }
    }
    return nullptr;
}

static bool CompareByLastPaid(const CDeterministicMN &_a, const CDeterministicMN &_b) {
    const CDeterministicMNState& as = *_a.state;
    const CDeterministicMNState& bs = *_b.state;
    if (as.lastPaidHeight == bs.lastPaidHeight) {
        if (as.registeredHeight == bs.registeredHeight)
            return _a.proTxHash < _b.proTxHash;
        else
            return as.registeredHeight < bs.registeredHeight;
    } else {
        return as.lastPaidHeight < bs.lastPaidHeight;
    }
}
static bool CompareByLastPaid(const CDeterministicMNCPtr &_a, const CDeterministicMNCPtr &_b) {
    return CompareByLastPaid(*_a, *_b);
}

CDeterministicMNCPtr CDeterministicMNList::GetMNPayee() const {
    if (mnMap->empty())
        return nullptr;

    CDeterministicMNCPtr best;
    for (const auto& dmn : valid_range()) {
        if (!best || CompareByLastPaid(dmn, best))
            best = dmn;
    }

    return best;
}

std::vector<CDeterministicMNCPtr> CDeterministicMNList::GetProjectedMNPayees(int count) const {
    std::vector<CDeterministicMNCPtr> result;
    result.reserve(count);

    CDeterministicMNList tmpMNList = Clone();
    for (int h = height; h < height + count; h++) {
        tmpMNList.SetHeight(h);

        CDeterministicMNCPtr payee = tmpMNList.GetMNPayee();
        // push the original MN object instead of the one from the temporary list
        result.push_back(GetMN(payee->proTxHash));

        CDeterministicMNStatePtr newState = std::make_shared<CDeterministicMNState>(*payee->state);
        newState->lastPaidHeight = h;
        tmpMNList.AddOrUpdateMN(payee->proTxHash, newState, nullptr);
    }

    return result;
}

void CDeterministicMNList::BuildDiff(const CDeterministicMNList& to, CDeterministicMNListDiff& diffRet) const {
    diffRet.height = to.height;

    for (const auto& p : *to.mnMap) {
        const auto& fromIt = mnMap->find(p.first);
        if (fromIt == mnMap->end() || *p.second->state != *fromIt->second->state) {
            diffRet.addedOrUpdatedMns.emplace(p.first, p.second->state);
        }
    }
    for (const auto& p : *mnMap) {
        const auto& toIt = to.mnMap->find(p.first);
        if (toIt == to.mnMap->end()) {
            diffRet.removedMns.insert(p.first);
        }
    }
}

CDeterministicMNList CDeterministicMNList::ApplyDiff(const CDeterministicMNListDiff& diff, const std::map<uint256, CProviderTXRegisterMNCPtr>& proTxMap) const {
    assert(diff.height == height + 1);

    CDeterministicMNList result = Clone();
    result.height = diff.height;

    for (const auto& hash : diff.removedMns) {
        result.mnMap->erase(hash);
    }
    for (const auto& p : diff.addedOrUpdatedMns) {
        auto proTxIt = proTxMap.find(p.first);
        assert(proTxIt != proTxMap.end());
        result.AddOrUpdateMN(p.first, p.second, proTxIt->second);
    }

    return result;
}


CDeterministicMNManager::CDeterministicMNManager(size_t nCacheSize, bool fMemory, bool fWipe)
        : db(GetDataDir() / "masternodes", nCacheSize, fMemory, fWipe),
          dbTransaction(db) {
}

void CDeterministicMNManager::Init() {
    LOCK(cs);
    if (!dbTransaction.Read(DB_MANAGER_STATE, state)) {
        state = CDeterministicMNManagerState();
    }

    if (state.firstMNHeight != -1) {
        RebuildLists(state.curHeight - LISTS_CACHE_SIZE, state.curHeight);
    }
}

bool CDeterministicMNManager::ProcessBlock(const CBlock& block, const CBlockIndex* pindex, CValidationState& _state) {
    LOCK(cs);

    int height = pindex->nHeight;

    CDeterministicMNList newList(height);
    CDeterministicMNList oldList;
    if (lists.count(state.curHeight)) {
        oldList = lists[state.curHeight];
        newList = oldList.Clone();
        newList.SetHeight(height);
        assert(oldList.GetHeight() + 1 == height);
    } else {
        assert(state.firstMNHeight == -1 || state.curHeight < state.firstMNHeight);
    }

    auto payee = oldList.GetMNPayee();

    std::set<CService> addrs;
    std::set<CKeyID> pubKeyIDs;
    for (const auto& dmn : newList.all_range()) {
        addrs.emplace(dmn->proTx->addr);
        pubKeyIDs.emplace(dmn->proTx->keyIDMasternode);
    }

    for (int i = 1; i < (int)block.vtx.size(); i++) {
        const CTransaction& tx = *block.vtx[i];

        // check if any existing MN collateral is spent by this transaction
        for (const auto& in : tx.vin) {
            const uint256& proTxHash = in.prevout.hash;
            auto dmn = newList.GetMN(proTxHash);
            if (dmn && dmn->proTx->nCollateralIndex == in.prevout.n) {
                newList.RemoveMN(proTxHash);

                LogPrintf("CDeterministicMNManager::%s -- MN %s removed from list because collateral was spent. height=%d, mapCurMNs.size=%d\n",
                          __func__, proTxHash.ToString(), height, newList.size());
            }
        }

        if (tx.nType == TRANSACTION_PROVIDER_REGISTER) {
            CProviderTXRegisterMN proTx;
            if (!GetTxPayload(tx, proTx)) {
                assert(false); // this should have been handled already
            }

            if (addrs.count(proTx.addr))
                return _state.DoS(100, false, REJECT_CONFLICT, "bad-provider-dup-addr");
            if (pubKeyIDs.count(proTx.keyIDMasternode))
                return _state.DoS(100, false, REJECT_CONFLICT, "bad-provider-dup-key");
            addrs.emplace(proTx.addr);
            pubKeyIDs.emplace(proTx.keyIDMasternode);

            dbTransaction.Write(std::make_pair(DB_MN, tx.GetHash()), proTx);

            CDeterministicMNState dmnState;
            dmnState.registeredHeight = height;
            // MN becomes mature after at least one full payment cycle
            dmnState.maturityHeight = height + Params().GetConsensus().nMasternodeMinimumConfirmations + oldList.valid_count();

            CDeterministicMN dmn;
            dmn.proTxHash = tx.GetHash();
            dmn.state = std::make_shared<CDeterministicMNState>(dmnState);
            // Use the result from GetProTx instead of making a new shared_ptr from proTx so that we actually use the cached version
            dmn.proTx = GetProTx(tx.GetHash());
            newList.AddOrUpdateMN(dmn);

            if (state.firstMNHeight == -1) {
                state.firstMNHeight = height;
            }

            LogPrintf("CDeterministicMNManager::%s -- MN %s added to MN list. height=%d, mapCurMNs.size=%d\n",
                      __func__, tx.GetHash().ToString(), height, newList.size());
        }
    }

    // The payee for the current block was determined by the previous block's list but it might have disappeared in the
    // current block. We still pay that MN one last time however.
    if (payee && newList.HasMN(payee->proTxHash)) {
        auto newState = std::make_shared<CDeterministicMNState>(*newList.GetMN(payee->proTxHash)->state);
        newState->lastPaidHeight = height;
        newList.AddOrUpdateMN(payee->proTxHash, newState, nullptr);
    }

    CDeterministicMNListDiff diff;
    oldList.BuildDiff(newList, diff);

    if (diff.HasChanges()) {
        dbTransaction.Write(std::make_pair(DB_LIST_DIFF, height), diff);
    }
    if ((height % SNAPSHOT_LIST_PERIOD) == 0) {
        dbTransaction.Write(std::make_pair(DB_LIST_SNAPSHOT, height), newList);
        LogPrintf("CDeterministicMNManager::%s -- Wrote snapshot. height=%d, mapCurMNs.size=%d\n",
                  __func__, pindex->nHeight, newList.size());
    }

    if (!diff.HasChanges()) {
        // nothing has changed, so lets instead point to the previous one
        std::swap(newList, oldList);
        newList.SetHeight(height);
    }
    lists[height] = newList;

    if (lists.size() > LISTS_CACHE_SIZE) {
        lists.erase(height - LISTS_CACHE_SIZE);
    }

    state.curHeight = height;
    state.curBlockHash = block.GetHash();

    UpdateSpork15Value();
    if (height == state.spork15Value) {
        LogPrintf("CDeterministicMNManager::%s -- spork15 is active now. height=%d\n", __func__, height);
    }

    dbTransaction.Write(DB_MANAGER_STATE, state);

    return true;
}

bool CDeterministicMNManager::UndoBlock(const CBlock& block, const CBlockIndex* pindex) {
    LOCK(cs);

    int height = pindex->nHeight;

    assert(state.curHeight == -1 || (state.curHeight == height && state.curBlockHash == block.GetHash()));

    dbTransaction.Erase(std::make_pair(DB_LIST_DIFF, height));
    dbTransaction.Erase(std::make_pair(DB_LIST_SNAPSHOT, height));

    lists.erase(height);

    if (height == state.firstMNHeight) {
        state.firstMNHeight = -1;
    }
    if (height == state.spork15Value) {
        LogPrintf("CDeterministicMNManager::%s -- spork15 is not active anymore. height=%d\n", __func__, height);
    }

    state.curHeight = height - 1;
    state.curBlockHash = pindex->pprev->GetBlockHash();
    dbTransaction.Write(DB_MANAGER_STATE, state);

    return true;
}

void CDeterministicMNManager::RebuildLists(int startHeight, int endHeight) {
    AssertLockHeld(cs);

    CDeterministicMNList snapshot;

    int snapshotHeight = -1;
    for (int h = startHeight; h >= state.firstMNHeight && h < endHeight; --h) {
        if (dbTransaction.Read(std::make_pair(DB_LIST_SNAPSHOT, h), snapshot)) {
            for (const auto& p : snapshot.all_range()) {
                snapshot.AddOrUpdateMN(p->proTxHash, nullptr, GetProTx(p->proTxHash));
            }
            snapshotHeight = h;
            break;
        }
    }
    if (snapshotHeight == -1) {
        snapshotHeight = state.firstMNHeight - 1;
        snapshot = CDeterministicMNList(snapshotHeight);
    }

    for (int h = snapshotHeight; h <= endHeight; h++) {
        if (h >= startHeight) {
            lists[h] = CDeterministicMNList(h, snapshot.GetMap());;
        }

        if (h < endHeight) {
            CDeterministicMNListDiff diff;
            if (!dbTransaction.Read(std::make_pair(DB_LIST_DIFF, h + 1), diff))
                continue;
            std::map<uint256, CProviderTXRegisterMNCPtr> proTxMap;
            for (const auto& p : diff.addedOrUpdatedMns) {
                proTxMap[p.first] = GetProTx(p.first);
            }
            snapshot = snapshot.ApplyDiff(diff, proTxMap);
        }
    }
}

void CDeterministicMNManager::UpdateSpork15Value() {
    // only update cached spork15 value when it was not set before. This is needed because spork values are very unreliable when starting the node
    int64_t newSpork15Value = sporkManager.GetSporkValue(SPORK_15_DETERMINISTIC_MNS_ENABLED);
    if (newSpork15Value != state.spork15Value && newSpork15Value != SPORK_15_DETERMINISTIC_MNS_DEFAULT) {
        state.spork15Value = newSpork15Value;
        LogPrintf("CDeterministicMNManager::%s -- Updated spork15 value to %d\n", __func__, state.spork15Value);
    }
}

CProviderTXRegisterMNCPtr CDeterministicMNManager::GetProTx(const uint256& proTxHash) {
    LOCK(cs);

    CProviderTXRegisterMNCPtr proTx;

    auto it = proTxCache.find(proTxHash);
    if (it != proTxCache.end()) {
        proTx = it->second.lock();
        if (!proTx) {
            proTxCache.erase(it);
        }
    }
    if (!proTx) {
        CProviderTXRegisterMN tmpProTx;
        if (dbTransaction.Read(std::make_pair(DB_MN, proTxHash), tmpProTx)) {
            proTx = std::make_shared<CProviderTXRegisterMN>(tmpProTx);
            proTxCache.emplace(proTxHash, proTx);
        }
    }

    return proTx;
}

CDeterministicMNList CDeterministicMNManager::GetListAtHeight(int height) {
    LOCK(cs);

    if (height < state.firstMNHeight || state.firstMNHeight < 0 || height > state.curHeight) {
        return CDeterministicMNList(height);
    }

    auto it = lists.find(height);
    if (it == lists.end()) {
        // this must be a very old entry, rebuild the list for it
        RebuildLists(height, height);
        it = lists.find(height);
    }
    if (it == lists.end()) {
        return CDeterministicMNList(height);
    }
    return it->second;
}

CDeterministicMNList CDeterministicMNManager::GetListAtChainTip() {
    LOCK(cs);
    return GetListAtHeight(state.curHeight);
}

CDeterministicMNCPtr CDeterministicMNManager::GetMN(int height, const uint256& proTxHash) {
    LOCK(cs);
    auto mnList = GetListAtHeight(height);
    return mnList.GetMN(proTxHash);
}

bool CDeterministicMNManager::HasValidMNAtHeight(int height, const uint256& proTxHash) {
    LOCK(cs);
    auto mnList = GetListAtHeight(height);
    return mnList.IsMNValid(proTxHash);
}

bool CDeterministicMNManager::HasValidMNAtChainTip(const uint256& proTxHash) {
    LOCK(cs);
    return HasValidMNAtHeight(state.curHeight, proTxHash);
}

bool CDeterministicMNManager::IsDeterministicMNsSporkActive(int height) {
    LOCK(cs);

    int64_t spork15Value = sporkManager.GetSporkValue(SPORK_15_DETERMINISTIC_MNS_ENABLED);
    if (spork15Value == SPORK_15_DETERMINISTIC_MNS_DEFAULT)
        spork15Value = state.spork15Value;
    if (spork15Value < 0)
        return false;
    if (height == -1)
        height = state.curHeight;
    return height >= spork15Value;
}
