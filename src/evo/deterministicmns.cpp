// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "deterministicmns.h"
#include "specialtx.h"

#include "validation.h"
#include "validationinterface.h"

static const char DB_MN = 'M';
static const char DB_LIST_SNAPSHOT = 'S';
static const char DB_LIST_STATE = 's';
static const char DB_BLOCK_INFO = 'B';

CDeterministicMNManager *deterministicMNManager;

CDeterministicMNManager::CDeterministicMNManager(size_t nCacheSize, bool fMemory, bool fWipe)
        : db(GetDataDir() / "masternodes", nCacheSize, fMemory, fWipe),
          dbTransaction(db) {
}

void CDeterministicMNManager::Init() {
    LOCK(cs);
    if (!dbTransaction.Read(DB_LIST_STATE, state)) {
        state = CDeterministicMNManagerState();
    }
    RecreateListFromSnapshot(state.curHeight, mapCurMNs);
}

bool CDeterministicMNManager::ProcessBlock(const CBlock &block, const CBlockIndex *pindex, CValidationState &state) {
    CDeterministicMNBlockInfo blockInfo;
    if (!ProcessBlockLocked(block, pindex, state, blockInfo))
        return false;

    // These must be called without the cs lock held
    for (const auto &proTxHash : blockInfo.mnsInBlock) {
        GetMainSignals().MasternodeAdded(proTxHash);
    }
    for (const auto &p : blockInfo.mnsRemovedInBlock) {
        GetMainSignals().MasternodeRemoved(p.first);
    }

    return true;
}

bool CDeterministicMNManager::ProcessBlockLocked(const CBlock &block, const CBlockIndex *pindex, CValidationState &_state, CDeterministicMNBlockInfo &blockInfo) {
    LOCK(cs);

    auto prevMNList = GetListAtHeight(pindex->nHeight - 1, true);
    std::set<CService> prevMNAddrs;
    for (const auto &p : prevMNList)
        prevMNAddrs.emplace(p.proTx.addr);

    for (int i = 1; i < (int)block.vtx.size(); i++) {
        const CTransaction &tx = *block.vtx[i];

        // check if any existing MN collateral is spent by this transaction
        for (const auto &in : tx.vin) {
            const uint256 &proTxHash = in.prevout.hash;
            if (mapCurMNs.count(proTxHash)) {
                CProviderTXRegisterMN proTx;
                if (dbTransaction.Read(std::make_pair(DB_MN, proTxHash), proTx) && proTx.nCollateralIndex == in.prevout.n) {
                    const CDeterministicMNState &dmnState = mapCurMNs[proTxHash];
                    blockInfo.mnsRemovedInBlock.emplace(proTxHash, dmnState);
                    mapCurMNs.erase(proTxHash);

                    LogPrintf("CDeterministicMNManager::%s -- MN %s removed from list because collateral was spent. height=%d, mapCurMNs.size=%d\n",
                              __func__, proTxHash.ToString(), pindex->nHeight, mapCurMNs.size());
                }
            }
        }

        if (tx.nType == TRANSACTION_PROVIDER_REGISTER) {
            CProviderTXRegisterMN proTx;
            if (!GetTxPayload(tx, proTx)) {
                assert(false); // this should have been handled already
            }


            if (blockInfo.mnsInBlock.count(tx.GetHash()) || prevMNAddrs.count(proTx.addr))
                return _state.DoS(100, false, REJECT_CONFLICT, "bad-provider-dup-addr");

            blockInfo.mnsInBlock.emplace(tx.GetHash());
            dbTransaction.Write(std::make_pair(DB_MN, tx.GetHash()), proTx);

            CDeterministicMNState dmnState;
            dmnState.registeredHeight = pindex->nHeight;
            mapCurMNs.emplace(tx.GetHash(), dmnState);

            if (state.firstMNHeight == -1) {
                state.firstMNHeight = pindex->nHeight;
            }

            LogPrintf("CDeterministicMNManager::%s -- MN %s added to MN list. height=%d, mapCurMNs.size=%d\n",
                      __func__, tx.GetHash().ToString(), pindex->nHeight, mapCurMNs.size());
        }
    }

    uint256 payeeProTxHash;
    CScript payeeScript;
    if (GetMNPayee(pindex->nHeight, payeeProTxHash, payeeScript)) {
        assert(mapCurMNs.count(payeeProTxHash));
        auto &dmnState = mapCurMNs[payeeProTxHash];
        // we store the payee + previous lastPaidHeight so that we can restore the value in UndoBlock
        blockInfo.payeeProTxHash = payeeProTxHash;
        blockInfo.prevPayeeHeight = dmnState.lastPaidHeight;
        dmnState.lastPaidHeight = pindex->nHeight;
    }

    if (!blockInfo.IsNull()) {
        dbTransaction.Write(std::make_pair(DB_BLOCK_INFO, (int64_t) pindex->nHeight), blockInfo);

        if (!blockInfo.mnsInBlock.empty() || !blockInfo.mnsRemovedInBlock.empty()) {
            state.blocksWithMNsCount++;
            if ((state.blocksWithMNsCount % SNAPSHOT_LIST_PERIOD) == 0) {
                dbTransaction.Write(std::make_pair(DB_LIST_SNAPSHOT, (int64_t) pindex->nHeight), mapCurMNs);
                LogPrintf("CDeterministicMNManager::%s -- Wrote snapshot. height=%d, mapCurMNs.size=%d\n",
                          __func__, pindex->nHeight, mapCurMNs.size());
            }
        }
    }

    state.curHeight = pindex->nHeight;
    state.curBlockHash = block.GetHash();

    UpdateSpork15Value();
    if (pindex->nHeight == state.spork15Value) {
        LogPrintf("CDeterministicMNManager::%s -- spork15 is active now. height=%d\n", __func__, pindex->nHeight);
    }

    dbTransaction.Write(DB_LIST_STATE, state);

    return true;
}

bool CDeterministicMNManager::UndoBlock(const CBlock &block, const CBlockIndex *pindex) {
    CDeterministicMNBlockInfo blockInfo;
    if (!UndoBlockLocked(block, pindex, blockInfo))
        return false;

    // These must be called without the cs lock held
    for (const auto &proTxHash : blockInfo.mnsInBlock) {
        GetMainSignals().MasternodeRemoved(proTxHash);
    }
    for (const auto &p : blockInfo.mnsRemovedInBlock) {
        GetMainSignals().MasternodeAdded(p.first);
    }

    return true;
}

bool CDeterministicMNManager::UndoBlockLocked(const CBlock &block, const CBlockIndex *pindex, CDeterministicMNBlockInfo &blockInfo) {
    LOCK(cs);

    assert(state.curHeight == pindex->nHeight && state.curBlockHash == block.GetHash());

    if (dbTransaction.Read(std::make_pair(DB_BLOCK_INFO, (int64_t) pindex->nHeight), blockInfo)) {
        if (!blockInfo.payeeProTxHash.IsNull()) {
            assert(mapCurMNs.count(blockInfo.payeeProTxHash));
            auto &dmnState = mapCurMNs[blockInfo.payeeProTxHash];
            dmnState.lastPaidHeight = blockInfo.prevPayeeHeight;
        }

        for (const auto &p : blockInfo.mnsRemovedInBlock) {
            const uint256 &proTxHash = p.first;

            CProviderTXRegisterMN proTx;
            if (!dbTransaction.Read(std::make_pair(DB_MN, proTxHash), proTx))
                assert(false);

            assert(!mapCurMNs.count(proTxHash));
            mapCurMNs.emplace(proTxHash, p.second); // restore old state

            LogPrintf("CDeterministicMNManager::%s -- MN %s restored and re-added to MN list. height=%d, mapCurMNs.size=%d\n",
                      __func__, proTxHash.ToString(), pindex->nHeight, mapCurMNs.size());
        }

        int foundCount = 0;
        for (int i = (int) block.vtx.size() - 1; i >= 1; --i) {
            const CTransaction &tx = *block.vtx[i];
            if (tx.nType == TRANSACTION_PROVIDER_REGISTER) {
                assert(blockInfo.mnsInBlock.count(tx.GetHash()));
                assert(dbTransaction.Exists(std::make_pair(DB_MN, tx.GetHash())));
                dbTransaction.Erase(std::make_pair(DB_MN, tx.GetHash()));
                mapCurMNs.erase(tx.GetHash());
                foundCount++;

                LogPrintf("CDeterministicMNManager::%s -- MN %s removed from MN list due to undo. height=%d, mapCurMNs.size=%d\n",
                          __func__, tx.GetHash().ToString(), pindex->nHeight, mapCurMNs.size());
            }
        }

        assert(foundCount == blockInfo.mnsInBlock.size());

        dbTransaction.Erase(std::make_pair(DB_BLOCK_INFO, (int64_t) pindex->nHeight));

        if (!blockInfo.mnsInBlock.empty() || !blockInfo.mnsRemovedInBlock.empty()) {
            if ((state.blocksWithMNsCount % SNAPSHOT_LIST_PERIOD) == 0) {
                dbTransaction.Erase(std::make_pair(DB_LIST_SNAPSHOT, (int64_t) pindex->nHeight));
                LogPrintf("CDeterministicMNManager::%s -- Erased snapshot. height=%d, mapCurMNs.size=%d\n",
                          __func__, pindex->nHeight, mapCurMNs.size());
            }
            state.blocksWithMNsCount--;
        }
    }

    if (pindex->nHeight == state.spork15Value) {
        LogPrintf("CDeterministicMNManager::%s -- spork15 is not active anymore. height=%d\n", __func__, pindex->nHeight);
    }

    state.curHeight = pindex->nHeight - 1;
    state.curBlockHash = pindex->pprev->GetBlockHash();
    dbTransaction.Write(DB_LIST_STATE, state);

    return true;
}

void CDeterministicMNManager::UpdateSpork15Value() {
    // only update cached spork15 value when it was not set before. This is needed because spork values are very unreliable when starting the node
    int64_t newSpork15Value = sporkManager.GetSporkValue(SPORK_15_DETERMINISTIC_MNS_ENABLED);
    if (newSpork15Value != state.spork15Value && newSpork15Value != SPORK_15_DETERMINISTIC_MNS_DEFAULT) {
        state.spork15Value = newSpork15Value;
        LogPrintf("CDeterministicMNManager::%s -- Updated spork15 value to %d\n", __func__, state.spork15Value);
    }
}

struct CompareByLastPaid {
    bool operator()(const CDeterministicMN &a, const CDeterministicMN &b) const {
        if (a.state.lastPaidHeight == b.state.lastPaidHeight) {
            if (a.state.registeredHeight == b.state.registeredHeight)
                return a.proTxHash < b.proTxHash;
            else
                return a.state.registeredHeight < b.state.registeredHeight;
        } else {
            return a.state.lastPaidHeight < b.state.lastPaidHeight;
        }
    }
};

bool CDeterministicMNManager::GetMNPayee(int64_t height, uint256 &proTxHashRet, CScript &payeeScriptRet) {
    LOCK(cs);
    auto mnList = GetListAtHeight(height - 1, false);
    if (mnList.empty())
        return false;
    const auto &it = std::min_element(mnList.begin(), mnList.end(), CompareByLastPaid());
    CProviderTXRegisterMN proTx;
    if (!GetRegisterMN(it->proTxHash, proTx))
        assert(false);
    proTxHashRet = it->proTxHash;
    payeeScriptRet = proTx.scriptPayout;
    return true;
}

bool CDeterministicMNManager::GetMNLastPaidHeight(const uint256 &proTxHash, int64_t height, int64_t &lastPaidHeightRet) {
    auto mnList = GetListAtHeight(height, false);
    for (const auto &dmn : mnList) {
        if (dmn.proTxHash == proTxHash) {
            lastPaidHeightRet = dmn.state.lastPaidHeight;
            return true;
        }
    }
    return false;
}

bool CDeterministicMNManager::GetRegisterMN(const uint256 &proTxHash, CProviderTXRegisterMN &proTx) {
    LOCK(cs);
    return dbTransaction.Read(std::make_pair(DB_MN, proTxHash), proTx);
}

bool CDeterministicMNManager::RecreateListFromSnapshot(int64_t height, std::map<uint256, CDeterministicMNState> &snapshot) {
    AssertLockHeld(cs);

    snapshot.clear();

    if (state.firstMNHeight < 0)
        return false;

    int64_t snapshotHeight = -1;
    for (int64_t h = height; h >= state.firstMNHeight; --h) {
        if (dbTransaction.Read(std::make_pair(DB_LIST_SNAPSHOT, (int64_t)h), snapshot)) {
            snapshotHeight = h;
            break;
        }
    }
    if (snapshotHeight == -1)
        snapshotHeight = state.firstMNHeight - 1;

    for (int64_t h = snapshotHeight + 1; h <= height; h++) {
        CDeterministicMNBlockInfo blockInfo;
        if (!dbTransaction.Read(std::make_pair(DB_BLOCK_INFO, (int64_t) h), blockInfo))
            continue;
        for (const auto &p : blockInfo.mnsRemovedInBlock) {
            snapshot.erase(p.first);
        }
        for (const auto &proTxHash : blockInfo.mnsInBlock) {
            CDeterministicMNState dmnState;
            dmnState.registeredHeight = h;
            snapshot.emplace(proTxHash, dmnState);
        }
        if (!blockInfo.payeeProTxHash.IsNull()) {
            assert(snapshot.count(blockInfo.payeeProTxHash));
            snapshot[blockInfo.payeeProTxHash].lastPaidHeight = h;
        }
    }
    return true;
}

std::vector<CDeterministicMN> CDeterministicMNManager::GetListAtHeight(int64_t height, bool detailed) {
    LOCK(cs);

    if (height < state.firstMNHeight || state.firstMNHeight < 0 || height > state.curHeight) {
        return std::vector<CDeterministicMN>();
    }

    std::map<uint256, CDeterministicMNState> *snapshot = NULL, localSnapshot;
    if (height == state.curHeight) {
        snapshot = &mapCurMNs;
    } else {
        RecreateListFromSnapshot(height, localSnapshot);
        snapshot = &localSnapshot;
    }
    std::vector<CDeterministicMN> mnList;
    for (const auto &p : *snapshot) {
        CDeterministicMN dmn;
        dmn.proTxHash = p.first;
        dmn.state = p.second;
        if (detailed && !dbTransaction.Read(std::make_pair(DB_MN, dmn.proTxHash), dmn.proTx))
            assert(false);
        mnList.emplace_back(dmn);
    }

    return mnList;
}

std::vector<CDeterministicMN> CDeterministicMNManager::GetListAtChainTip(bool detailed) {
    LOCK(cs);
    return GetListAtHeight(state.curHeight, detailed);
}

bool CDeterministicMNManager::HasMNAtHeight(int height, const uint256 &proTxHash) {
    LOCK(cs);
    if (height == state.curHeight)
        return HasMNAtChainTip(proTxHash);

    auto mnList = GetListAtHeight(height, false);
    for (const auto &dmn : mnList) {
        if (dmn.proTxHash == proTxHash)
            return true;
    }
    return false;
}

bool CDeterministicMNManager::HasMNAtChainTip(const uint256 &proTxHash) {
    LOCK(cs);
    return mapCurMNs.count(proTxHash) != 0;
}

bool CDeterministicMNManager::GetMNByMasternodeKey(int64_t height, const CKeyID &keyIDMasternode, CDeterministicMN &dmnRet) {
    auto mnList = GetListAtHeight(height, true);
    for (const auto &dmn : mnList) {
        if (dmn.proTx.keyIDMasternode == keyIDMasternode) {
            dmnRet = dmn;
            return true;
        }
    }
    return false;
}

bool CDeterministicMNManager::IsDeterministicMNsSporkActive(int64_t height) {
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
