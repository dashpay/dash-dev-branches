// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DASH_DETERMINISTICMNS_H
#define DASH_DETERMINISTICMNS_H

#include "providertx.h"
#include "dbwrapper.h"
#include "sync.h"
#include "spork.h"

#include <map>

class CBlock;
class CBlockIndex;
class CValidationState;

class CDeterministicMNState {
public:
    int64_t registeredHeight{-1};
    int64_t lastPaidHeight{0};
    int32_t PoSePenality{0};

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(registeredHeight);
        READWRITE(lastPaidHeight);
        READWRITE(PoSePenality);
    }
};

class CDeterministicMNBlockInfo {
public:
    std::set<uint256> mnsInBlock;
    std::map<uint256, CDeterministicMNState> mnsRemovedInBlock;
    uint256 payeeProTxHash;
    int64_t prevPayeeHeight{};

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(mnsInBlock);
        READWRITE(mnsRemovedInBlock);
        READWRITE(payeeProTxHash);
        READWRITE(prevPayeeHeight);
    }

    bool IsNull() const {
        return mnsInBlock.empty() && mnsRemovedInBlock.empty() && payeeProTxHash.IsNull() && prevPayeeHeight == 0;
    }
};

class CDeterministicMN {
public:
    uint256 proTxHash;
    CProviderTXRegisterMN proTx;
    CDeterministicMNState state;
};

class CDeterministicMNListState {
public:
    int64_t firstMNHeight{-1};
    int64_t blocksWithMNsCount{0};
    int64_t curHeight{0};
    uint256 curBlockHash;
    int64_t spork15Value{SPORK_15_DETERMINISTIC_MNS_DEFAULT};

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(firstMNHeight);
        READWRITE(blocksWithMNsCount);
        READWRITE(curHeight);
        READWRITE(curBlockHash);
        READWRITE(spork15Value);
    }
};

class CDeterministicMNList {
    static const int SNAPSHOT_LIST_PERIOD = 10;

private:
    CCriticalSection cs;

    CDBWrapper db;
    CDBTransaction dbTransaction;

    std::map<uint256, CDeterministicMNState> mapCurMNs;
    CDeterministicMNListState state;

public:
    CDeterministicMNList(size_t nCacheSize, bool fMemory=false, bool fWipe=false);

    std::unique_ptr<CScopedDBTransaction> BeginTransaction() {
        auto t = CScopedDBTransaction::Begin(dbTransaction);
        t->SetRollbackHandler([&] {
           Init();
        });
        return t;
    }

    void Init();

    bool ProcessBlock(const CBlock &block, const CBlockIndex *pindex, CValidationState &state);
    bool ProcessBlockLocked(const CBlock &block, const CBlockIndex *pindex, CValidationState &state, CDeterministicMNBlockInfo &blockInfo);
    bool UndoBlock(const CBlock &block, const CBlockIndex *pindex);
    bool UndoBlockLocked(const CBlock &block, const CBlockIndex *pindex, CDeterministicMNBlockInfo &blockInfo);

    bool GetMNPayee(int64_t height, uint256 &proTxHashRet, CScript &payeeScriptRet);
    bool GetMNLastPaidHeight(const uint256 &proTxHash, int64_t height, int64_t &lastPaidHeightRet);

    bool GetRegisterMN(const uint256 &proTxHash, CProviderTXRegisterMN &proTx);

    // TODO implement cache
    std::vector<CDeterministicMN> GetListAtHeight(int64_t height, bool detailed);
    std::vector<CDeterministicMN> GetListAtChainTip(bool detailed);

    bool HasMNAtHeight(int height, const uint256 &proTxHash);
    bool HasMNAtChainTip(const uint256 &proTxHash);

    bool IsDeterministicMNsSporkActive(int64_t height = -1);

private:
    bool RecreateListFromSnapshot(int64_t height, std::map<uint256, CDeterministicMNState> &snapshot);
};

extern CDeterministicMNList *deterministicMNList;

#endif//DASH_DETERMINISTICMNS_H