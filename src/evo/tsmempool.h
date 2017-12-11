// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DASH_TSMEMPOOL_H
#define DASH_TSMEMPOOL_H

#include "primitives/transaction.h"
#include "subtx.h"
#include "users.h"

#include <list>
#include <memory>

class CTsMempoolTsEntry {
public:
    CTransition ts;
    int64_t addedTime;

    CTsMempoolTsEntry(const CTransition &_ts, int64_t _addedTime)
            : ts(_ts),
              addedTime(_addedTime) {
    }
};
typedef std::shared_ptr<CTsMempoolTsEntry> CTsMempoolTsEntryPtr;

class CTsMempool {
    static const int64_t CLEANUP_INTERVALL = 1000 * 5;
    static const int64_t CLEANUP_TIMEOUT = 1000 * 60 * 5; // TODO find good timeout

    typedef std::map<uint256, CTsMempoolTsEntryPtr> TsMap;
    typedef std::map<uint256, TsMap> TsByUsersMap;

public:
    CCriticalSection cs;

private:
    TsMap transitions;
    TsByUsersMap transitionsByUsers;

    int64_t lastCleanupTime{};

public:
    void AddTransition(const CTransition &ts);
    void RemoveTransition(const uint256 &tsHash);
    bool GetTransition(const uint256 &tsHash, CTransition &ts);

    bool GetUsers(std::vector<uint256> &regTxIds);
    bool GetTransitionsForUser(const uint256 &regTxId, std::vector<CTransition> &transitions);
    bool GetNextTransitionForUser(const CEvoUser &user, CTransition &ts);

    void ReAddForReorg(const CBlock &block);
    void RemoveForBlock(const CBlock &block);

private:
    bool isEligableForCleanup(const CTsMempoolTsEntryPtr &entry);
    void cleanup();
};

extern CTsMempool tsMempool;

#endif//DASH_TSMEMPOOL_H
