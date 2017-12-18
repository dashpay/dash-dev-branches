// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tsmempool.h"
#include "tsvalidation.h"
#include "consensus/validation.h"

CTsMempool tsMempool;

void CTsMempool::AddTransition(const CTransition &ts) {
    LOCK(cs);

    /*
     * TODO limit number of orphan transitions per user. This is especially important because someone could spam us
     * with unfunded transitions which will never be mined and thus fill up the pool.
     */

    if (transitions.count(ts.GetHash())) {
        transitions[ts.GetHash()]->addedTime = GetTimeMillis();
        return;
    }

    CTsMempoolTsEntryPtr entry = std::make_shared<CTsMempoolTsEntry>(ts, GetTimeMillis());

    auto it = transitionsByUsers.find(ts.hashRegTx);
    if (it == transitionsByUsers.end()) {
        it = transitionsByUsers.emplace(ts.hashRegTx, TsMap()).first;
    }
    it->second.emplace(ts.GetHash(), entry);

    transitions.emplace(ts.GetHash(), entry);

    if (GetTimeMillis() - lastCleanupTime >= CLEANUP_INTERVALL) {
        cleanup();
    }
}

void CTsMempool::RemoveTransition(const uint256 &tsHash) {
    LOCK(cs);

    auto it = transitions.find(tsHash);
    if (it == transitions.end()) {
        return;
    }
    CTsMempoolTsEntryPtr entry = it->second;

    transitions.erase(tsHash);

    TsMap &byUsersMap = transitionsByUsers.find(entry->ts.hashRegTx)->second;
    byUsersMap.erase(tsHash);
    if (byUsersMap.empty()) {
        transitionsByUsers.erase(entry->ts.hashRegTx);
    }

    waitForRelay.erase(tsHash);
}

bool CTsMempool::GetTransition(const uint256 &tsHash, CTransition &ts) {
    LOCK(cs);

    auto it = transitions.find(tsHash);
    if (it == transitions.end()) {
        return false;
    }
    ts = it->second->ts;
    return true;
}

bool CTsMempool::Exists(const uint256 &tsHash) {
    LOCK(cs);
    return transitions.count(tsHash) != 0;
}

bool CTsMempool::GetUsers(std::vector<uint256> &regTxIds) {
    LOCK(cs);
    regTxIds.clear();
    regTxIds.reserve(transitionsByUsers.size());
    for (const auto &p : transitionsByUsers) {
        regTxIds.push_back(p.first);
    }
    return true;
}

bool CTsMempool::GetTransitionsForUser(const uint256 &regTxId, std::vector<CTransition> &transitions) {
    LOCK(cs);
    transitions.clear();

    auto it = transitionsByUsers.find(regTxId);
    if (it == transitionsByUsers.end()) {
        LogPrintf("CTsMempool::GetTransitionsForUser -- User %s not found\n", regTxId.ToString());
        return false;
    }

    transitions.reserve(it->second.size());
    for (const auto &p : it->second) {
        transitions.push_back(p.second->ts);
    }

    return true;
}

bool CTsMempool::GetNextTransitionForUser(const CEvoUser &user, CTransition &ts) {
    auto it = transitionsByUsers.find(user.GetRegTxId());
    if (it == transitionsByUsers.end()) {
        LogPrintf("CTsMempool::GetNextTransitionForUser -- User %s not found\n", user.GetRegTxId().ToString());
        return false;
    }

    /*
     * Return first valid transition for given user
     */

    for (const auto &p : it->second) {
        CValidationState state;
        if (!CheckTransitionForUser(p.second->ts, user, true, state))
            continue;

        ts = p.second->ts;
        return true;
    }
    return false;
}

void CTsMempool::GetTransitionsChain(const uint256 &lastTsHash, const uint256 &stopAtTsHash, std::vector<CTransition> &result) {
    LOCK(cs);
    result.clear();
    uint256 cur = lastTsHash;
    while (cur != stopAtTsHash) {
        const auto it = transitions.find(cur);
        if (it == transitions.end())
            break;
        result.push_back(it->second->ts);
        cur = it->second->ts.hashPrevTransition;
    }
    std::reverse(result.begin(), result.end());
}

void CTsMempool::AddWaitForRelay(const uint256 &tsHash) {
    LOCK(cs);
    assert(transitions.count(tsHash) != 0);
    waitForRelay.insert(tsHash);
}

void CTsMempool::RemoveWaitForRelay(const uint256 &tsHash) {
    LOCK(cs);
    waitForRelay.erase(tsHash);
}

void CTsMempool::RemoveWaitForRelay(const std::vector<uint256> &tsHashes) {
    LOCK(cs);
    for (const uint256 &tsHash : tsHashes)
        waitForRelay.erase(tsHash);
}

void CTsMempool::GetNowValidWaitForRelayTransitions(std::vector<uint256> &result) {
    LOCK(cs);

    std::list<uint256> tmp;

    for (const uint256 &tsHash : waitForRelay) {
        const auto entry = transitions.find(tsHash);
        assert(entry != transitions.end());

        CValidationState state;
        if (CheckTransition(entry->second->ts, true, true, state)) {
            tmp.push_back(entry->first);
        }
    }

    result.clear();
    std::set<uint256> added;

    // Make sure we return the list in the correct order, meaning that parent transitions must appear first
    while (!tmp.empty()) {
        const uint256 &tsHash = tmp.front();
        tmp.pop_front();

        const auto it = transitions.find(tsHash);
        assert(it != transitions.end());
        const CTransition &ts = it->second->ts;

        // does the current TS have a parent that needs to be relayed first
        if (!ts.hashPrevTransition.IsNull() && waitForRelay.count(ts.hashPrevTransition)) {
            // did we already add it to the result?
            if (!added.count(ts.hashPrevTransition)) {
                // try again later
                tmp.push_back(tsHash);
                continue;
            }
        }
        result.push_back(tsHash);
        added.insert(tsHash);
    }
}

void CTsMempool::ReAddForReorg(const CBlock &block) {
    LOCK(cs);

    for (int i = (int)block.vts.size() - 1; i >= 0; i--) {
        const CTransition &ts = block.vts[i];
        AddTransition(ts);
    }
}

void CTsMempool::RemoveForBlock(const CBlock &block) {
    LOCK(cs);

    for (const CTransition &ts : block.vts) {
        RemoveTransition(ts.GetHash());
    }

    cleanup();
}

bool CTsMempool::isEligableForCleanup(const CTsMempoolTsEntryPtr &entry) {
    LOCK(cs);

    const CTransition &ts = entry->ts;

    CEvoUser user;
    if (!evoUserDB->GetUser(ts.hashRegTx, user) && !BuildUserFromMempool(ts.hashRegTx, user)) {
        return true;
    }

    TopupUserFromMempool(user);

    // get chain of TSs back to user
    std::vector<CTransition> tsChain;
    GetTransitionsChain(ts.hashPrevTransition, user.GetHashLastTransition(), tsChain);

    // now try to process them on the temporary user
    for (const auto &ts2 : tsChain) {
        CValidationState state;
        if (!CheckTransitionForUser(ts2, user, true, state))
            return true;
        if (!ProcessTransitionForUser(ts2, user, state))
            return true;
    }

    return false;
}

void CTsMempool::cleanup() {
    std::set<uint256> forCleanup;

    int64_t curTime = GetTimeMillis();

    for (const auto &p : transitions) {
        if (curTime - p.second->addedTime > CLEANUP_TIMEOUT && isEligableForCleanup(p.second)) {
            forCleanup.emplace(p.second->ts.GetHash());
        }
    }

    for (const auto &tsHash : forCleanup) {
        RemoveTransition(tsHash);
        LogPrintf("CTsMempool::cleanup -- TS %s removed\n", tsHash.ToString());
    }

    lastCleanupTime = GetTimeMillis();
}
