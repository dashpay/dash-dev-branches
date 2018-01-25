// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "messagesigner.h"
#include "users.h"

CEvoUserDB *evoUserDB;

static const char DB_USER = 'U';
static const char DB_USER_BY_NAME = 'u';
static const char DB_TRANSITION = 'T';
static const char DB_TRANSITION_BLOCK_HASH = 't';

bool CEvoUser::VerifySig(const std::string &msg, const std::vector<unsigned char> &sig, std::string &errorRet) const {
    return CMessageSigner::VerifyMessage(GetCurPubKeyID(), sig, msg, errorRet);
}

CEvoUserDB::CEvoUserDB(size_t nCacheSize, bool fMemory, bool fWipe)
        : db(GetDataDir() / "users", nCacheSize, fMemory, fWipe),
          dbTransaction(db){
}

bool CEvoUserDB::WriteUser(const CEvoUser &user) {
    LOCK(cs);
    dbTransaction.Write(std::make_pair(DB_USER, user.GetRegTxId()), user);
    dbTransaction.Write(std::make_pair(DB_USER_BY_NAME, user.GetUserName()), user.GetRegTxId());
    return true;
}

bool CEvoUserDB::DeleteUser(const uint256 &regTxId) {
    LOCK(cs);

    CEvoUser user;
    if (!GetUser(regTxId, user))
        return false;

    dbTransaction.Erase(std::make_pair(DB_USER, regTxId));
    dbTransaction.Erase(std::make_pair(DB_USER_BY_NAME, user.GetUserName()));
    return true;
}

bool CEvoUserDB::GetUser(const uint256 &regTxId, CEvoUser &user) {
    LOCK(cs);
    return dbTransaction.Read(std::make_pair(DB_USER, regTxId), user);
}

bool CEvoUserDB::GetUserIdByName(const std::string &userName, uint256 &regTxId) {
    LOCK(cs);
    return dbTransaction.Read(std::make_pair(DB_USER_BY_NAME, userName), regTxId);
}

bool CEvoUserDB::UserExists(const uint256 &regTxId) {
    LOCK(cs);
    return dbTransaction.Exists(std::make_pair(DB_USER, regTxId));
}

bool CEvoUserDB::UserNameExists(const std::string &userName) {
    LOCK(cs);
    return dbTransaction.Exists(std::make_pair(DB_USER_BY_NAME, userName));
}

bool CEvoUserDB::WriteTransition(const CTransition &ts) {
    LOCK(cs);
    dbTransaction.Write(std::make_pair(DB_TRANSITION, ts.GetHash()), ts);
    return true;
}

bool CEvoUserDB::DeleteTransition(const uint256 &tsHash) {
    LOCK(cs);
    dbTransaction.Erase(std::make_pair(DB_TRANSITION, tsHash));
    return true;
}

bool CEvoUserDB::TransitionExists(const uint256 &tsHash) {
    LOCK(cs);
    return dbTransaction.Exists(std::make_pair(DB_TRANSITION, tsHash));
}

bool CEvoUserDB::GetTransition(const uint256 &tsHash, CTransition &ts) {
    LOCK(cs);
    return dbTransaction.Read(std::make_pair(DB_TRANSITION, tsHash), ts);
}

bool CEvoUserDB::GetLastTransitionForUser(const uint256 &regTxId, CTransition &ts) {
    LOCK(cs);
    std::vector<CTransition> tmp;
    if (!GetTransitionsForUser(regTxId, 1, tmp))
        return false;
    if (tmp.empty())
        return false;
    ts = tmp[0];
    return true;
}

bool CEvoUserDB::GetTransitionsForUser(const uint256 &regTxId, int maxCount, std::vector<CTransition> &transitions) {
    LOCK(cs);
    CEvoUser user;
    if (!GetUser(regTxId, user))
        return false;

    transitions.clear();
    uint256 tsHash = user.GetHashLastTransition();
    while ((maxCount == -1 || (int)transitions.size() < maxCount) && !tsHash.IsNull()) {
        CTransition ts;
        if (!GetTransition(tsHash, ts))
            return false;
        transitions.push_back(ts);
        tsHash = ts.hashPrevTransition;
    }
    std::reverse(transitions.begin(), transitions.end());
    return true;
}

bool CEvoUserDB::WriteTransitionBlockHash(const uint256 &tsHash, const uint256 &blockHash) {
    LOCK(cs);
    dbTransaction.Write(std::make_pair(DB_TRANSITION_BLOCK_HASH, tsHash), blockHash);
    return true;
}

bool CEvoUserDB::GetTransitionBlockHash(const uint256 &tsHash, uint256 &blockHash) {
    LOCK(cs);
    return dbTransaction.Read(std::make_pair(DB_TRANSITION_BLOCK_HASH, tsHash), blockHash);
}

bool CEvoUserDB::DeleteTransitionBlockHash(const uint256 &tsHash) {
    LOCK(cs);
    dbTransaction.Erase(std::make_pair(DB_TRANSITION_BLOCK_HASH, tsHash));
    return true;
}

bool CEvoUserDB::Commit() {
    return dbTransaction.Commit();
}

void CEvoUserDB::Rollback() {
    dbTransaction.Clear();
}

bool CEvoUserDB::IsTransactionClean() {
    return dbTransaction.IsClean();
}
