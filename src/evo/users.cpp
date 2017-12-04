// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "messagesigner.h"
#include "users.h"

CEvoUserDB *evoUserDB;

static const char DB_USER = 'U';
static const char DB_USER_BY_NAME = 'u';

bool CEvoUser::VerifySig(const std::string &msg, const std::vector<unsigned char> &sig, std::string &errorRet) {
    return CMessageSigner::VerifyMessage(GetCurPubKey(), sig, msg, errorRet);
}

CEvoUserDB::CEvoUserDB(size_t nCacheSize, bool fMemory, bool fWipe)
        : db(GetDataDir() / "users", nCacheSize, fMemory, fWipe),
          transaction(db){
}

bool CEvoUserDB::WriteUser(const CEvoUser &user) {
    LOCK(cs);
    transaction.Write(std::make_pair(DB_USER, user.GetRegTxId()), user);
    transaction.Write(std::make_pair(DB_USER_BY_NAME, user.GetUserName()), user.GetRegTxId());
    return true;
}

bool CEvoUserDB::DeleteUser(const uint256 &regTxId) {
    LOCK(cs);

    CEvoUser user;
    if (!GetUser(regTxId, user))
        return false;

    transaction.Erase(std::make_pair(DB_USER, regTxId));
    transaction.Erase(std::make_pair(DB_USER_BY_NAME, user.GetUserName()));
    return true;
}

bool CEvoUserDB::GetUser(const uint256 &regTxId, CEvoUser &user) {
    LOCK(cs);
    return transaction.Read(std::make_pair(DB_USER, regTxId), user);
}

bool CEvoUserDB::GetUserIdByName(const std::string &userName, uint256 &regTxId) {
    LOCK(cs);
    return transaction.Read(std::make_pair(DB_USER_BY_NAME, userName), regTxId);
}

bool CEvoUserDB::UserExists(const uint256 &regTxId) {
    LOCK(cs);
    return transaction.Exists(std::make_pair(DB_USER, regTxId));
}

bool CEvoUserDB::UserNameExists(const std::string &userName) {
    LOCK(cs);
    return transaction.Exists(std::make_pair(DB_USER_BY_NAME, userName));
}


bool CEvoUserDB::Commit() {
    return transaction.Commit();
}

void CEvoUserDB::Rollback() {
    transaction.Clear();
}

bool CEvoUserDB::IsTransactionClean() {
    return transaction.IsClean();
}
