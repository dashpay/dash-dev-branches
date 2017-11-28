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
        : db(GetDataDir() / "users", nCacheSize, fMemory, fWipe) {
}

bool CEvoUserDB::WriteUser(const CEvoUser &user) {
    LOCK(cs);
    if (!db.Write(std::make_pair(DB_USER, user.GetRegTxId()), user))
        return false;
    if (!db.Write(std::make_pair(DB_USER_BY_NAME, user.GetUserName()), user.GetRegTxId()))
        return false;
    return true;
}

bool CEvoUserDB::DeleteUser(const uint256 &regTxId) {
    LOCK(cs);

    CEvoUser user;
    if (!GetUser(regTxId, user))
        return false;

    if (!db.Erase(std::make_pair(DB_USER, regTxId)))
        return false;
    if (!db.Erase(std::make_pair(DB_USER_BY_NAME, user.GetUserName())))
        return false;
    return true;
}

bool CEvoUserDB::GetUser(const uint256 &regTxId, CEvoUser &user) {
    LOCK(cs);
    return db.Read(std::make_pair(DB_USER, regTxId), user);
}

bool CEvoUserDB::GetUserIdByName(const std::string &userName, uint256 &regTxId) {
    LOCK(cs);
    return db.Read(std::make_pair(DB_USER_BY_NAME, userName), regTxId);
}

bool CEvoUserDB::UserExists(const uint256 &regTxId) {
    LOCK(cs);
    return db.Exists(std::make_pair(DB_USER, regTxId));
}

bool CEvoUserDB::UserNameExists(const std::string &userName) {
    LOCK(cs);
    return db.Exists(std::make_pair(DB_USER_BY_NAME, userName));
}