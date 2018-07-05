// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "messagesigner.h"
#include "users.h"
#include "subtx.h"
#include "evodb.h"
#include "user.h"

static const std::string DB_USER = "subtx_U";
static const std::string DB_USER_BY_NAME = "subtx_u";
static const std::string DB_USER_PUBKEY = "subtx_pk";
static const std::string DB_USER_HASHSTPACKET = "subtx_hst";
static const std::string DB_UNSPENT_SUBTX = "subtx_s";

CEvoUserDb::CEvoUserDb(CEvoDB& _evoDb)
        : evoDb(_evoDb)
{
}

void CEvoUserDb::WriteUser(const CEvoUser& user) {
    evoDb.Write(std::make_pair(DB_USER, user.GetRegTxId()), user);
    evoDb.Write(std::make_pair(DB_USER_BY_NAME, user.GetUserName()), user.GetRegTxId());
}

void CEvoUserDb::DeleteUser(const uint256& regTxId) {
    CEvoUser user;
    if (!GetUser(regTxId, user))
        return;

    evoDb.Erase(std::make_pair(DB_USER, regTxId));
    evoDb.Erase(std::make_pair(DB_USER_BY_NAME, user.GetUserName()));
}

bool CEvoUserDb::GetUser(const uint256& regTxId, CEvoUser& user) {
    return evoDb.Read(std::make_pair(DB_USER, regTxId), user);
}

bool CEvoUserDb::GetUserIdByName(const std::string& userName, uint256& regTxId) {
    return evoDb.Read(std::make_pair(DB_USER_BY_NAME, userName), regTxId);
}

bool CEvoUserDb::UserExists(const uint256& regTxId) {
    return evoDb.Exists(std::make_pair(DB_USER, regTxId));
}

bool CEvoUserDb::UserNameExists(const std::string& userName) {
    return evoDb.Exists(std::make_pair(DB_USER_BY_NAME, userName));
}

void CEvoUserDb::PushPubKey(const uint256& regTxId, const CKeyID& keyId)
{
    PushStack(evoDb, std::make_pair(DB_USER_PUBKEY, regTxId), keyId);
}

bool CEvoUserDb::PopPubKey(const uint256& regTxId, CKeyID& oldTop, CKeyID& newTop)
{
    return PopStackItem(evoDb, std::make_pair(DB_USER_PUBKEY, regTxId), oldTop, newTop);
}

void CEvoUserDb::PushHashSTPacket(const uint256& regTxId, const uint256& hashSTPacket)
{
    PushStack(evoDb, std::make_pair(DB_USER_HASHSTPACKET, regTxId), hashSTPacket);
}

bool CEvoUserDb::PopHashSTPacket(const uint256& regTxId, uint256& oldTop, uint256& newTop)
{
    return PopStackItem(evoDb, std::make_pair(DB_USER_HASHSTPACKET, regTxId), oldTop, newTop);
}

void CEvoUserDb::WriteUnspentSubTx(const uint256& regTxId, const uint256& subTxHash)
{
    uint256 key = ::SerializeHash(std::make_pair(regTxId, subTxHash));
    evoDb.Write(std::make_pair(DB_UNSPENT_SUBTX, key), 1);
}

void CEvoUserDb::DeleteUnspentSubTx(const uint256& regTxId, const uint256& subTxHash)
{
    uint256 key = ::SerializeHash(std::make_pair(regTxId, subTxHash));
    evoDb.Erase(std::make_pair(DB_UNSPENT_SUBTX, key));
}

bool CEvoUserDb::HasUnspentSubTx(const uint256& regTxId, const uint256& subTxHash)
{
    uint256 key = ::SerializeHash(std::make_pair(regTxId, subTxHash));
    return evoDb.Exists(std::make_pair(DB_UNSPENT_SUBTX, key));
}
