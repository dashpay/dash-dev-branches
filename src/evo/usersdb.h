// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DASH_EVO_USERDB_H
#define DASH_EVO_USERDB_H

#include "pubkey.h"
#include "uint256.h"
#include "serialize.h"

class CEvoDB;
class CEvoUser;
class CSubTxTransition;

class CEvoUserDb 
{
private:
    CEvoDB& evoDb;

public:
    CEvoUserDb(CEvoDB& _evoDb);

    void WriteUser(const CEvoUser& user);
    void DeleteUser(const uint256& regTxId);

    bool GetUser(const uint256& regTxId, CEvoUser& user);
    bool GetUserIdByName(const std::string& userName, uint256& regTxId);
    bool UserExists(const uint256& regTxId);
    bool UserNameExists(const std::string& userName);

    void PushSubTx(const uint256& regTxId, const uint256& hashSubTx);
    bool PopSubTx(const uint256& regTxId, uint256& oldTop, uint256& newTop);
    std::vector<uint256> ListUserSubTxs(const uint256& regTxId, size_t maxCount = std::numeric_limits<size_t>::max());

    void PushPubKey(const uint256& regTxId, const CKeyID& keyId);
    bool PopPubKey(const uint256& regTxId, CKeyID& oldTop, CKeyID& newTop);

    void PushHashSTPacket(const uint256& regTxId, const uint256& hashSTPacket);
    bool PopHashSTPacket(const uint256& regTxId, uint256& oldTop, uint256& newTop);

private:
    template<typename DB, typename K, typename V>
    void PushStack(DB& db, const K& k, const V& v)
    {
        int64_t stackIndex = -1;
        if (!db.Read(std::make_pair(std::string("stacktop"), k), stackIndex)) {
            stackIndex = 0;
        } else {
            stackIndex++;
        }
        auto stackKey = std::make_pair(k, stackIndex);
        db.Write(std::make_pair(std::string("stack"), stackKey), v);
        db.Write(std::make_pair(std::string("stacktop"), k), stackIndex);
    }
    template<typename DB, typename K>
    int64_t GetTopStackIndex(DB& db, const K& k)
    {
        int64_t stackIndex = -1;
        if (!db.Read(std::make_pair(std::string("stacktop"), k), stackIndex)) {
            return -1;
        }
        return stackIndex;
    }
    template<typename DB, typename K, typename V>
    bool GetStackItem(DB& db, const K& k, size_t index, V& v)
    {
        auto stackKey = std::make_pair(k, (int64_t)index);
        return db.Read(std::make_pair(std::string("stack"), stackKey), v);
    }
    template<typename DB, typename K, typename V>
    bool PopStackItem(DB& db, const K& k, V& oldTopItem, V& newTopItem)
    {
        int64_t topIndex = GetTopStackIndex(db, k);
        if (topIndex == (size_t)-1) {
            return false;
        }

        if (!GetStackItem(db, k, topIndex, oldTopItem)) {
            return false;
        }

        db.Erase(std::make_pair(std::string(std::string("stack")), std::make_pair(k, topIndex)));

        if (topIndex == 0) {
            db.Erase(std::make_pair(std::string("stacktop"), k));
            newTopItem = V();
            return true;
        }
        topIndex--;

        db.Write(std::make_pair(std::string("stacktop"), k), topIndex);

        GetStackItem(db, k, topIndex, newTopItem);
        return true;
    }

    template<typename DB, typename K, typename V>
    void ListStackItems(DB& db, const K& k, std::vector<V>& ret)
    {
        ret.clear();
        size_t i = 0;
        while (true) {
            V v;
            if (!GetStackItem(db, k, i, v)) {
                break;
            }
            ret.emplace_back(std::move(v));
            i++;
        }
    };
};

#endif //DASH_EVO_USERDB_H
