// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DASH_USERS_H
#define DASH_USERS_H

#include "sync.h"
#include "pubkey.h"
#include "dbwrapper.h"
#include "uint256.h"
#include "serialize.h"
#include "transition.h"

class CEvoUser {
private:
    uint256 regTxId;
    std::string userName;
    std::vector<CKeyID> pubKeyIDs;
    std::vector<uint256> subTxIds;
    uint256 lastTransition;

    CAmount topupCredits{};
    CAmount spentCredits{};

    bool closed{};

public:
    CEvoUser() {}
    CEvoUser(const uint256 &_regTxId, const std::string &_userName, const CKeyID &_pubKeyID)
            : regTxId(_regTxId),
              userName(_userName),
              pubKeyIDs{_pubKeyID}
    {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        //READWRITE(*const_cast<int32_t*>(&this->nVersion));
        //nVersion = this->nVersion;
        READWRITE(regTxId);
        READWRITE(userName);
        READWRITE(pubKeyIDs);
        READWRITE(subTxIds);
        READWRITE(lastTransition);
        READWRITE(topupCredits);
        READWRITE(spentCredits);
        READWRITE(closed);
    }

    const uint256 &GetRegTxId() const {
        return regTxId;
    }

    const std::string &GetUserName() const {
        return userName;
    }

    CAmount GetTopUpCredits() const {
        return topupCredits;
    }

    CAmount GetSpentCredits() const {
        return spentCredits;
    }

    CAmount GetCreditBalance() const {
        return topupCredits - spentCredits;
    }

    void AddTopUp(CAmount amount) {
        topupCredits += amount;
    }

    void AddSpend(CAmount amount) {
        spentCredits += amount;
    }

    void SetClosed(bool _closed) {
        closed = _closed;
    }

    bool IsClosed() const {
        return closed;
    }

    void PushPubKeyID(const CKeyID &keyID) {
        pubKeyIDs.push_back(keyID);
    }
    CKeyID PopPubKeyID() {
        assert(pubKeyIDs.size() != 0);
        CKeyID ret(pubKeyIDs.back());
        pubKeyIDs.pop_back();
        return ret;
    }
    const CKeyID &GetCurPubKeyID() const {
        assert(pubKeyIDs.size() != 0);
        return pubKeyIDs.back();
    }
    
    void PushSubTx(const uint256 &subTxId) {
        subTxIds.push_back(subTxId);
    }
    uint256 PopSubTx() {
        assert(subTxIds.size() != 0);
        uint256 ret(subTxIds.back());
        subTxIds.pop_back();
        return ret;
    }
    const std::vector<uint256> &GetSubTxIds() const {
        return subTxIds;
    }

    const uint256 &GetLastTransition() const {
        return lastTransition;
    }
    void SetLastTransition(const uint256 &tsHash) {
        lastTransition = tsHash;
    }

    bool VerifySig(const std::string &msg, const std::vector<unsigned char> &sig, std::string &errorRet) const;
};

class CEvoUserDB {
public:
    CCriticalSection cs;

    struct RAIITransaction {
        CEvoUserDB &userDb;
        RAIITransaction(CEvoUserDB &_userDb) : userDb(_userDb) {}
        ~RAIITransaction() {
            userDb.Rollback();
        }
    };

private:
    CDBWrapper db;
    CDBTransaction dbTransaction;

public:
    CEvoUserDB(size_t nCacheSize, bool fMemory=false, bool fWipe=false);

    bool WriteUser(const CEvoUser &user);
    bool DeleteUser(const uint256 &regTxId);

    bool GetUser(const uint256 &regTxId, CEvoUser &user);
    bool GetUserIdByName(const std::string &userName, uint256 &regTxId);
    bool UserExists(const uint256 &regTxId);
    bool UserNameExists(const std::string &userName);

    bool WriteTransition(const CTransition &ts);
    bool DeleteTransition(const uint256 &tsHash);
    bool GetTransition(const uint256 &tsHash, CTransition &ts);
    bool GetLastTransitionForUser(const uint256 &regTxId, CTransition &ts);
    bool GetTransitionsForUser(const uint256 &regTxId, int maxCount, std::vector<CTransition> &transitions);

    bool WriteTransitionBlockHash(const uint256 &tsHash, const uint256 &blockHash);
    bool GetTransitionBlockHash(const uint256 &tsHash, uint256 &blockHash);
    bool DeleteTransitionBlockHash(const uint256 &tsHash);

    bool Commit();
    void Rollback();
    bool IsTransactionClean();

    std::unique_ptr<RAIITransaction> BeginTransaction() {
        assert(IsTransactionClean());
        return std::unique_ptr<RAIITransaction>(new RAIITransaction(*this));
    }
};

extern CEvoUserDB *evoUserDB;

#endif //DASH_USERS_H
