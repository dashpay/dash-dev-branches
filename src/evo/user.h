// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DASH_EVO_USER_H
#define DASH_EVO_USER_H

#include "sync.h"
#include "pubkey.h"
#include "uint256.h"
#include "serialize.h"
#include "amount.h"

class CEvoUser {
private:
    uint256 regTxId;
    std::string userName;

    CKeyID curPubKeyID;
    uint256 hashCurSubTx;
    uint256 hashCurSTPacket;

    CAmount topupCredits{};
    CAmount spentCredits{};

    bool closed{};

public:
    CEvoUser() {}
    CEvoUser(const uint256& _regTxId, const std::string& _userName, const CKeyID& _pubKeyID)
            : regTxId(_regTxId),
              userName(_userName),
              hashCurSubTx(regTxId),
              curPubKeyID(_pubKeyID)
    {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        //nVersion = this->nVersion;
        READWRITE(regTxId);
        READWRITE(userName);
        READWRITE(curPubKeyID);
        READWRITE(hashCurSubTx);
        READWRITE(hashCurSTPacket);
        READWRITE(topupCredits);
        READWRITE(spentCredits);
        READWRITE(closed);
    }

    const uint256& GetRegTxId() const {
        return regTxId;
    }

    const std::string& GetUserName() const {
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

    void SetCurPubKeyID(const CKeyID& _keyID) {
        curPubKeyID = _keyID;
    }

    const CKeyID& GetCurPubKeyID() const {
        return curPubKeyID;
    }

    void SetCurSubTx(const uint256& _subTxHash) {
        hashCurSubTx = _subTxHash;
    }

    void SetCurHashSTPacket(const uint256& _hashSTPacket) {
        hashCurSTPacket = _hashSTPacket;
    }

    const uint256& GetCurSubTx() const {
        return hashCurSubTx;
    }
    const uint256& GetCurHashSTPacket() const {
        return hashCurSTPacket;
    }
};

#endif //DASH_EVO_USER_H
