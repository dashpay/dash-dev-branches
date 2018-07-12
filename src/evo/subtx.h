// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DASH_EVO_SUBTX_H
#define DASH_EVO_SUBTX_H

#include "key.h"
#include "validation.h"
#include "pubkey.h"
#include "serialize.h"
#include "users.h"
#include "univalue.h"

static const CAmount MIN_SUBTX_TOPUP = 0.0001 * COIN;

static const CAmount EVO_TS_MIN_FEE = 1000; // TODO find good min fee
static const CAmount EVO_TS_MAX_FEE = EVO_TS_MIN_FEE * 10; // TODO find good max fee

class CSubTxRegister
{
public:
    static const int CURRENT_VERSION = 1;

public:
    uint16_t nVersion{CURRENT_VERSION};
    std::string userName;
    CKeyID pubKeyID;
    std::vector<unsigned char> vchSig;

    // TODO replay protection?

    ADD_SERIALIZE_METHODS;

    template<typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nVersion);
        READWRITE(userName);
        READWRITE(pubKeyID);
        READWRITE(vchSig);
    }

    uint256 GetHash() const
    {
        return ::SerializeHash(*this);
    }

    uint256 GetSignHash() const
    {
        CSubTxRegister tmp = *this;
        tmp.vchSig.clear();
        return ::SerializeHash(tmp);
    }

    UniValue ToJson() const;
};

class CSubTxTopup
{
public:
    static const int CURRENT_VERSION = 1;

public:
    uint16_t nVersion{CURRENT_VERSION};
    uint256 regTxId;

    ADD_SERIALIZE_METHODS;

    template<typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nVersion);
        READWRITE(regTxId);
    }

    uint256 GetHash() const
    {
        return ::SerializeHash(*this);
    }

    UniValue ToJson() const;
};

class CSubTxForExistingUserBase
{
public:
    CSubTxForExistingUserBase(uint16_t _nVersion) :
            nVersion(_nVersion)
    {
    }
    virtual ~CSubTxForExistingUserBase() {}

    uint16_t nVersion{};
    uint256 regTxId;
    uint256 hashPrevSubTx;
    CAmount creditFee{};
    std::vector<unsigned char> vchSig; // TODO this will be a BLS threshold+aggregate sig in the future
};

template<class SubTx>
class CSubTxForExistingUserBase2 : public CSubTxForExistingUserBase
{
public:
    CSubTxForExistingUserBase2() :
            CSubTxForExistingUserBase(SubTx::CURRENT_VERSION)
    {
    }

    uint256 GetSignHash() const
    {
        SubTx tmp = *(SubTx*)this;
        tmp.vchSig.clear();
        return ::SerializeHash(tmp);
    }

    uint256 GetHash() const
    {
        return ::SerializeHash(*((SubTx*)this));
    }
};

class CSubTxResetKey : public CSubTxForExistingUserBase2<CSubTxResetKey>
{
public:
    static const int CURRENT_VERSION = 1;

public:
    CKeyID newPubKeyId;

    ADD_SERIALIZE_METHODS;

    template<typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nVersion);
        READWRITE(regTxId);
        READWRITE(hashPrevSubTx);
        READWRITE(creditFee);
        READWRITE(newPubKeyId);
        READWRITE(vchSig);
    }

    UniValue ToJson() const;
};

class CSubTxCloseAccount : public CSubTxForExistingUserBase2<CSubTxCloseAccount>
{
public:
    static const int CURRENT_VERSION = 1;

public:
    ADD_SERIALIZE_METHODS;

    template<typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nVersion);
        READWRITE(regTxId);
        READWRITE(hashPrevSubTx);
        READWRITE(creditFee);
        READWRITE(vchSig);
    }

    UniValue ToJson() const;
};

class CSubTxTransition : public CSubTxForExistingUserBase2<CSubTxTransition>
{
public:
    static const int CURRENT_VERSION = 1;

public:
    uint256 hashSTPacket;

    ADD_SERIALIZE_METHODS;

    template<typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nVersion);
        READWRITE(regTxId);
        READWRITE(hashPrevSubTx);
        READWRITE(creditFee);
        READWRITE(hashSTPacket);
        READWRITE(vchSig);
    }

    UniValue ToJson() const;
};

uint256 GetRegTxIdFromSubTx(const CTransaction& tx);
CAmount GetSubTxFee(const CTransaction& tx);
uint256 GetSubTxHashPrevSubTx(const CTransaction& tx);
UniValue SubTxToJson(const CTransaction& tx);

#endif //DASH_EVO_SUBTX_H
