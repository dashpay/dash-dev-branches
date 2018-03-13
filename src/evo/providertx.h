// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DASH_PROVIDERTX_H
#define DASH_PROVIDERTX_H

#include "primitives/transaction.h"
#include "consensus/validation.h"

#include "netaddress.h"
#include "pubkey.h"

class CBlockIndex;
class UniValue;

class CProRegTX
{
public:
    static const int CURRENT_VERSION = 1;

public:
    int16_t nVersion{CURRENT_VERSION}; // message version
    int32_t nProtocolVersion{-1};
    uint32_t nCollateralIndex{(uint32_t) - 1};
    CService addr;
    CKeyID keyIDOperator;
    CKeyID keyIDOwner;
    CScript scriptPayout;
    uint256 inputsHash; // replay protection
    std::vector<unsigned char> vchSig;

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nVersion);
        READWRITE(nProtocolVersion);
        READWRITE(nCollateralIndex);
        READWRITE(addr);
        READWRITE(keyIDOperator);
        READWRITE(keyIDOwner);
        READWRITE(*(CScriptBase*)(&scriptPayout));
        READWRITE(inputsHash);
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(vchSig);
        }
    }

    std::string ToString() const;
    void ToJson(UniValue& obj) const;
};
typedef std::shared_ptr<CProRegTX> CProRegTXPtr;
typedef std::shared_ptr<const CProRegTX> CProRegTXCPtr;

class CProUpServTX
{
public:
    static const int CURRENT_VERSION = 1;

public:
    int16_t nVersion{CURRENT_VERSION}; // message version
    uint256 proTxHash;
    int32_t nProtocolVersion{-1};
    CService addr;
    uint256 inputsHash; // replay protection
    std::vector<unsigned char> vchSig;

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nVersion);
        READWRITE(proTxHash);
        READWRITE(nProtocolVersion);
        READWRITE(addr);
        READWRITE(inputsHash);
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(vchSig);
        }
    }

public:
    std::string ToString() const;
    void ToJson(UniValue& obj) const;
};

bool CheckProRegTx(const CTransaction& tx, const CBlockIndex* pindex, CValidationState& state);
bool CheckProUpServTx(const CTransaction& tx, const CBlockIndex* pindex, CValidationState& state);

bool IsProTxCollateral(const CTransaction& tx, uint32_t n);
uint32_t GetProTxCollateralIndex(const CTransaction& tx);

#endif//DASH_PROVIDERTX_H
