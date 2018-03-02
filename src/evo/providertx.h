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

class CProviderTXRegisterMN {
public:
    static const int CURRENT_VERSION = 1;

public:
    int16_t nVersion{CURRENT_VERSION}; // message version
    int32_t nProtocolVersion{-1};
    int32_t nCollateralIndex{-1};
    CService addr;
    CKeyID keyIDMasternode;
    CScript scriptPayout;
    uint256 inputsHash; // replay protection
    std::vector<unsigned char> vchSig;

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nVersion);
        READWRITE(nProtocolVersion);
        READWRITE(nCollateralIndex);
        READWRITE(addr);
        READWRITE(keyIDMasternode);
        READWRITE(*(CScriptBase*)(&scriptPayout));
        READWRITE(inputsHash);
        READWRITE(vchSig);
    }

    std::string ToString() const;
    void ToJson(UniValue &obj) const;
};

bool CheckProviderTxRegister(const CTransaction &tx, const CBlockIndex *pindex, CValidationState &state);
bool IsProTxCollateral(const CTransaction &tx, int n);
int GetProTxCollateralIndex(const CTransaction &tx);

#endif//DASH_PROVIDERTX_H
