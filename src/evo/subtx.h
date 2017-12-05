// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DASH_SUBTX_H
#define DASH_SUBTX_H

#include "key.h"
#include "validation.h"
#include "pubkey.h"
#include "serialize.h"
#include "users.h"

class UniValue;
class CSubTxData;

static const int MAX_SUBTX_DATA_LEN = 256;
static const CAmount MIN_SUBTX_TOPUP = 0.0001 * COIN;

bool IsSubTx(const CTransaction &tx);
bool GetSubTxData(const CTransaction &tx, CSubTxData &subTxData);

bool CheckSubTx(const CTransaction &tx, CValidationState &state);
bool ProcessSubTx(const CTransaction &tx, CValidationState &state);
bool UndoSubTx(const CTransaction &tx, CValidationState &state);

bool CheckSubTxsInBlock(const CBlock &block, CValidationState &state);
bool ProcessSubTxsInBlock(const CBlock &block, CValidationState &state);
bool UndoSubTxsInBlock(const CBlock &block, CValidationState &state);

enum SubTxAction {
    SubTxAction_Invalid = 0,
    SubTxAction_Register = 1,
    SubTxAction_TopUp = 2,
};

class CSubTxData {
public:
    // Default SubTx version.
    static const int32_t CURRENT_VERSION = 0x00010000; // Evo 1.0.0

    int32_t nVersion;
    SubTxAction action{SubTxAction_Invalid};

    // only valid for register
    std::string userName;
    CKeyID pubKeyID;
    std::vector<unsigned char> vchSig;

    // only valid for topup
    uint256 regTxId;

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(VARINT(this->nVersion));

        int _action = action;
        READWRITE(VARINT(_action));
        action = (SubTxAction)_action;

        switch (action) {
            case SubTxAction_Register:
                READWRITE(userName);
                READWRITE(pubKeyID);
                READWRITE(vchSig);
                break;
            case SubTxAction_TopUp:
                READWRITE(regTxId);
                break;
            default:
                throw std::ios_base::failure(strprintf("invalid subtx action %d", action));
        }
    }

    bool Check(const CTransaction &tx, CValidationState &state);
    bool Process(const CTransaction &tx, CValidationState &state);
    bool Undo(const CTransaction &tx, CValidationState &state);

    void ToJSON(UniValue &uv) const;

    bool CheckRegister(const CTransaction &subTx, CValidationState &state) const;
    bool ProcessRegister(const CTransaction &subTx, CValidationState &state) const;
    bool UndoRegister(const CTransaction &subTx, CValidationState &state) const;

    std::string MakeSignMessage() const;
    bool Sign(const CKey &key);

    bool CheckTopUp(const CTransaction &subTx, CValidationState &state) const;

    bool ProcessTopUp(const CTransaction &subTx, CValidationState &state) const;

    bool UndoTopUp(const CTransaction &subTx, CValidationState &state) const;
};


#endif //DASH_SUBTX_H
