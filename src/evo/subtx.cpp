// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/validation.h"
#include "messagesigner.h"
#include "script/standard.h"
#include "subtx.h"
#include "users.h"

bool IsSubTx(const CTransaction &tx) {
    for (const CTxOut &txout : tx.vout) {
        txnouttype txType;
        std::vector<std::vector<unsigned char> > solutions;

        if (Solver(txout.scriptPubKey, txType, solutions) && txType == TX_SUBSCRIPTION) {
            return true;
        }
    }
    return false;
}

static bool GetSubTxData(const CTxOut &txout, std::vector<unsigned char> &data) {
    opcodetype opcode;
    auto it = txout.scriptPubKey.begin() + 1;
    return txout.scriptPubKey.GetOp(it, opcode, data);
}

static bool GetSubTxData(const CTransaction &tx, std::vector<unsigned char> &data, CValidationState &state) {
    if (!GetSubTxData(tx.vout[0], data)) {
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-data");
    }

    if (data.size() > MAX_SUBTX_DATA_LEN) {
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-datalen");
    }
    return true;
}

bool IsSubTxDataValid(const CTransaction &tx, CValidationState &state) {
    if (!IsSubTx(tx))
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-notsubtx");

    // first output must be OP_SUBSCRIPTION + data pushes only
    const CTxOut &subTxOut = tx.vout[0];
    if (subTxOut.scriptPubKey.size() < 2 || subTxOut.scriptPubKey[0] != OP_SUBSCRIPTION || !subTxOut.scriptPubKey.IsPushOnly(subTxOut.scriptPubKey.begin()+1)) {
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-opcode");
    }

    // remaining outputs must be standard (non-data) types
    for (size_t i = 1; i < tx.vout.size(); i++) {
        const CTxOut &txOut = tx.vout[i];

        txnouttype txType;
        std::vector <std::vector<unsigned char>> solutions;
        if (!Solver(txOut.scriptPubKey, txType, solutions)) {
            return state.DoS(10, false, REJECT_INVALID, "bad-subtx-badchange");
        }
        if (txType != TX_PUBKEY && txType != TX_PUBKEYHASH && txType != TX_SCRIPTHASH) {
            return state.DoS(10, false, REJECT_INVALID, "bad-subtx-badchange");
        }
    }

    std::vector<unsigned char> subTxData;
    if (!GetSubTxData(tx, subTxData, state))
        return false;

    // try to deserialize the data
    try {
        CSubTxData *p = CSubTxData::Deserialize(subTxData);
        if (!p)
            return state.DoS(10, false, REJECT_INVALID, "bad-subtx-data");
        delete p;
    } catch (...) {
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-data");
    }

    return true;
}

bool CheckSubTx(const CTransaction &tx, CValidationState &state) {
    // should never happen, but we want to be extra secure
    if (!IsSubTx(tx) || !IsSubTxDataValid(tx, state))
        return false;

    std::vector<unsigned char> subTxData;
    if (!GetSubTxData(tx, subTxData, state))
        return false;

    CSubTxData *p = CSubTxData::Deserialize(subTxData);
    assert(p); // previous validation should have handled this

    bool result = p->Check(tx, state);
    delete p;
    return result;
}

bool ProcessSubTx(const CTransaction &tx, CValidationState &state) {
    // should never happen, but we want to be extra secure
    if (!IsSubTx(tx) || !IsSubTxDataValid(tx, state))
        return false;

    std::vector<unsigned char> subTxData;
    if (!GetSubTxData(tx, subTxData, state))
        return false;

    CSubTxData *p = CSubTxData::Deserialize(subTxData);
    assert(p); // previous validation should have handled this

    bool result = p->Process(tx, state);
    delete p;
    return result;
}

bool UndoSubTx(const CTransaction &tx, CValidationState &state) {
    // should never happen, but we want to be extra secure
    if (!IsSubTx(tx) || !IsSubTxDataValid(tx, state))
        return false;

    std::vector<unsigned char> subTxData;
    if (!GetSubTxData(tx, subTxData, state))
        return false;

    CSubTxData *p = CSubTxData::Deserialize(subTxData);
    assert(p); // previous validation should have handled this

    bool result = p->Undo(tx, state);
    delete p;
    return result;
}

CSubTxData *CSubTxData::Deserialize(const std::vector<unsigned char> &data) {
    if (data.size() == 0)
        return nullptr;
    SubTxAction action = (SubTxAction)data[0];
    CDataStream ds(data, SER_DISK, CLIENT_VERSION);
    switch (action) {
        case SubTxAction_Register: {
            CSubTxRegister *p = new CSubTxRegister();
            ds >> *p;
            return p;
        }
        case SubTxAction_TopUp: {
            CSubTxTopUp *p = new CSubTxTopUp();
            ds >> *p;
            return p;
        }
        case SubTxAction_ResetKey: {
            CSubTxResetKey *p = new CSubTxResetKey();
            ds >> *p;
            return p;
        }
        case SubTxAction_Close: {
            CSubTxClose *p = new CSubTxClose();
            ds >> *p;
            return p;
        }
        default:
            LogPrintf("CSubTxData::Deserialize -- unknown or invalid action %d\n", action);
            return nullptr;
    }

    // should never get to this point
    return nullptr;
}

bool CSubTxRegister::Check(const CTransaction &subTx, CValidationState &state) {
    if (evoUserDB->UserNameExists(userName))
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-dupusername");

    if (subTx.vout[0].nValue < MIN_SUBTX_TOPUP)
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-lowtopup");

    CEvoUser dummyUser(subTx.GetHash(), userName, pubKey);

    std::string verifyError;
    if (!dummyUser.VerifySig(MakeSignMessage(), vchSig, verifyError))
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-sig", false, verifyError);

    // TODO check username and pubKey validity

    return true;
}

bool CSubTxRegister::Process(const CTransaction &subTx, CValidationState &state) {
    CEvoUser user(subTx.GetHash(), userName, pubKey);
    user.PushSubTx(subTx.GetHash());
    user.AddTopUp(subTx.vout[0].nValue);

    if (!evoUserDB->WriteUser(user)) {
        return state.Error(strprintf("CSubTxRegister::Process: failed to write user with name %s", userName));
    }
    return true;
}

bool CSubTxRegister::Undo(const CTransaction &subTx, CValidationState &state) {
    if (!evoUserDB->DeleteUser(subTx.GetHash())) {
        return state.Error(strprintf("CSubTxRegister::Undo: failed to delete user with name %s", userName));
    }
    return true;
}

std::string CSubTxRegister::MakeSignMessage() const {
    return "register|" + userName + "|" + pubKey.GetID().ToString();
}

bool CSubTxRegister::Sign(const CKey &key) {
    return CMessageSigner::SignMessage(MakeSignMessage(), vchSig, key);
}

bool CSubTxDataExistingUser::Check(const CTransaction &subTx, CValidationState &state) {
    CEvoUser user;
    if (!evoUserDB->GetUser(GetRegTxId(), user))
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-noaccount");
    if (user.IsClosed())
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-accountclosed");
    return Check(subTx, user, state);
}

bool CSubTxDataExistingUser::Process(const CTransaction &subTx, CValidationState &state) {
    CEvoUser user;
    if (!evoUserDB->GetUser(GetRegTxId(), user))
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-noaccount");
    if (user.IsClosed())
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-accountclosed");
    user.PushSubTx(subTx.GetHash());
    if (!Process(subTx, user, state))
        return false;
    if (!evoUserDB->WriteUser(user))
        return state.Error(strprintf("CSubTxDataExistingUser::Process: failed to write user with id %s", GetRegTxId().ToString()));
    return true;
}

bool CSubTxDataExistingUser::Undo(const CTransaction &subTx, CValidationState &state) {
    CEvoUser user;
    if (!evoUserDB->GetUser(GetRegTxId(), user))
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-noaccount");
    if (!Undo(subTx, user, state))
        return false;

    uint256 poppedId = user.PopSubTx();
    if (poppedId != subTx.GetHash()) {
        return state.Error(strprintf("CSubTxDataExistingUser::Process: popped subTxId %s is not expected id %s", poppedId.ToString(), subTx.GetHash().ToString()));
    }

    if (!evoUserDB->WriteUser(user))
        return state.Error(strprintf("CSubTxDataExistingUser::Process: failed to write user with id %s", GetRegTxId().ToString()));
    return true;
}

bool CSubTxTopUp::Check(const CTransaction &subTx, CEvoUser &user, CValidationState &state) {
    if (subTx.vout[0].nValue < MIN_SUBTX_TOPUP)
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-lowtopup");
    return true;
}

bool CSubTxTopUp::Process(const CTransaction &subTx, CEvoUser &user, CValidationState &state) {
    user.AddTopUp(subTx.vout[0].nValue);
    return true;
}

bool CSubTxTopUp::Undo(const CTransaction &subTx, CEvoUser &user, CValidationState &state) {
    user.AddTopUp(-subTx.vout[0].nValue);
    return true;
}

bool CSubTxResetKey::Check(const CTransaction &subTx, CEvoUser &user, CValidationState &state) {
    if (subTx.vout[0].nValue != 0)
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-nztopup");

    std::string verifyError;
    if (!user.VerifySig(MakeSignMessage(), lastPubkeySig, verifyError))
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-sig", false, verifyError);
    return true;
}

bool CSubTxResetKey::Process(const CTransaction &subTx, CEvoUser &user, CValidationState &state) {
    user.PushPubKey(newPubKey);
    return true;
}

bool CSubTxResetKey::Undo(const CTransaction &subTx, CEvoUser &user, CValidationState &state) {
    CPubKey k = user.PopPubKey();
    if (k != newPubKey) {
        return state.Error(strprintf("CSubTxResetKey::Undo: popped key %s != expected key %s", k.GetID().ToString(), newPubKey.GetID().ToString()));
    }
    return true;
}

std::string CSubTxResetKey::MakeSignMessage() const {
    return "resetkey|" + regTxId.ToString() + "|" + newPubKey.GetID().ToString();
}

bool CSubTxResetKey::Sign(const CKey &key) {
    return CMessageSigner::SignMessage(MakeSignMessage(), lastPubkeySig, key);
}

bool CSubTxClose::Check(const CTransaction &subTx, CEvoUser &user, CValidationState &state) {
    if (subTx.vout[0].nValue != 0)
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-nztopup");

    std::string verifyError;
    if (!user.VerifySig(MakeSignMessage(), lastPubkeySig, verifyError))
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-sig", false, verifyError);
    return true;
}

bool CSubTxClose::Process(const CTransaction &subTx, CEvoUser &user, CValidationState &state) {
    user.SetClosed(true);
    return true;
}

bool CSubTxClose::Undo(const CTransaction &subTx, CEvoUser &user, CValidationState &state) {
    if (!user.IsClosed())
        return state.Error(strprintf("CSubTxClose::Undo: expected account %s to be closed", GetRegTxId().ToString()));
    user.SetClosed(false);
    return true;
}

std::string CSubTxClose::MakeSignMessage() const {
    return "close|" + regTxId.ToString();
}

bool CSubTxClose::Sign(const CKey &key) {
    return CMessageSigner::SignMessage(MakeSignMessage(), lastPubkeySig, key);
}