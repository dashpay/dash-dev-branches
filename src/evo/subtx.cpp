// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/validation.h"
#include "messagesigner.h"
#include "script/standard.h"
#include "tinyformat.h"
#include "univalue.h"

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

bool GetSubTxData(const CTransaction &tx, CSubTxData &subTxData) {
    std::vector<unsigned char> subTxData2;
    if (!GetSubTxData(tx.vout[0], subTxData2))
        return false;

    CDataStream ds(subTxData2, SER_NETWORK, CLIENT_VERSION);
    try {
        ds >> subTxData;
    } catch (...) {
        return false;
    }
    return true;
}

static bool CheckSubTxStructure(const CTransaction &tx, CValidationState &state) {
    if (!IsSubTx(tx))
        return state.DoS(100, false, REJECT_INVALID, "bad-subtx-notsubtx");

    if (tx.IsCoinBase()) {
        return state.DoS(100, false, REJECT_INVALID, "bad-subtx-cb");
    }

    // first output must be OP_SUBSCRIPTION + data pushes only
    const CTxOut &subTxOut = tx.vout[0];
    if (subTxOut.scriptPubKey.size() < 2 || subTxOut.scriptPubKey[0] != OP_SUBSCRIPTION || !subTxOut.scriptPubKey.IsPushOnly(subTxOut.scriptPubKey.begin()+1)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-subtx-opcode");
    }

    // remaining outputs must be standard (non-data) types
    for (size_t i = 1; i < tx.vout.size(); i++) {
        const CTxOut &txOut = tx.vout[i];

        txnouttype txType;
        std::vector <std::vector<unsigned char>> solutions;
        if (!Solver(txOut.scriptPubKey, txType, solutions)) {
            return state.DoS(100, false, REJECT_INVALID, "bad-subtx-badchange");
        }
        if (txType != TX_PUBKEY && txType != TX_PUBKEYHASH && txType != TX_SCRIPTHASH) {
            return state.DoS(100, false, REJECT_INVALID, "bad-subtx-badchange");
        }
    }

    std::vector<unsigned char> subTxData;
    if (!GetSubTxData(tx.vout[0], subTxData)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-subtx-data");
    }

    if (subTxData.size() > MAX_SUBTX_DATA_LEN) {
        return state.DoS(100, false, REJECT_INVALID, "bad-subtx-datalen");
    }

    return true;
}

bool CheckSubTx(const CTransaction &tx, CValidationState &state) {
    if (!CheckSubTxStructure(tx, state))
        return false;

    CSubTxData subTxData;
    if (!GetSubTxData(tx, subTxData))
        return state.DoS(100, false, REJECT_INVALID, "bad-subtx-data");

    return subTxData.Check(tx, state);
}

bool ProcessSubTx(const CTransaction &tx, CValidationState &state) {
    // should never happen, but we want to be extra secure
    if (!CheckSubTxStructure(tx, state))
        return false;

    CSubTxData subTxData;
    if (!GetSubTxData(tx, subTxData))
        return state.DoS(100, false, REJECT_INVALID, "bad-subtx-data");

    return subTxData.Process(tx, state);
}

bool UndoSubTx(const CTransaction &tx, CValidationState &state) {
    // should never happen, but we want to be extra secure
    if (!CheckSubTxStructure(tx, state))
        return false;

    CSubTxData subTxData;
    if (!GetSubTxData(tx, subTxData))
        return state.DoS(100, false, REJECT_INVALID, "bad-subtx-data");

    return subTxData.Undo(tx, state);
}

bool CheckSubTxsInBlock(const CBlock &block, CValidationState &state) {
    for (const CTransaction &tx : block.vtx) {
        if (!IsSubTx(tx))
            continue;
        if (!CheckSubTx(tx, state))
            return false;
    }
    return true;
}

bool ProcessSubTxsInBlock(const CBlock &block, CValidationState &state) {
    for (const CTransaction &tx : block.vtx) {
        if (!IsSubTx(tx))
            continue;
        if (!CheckSubTx(tx, state))
            return false;
        if (!ProcessSubTx(tx, state))
            return false;
    }
    return true;
}

bool UndoSubTxsInBlock(const CBlock &block, CValidationState &state) {
    for (int i = block.vtx.size() - 1; i >= 0; i--) {
        const CTransaction &tx = block.vtx[i];
        if (!IsSubTx(tx))
            continue;
        if (!UndoSubTx(tx, state))
            return false;
    }
    return true;
}

bool CSubTxData::Check(const CTransaction &tx, CValidationState &state) {
    switch (action) {
        case SubTxAction_Register:
            return CheckRegister(tx, state);
        case SubTxAction_TopUp:
            return CheckTopUp(tx, state);
        default:
            return state.DoS(100, false, REJECT_INVALID, "bad-subtx-action");
    }
}

bool CSubTxData::Process(const CTransaction &tx, CValidationState &state) {
    switch (action) {
        case SubTxAction_Register:
            return ProcessRegister(tx, state);
        case SubTxAction_TopUp:
            return ProcessTopUp(tx, state);
        default:
            return state.DoS(100, false, REJECT_INVALID, "bad-subtx-action");
    }
}

bool CSubTxData::Undo(const CTransaction &tx, CValidationState &state) {
    switch (action) {
        case SubTxAction_Register:
            return UndoRegister(tx, state);
        case SubTxAction_TopUp:
            return UndoTopUp(tx, state);
        default:
            return state.DoS(100, false, REJECT_INVALID, "bad-subtx-action");
    }
}


bool CSubTxData::CheckRegister(const CTransaction &subTx, CValidationState &state) const {
    if (evoUserDB->UserNameExists(userName))
        return state.DoS(100, false, REJECT_INVALID, "bad-subtx-dupusername");

    if (subTx.vout[0].nValue < MIN_SUBTX_TOPUP)
        return state.DoS(100, false, REJECT_INVALID, "bad-subtx-lowtopup");

    CEvoUser dummyUser(subTx.GetHash(), userName, pubKeyID);

    std::string verifyError;
    if (!dummyUser.VerifySig(MakeSignMessage(), vchSig, verifyError))
        return state.DoS(100, false, REJECT_INVALID, "bad-subtx-sig", false, verifyError);

    // TODO check username and pubKey validity

    return true;
}

bool CSubTxData::ProcessRegister(const CTransaction &subTx, CValidationState &state) const {
    CEvoUser user(subTx.GetHash(), userName, pubKeyID);

    user.PushSubTx(subTx.GetHash());
    user.AddTopUp(subTx.vout[0].nValue);

    if (!evoUserDB->WriteUser(user)) {
        return state.Error(strprintf("CSubTxRegister::Process: failed to write user with name %s", userName));
    }
    return true;
}

bool CSubTxData::UndoRegister(const CTransaction &subTx, CValidationState &state) const {
    if (!evoUserDB->DeleteUser(subTx.GetHash())) {
        return state.Error(strprintf("CSubTxRegister::Undo: failed to delete user with name %s", userName));
    }
    return true;
}

bool CSubTxData::CheckTopUp(const CTransaction &subTx, CValidationState &state) const {
    CEvoUser user;
    if (!evoUserDB->GetUser(regTxId, user))
        return state.DoS(100, false, REJECT_INVALID, "bad-subtx-noaccount");
    if (user.IsClosed())
        return state.DoS(100, false, REJECT_INVALID, "bad-subtx-accountclosed");

    if (subTx.vout[0].nValue < MIN_SUBTX_TOPUP)
        return state.DoS(100, false, REJECT_INVALID, "bad-subtx-lowtopup");

    return true;
}

bool CSubTxData::ProcessTopUp(const CTransaction &subTx, CValidationState &state) const {
    CEvoUser user;
    if (!evoUserDB->GetUser(regTxId, user))
        return state.DoS(100, false, REJECT_INVALID, "bad-subtx-noaccount");
    if (user.IsClosed())
        return state.DoS(100, false, REJECT_INVALID, "bad-subtx-accountclosed");

    user.PushSubTx(subTx.GetHash());
    user.AddTopUp(subTx.vout[0].nValue);

    if (!evoUserDB->WriteUser(user))
        return state.Error(strprintf("CSubTxDataExistingUser::Process: failed to write user with id %s", regTxId.ToString()));
    return true;
}

bool CSubTxData::UndoTopUp(const CTransaction &subTx, CValidationState &state) const {
    CEvoUser user;
    if (!evoUserDB->GetUser(regTxId, user))
        return state.DoS(100, false, REJECT_INVALID, "bad-subtx-noaccount");

    user.AddTopUp(-subTx.vout[0].nValue);

    uint256 poppedId = user.PopSubTx();
    if (poppedId != subTx.GetHash()) {
        return state.Error(strprintf("CSubTxDataExistingUser::Process: popped subTxId %s is not expected id %s", poppedId.ToString(), subTx.GetHash().ToString()));
    }

    if (!evoUserDB->WriteUser(user))
        return state.Error(strprintf("CSubTxDataExistingUser::Process: failed to write user with id %s", regTxId.ToString()));

    return true;
}


void CSubTxData::ToJSON(UniValue &uv) const {
    uv.setObject();
    switch (action) {
        case SubTxAction_Register:
            uv.push_back(Pair("action", "register"));
            uv.push_back(Pair("uname", userName));
            uv.push_back(Pair("pubkeyid", pubKeyID.ToString()));
            uv.push_back(Pair("vchSigSize", vchSig.size()));
            break;
        case SubTxAction_TopUp:
            uv.push_back(Pair("action", "topup"));
            uv.push_back(Pair("regtxid", regTxId.ToString()));
            break;
        default:
            uv.push_back(Pair("action", "invalid"));
            break;
    }
}

std::string CSubTxData::MakeSignMessage() const {
    switch (action) {
        case SubTxAction_Register:
            return "register|" + userName + "|" + pubKeyID.ToString();
        case SubTxAction_TopUp:
            // we don't do signing for topup
            return "";
        default:
            return "";
    }
}

bool CSubTxData::Sign(const CKey &key) {
    return CMessageSigner::SignMessage(MakeSignMessage(), vchSig, key);
}
