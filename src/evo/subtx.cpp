// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tinyformat.h"

#include "specialtx.h"
#include "subtx.h"

UniValue CSubTxRegister::ToJson() const
{
    UniValue v(UniValue::VOBJ);
    v.push_back(Pair("unserName", userName));
    v.push_back(Pair("pubKeyId", pubKeyID.ToString()));
    v.push_back(Pair("vchSigSize", (int)vchSig.size()));
    return v;
}

UniValue CSubTxTopup::ToJson() const
{
    UniValue v(UniValue::VOBJ);
    v.push_back(Pair("regTxId", regTxId.ToString()));
    return v;
}

UniValue CSubTxResetKey::ToJson() const
{
    UniValue v(UniValue::VOBJ);
    v.push_back(Pair("regTxId", regTxId.ToString()));
    v.push_back(Pair("hashPrevSubTx", hashPrevSubTx.ToString()));
    v.push_back(Pair("creditFee", creditFee));
    v.push_back(Pair("newPubKeyId", newPubKeyId.ToString()));
    return v;
}

UniValue CSubTxCloseAccount::ToJson() const
{
    UniValue v(UniValue::VOBJ);
    v.push_back(Pair("regTxId", regTxId.ToString()));
    v.push_back(Pair("hashPrevSubTx", hashPrevSubTx.ToString()));
    v.push_back(Pair("creditFee", creditFee));
    return v;
}

UniValue CSubTxTransition::ToJson() const
{
    UniValue v(UniValue::VOBJ);
    v.push_back(Pair("regTxId", regTxId.ToString()));
    v.push_back(Pair("hashPrevSubTx", hashPrevSubTx.ToString()));
    v.push_back(Pair("creditFee", creditFee));
    v.push_back(Pair("hashSTPacket", hashSTPacket.ToString()));
    return v;
}

uint256 GetSubTxHashPrevSubTx(const CTransaction& tx)
{
    if (tx.nType == TRANSACTION_SUBTX_RESETKEY) {
        CSubTxResetKey subTx;
        GetTxPayloadAssert(tx, subTx);
        return subTx.hashPrevSubTx;
    } else if (tx.nType == TRANSACTION_SUBTX_CLOSEACCOUNT) {
        CSubTxCloseAccount subTx;
        GetTxPayloadAssert(tx, subTx);
        return subTx.hashPrevSubTx;
    } else if (tx.nType == TRANSACTION_SUBTX_TRANSITION) {
        CSubTxTransition subTx;
        GetTxPayloadAssert(tx, subTx);
        return subTx.hashPrevSubTx;
    }
    return uint256();
}
