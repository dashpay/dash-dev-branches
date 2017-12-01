// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tinyformat.h"

#include "specialtx.h"
#include "subtx.h"

UniValue CSubTxRegister::ToJson() const
{
    UniValue v(UniValue::VOBJ);
    v.push_back(Pair("txType", "subTxRegister"));
    v.push_back(Pair("version", nVersion));
    v.push_back(Pair("userName", userName));
    v.push_back(Pair("pubKeyId", pubKeyID.ToString()));
    return v;
}

UniValue CSubTxTopup::ToJson() const
{
    UniValue v(UniValue::VOBJ);
    v.push_back(Pair("txType", "subTxTopup"));
    v.push_back(Pair("version", nVersion));
    v.push_back(Pair("regTxId", regTxId.ToString()));
    return v;
}

UniValue CSubTxResetKey::ToJson() const
{
    UniValue v(UniValue::VOBJ);
    v.push_back(Pair("txType", "subTxResetKey"));
    v.push_back(Pair("version", nVersion));
    v.push_back(Pair("regTxId", regTxId.ToString()));
    v.push_back(Pair("hashPrevSubTx", hashPrevSubTx.ToString()));
    v.push_back(Pair("creditFee", creditFee));
    v.push_back(Pair("newPubKeyId", newPubKeyId.ToString()));
    return v;
}

UniValue CSubTxCloseAccount::ToJson() const
{
    UniValue v(UniValue::VOBJ);
    v.push_back(Pair("txType", "subTxCloseAccount"));
    v.push_back(Pair("version", nVersion));
    v.push_back(Pair("regTxId", regTxId.ToString()));
    v.push_back(Pair("hashPrevSubTx", hashPrevSubTx.ToString()));
    v.push_back(Pair("creditFee", creditFee));
    return v;
}

UniValue CSubTxTransition::ToJson() const
{
    UniValue v(UniValue::VOBJ);
    v.push_back(Pair("txType", "subTxTransition"));
    v.push_back(Pair("version", nVersion));
    v.push_back(Pair("regTxId", regTxId.ToString()));
    v.push_back(Pair("hashPrevSubTx", hashPrevSubTx.ToString()));
    v.push_back(Pair("creditFee", creditFee));
    v.push_back(Pair("hashSTPacket", hashSTPacket.ToString()));
    return v;
}

template<typename SubTx>
uint256 GetRegTxIdFromSubTxHelper(const CTransaction& tx)
{
    SubTx subTx;
    if (!GetTxPayload(tx, subTx)) {
        return uint256();
    }

    return subTx.regTxId;
}

uint256 GetRegTxIdFromSubTx(const CTransaction& tx)
{
    if (tx.nType == TRANSACTION_SUBTX_REGISTER) {
        return tx.GetHash();
    } else if (tx.nType == TRANSACTION_SUBTX_RESETKEY) {
        return GetRegTxIdFromSubTxHelper<CSubTxResetKey>(tx);
    } else if (tx.nType == TRANSACTION_SUBTX_CLOSEACCOUNT) {
        return GetRegTxIdFromSubTxHelper<CSubTxCloseAccount>(tx);
    } else if (tx.nType == TRANSACTION_SUBTX_TRANSITION) {
        return GetRegTxIdFromSubTxHelper<CSubTxTransition>(tx);
    }
    return uint256();
}

template<typename SubTx>
CAmount GetSubTxFeeHelper(const CTransaction& tx)
{
    SubTx subTx;
    if (!GetTxPayload(tx, subTx)) {
        return 0;
    }

    return subTx.creditFee;
}

CAmount GetSubTxFee(const CTransaction& tx)
{
    if (tx.nType == TRANSACTION_SUBTX_RESETKEY) {
        return GetSubTxFeeHelper<CSubTxResetKey>(tx);
    } else if (tx.nType == TRANSACTION_SUBTX_CLOSEACCOUNT) {
        return GetSubTxFeeHelper<CSubTxCloseAccount>(tx);
    } else if (tx.nType == TRANSACTION_SUBTX_TRANSITION) {
        return GetSubTxFeeHelper<CSubTxTransition>(tx);
    }
    return 0;
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

template<typename SubTx>
UniValue SubTxToJsonHelper(const CTransaction& tx)
{
    SubTx subTx;
    if (!GetTxPayload(tx, subTx)) {
        UniValue json(UniValue::VOBJ);
        json.push_back(Pair("error", "invalid tx payload"));
        return json;
    }

    return subTx.ToJson();
}

UniValue SubTxToJson(const CTransaction& tx)
{
    if (tx.nType == TRANSACTION_SUBTX_REGISTER) {
        return SubTxToJsonHelper<CSubTxRegister>(tx);
    } else if (tx.nType == TRANSACTION_SUBTX_RESETKEY) {
        return SubTxToJsonHelper<CSubTxResetKey>(tx);
    } else if (tx.nType == TRANSACTION_SUBTX_CLOSEACCOUNT) {
        return SubTxToJsonHelper<CSubTxCloseAccount>(tx);
    } else if (tx.nType == TRANSACTION_SUBTX_TRANSITION) {
        return SubTxToJsonHelper<CSubTxTransition>(tx);
    }

    UniValue json(UniValue::VOBJ);
    json.push_back(Pair("error", "unknown tx type"));
    return json;
}