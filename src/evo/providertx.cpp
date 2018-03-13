// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "providertx.h"
#include "specialtx.h"
#include "deterministicmns.h"

#include "hash.h"
#include "clientversion.h"
#include "streams.h"
#include "messagesigner.h"
#include "chainparams.h"
#include "validation.h"
#include "univalue.h"
#include "core_io.h"
#include "script/standard.h"
#include "base58.h"

template <typename ProTx>
static bool CheckService(const ProTx& proTx, const CBlockIndex* pindex, CValidationState& state)
{
    if (proTx.nProtocolVersion < MIN_EVO_PROTO_VERSION || proTx.nProtocolVersion > MAX_PROTX_PROTO_VERSION)
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-proto-version");

    if (!proTx.addr.IsValid() || (Params().NetworkIDString() != CBaseChainParams::REGTEST && !proTx.addr.IsRoutable()))
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-addr");
    if (Params().NetworkIDString() != CBaseChainParams::REGTEST && !proTx.addr.IsRoutable())
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-addr");

    if (pindex) {
        auto mnList = deterministicMNManager->GetListAtHeight(pindex->nHeight);
        for (const auto& dmn : mnList.all_range()) {
            if (dmn->state->addr == proTx.addr)
                return state.DoS(10, false, REJECT_DUPLICATE, "bad-protx-dup-addr");
        }
    }
    return true;
}

template <typename ProTx>
static bool CheckInputsHashAndSig(const CTransaction &tx, const ProTx& proTx, const CKeyID &keyID, CValidationState& state)
{
    uint256 inputsHash = CalcTxInputsHash(tx);
    if (inputsHash != proTx.inputsHash)
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-inputs-hash");

    std::string strError;
    if (!CHashSigner::VerifyHash(::SerializeHash(proTx), keyID, proTx.vchSig, strError))
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-sig", false, strError);

    return true;
}

bool CheckProRegTx(const CTransaction& tx, const CBlockIndex* pindex, CValidationState& state)
{
    AssertLockHeld(cs_main);

    CProRegTX ptx;
    if (!GetTxPayload(tx, ptx))
        return state.DoS(100, false, REJECT_INVALID, "bad-tx-payload");

    if (ptx.nVersion != CProRegTX::CURRENT_VERSION)
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-version");

    if (!CheckService(ptx, pindex, state))
        return false;

    if (ptx.nCollateralIndex >= tx.vout.size())
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-collateral-index");
    if (tx.vout[ptx.nCollateralIndex].nValue != 1000 * COIN)
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-collateral");
    if (ptx.keyIDOperator.IsNull())
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-key-operator");
    if (ptx.keyIDOwner.IsNull())
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-key-owner");
    // we may support P2SH later, but restrict it for now (while in transitioning phase from old MN list to deterministic list)
    if (!ptx.scriptPayout.IsPayToPublicKeyHash())
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-payee");

    CTxDestination payoutDest;
    if (!ExtractDestination(ptx.scriptPayout, payoutDest)) {
        // should not happen as we checked script types before
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-payee");
    }
    // don't allow reuse of keys for different purposes
    if (payoutDest == CTxDestination(ptx.keyIDOperator) || payoutDest == CTxDestination(ptx.keyIDOwner)) {
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-payee");
    }

    // This is a temporary restriction that will be lifted later
    // It is required while we are transitioning from the old MN list to the deterministic list
    if (tx.vout[ptx.nCollateralIndex].scriptPubKey != ptx.scriptPayout)
        return state.DoS(10, false, REJECT_INVALID, "bad-protx-payee-collateral");

    if (pindex) {
        auto mnList = deterministicMNManager->GetListAtHeight(pindex->nHeight);
        std::set<CKeyID> keyIDs;
        for (const auto& dmn : mnList.all_range()) {
            keyIDs.emplace(dmn->state->keyIDOperator);
            keyIDs.emplace(dmn->state->keyIDOwner);
        }
        if (keyIDs.count(ptx.keyIDOperator) || keyIDs.count(ptx.keyIDOwner)) {
            return state.DoS(10, false, REJECT_DUPLICATE, "bad-protx-dup-key");
        }

        if (ptx.keyIDOperator != ptx.keyIDOwner && !deterministicMNManager->IsDeterministicMNsSporkActive(pindex->nHeight)) {
            return state.DoS(10, false, REJECT_INVALID, "bad-protx-owner-key-not-same");
        }
    }

    if (!CheckInputsHashAndSig(tx, ptx, ptx.keyIDOwner, state))
        return false;

    return true;
}

bool CheckProUpServTx(const CTransaction& tx, const CBlockIndex* pindex, CValidationState& state)
{
    AssertLockHeld(cs_main);

    CProUpServTX ptx;
    if (!GetTxPayload(tx, ptx))
        return state.DoS(100, false, REJECT_INVALID, "bad-tx-payload");

    if (ptx.nVersion != CProRegTX::CURRENT_VERSION)
        return state.DoS(100, false, REJECT_INVALID, "bad-protx-version");

    if (!CheckService(ptx, pindex, state))
        return false;

    if (pindex) {
        auto mn = deterministicMNManager->GetMN(pindex->nHeight, ptx.proTxHash);
        if (!mn)
            return state.DoS(100, false, REJECT_INVALID, "bad-protx-hash");
        // we can only check the signature if pindex != NULL and the MN is known
        if (!CheckInputsHashAndSig(tx, ptx, mn->state->keyIDOperator, state))
            return false;
    }

    return true;
}

std::string CProRegTX::ToString() const
{
    CTxDestination dest;
    std::string payee = "unknown";
    if (ExtractDestination(scriptPayout, dest)) {
        payee = CBitcoinAddress(dest).ToString();
    }

    return strprintf("CProRegTX(nVersion=%d, nProtocolVersion=%d, nCollateralIndex=%d, addr=%s, keyIDOperator=%s, keyIDOwner=%s, scriptPayout=%s)",
        nVersion, nProtocolVersion, nCollateralIndex, addr.ToString(), keyIDOperator.ToString(), keyIDOwner.ToString(), payee);
}

void CProRegTX::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("version", nVersion));
    obj.push_back(Pair("protocolVersion", nProtocolVersion));
    obj.push_back(Pair("collateralIndex", (int)nCollateralIndex));
    obj.push_back(Pair("service", addr.ToString(false)));
    obj.push_back(Pair("keyIDOperator", keyIDOperator.ToString()));
    obj.push_back(Pair("keyIDOwner", keyIDOwner.ToString()));

    UniValue payoutObj(UniValue::VOBJ);
    payoutObj.push_back(Pair("scriptHex", HexStr(scriptPayout)));
    payoutObj.push_back(Pair("scriptAsm", ScriptToAsmStr(scriptPayout)));


    CTxDestination dest;
    if (ExtractDestination(scriptPayout, dest)) {
        CBitcoinAddress bitcoinAddress(dest);
        payoutObj.push_back(Pair("address", bitcoinAddress.ToString()));
    }

    obj.push_back(Pair("payout", payoutObj));
    obj.push_back(Pair("inputsHash", inputsHash.ToString()));
}

std::string CProUpServTX::ToString() const
{
    return strprintf("CProUpServTX(nVersion=%d, proTxHash=%s, nProtocolVersion=%d, addr=%s)",
                     nVersion, proTxHash.ToString(), nProtocolVersion, addr.ToString());
}

void CProUpServTX::ToJson(UniValue& obj) const
{
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("version", nVersion));
    obj.push_back(Pair("proTxHash", proTxHash.ToString()));
    obj.push_back(Pair("protocolVersion", nProtocolVersion));
    obj.push_back(Pair("service", addr.ToString(false)));
}

bool IsProTxCollateral(const CTransaction& tx, uint32_t n)
{
    return GetProTxCollateralIndex(tx) == n;
}

uint32_t GetProTxCollateralIndex(const CTransaction& tx)
{
    if (tx.nVersion < 3 || tx.nType != TRANSACTION_PROVIDER_REGISTER)
        return (uint32_t) - 1;
    CProRegTX proTx;
    if (!GetTxPayload(tx, proTx))
        assert(false);
    return proTx.nCollateralIndex;
}
