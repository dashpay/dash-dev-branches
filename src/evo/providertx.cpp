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

bool CheckProviderTxRegister(const CTransaction &tx, const CBlockIndex *pindex, CValidationState &state) {
    AssertLockHeld(cs_main);

    CProviderTXRegisterMN ptx;
    if (!GetTxPayload(tx, ptx))
        return state.DoS(100, false, REJECT_INVALID, "bad-tx-payload");

    if (ptx.nVersion != CProviderTXRegisterMN::CURRENT_VERSION)
        return state.DoS(100, false, REJECT_INVALID, "bad-provider-version");
    if (ptx.nProtocolVersion < MIN_EVO_PROTO_VERSION || ptx.nProtocolVersion > PROTOCOL_VERSION)
        return state.DoS(10, false, REJECT_INVALID, "bad-provider-proto-version");

    if (ptx.nCollateralIndex < 0 || ptx.nCollateralIndex >= tx.vout.size())
        return state.DoS(10, false, REJECT_INVALID, "bad-provider-collateral-index");
    if (tx.vout[ptx.nCollateralIndex].nValue != 1000 * COIN)
        return state.DoS(10, false, REJECT_INVALID, "bad-provider-collateral");
    if (!ptx.addr.IsValid() || (Params().NetworkIDString() != CBaseChainParams::REGTEST && !ptx.addr.IsRoutable()))
        return state.DoS(10, false, REJECT_INVALID, "bad-provider-addr");
    if (Params().NetworkIDString() != CBaseChainParams::REGTEST && !ptx.addr.IsRoutable())
        return state.DoS(10, false, REJECT_INVALID, "bad-provider-addr");
    if (ptx.keyIDMasternode.IsNull())
        return state.DoS(10, false, REJECT_INVALID, "bad-provider-mnkey");
    // we may support P2SH later, but restrict it for now (while in transitioning phase from old MN list to deterministic list)
    if (!ptx.scriptPayout.IsPayToPublicKey() && !ptx.scriptPayout.IsPayToPublicKeyHash())
        return state.DoS(10, false, REJECT_INVALID, "bad-provider-payee");

    // This is a temporary restriction that will be lifted later
    // It is required while we are transitioning from the old MN list to the deterministic list
    if (tx.vout[ptx.nCollateralIndex].scriptPubKey != ptx.scriptPayout)
        return state.DoS(10, false, REJECT_INVALID, "bad-provider-payee-collateral");

    uint256 inputsHash = CalcTxInputsHash(tx);
    if (inputsHash != ptx.inputsHash)
        return state.DoS(100, false, REJECT_INVALID, "bad-provider-inputs-hash");

    if (pindex) {
        auto mnList = deterministicMNList->GetListAtHeight(pindex->nHeight, true);
        for (const auto &dmn : mnList) {
            if (dmn.proTx.addr == ptx.addr)
                return state.DoS(10, false, REJECT_DUPLICATE, "bad-provider-dup-addr");
        }
    }

    CProviderTXRegisterMN tmpPtx(ptx);
    tmpPtx.vchSig.clear();

    std::string strError;
    if (!CHashSigner::VerifyHash(::SerializeHash(tmpPtx), ptx.keyIDMasternode, ptx.vchSig, strError))
        return state.DoS(100, false, REJECT_INVALID, "bad-provider-sig", false, strError);

    return true;
}

std::string CProviderTXRegisterMN::ToString() const {
    CTxDestination dest;
    std::string payee = "unknown";
    if (ExtractDestination(scriptPayout, dest)) {
        payee = CBitcoinAddress(dest).ToString();
    }

    return strprintf("CProviderTXRegisterMN(nVersion=%d, nProtocolVersion=%d, nCollateralIndex=%d, addr=%s, keyIDMasternode=%s, scriptPayout=%s)",
        nVersion, nProtocolVersion, nCollateralIndex, addr.ToString(), keyIDMasternode.ToString(), payee);
}

void CProviderTXRegisterMN::ToJson(UniValue &obj) {
    obj.clear();
    obj.setObject();
    obj.push_back(Pair("version", nVersion));
    obj.push_back(Pair("protocolVersion", nProtocolVersion));
    obj.push_back(Pair("collateralIndex", nCollateralIndex));
    obj.push_back(Pair("service", addr.ToString(false)));
    obj.push_back(Pair("keyIDMasternode", keyIDMasternode.ToString()));

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